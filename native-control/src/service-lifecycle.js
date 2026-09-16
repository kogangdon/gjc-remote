import path from 'node:path';
import { randomBytes } from 'node:crypto';
import {
  SERVICE_OPERATIONS,
  buildServiceCandidateProof,
  buildServiceFinalProof,
  buildServiceManifest,
  buildServiceManualCleanup,
  buildServiceOldProof,
  buildServicePlatformState,
  buildServiceReferenceRecord,
  buildServiceReferenceSlot,
  buildServiceResourceProof,
  buildServiceStatusReceipt,
  buildServiceTombstone,
  buildServiceTransaction,
  buildServiceTransitionProof,
  serviceConfigurationFingerprint,
  serviceKeyForTarget,
  serviceRolesFingerprint,
  validateServiceLifecycleRequest,
} from '@gjc-remote/shared/service-lifecycle-envelope';
import { canonicalJsonHash } from '@gjc-remote/shared/strict-json';

const MUTATIONS = new Set(['install', 'update', 'rollback', 'uninstall']);
const MANUAL_REASONS = new Set([
  'foreign-resource',
  'hybrid-proof',
  'recreated-resource',
  'torn-protected-state',
  'activation-drift',
  'ambiguous-process-tree',
  'process-tree-overflow',
  'incompatible-predecessor',
  'platform-evidence-gap',
]);
const HEX = /^[0-9a-f]{64}$/;
const NONCE = /^[0-9a-f]{32}$/;
const SAFE_ERROR_CODE = /^(?:SERVICE|DEPLOYMENT|NATIVE|RELEASE|INVENTORY)_[A-Z0-9_]{1,63}$/;
const plain = (v) => v !== null && typeof v === 'object' && !Array.isArray(v) && Object.getPrototypeOf(v) === Object.prototype;
const hash = (v) => canonicalJsonHash(v);

function fail(code, operation, writes = 0, cause) {
  const error = new Error(`${operation} failed`);
  error.name = 'ServiceLifecycleError'; error.code = code; error.operation = operation;
  error.writes = Number.isSafeInteger(writes) && writes >= 0 ? writes : 0;
  if (cause !== undefined) error.cause = cause;
  throw error;
}
function required(object, name, operation, ...args) {
  if (!object || typeof object[name] !== 'function') fail('SERVICE_INVALID', operation);
  return object[name](...args);
}
async function requiredAsync(object, name, operation, ...args) {
  return Promise.resolve(required(object, name, operation, ...args));
}
function writesOf(session, driver) {
  return (Number.isSafeInteger(session?.writes) ? session.writes : 0) +
    (Number.isSafeInteger(driver?.writes) ? driver.writes : 0);
}
function nonce() { return randomBytes(16).toString('hex'); }
function validHash(v) { return typeof v === 'string' && HEX.test(v); }
function validAbsoluteEntrypoint(v, platform) {
  return typeof v === 'string' && v.length > 0 &&
    (platform === 'win32' ? /^(?:[A-Za-z]:[\\/]|\\\\)/.test(v) : v.startsWith('/'));
}
function validNonce(v) { return typeof v === 'string' && NONCE.test(v); }
function same(left, right) { try { return hash(left) === hash(right); } catch { return false; } }
function safeErrorCode(error) {
  try {
    const code = error?.code;
    return typeof code === 'string' && SAFE_ERROR_CODE.test(code) ? code : null;
  } catch { return null; }
}
function safeErrorAmbiguous(error) {
  try { return error?.ambiguous === true; } catch { return false; }
}
function safeErrorReason(error) {
  try {
    const reason = error?.reason;
    return typeof reason === 'string' ? reason : null;
  } catch { return null; }
}

function bootFingerprint(platform, bootId) {
  return typeof bootId === 'string' && bootId.length > 0
    ? hash({ kind: `${platform === 'win32' ? 'windows' : 'linux'}-boot/v1`, bootId })
    : null;
}

// Linux's native resource fingerprint is a hash of the complete descriptor
// (unit/drop-in bytes, enablement link, and manager state).  The Linux driver
// also needs the hash of the primary unit/drop-in bytes for its on-disk CAS;
// these are deliberately different authorities.
function rawResourceSha256(probe, component) {
  const descriptor = probe?.resourceDescriptor;
  if (!plain(descriptor)) return null;
  const field = component === 'bot' ? 'botUnitSha256' : 'dropinSha256';
  const value = descriptor[field];
  return value === null || value === undefined ? null : validHash(value) ? value : null;
}

function releaseFingerprint(value) {
  return value?.applicationManifestFingerprint ?? value?.manifestFingerprint ??
    value?.manifest?.manifestFingerprint ?? null;
}

/* Deployment manifests carry component-relative entrypoints.  A publication
 * receipt may expose its absolute root under publishedPath; a pre-normalized
 * absolute entrypoint is accepted for retained deployments.  Relative paths
 * without an authenticated publication root are refused before the first
 * store write. */
function normalizeEntrypoint(value, component, publication, platform) {
  const manifest = value?.manifest ?? value?.application ?? value?.applicationManifest ?? value;
  const configured = value?.entrypointPath ?? manifest?.entrypointPath ??
    manifest?.entrypoints?.[component] ?? manifest?.configuration?.entrypointPath;
  if (typeof configured !== 'string' || configured.length === 0) fail('SERVICE_INVALID', 'acquire_release');
  const isAbsolute = platform === 'win32' ? /^(?:[A-Za-z]:[\\/]|\\\\)/.test(configured) : configured.startsWith('/');
  if (isAbsolute) return configured;
  // A relative entrypoint is meaningful only after publication has returned
  // an authenticated root binding.  Never resolve it against a manifest path
  // or the controller's cwd: those values are not proof of the installed
  // release directory.
  const root = publication?.publishedPath;
  if (!validAbsoluteEntrypoint(root, platform)) fail('SERVICE_PENDING', 'acquire_release');
  const resolved = platform === 'win32'
    ? path.win32.resolve(root, configured.replaceAll('/', '\\'))
    : path.posix.resolve(root, configured);
  const prefix = platform === 'win32' ? path.win32.resolve(root) : path.posix.resolve(root);
  const folded = platform === 'win32' ? resolved.toLowerCase() : resolved;
  const foldedPrefix = platform === 'win32' ? prefix.toLowerCase() : prefix;
  if (folded !== foldedPrefix && !folded.startsWith(`${foldedPrefix}${platform === 'win32' ? '\\' : '/'}`)) fail('SERVICE_INVALID', 'acquire_release');
  return resolved;
}

function normalizeRelease(value, request, platform, publication = null) {
  if (!plain(value)) fail('SERVICE_INVALID', 'acquire_release');
  const manifest = value.manifest ?? value.application ?? value.applicationManifest ?? value;
  const applicationManifestFingerprint = releaseFingerprint(value) ?? releaseFingerprint(manifest);
  const shawl = value.shawlManifest ?? value.shawl?.manifest ?? null;
  const shawlManifestFingerprint = value.shawlManifestFingerprint ?? shawl?.manifestFingerprint ?? null;
  const compatibilityFingerprint = value.compatibilityFingerprint ?? manifest.compatibilityFingerprint ??
    (manifest.compatibility ? hash(manifest.compatibility) : null);
  const releaseSequence = value.releaseSequence ?? manifest.releaseSequence;
  const releaseTreeFingerprint = value.releaseTreeFingerprint ?? manifest.inventory?.treeFingerprint ?? manifest.releaseTreeFingerprint;
  if (!validHash(applicationManifestFingerprint) || (platform === 'win32' && !validHash(shawlManifestFingerprint)) ||
      !Number.isSafeInteger(releaseSequence) || releaseSequence < 1 || !validHash(releaseTreeFingerprint) ||
      !validHash(compatibilityFingerprint)) fail('SERVICE_INVALID', 'acquire_release');
  const entrypointPath = normalizeEntrypoint(value, request.target.component, publication, platform);
  return Object.freeze({
    manifest, shawlManifest: shawl, applicationManifestFingerprint, shawlManifestFingerprint,
    releaseSequence, releaseTreeFingerprint, compatibilityFingerprint, entrypointPath,
  });
}

function authenticatedOldRelease(session, manifest, platform, operation) {
  if (platform !== 'win32' || !manifest?.present) return null;
  if (typeof session?.readRetainedDeploymentEnvelope !== 'function') fail('SERVICE_PENDING', operation);
  const retained = required(session, 'readRetainedDeploymentEnvelope', operation, {
    purpose: 'application', manifestFingerprint: manifest.value.applicationManifestFingerprint,
  });
  const signed = retained?.manifest;
  const entrypointPath = signed?.entrypointPath ?? signed?.entrypoints?.[manifest.value.component];
  if (!validHash(manifest.value.applicationManifestFingerprint) ||
      !validAbsoluteEntrypoint(entrypointPath, platform) ||
      signed?.manifestFingerprint !== manifest.value.applicationManifestFingerprint) {
    fail('SERVICE_PENDING', operation);
  }
  return { entrypointPath, applicationManifestFingerprint: manifest.value.applicationManifestFingerprint };
}

function oldProof(receipt, platform) {
  if (!receipt?.present) return buildServiceOldProof({ disposition: 'absent', manifestFingerprint: null, resourceProof: null, applicationManifestFingerprint: null, shawlManifestFingerprint: null, serviceGeneration: 0, activation: 'disabled-not-startable' }, platform);
  const value = receipt.value;
  return buildServiceOldProof({ disposition: 'stable', manifestFingerprint: value.manifestFingerprint, resourceProof: value.resourceProof, applicationManifestFingerprint: value.applicationManifestFingerprint, shawlManifestFingerprint: value.shawlManifestFingerprint ?? null, serviceGeneration: value.serviceGeneration, activation: 'enabled' }, platform);
}
function candidateProof(release, platform, uninstall = false) {
  return buildServiceCandidateProof(uninstall
    ? { disposition: 'none', applicationManifestFingerprint: null, shawlManifestFingerprint: null, releaseSequence: 0, releaseTreeFingerprint: null, compatibilityFingerprint: null }
    : { disposition: 'release', applicationManifestFingerprint: release.applicationManifestFingerprint, shawlManifestFingerprint: release.shawlManifestFingerprint, releaseSequence: release.releaseSequence, releaseTreeFingerprint: release.releaseTreeFingerprint, compatibilityFingerprint: release.compatibilityFingerprint }, platform);
}
function phaseState(platform, phase) { return buildServicePlatformState(platform, phase); }
function receiptPublication(publication) {
  if (!publication) return null;
  if (Array.isArray(publication.artifacts)) return publication.artifacts;
  if (publication.binding) return [publication.binding];
  if (publication.kind === 'service-artifact-binding') return [publication];
  return null;
}
function combinePublications(...publications) {
  const artifacts = publications.flatMap((publication) => receiptPublication(publication) ?? []);
  return artifacts.length === 0 ? null : { artifacts };
}
function referencesFor(tx, current, previous, provisional = null) {
  const slot = (entry, publication) => {
    if (!entry) return null;
    const artifacts = receiptPublication(publication);
    if (!artifacts || artifacts.length === 0) fail('SERVICE_PENDING', 'publish_references');
    if (tx.platform === 'win32' && entry === current?.value) {
      const kinds = new Set(artifacts.map((artifact) => artifact.artifactKind));
      if (!kinds.has('application') || !kinds.has('shawl')) fail('SERVICE_PENDING', 'publish_references');
    }
    if (tx.platform === 'linux' && tx.component === 'daemon' &&
        !artifacts.some((artifact) => artifact.artifactKind === 'shared-template')) {
      fail('SERVICE_PENDING', 'publish_references');
    }
    return buildServiceReferenceSlot({
      serviceGeneration: entry.serviceGeneration,
      // Rotating current to previous retains the original transaction
      // identity; the successor transaction owns only the new current slot.
      transactionId: entry.transactionId ?? tx.transactionId,
      transactionNonce: entry.transactionNonce ?? tx.transactionNonce,
      artifacts,
    }, { platform: tx.platform, component: tx.component });
  };
  return buildServiceReferenceRecord({ serviceKey: tx.serviceKey, component: tx.component, platform: tx.platform, architecture: tx.architecture, serviceGeneration: tx.serviceGeneration, current: slot(current?.value, current?.publication), previous: slot(previous?.value, previous?.publication), provisional: slot(provisional?.value, provisional?.publication) });
}
function startupEvidenceFromProof(startup, probe, manifest, resource, platform, ownership, service, tree, now) {
  if (ownership === 'absent') return 'none';
  if (!startup?.present || !plain(startup.value)) return 'unavailable';
  const proof = startup.value;
  const bindsCurrent = ownership === 'owned' &&
    proof.serviceGeneration === manifest.serviceGeneration &&
    proof.resourceProof === resource.resourceProof &&
    proof.applicationManifestFingerprint === manifest.applicationManifestFingerprint;
  if (!bindsCurrent || (probe.platformPhase ?? probe.platformState?.phase) === 'absent') return 'invalidated';
  const currentBoot = bootFingerprint(platform, probe.bootId);
  if (currentBoot !== null && proof.bootFingerprint !== currentBoot) return 'invalidated';
  if (service === 'running' && tree === 'exact-current' && Number.isSafeInteger(now) && now <= proof.expiresAtMs) {
    return 'fresh-current-epoch';
  }
  return 'historical-current-epoch';
}
function statusFromProbe(probe, manifest, resource, platform, architecture, now, recovery = 'clean', tx = null, startup = null) {
  if (!plain(probe)) fail('SERVICE_INVALID', 'probe_status');
  const durable = validHash(manifest?.manifestFingerprint) && validHash(resource?.resourceProof) &&
    manifest.resourceProof === resource.resourceProof;
  const observedPhase = probe.platformPhase ?? probe.platformState?.phase;
  const physicalAbsent = observedPhase === 'absent';
  const resourceMatches = validHash(probe.resourceFingerprint) &&
    validHash(resource?.platformResourceFingerprint) &&
    probe.resourceFingerprint === resource.platformResourceFingerprint;
  const explicitOwnership = ['absent', 'owned', 'foreign', 'ambiguous'].includes(probe.ownership)
    ? probe.ownership : null;
  // A missing native resource alongside durable O/R metadata is not a clean
  // absence: it is a torn or manually altered installation.  Only an empty
  // store (or a durable uninstalled state with no current records) is absent.
  const ownership = durable
    ? (explicitOwnership === 'foreign' ? 'foreign' :
      explicitOwnership === 'ambiguous' || explicitOwnership === 'absent' ? 'ambiguous' :
      resourceMatches && !physicalAbsent && !probe.driftReasons?.length ? 'owned' : 'ambiguous')
    : (explicitOwnership === 'foreign' || explicitOwnership === 'ambiguous'
      ? explicitOwnership : recovery !== 'clean' ? 'ambiguous' : physicalAbsent ? 'absent' : 'foreign');
  const serviceSnapshot = plain(probe.service) ? probe.service : null;
  const serviceState = typeof probe.service === 'string' ? probe.service :
    serviceSnapshot?.runtime?.state;
  const service = ['running', 'stopped', 'missing', 'transitioning', 'unknown'].includes(serviceState)
    ? serviceState
    : physicalAbsent ? 'missing' :
      ['trial', 'final-restart-armed'].includes(observedPhase) ? 'transitioning' :
      ['final', 'final-auto'].includes(observedPhase) ? 'running' : 'unknown';
  const platformActivation = plain(probe.platformState) ? probe.platformState.activation : null;
  const phaseActivation = ['final', 'final-auto'].includes(observedPhase) ? 'enabled' :
    ['trial', 'final-restart-armed'].includes(observedPhase) ? 'suppressed-controller-startable' :
    observedPhase === 'created-protected' ? 'disabled-not-startable' : null;
  const activation = ['enabled', 'suppressed-controller-startable', 'disabled-not-startable', 'drifted', 'unknown'].includes(probe.activation)
    ? probe.activation
    : ['enabled', 'suppressed-controller-startable', 'disabled-not-startable', 'drifted', 'unknown'].includes(platformActivation)
      ? platformActivation
      : phaseActivation ?? (physicalAbsent ? 'disabled-not-startable' : 'unknown');
  const treeObservation = probe.tree ?? probe.process?.tree;
  const tree = ['empty', 'exact-current', 'ambiguous', 'overflow', 'unknown'].includes(treeObservation)
    ? treeObservation
    : treeObservation?.processCount === 0 ? 'empty'
      : plain(treeObservation) && validHash(treeObservation.treeFingerprint) ? 'exact-current'
        : physicalAbsent ? 'empty' : 'unknown';
  if (['ambiguous', 'foreign'].includes(ownership) && recovery === 'clean') recovery = 'manual-cleanup';
  const startupEvidence = startupEvidenceFromProof(startup, probe, manifest, resource, platform, ownership, service, tree, now);
  return Object.freeze({ ...buildServiceStatusReceipt({
    component: manifest.component, serviceKey: manifest.serviceKey, platform, architecture,
    serviceGeneration: ownership === 'owned' ? manifest.serviceGeneration : 0,
    manifestFingerprint: ownership === 'owned' ? manifest.manifestFingerprint : null,
    resourceProof: ownership === 'owned' ? resource.resourceProof : null,
    transactionFingerprint: recovery === 'pending' ? tx?.transactionFingerprint ?? null : null,
    ownership, service, activation, tree,
    startupEvidence,
    connectivityObservation: probe.connectivityObservation ?? 'unknown', providerHealth: 'unknown', workspaceHealth: 'unknown',
    supervisorProvenance: platform === 'linux' ? 'not-applicable' : (ownership === 'owned' ? 'project-attested-unsigned-upstream' : 'unknown'),
    recovery, observedAtMs: now,
  }), writes: 0 });
}

export class ServiceLifecycle {
  #options;
  constructor(options = {}) { if (!plain(options)) fail('SERVICE_INVALID', 'create_service_lifecycle'); this.#options = Object.freeze({ ...options }); }
  #platform(request) { return this.#options.platform ?? request?.platform ?? process.platform; }
  #architecture(request) { return this.#options.architecture ?? request?.architecture ?? (process.arch === 'arm64' ? 'arm64' : 'x64'); }
  #preflight(operation, request) {
    if (!this.#options.store) fail('SERVICE_INVALID', 'open_service_store');
    // Status is probe-only.  Its store may be absent, and driver construction
    // is deferred until an existing session proves that a probe is needed.
    if (operation !== 'status' && !this.#options.driver && typeof this.#options.createDriver !== 'function') fail('SERVICE_INVALID', 'create_service_driver');
    if (MUTATIONS.has(operation)) {
      if (!this.#options.native) fail('SERVICE_INVALID', 'create_service_driver');
      if (operation !== 'uninstall' && typeof this.#options.observeApplication !== 'function') fail('SERVICE_INVALID', 'run_startup_gate');
      if (operation === 'install' || operation === 'update') {
        if (!this.#options.acquisition && typeof this.#options.createAcquisition !== 'function') fail('SERVICE_INVALID', 'create_service_acquisition');
        if (typeof this.#options.compatibility !== 'function') fail('SERVICE_INVALID', 'verify_compatibility');
      }
      if (operation !== 'uninstall' && typeof this.#options.planResource !== 'function') fail('SERVICE_INVALID', 'plan_resource');
    }
    // Recovery is classified against the durable journal before any edge is
    // replayed. Authorities are gated after classification so unknown/manual
    // outcomes remain write-free while continuation paths fail closed before
    // their first journal or native write.
    if (operation === 'recover' && !this.#options.native) fail('SERVICE_INVALID', 'create_service_driver');
    void request;
  }
  #open(mode, request) {
    const source = this.#options.store;
    if (typeof source === 'function') return source({ mode, request });
    const method = mode === 'read-only' ? 'openReadOnly' : mode === 'recovery' ? 'openRecovery' : 'openMutation';
    return required(source, method, 'open_service_store', request);
  }
  async #driver(session, request, release) {
    if (!this.#options.driver && typeof this.#options.createDriver !== 'function') fail('SERVICE_INVALID', 'create_service_driver');
    const context = { session, request, release, native: this.#options.native };
    if (typeof session?.handoffDriverLocks === 'function') {
      context.locks = required(session, 'handoffDriverLocks', 'handoff_driver_locks');
    } else if (typeof this.#options.createDriver === 'function' || typeof this.#options.driver === 'function') {
      fail('SERVICE_INVALID', 'handoff_driver_locks');
    }
    const driver = typeof this.#options.driver === 'function' ? await this.#options.driver(context) : this.#options.driver ?? await this.#options.createDriver(context);
    if (!driver || typeof driver !== 'object') fail('SERVICE_INVALID', 'create_service_driver');
    return driver;
  }
  async #acquisition(session, request) {
    const sourceDescription = request.source ?? this.#options.recoverySource;
    const native = sourceDescription?.kind === 'github-release' ? null : this.#options.native;
    const acquisition = typeof this.#options.acquisition === 'function'
      ? await this.#options.acquisition({ session, request, native, source: sourceDescription })
      : this.#options.acquisition ?? await this.#options.createAcquisition({ session, request, native, source: sourceDescription });
    if (!acquisition || typeof acquisition.readManifests !== 'function' || typeof acquisition.reserve !== 'function' || typeof acquisition.publish !== 'function' || typeof acquisition.close !== 'function') fail('SERVICE_INVALID', 'create_service_acquisition');
    return acquisition;
  }
  #recoveryAuthorities(classifier, phase, operation) {
    if (classifier === 'manual-cleanup' || classifier === 'not-in-trial') return;
    const acquisitionPhase = phase === 'prepared' || phase === 'sequence-reserved';
    const trialContinuation = operation !== 'uninstall' &&
      ['continue', 'resume', 'retrial', 'stop-and-retrial', 'resuppress-and-retrial', 'stop-and-continue', 'resume-activation'].includes(classifier);
    if (acquisitionPhase && (!this.#options.acquisition && typeof this.#options.createAcquisition !== 'function')) fail('SERVICE_PENDING', 'recover');
    if (trialContinuation && typeof this.#options.observeApplication !== 'function') fail('SERVICE_PENDING', 'recover');
    if (acquisitionPhase && typeof this.#options.compatibility !== 'function') fail('SERVICE_PENDING', 'recover');
  }
  #append(session, tx, phase, substep) {
    const journal = required(session, 'readJournal', 'read_service_journal');
    const previous = journal.entries.at(-1);
    return required(session, 'appendJournal', 'append_service_journal', buildServiceTransaction({ ...tx, phase, substep, previousJournalFingerprint: previous?.transactionFingerprint ?? tx.previousJournalFingerprint ?? null }));
  }
  async #persistManual(session, tx, operation, error, driver) {
    // A failed manual marker publication leaves the transaction ambiguous. Do
    // not let that secondary failure disappear behind the original error: the
    // caller must receive a bounded manual-cleanup refusal instead.
    const persistFailure = () => {
      const sanitized = new Error(`${operation} failed`);
      sanitized.name = 'ServiceLifecycleError';
      sanitized.code = 'SERVICE_MANUAL_CLEANUP';
      sanitized.operation = operation;
      sanitized.writes = writesOf(session, driver);
      sanitized.ambiguous = true;
      throw sanitized;
    };
    if (!tx || typeof session?.publishManualCleanup !== 'function') return persistFailure();
    const code = safeErrorCode(error);
    const requestedReason = safeErrorReason(error);
    // Native drivers use more detailed drift labels than the shared envelope
    // permits. Preserve recognized reasons and classify every other mismatch
    // as an evidence gap rather than constructing an invalid record.
    let reason = 'platform-evidence-gap';
    if (MANUAL_REASONS.has(requestedReason)) reason = requestedReason;
    else if (requestedReason === null && code === 'SERVICE_ACCESS_DENIED') reason = 'foreign-resource';
    else if (requestedReason === null && safeErrorAmbiguous(error)) reason = 'ambiguous-process-tree';
    const action = reason === 'foreign-resource'
      ? 'remove-foreign-activation'
      : ['ambiguous-process-tree', 'process-tree-overflow'].includes(reason)
        ? 'quiesce-recorded-process-tree'
        : reason === 'recreated-resource'
          ? 'remove-unmarked-resource'
          : reason === 'incompatible-predecessor'
            ? 'restore-recorded-predecessor'
            : 'repair-protected-control-store';
    try {
      const observed = typeof driver?.probe === 'function' ? driver.probe() : null;
      const latest = session.readJournal().entries.at(-1) ?? tx;
      const record = buildServiceManualCleanup({ component: tx.component, serviceKey: tx.serviceKey, platform: tx.platform, architecture: tx.architecture, serviceGeneration: tx.serviceGeneration, transactionId: tx.transactionId, journalFingerprint: latest.transactionFingerprint, phase: latest.phase, reason, operatorAction: action, expectedDisposition: tx.old.disposition === 'absent' ? 'absent' : 'stable-old', expectedOldProofFingerprint: tx.old.oldFingerprint, observedDisposition: observed?.ownership === 'foreign' ? 'foreign' : observed?.tree === 'ambiguous' ? 'ambiguous' : 'hybrid', observedFingerprint: validHash(observed?.resourceFingerprint) ? observed.resourceFingerprint : null, blockedUntilOperatorAction: true });
      const expected = required(session, 'readManualCleanup', 'read_manual_cleanup');
      const published = await Promise.resolve(session.publishManualCleanup(record, expected));
      // The native store returns a receipt. Treat an absent, malformed, or
      // mismatched receipt as a persistence failure; otherwise callers could
      // report the original operation while no durable manual marker exists.
      if (!plain(published) || published.present !== true || !plain(published.value) ||
          published.value.manualCleanupFingerprint !== record.manualCleanupFingerprint ||
          !same(published.value, record)) {
        return persistFailure();
      }
    } catch {
      return persistFailure();
    }
  }
  async #mutate(operation, request) {
    const platform = this.#platform(request); const architecture = this.#architecture(request);
    try { validateServiceLifecycleRequest(operation, request, { platform, architecture }); } catch (error) { fail('SERVICE_INVALID', operation, 0, error); }
    this.#preflight(operation, request);
    const session = this.#open('mutation', request); let driver = null; let acquisition = null; let tx = null;
    try {
      if (!session || session.component !== request.target.component || session.platform !== platform || session.architecture !== architecture || session.serviceKey !== serviceKeyForTarget(request.target)) fail('SERVICE_SCOPE_MISMATCH', 'open_service_store');
      const current = required(session, 'readManifest', 'read_manifest', 'current');
      const currentResource = required(session, 'readResourceProof', 'read_resource_proof', 'current');
      const references = required(session, 'readReferences', 'read_references');
      const journal = required(session, 'readJournal', 'read_service_journal');
      const manual = required(session, 'readManualCleanup', 'read_manual_cleanup');
      const startup = required(session, 'readStartupProof', 'read_startup_proof');
      // Compare both sequence floors while the session still has the
      // artifact fence and before constructing a driver or appending the
      // prepared journal edge.
      // Rollback has no caller-supplied floor CAS: its retained publication
      // and the current stable floor witness are admitted together by the
      // store's rollback assertion below.  Do not manufacture a floor CAS
      // from undefined request fields (or mutate a journal before that
      // admission succeeds).
      let floorCas = null;
      if (operation !== 'rollback') {
        const floorInput = { applicationSequenceFloor: request.expected.applicationSequenceFloor };
        if (platform === 'win32') floorInput.shawlSequenceFloor = request.expected.shawlSequenceFloor;
        floorCas = required(session, 'assertFloorCas', 'assert_floor_cas', floorInput);
        if (!plain(floorCas) || !plain(floorCas.application) || !plain(floorCas.application.floor) ||
            !Number.isSafeInteger(floorCas.application.floor.committedSequence) ||
            (platform === 'win32' && (!plain(floorCas.shawl) || !plain(floorCas.shawl.floor) ||
              !Number.isSafeInteger(floorCas.shawl.floor.committedSequence)))) {
          fail('SERVICE_PENDING', operation);
        }
      }
      const siblings = platform === 'linux'
        ? required(session, 'readSiblingReferences', 'read_sibling_references')
        : [];
      if (typeof session.acceptProvisionalMetadata !== 'function' ||
          typeof session.publishCurrentMetadata !== 'function') {
        fail('SERVICE_INVALID', operation);
      }
      if (manual.present || journal.pending !== null || (journal.entries.at(-1) && journal.entries.at(-1).phase !== 'committed')) fail(manual.present ? 'SERVICE_MANUAL_CLEANUP' : 'SERVICE_PENDING', operation);
      // The store binds roles/configuration in every durable manifest.  Check
      // that authority before constructing a driver or appending `prepared`.
      const requestedRolesFingerprint = serviceRolesFingerprint(request.roles, platform);
      if (current.present && (current.value.rolesFingerprint !== requestedRolesFingerprint ||
          !same(current.value.roles, request.roles))) fail('SERVICE_SCOPE_MISMATCH', operation);
      const oldManifest = current.present ? current.value : { serviceGeneration: 0, manifestFingerprint: null, applicationManifestFingerprint: null, shawlManifestFingerprint: null, component: request.target.component, serviceKey: session.serviceKey, platform, architecture, configuration: request.configuration };
      const driverRequest = request.configuration ? request : { ...request, configuration: oldManifest.configuration };
      if (!driverRequest.configuration) fail('SERVICE_SCOPE_MISMATCH', operation);
      const boundConfigurationFingerprint = serviceConfigurationFingerprint(driverRequest.configuration, { component: request.target.component, platform });
      if (current.present && current.value.configurationFingerprint !== boundConfigurationFingerprint) fail('SERVICE_SCOPE_MISMATCH', operation);
      if (currentResource.present && (currentResource.value.rolesFingerprint !== requestedRolesFingerprint || currentResource.value.configurationFingerprint !== boundConfigurationFingerprint)) fail('SERVICE_SCOPE_MISMATCH', operation);
      const oldResource = currentResource.present ? currentResource.value : { resourceProof: null, platformResourceFingerprint: null };
      const old = oldProof(current, platform);
      if (operation === 'install' ? (old.disposition !== 'absent' || request.expected.serviceGeneration !== 0 || request.expected.resourceProof !== null) : (old.disposition !== 'stable' || request.expected.serviceGeneration !== old.serviceGeneration || request.expected.resourceProof !== old.resourceProof || (request.expected.currentManifestFingerprint && request.expected.currentManifestFingerprint !== old.manifestFingerprint))) fail('SERVICE_STALE', operation);
      let release = null; let publicationResult = null; let previousEntry = null;
      if (operation === 'rollback') {
        if (!request.expected.predecessorManifestFingerprint || !references.present || !references.value?.previous) fail('SERVICE_STALE', operation);
        previousEntry = references.value.previous;
        const retained = required(session, 'readRetainedDeploymentEnvelope', 'read_retained_deployment_envelope', { purpose: 'application', manifestFingerprint: request.expected.predecessorManifestFingerprint });
        const retainedManifest = retained?.manifest;
        if (!retainedManifest || retainedManifest.manifestFingerprint !== request.expected.predecessorManifestFingerprint) fail('SERVICE_SCOPE_MISMATCH', operation);
        const previousApplicationPublication = required(session, 'readPublicationReceipt', 'read_publication_receipt', { slot: 'previous', artifactKind: 'application' });
        if (typeof session.assertApplicationRollback !== 'function') fail('SERVICE_PENDING', operation);
        try {
          required(session, 'assertApplicationRollback', 'assert_application_rollback', { manifest: retainedManifest, publication: previousApplicationPublication });
        } catch (error) {
          if (['SERVICE_SCOPE_MISMATCH', 'SERVICE_STALE'].includes(error?.code)) throw error;
          fail('SERVICE_PENDING', operation, writesOf(session, driver), error);
        }
        let retainedShawlManifest = null;
        if (platform === 'win32') {
          const shawl = required(session, 'readRetainedDeploymentEnvelope', 'read_retained_deployment_envelope', { purpose: 'shawl', manifestFingerprint: previousEntry.artifacts.find((v) => v.artifactKind === 'shawl')?.manifestFingerprint });
          const previousShawlPublication = required(session, 'readPublicationReceipt', 'read_publication_receipt', { slot: 'previous', artifactKind: 'shawl' });
          retainedShawlManifest = shawl.manifest;
          if (typeof session.assertShawlRollback !== 'function') fail('SERVICE_PENDING', operation);
          try {
            required(session, 'assertShawlRollback', 'assert_shawl_rollback', { manifest: retainedShawlManifest, publication: previousShawlPublication });
          } catch (error) {
            if (['SERVICE_SCOPE_MISMATCH', 'SERVICE_STALE'].includes(error?.code)) throw error;
            fail('SERVICE_PENDING', operation, writesOf(session, driver), error);
          }
        }
        release = normalizeRelease({ manifest: retainedManifest, shawlManifest: retainedShawlManifest, applicationManifestFingerprint: retainedManifest.manifestFingerprint, shawlManifestFingerprint: retainedShawlManifest?.manifestFingerprint ?? (platform === 'win32' ? old.shawlManifestFingerprint : null), releaseSequence: retainedManifest.releaseSequence, releaseTreeFingerprint: retainedManifest.inventory?.treeFingerprint ?? retainedManifest.releaseTreeFingerprint, compatibilityFingerprint: retainedManifest.compatibilityFingerprint ?? hash(retainedManifest.compatibility ?? {}), entrypointPath: retainedManifest.entrypointPath ?? retainedManifest.entrypoints?.[request.target.component] }, request, platform, previousEntry);
        publicationResult = { application: { publication: previousApplicationPublication } };
        if (platform === 'win32') publicationResult.shawl = { publication: previousShawlPublication };
      } else if (operation !== 'uninstall') {
        acquisition = await this.#acquisition(session, request);
        const manifests = await requiredAsync(acquisition, 'readManifests', 'read_service_acquisition_manifests');
        release = normalizeRelease({ manifest: manifests.application, shawlManifest: manifests.shawl, applicationManifestFingerprint: manifests.application?.manifestFingerprint, shawlManifestFingerprint: manifests.shawl?.manifestFingerprint, releaseSequence: manifests.application?.releaseSequence, releaseTreeFingerprint: manifests.application?.inventory?.treeFingerprint ?? manifests.application?.releaseTreeFingerprint, compatibilityFingerprint: manifests.application?.compatibilityFingerprint ?? (manifests.application?.compatibility ? hash(manifests.application.compatibility) : null), entrypointPath: manifests.application?.entrypointPath ?? manifests.application?.entrypoints?.[request.target.component] }, request, platform, null);
      }
      const beforeResource = operation === 'install' ? null : oldResource.platformResourceFingerprint;
      if (operation !== 'install' && !validHash(beforeResource)) fail('SERVICE_SCOPE_MISMATCH', operation);
      const planned = operation === 'uninstall' ? null : await this.#options.planResource({ operation, request, release, old, session, platform, architecture });
      const validPlanPart = (part) => plain(part) && Object.keys(part).length === 2 && validHash(part.resourceFingerprint) && plain(part.resourceDescriptor) && Object.keys(part.resourceDescriptor).length > 0;
      if (operation !== 'uninstall' && (!plain(planned) || Object.keys(planned).length !== 2 || !validPlanPart(planned.trial) || !validPlanPart(planned.final))) fail('SERVICE_INVALID', 'plan_resource');
      const trialResource = operation === 'uninstall' ? beforeResource : planned.trial.resourceFingerprint;
      const finalResource = operation === 'uninstall' ? null : planned.final.resourceFingerprint;
      const generation = old.serviceGeneration + 1;
      const candidate = candidateProof(release, platform, operation === 'uninstall');
      const transactionId = request.transactionId ?? `svc-${Date.now()}-${randomBytes(4).toString('hex')}`;
      const transactionNonce = nonce();
      const configuration = request.configuration ?? oldManifest.configuration;
      const configurationFingerprint = operation === 'uninstall' ? hash(configuration ?? {}) : serviceConfigurationFingerprint(configuration, { component: request.target.component, platform });
      const rolesFingerprint = serviceRolesFingerprint(request.roles, platform);
      const predictedResource = operation === 'uninstall' ? null : buildServiceResourceProof({ serviceKey: session.serviceKey, component: request.target.component, platform, architecture, operation, serviceGeneration: generation, applicationManifestFingerprint: candidate.applicationManifestFingerprint ?? old.applicationManifestFingerprint, shawlManifestFingerprint: candidate.shawlManifestFingerprint ?? old.shawlManifestFingerprint, configurationFingerprint, rolesFingerprint, transactionId, transactionNonce, predecessorResourceProof: old.resourceProof, platformResourceFingerprint: finalResource, platformState: phaseState(platform, 'final') });
      const transition = buildServiceTransitionProof({ oldFingerprint: old.oldFingerprint, candidateFingerprint: candidate.candidateFingerprint, expectedBeforeResourceFingerprint: operation === 'install' ? null : beforeResource, expectedAfterResourceFingerprint: operation === 'uninstall' ? null : finalResource, platformResourceFingerprint: operation === 'uninstall' ? beforeResource : trialResource, platformState: phaseState(platform, 'trial') }, platform);
      const final = buildServiceFinalProof({ disposition: operation === 'uninstall' ? 'absent' : 'stable', manifestFingerprint: operation === 'uninstall' ? null : candidate.applicationManifestFingerprint, resourceProof: operation === 'uninstall' ? null : predictedResource.resourceProof, applicationManifestFingerprint: operation === 'uninstall' ? null : candidate.applicationManifestFingerprint, shawlManifestFingerprint: operation === 'uninstall' ? null : candidate.shawlManifestFingerprint, serviceGeneration: generation, activation: operation === 'uninstall' ? 'disabled-not-startable' : 'enabled' }, platform);
      const tx = buildServiceTransaction({ transactionId, transactionNonce, operation, component: request.target.component, serviceKey: session.serviceKey, platform, architecture, serviceGeneration: generation, old, candidate, transition, final, phase: 'prepared', substep: 'none', previousJournalFingerprint: journal.head?.present ? journal.head.value.transactionFingerprint : null });
      const provisionalManifest = operation === 'uninstall' ? null : buildServiceManifest({ serviceKey: session.serviceKey, component: request.target.component, platform, architecture, serviceGeneration: generation, applicationManifestFingerprint: candidate.applicationManifestFingerprint, shawlManifestFingerprint: candidate.shawlManifestFingerprint, predecessorManifestFingerprint: operation === 'install' ? null : old.manifestFingerprint, configuration, configurationFingerprint, roles: request.roles, rolesFingerprint, resourceProof: predictedResource.resourceProof, platformState: phaseState(platform, 'final') });
      const driverRelease = release
        ? { entrypointPath: release.entrypointPath, applicationManifestFingerprint: release.applicationManifestFingerprint }
        : operation === 'uninstall'
          ? authenticatedOldRelease(session, current, platform, operation)
          : null;
      if (platform === 'win32' && (!driverRelease || !validAbsoluteEntrypoint(driverRelease.entrypointPath, platform) || !validHash(driverRelease.applicationManifestFingerprint))) {
        // Windows SCM mutations must never receive an undefined release.  A
        // retained/reference binding may be supplied by a future store
        // accessor; until then refuse before the prepared journal edge.
        fail('SERVICE_PENDING', operation);
      }
      driver = await this.#driver(session, driverRequest, driverRelease);
      if (typeof driver.probe !== 'function') fail('SERVICE_INVALID', 'probe_mutation');
      // Driver construction validates the concrete session/lock authority
      // before the first journal write.  The platform probe itself must run
      // after the prepared head exists: both native drivers intentionally
      // require that journal authority for mutation replay checks.
      this.#append(session, tx, 'prepared', 'none');
      if (operation !== 'uninstall') {
        required(session, 'acceptProvisionalMetadata', 'accept_provisional_metadata', {
          transaction: tx,
          manifest: provisionalManifest,
          resource: predictedResource,
        });
      }
      const observed = required(driver, 'probe', 'probe_mutation');
      // Linux publication/removal uses the raw unit/drop-in CAS; Windows
      // authenticates the complete SCM resource fingerprint instead.
      const expectedCurrentResource = operation === 'install'
        ? null
        : platform === 'linux'
          ? rawResourceSha256(observed, request.target.component)
          : beforeResource;
      if (operation !== 'install' && !validHash(expectedCurrentResource)) fail('SERVICE_SCOPE_MISMATCH', operation);
      if (operation !== 'install' && observed.resourceFingerprint !== beforeResource) fail('SERVICE_STALE', operation);
      if (operation === 'install' && observed.platformPhase !== 'absent') fail('SERVICE_STALE', operation);
      if (operation !== 'uninstall' && operation !== 'rollback') {
        await this.#options.compatibility({ operation, request, release, old, session });
        const appFloor = required(session, 'readApplicationFloor', 'read_application_floor');
        const shawlFloor = platform === 'win32' ? required(session, 'readShawlFloor', 'read_shawl_floor') : null;
        await requiredAsync(acquisition, 'reserve', 'reserve_service_acquisition', { transaction: tx, currentApplicationSequence: appFloor.floor.committedSequence, currentShawlSequence: platform === 'win32' ? shawlFloor.floor.committedSequence : null });
        this.#append(session, tx, 'sequence-reserved', 'observed');
        publicationResult = await requiredAsync(acquisition, 'publish', 'publish_service_acquisition', { transaction: buildServiceTransaction({ ...tx, phase: 'sequence-reserved', substep: 'observed', previousJournalFingerprint: session.readJournal().entries.at(-1).transactionFingerprint }) });
        this.#append(session, tx, 'release-published', 'observed');
      }
      if (operation !== 'rollback' && operation !== 'uninstall' && !acquisition) fail('SERVICE_INVALID', operation);
      this.#append(session, tx, 'transition-marker-intent', 'intent');
      if (operation === 'uninstall') {
        await requiredAsync(driver, 'stopAndQuiesce', 'stop_and_quiesce', { expectedResourceFingerprint: beforeResource });
        this.#append(session, tx, 'tombstoned', 'intent');
        const tombstone = buildServiceTombstone({ component: request.target.component, serviceKey: session.serviceKey, platform, architecture, serviceGeneration: generation, transactionId: tx.transactionId, transactionFingerprint: session.readJournal().entries.at(-1).transactionFingerprint, resourceProof: old.resourceProof, currentManifestFingerprint: old.manifestFingerprint, applicationSequenceFloor: floorCas.application.floor.committedSequence, shawlSequenceFloor: platform === 'win32' ? floorCas.shawl.floor.committedSequence : null });
        required(session, 'publishTombstone', 'publish_tombstone', tombstone, required(session, 'readTombstone', 'read_tombstone'));
        await requiredAsync(driver, 'removeResource', 'remove_resource', platform === 'linux' ? { expectedCurrentSha256: expectedCurrentResource, siblings } : { expectedResourceFingerprint: beforeResource });
        if (startup.present) required(session, 'removeStartupProof', 'remove_startup_proof', startup);
        const empty = buildServiceReferenceRecord({ serviceKey: session.serviceKey, component: request.target.component, platform, architecture, serviceGeneration: generation, current: null, previous: null, provisional: null });
        required(session, 'publishReferences', 'publish_references', empty, references);
        this.#append(session, tx, 'references-released', 'observed');
        for (const slot of ['current', 'previous']) { const m = required(session, 'readManifest', 'read_manifest', slot); const r = required(session, 'readResourceProof', 'read_resource_proof', slot); if (m.present) required(session, 'removeManifest', 'remove_manifest', slot, m); if (r.present) required(session, 'removeResourceProof', 'remove_resource_proof', slot, r); }
      } else {
        const suppressed = { phase: 'transition-marker-intent', release: { entrypointPath: release.entrypointPath, applicationManifestFingerprint: release.applicationManifestFingerprint }, expectedCurrentSha256: expectedCurrentResource };
        if (platform === 'linux') suppressed.siblings = siblings;
        const published = await requiredAsync(driver, 'publishSuppressedResource', 'publish_suppressed_resource', suppressed);
        if (!plain(published) || published.resourceFingerprint !== trialResource || !same(published.resourceDescriptor, planned.trial.resourceDescriptor)) fail('SERVICE_MANUAL_CLEANUP', operation);
        if (operation !== 'install') await requiredAsync(driver, 'stopAndQuiesce', 'stop_and_quiesce', { expectedResourceFingerprint: beforeResource });
        const trial = await requiredAsync(driver, 'startTrial', 'start_trial', { expectedResourceFingerprint: trialResource });
        if (!plain(trial) || trial.resourceFingerprint !== trialResource) fail('SERVICE_MANUAL_CLEANUP', operation);
        await requiredAsync(driver, 'runStartupGate', 'run_startup_gate', { trial, observeApplication: this.#options.observeApplication });
        if (platform === 'linux') await requiredAsync(driver, 'armFinalRestart', 'arm_final_restart', { release: { entrypointPath: release.entrypointPath, applicationManifestFingerprint: release.applicationManifestFingerprint }, siblings });
        let activation;
        if (platform === 'linux') {
          activation = await requiredAsync(driver, 'enableFinal', 'enable_final');
        } else {
          await requiredAsync(driver, 'armFinalRestart', 'arm_final_restart');
          activation = await requiredAsync(driver, 'enableFinal', 'enable_final');
        }
        if (!plain(activation) || !validHash(activation.resourceFingerprint)) fail('SERVICE_PENDING', operation);
        const activated = activation.resourceFingerprint;
        if (activated !== finalResource || !same(activation.resourceDescriptor, planned.final.resourceDescriptor)) fail('SERVICE_MANUAL_CLEANUP', operation);
        const resource = buildServiceResourceProof({ serviceKey: session.serviceKey, component: request.target.component, platform, architecture, operation, serviceGeneration: generation, applicationManifestFingerprint: candidate.applicationManifestFingerprint, shawlManifestFingerprint: candidate.shawlManifestFingerprint, configurationFingerprint, rolesFingerprint, transactionId: tx.transactionId, transactionNonce: tx.transactionNonce, predecessorResourceProof: old.resourceProof, platformResourceFingerprint: activated, platformState: phaseState(platform, 'final') });
        const manifest = buildServiceManifest({ serviceKey: session.serviceKey, component: request.target.component, platform, architecture, serviceGeneration: generation, applicationManifestFingerprint: candidate.applicationManifestFingerprint, shawlManifestFingerprint: candidate.shawlManifestFingerprint, predecessorManifestFingerprint: operation === 'install' ? null : old.manifestFingerprint, configuration, configurationFingerprint, roles: request.roles, rolesFingerprint, resourceProof: resource.resourceProof, platformState: phaseState(platform, 'final') });
        if (operation !== 'install') {
          // Rotate the predecessor pair in the same resource-then-manifest
          // order used by the store's pair publication contract.
          required(session, 'publishResourceProof', 'publish_resource_proof', 'previous', oldResource, required(session, 'readResourceProof', 'read_resource_proof', 'previous'));
          required(session, 'publishManifest', 'publish_manifest', 'previous', oldManifest, required(session, 'readManifest', 'read_manifest', 'previous'));
        }
        required(session, 'publishCurrentMetadata', 'publish_current_metadata', { transaction: tx, manifest, resource, expectedManifest: current, expectedResource: currentResource });
        const currentPublication = combinePublications(publicationResult?.application?.publication ?? publicationResult?.application, publicationResult?.shawl?.publication ?? publicationResult?.shawl);
        const previousPublication = references.present ? { artifacts: references.value.current?.artifacts } : null;
        const previousValue = operation === 'install' ? null : {
          ...oldManifest,
          transactionId: references.value.current?.transactionId ?? null,
          transactionNonce: references.value.current?.transactionNonce ?? null,
        };
        const templatePublication = platform === 'linux' && request.target.component === 'daemon'
          ? (typeof session.createSharedTemplateBinding === 'function'
            ? required(session, 'createSharedTemplateBinding', 'create_shared_template_binding')
            : fail('SERVICE_PENDING', 'create_shared_template_binding'))
          : null;
        const refs = referencesFor(tx, { value: manifest, publication: combinePublications(templatePublication, currentPublication) }, operation === 'install' ? null : { value: previousValue, publication: previousPublication });
        required(session, 'publishReferences', 'publish_references', refs, references);
      }
      this.#append(session, tx, 'committed', 'observed');
      return Object.freeze({ operation, transactionId: tx.transactionId, transactionFingerprint: tx.transactionFingerprint, serviceGeneration: generation, writes: writesOf(session, driver) });
    } catch (error) {
      const errorCode = safeErrorCode(error);
      if (tx && (safeErrorAmbiguous(error) || errorCode === 'SERVICE_MANUAL_CLEANUP' || errorCode === 'SERVICE_SCOPE_MISMATCH' || errorCode === 'SERVICE_STALE')) await this.#persistManual(session, tx, operation, error, driver);
      if (error?.name === 'ServiceLifecycleError') throw error;
      const wrapped = error instanceof Error ? error : new Error(String(error));
      wrapped.name = 'ServiceLifecycleError'; wrapped.operation = operation; wrapped.writes = writesOf(session, driver);
      // Preserve only the bounded error context accepted by the public CLI
      // when a dependency throws a plain object instead of an Error.
      if (wrapped !== error && errorCode !== null) wrapped.code = errorCode;
      if (wrapped !== error && safeErrorAmbiguous(error)) wrapped.ambiguous = true;
      throw wrapped;
    } finally { try { await acquisition?.close?.(); } finally { required(session, 'close', 'close_service_store'); } }
  }
  async install(request) { return this.#mutate('install', request); }
  async update(request) { return this.#mutate('update', request); }
  async rollback(request) { return this.#mutate('rollback', request); }
  async uninstall(request) { return this.#mutate('uninstall', request); }
  async status(request) {
    const platform = this.#platform(request); const architecture = this.#architecture(request);
    try { validateServiceLifecycleRequest('status', request, { platform, architecture }); } catch (error) { fail('SERVICE_INVALID', 'status', 0, error); }
    this.#preflight('status', request); const session = this.#open('read-only', request);
    if (session === null) {
      return Object.freeze({
        ...buildServiceStatusReceipt({
          component: request.target.component,
          serviceKey: serviceKeyForTarget(request.target),
          platform, architecture,
          serviceGeneration: 0, manifestFingerprint: null, resourceProof: null,
          transactionFingerprint: null,
          ownership: 'absent', service: 'missing', activation: 'disabled-not-startable', tree: 'empty',
          startupEvidence: 'none', connectivityObservation: 'unknown',
          providerHealth: 'unknown', workspaceHealth: 'unknown',
          supervisorProvenance: platform === 'linux' ? 'not-applicable' : 'unknown',
          recovery: 'clean', observedAtMs: this.#options.clock?.() ?? Date.now(),
        }),
        writes: 0,
      });
    }
    try {
      if (session.component !== request.target.component || session.platform !== platform || session.architecture !== architecture || session.serviceKey !== serviceKeyForTarget(request.target)) fail('SERVICE_SCOPE_MISMATCH', 'status');
      const manifest = required(session, 'readManifest', 'read_manifest', 'current');
      const resource = required(session, 'readResourceProof', 'read_resource_proof', 'current');
      if (manifest.present && (manifest.value.rolesFingerprint !== serviceRolesFingerprint(request.roles, platform) || !same(manifest.value.roles, request.roles))) fail('SERVICE_SCOPE_MISMATCH', 'status');
      const journal = required(session, 'readJournal', 'read_service_journal');
      const startup = typeof session.readStartupProof === 'function'
        ? session.readStartupProof()
        : { present: false, value: null };
      const manual = typeof session.readManualCleanup === 'function' ? session.readManualCleanup() : { present: false, value: null };
      // A bootstrapped store can legitimately have no service journal yet.
      // Do not construct a mutation driver merely to report the canonical
      // absent state; status remains strictly read-only.
      if (!manifest.present && !resource.present &&
          journal.entries.length === 0 && journal.pending === null) {
        return Object.freeze({
          ...buildServiceStatusReceipt({
            component: request.target.component,
            serviceKey: session.serviceKey,
            platform, architecture,
            serviceGeneration: 0, manifestFingerprint: null, resourceProof: null,
            transactionFingerprint: null,
            ownership: 'absent', service: 'missing', activation: 'disabled-not-startable', tree: 'empty',
            startupEvidence: 'none', connectivityObservation: 'unknown',
            providerHealth: 'unknown', workspaceHealth: 'unknown',
            supervisorProvenance: platform === 'linux' ? 'not-applicable' : 'unknown', recovery: 'clean',
            observedAtMs: this.#options.clock?.() ?? Date.now(),
          }),
          writes: 0,
        });
      }
      const persistedConfiguration = manifest.present ? manifest.value.configuration : undefined;
      const statusRelease = manifest.present
        ? authenticatedOldRelease(session, manifest, platform, 'status')
        : null;
      if (platform === 'win32' && (!statusRelease || !validHash(statusRelease.applicationManifestFingerprint))) fail('SERVICE_PENDING', 'status');
      const statusRequest = persistedConfiguration && !request.configuration
        ? { ...request, configuration: persistedConfiguration }
        : request;
      const driver = await this.#driver(session, statusRequest, statusRelease);
      const first = await requiredAsync(driver, 'probe', 'probe_status');
      const second = await requiredAsync(driver, 'probe', 'probe_status');
      if (!same({ ...first, resourceFingerprint: first?.resourceFingerprint ?? null, platformPhase: first?.platformPhase ?? null }, { ...second, resourceFingerprint: second?.resourceFingerprint ?? null, platformPhase: second?.platformPhase ?? null })) fail('SERVICE_PENDING', 'status');
      const fallback = { component: request.target.component, serviceKey: session.serviceKey, serviceGeneration: 0, manifestFingerprint: null };
      const currentManifest = manifest.present ? manifest.value : fallback;
      const latest = journal.entries.at(-1);
      const pending = journal.pending !== null || (latest && latest.phase !== 'committed');
      const recovery = manual.present ? 'manual-cleanup' : pending ? 'pending' : 'clean';
      const evidenceProbe = manifest.present && resource.present
        ? second
        : second?.ownership === 'owned' ? { ...second, ownership: 'ambiguous' } : second;
      return statusFromProbe(evidenceProbe, currentManifest, resource.present ? resource.value : { resourceProof: null }, platform, architecture, this.#options.clock?.() ?? Date.now(), recovery, pending ? (journal.pending ?? latest) : null, startup);
    } finally { required(session, 'close', 'close_service_store'); }
  }
  async recover(request) {
    const platform = this.#platform(request); const architecture = this.#architecture(request);
    try { validateServiceLifecycleRequest('recover', request, { platform, architecture }); } catch (error) { fail('SERVICE_INVALID', 'recover', 0, error); }
    this.#preflight('recover', request); const session = this.#open('recovery', request); let driver = null; let replayAcquisition = null; let classified = false;
    try {
      const journal = required(session, 'readJournal', 'read_service_journal'); const head = journal.entries.at(-1); if (!head || head.transactionId !== request.expected.transactionId || head.transactionFingerprint !== request.expected.journalFingerprint) fail('SERVICE_STALE', 'recover');
      if (journal.pending !== null && journal.pending !== undefined && !same(journal.pending, head)) fail('SERVICE_PENDING', 'recover');
      const committedIndex = journal.entries.reduce((index, entry, position) => entry?.phase === 'committed' ? position : index, -1);
      if (journal.entries.slice(committedIndex + 1).some((entry) => entry?.transactionId !== head.transactionId)) fail('SERVICE_PENDING', 'recover');
      // A journal entry is the recovery authority.  Rebuilding it here also
      // checks all four proof edges (O/C/T/F); accepting a caller-shaped
      // transaction would allow adoption of a different operation.
      let transaction = null;
      try { transaction = buildServiceTransaction(head); } catch { /* classifier still runs for a write-free pending result */ }
      if (transaction !== null && (!same(transaction, head) || transaction.transactionId !== request.expected.transactionId ||
          transaction.transactionFingerprint !== request.expected.journalFingerprint ||
          transaction.transition.oldFingerprint !== transaction.old.oldFingerprint ||
          transaction.transition.candidateFingerprint !== transaction.candidate.candidateFingerprint ||
          transaction.final.serviceGeneration !== transaction.serviceGeneration)) transaction = null;
      if (head.phase === 'committed') fail('SERVICE_PENDING', 'recover');
      const manifest = required(session, 'readManifest', 'read_manifest', 'current');
      const release = manifest.present
        ? authenticatedOldRelease(session, manifest, platform, 'recover')
        : null;
      if (platform === 'win32' && manifest.present && (!release || !validAbsoluteEntrypoint(release.entrypointPath, platform) || !validHash(release.applicationManifestFingerprint))) fail('SERVICE_PENDING', 'recover');
      // Authenticate the retained candidate, publication root, and protected
      // configuration before constructing a driver.  A prepared first install
      // has no current manifest, so blindly constructing a Linux/Windows
      // driver here would pass null configuration/release into platform code.
      let candidateRelease = null;
      let retainedManifest = null;
      let recoveryConfiguration = manifest.present ? manifest.value.configuration : null;
      if (['prepared', 'sequence-reserved'].includes(head.phase) && transaction === null) fail('SERVICE_PENDING', 'recover');
      const candidateFingerprint = transaction?.candidate?.applicationManifestFingerprint ?? null;
      if (candidateFingerprint !== null) {
        if (typeof session.readRetainedDeploymentEnvelope !== 'function') fail('SERVICE_PENDING', 'recover');
        const retained = required(session, 'readRetainedDeploymentEnvelope', 'read_retained_deployment_envelope', {
          purpose: 'application', manifestFingerprint: candidateFingerprint,
        });
        retainedManifest = retained?.manifest ?? null;
        if (!plain(retainedManifest) || retainedManifest.manifestFingerprint !== candidateFingerprint) fail('SERVICE_PENDING', 'recover');
        const publication = typeof session.readPublicationReceipt === 'function'
          ? (() => { try { return session.readPublicationReceipt({ slot: 'provisional', artifactKind: 'application' }); } catch { return null; } })()
          : null;
        let retainedShawl = null;
        if (transaction.candidate.shawlManifestFingerprint !== null) {
          if (typeof session.readRetainedDeploymentEnvelope !== 'function') fail('SERVICE_PENDING', 'recover');
          const shawl = required(session, 'readRetainedDeploymentEnvelope', 'read_retained_deployment_envelope', {
            purpose: 'shawl', manifestFingerprint: transaction.candidate.shawlManifestFingerprint,
          });
          retainedShawl = shawl?.manifest ?? null;
          if (!plain(retainedShawl) || retainedShawl.manifestFingerprint !== transaction.candidate.shawlManifestFingerprint) fail('SERVICE_PENDING', 'recover');
        }
        candidateRelease = normalizeRelease({
          manifest: retainedManifest,
          shawlManifest: retainedShawl,
          applicationManifestFingerprint: candidateFingerprint,
          shawlManifestFingerprint: transaction.candidate.shawlManifestFingerprint,
          releaseSequence: transaction.candidate.releaseSequence,
          releaseTreeFingerprint: transaction.candidate.releaseTreeFingerprint,
          compatibilityFingerprint: transaction.candidate.compatibilityFingerprint,
          entrypointPath: retainedManifest.entrypointPath ?? retainedManifest.entrypoints?.[transaction.component],
        }, request, platform, publication);
        recoveryConfiguration ??= retainedManifest.configuration ?? null;
      }
      if (!recoveryConfiguration && typeof session.readProvisionalMetadata === 'function') {
        const provisional = session.readProvisionalMetadata();
        recoveryConfiguration = provisional?.value?.manifest?.configuration ?? provisional?.manifest?.configuration ?? null;
      }
      if (transaction && (head.phase === 'prepared' || head.phase === 'sequence-reserved') &&
          transaction.operation !== 'uninstall' && transaction.operation !== 'rollback') {
        if (!candidateRelease || !plain(recoveryConfiguration)) fail('SERVICE_PENDING', 'recover');
        let configurationFingerprint;
        try { configurationFingerprint = serviceConfigurationFingerprint(recoveryConfiguration, { component: transaction.component, platform }); } catch { fail('SERVICE_PENDING', 'recover'); }
        const authenticatedFingerprint = manifest.present
          ? manifest.value.configurationFingerprint
          : retainedManifest?.configurationFingerprint ?? null;
        if (!validHash(authenticatedFingerprint) || authenticatedFingerprint !== configurationFingerprint) fail('SERVICE_PENDING', 'recover');
      }
      const recoveryRequest = recoveryConfiguration ? { ...request, configuration: recoveryConfiguration } : request;
      // Bind a fresh driver to the authenticated candidate release. Passing
      // the persisted predecessor would make SCM/ExecStart probes authenticate
      // the wrong transition state.
      const driverRelease = candidateRelease
        ? { entrypointPath: candidateRelease.entrypointPath, applicationManifestFingerprint: candidateRelease.applicationManifestFingerprint }
        : release;
      if (transaction && transaction.operation !== 'uninstall' && transaction.operation !== 'rollback' &&
          (!candidateRelease || !recoveryConfiguration)) fail('SERVICE_PENDING', 'recover');
      driver = await this.#driver(session, recoveryRequest, driverRelease);
      let classification;
      try {
        classification = required(driver, 'recoverTrialState', 'recover_trial_state');
      } catch (error) {
        // Native classifiers intentionally expose only trial/activation
        // heads.  The earlier acquisition heads have their own journal/floor
        // admission below and are not guessed from platform state.
        if (['prepared', 'sequence-reserved', 'release-published'].includes(head.phase) && error?.code === 'SERVICE_PENDING') {
          classification = { classification: 'not-in-trial', phase: head.phase };
        } else throw error;
      }
      if (!plain(classification)) fail('SERVICE_PENDING', 'recover');
      const recovery = classification.recovery;
      const named = classification.classification;
      if (recovery !== undefined && named !== undefined && recovery !== named) fail('SERVICE_PENDING', 'recover');
      const classifier = recovery ?? named;
      const known = new Set(['manual-cleanup', 'resume-activation', 'stop-and-continue', 'resuppress-and-retrial', 'retrial', 'stop-and-retrial', 'continue', 'resume', 'not-in-trial']);
      if (!known.has(classifier) || classification.phase !== head.phase) fail('SERVICE_PENDING', 'recover');
      // `not-in-trial` is an observation, not permission to replay a journal
      // edge.  Refuse it before any publish/start or journal write; callers
      // must provide a fresh supported classifier from the native authority.
      if (classifier === 'not-in-trial') fail('SERVICE_PENDING', 'recover');
      this.#recoveryAuthorities(classifier, head.phase, transaction?.operation ?? null);
      classified = true;
      if (classifier === 'manual-cleanup') {
        const error = Object.assign(new Error('manual cleanup required'), { code: 'SERVICE_MANUAL_CLEANUP', ambiguous: true, reason: classification.reason });
        await this.#persistManual(session, head, 'recover', error, driver);
        fail('SERVICE_MANUAL_CLEANUP', 'recover', writesOf(session, driver));
      }
      if (transaction === null) fail('SERVICE_PENDING', 'recover');

      const operation = transaction.operation;
      const releaseForDriver = candidateRelease
        ? { entrypointPath: candidateRelease.entrypointPath, applicationManifestFingerprint: candidateRelease.applicationManifestFingerprint }
        : release;
      if ((head.phase === 'prepared' || head.phase === 'sequence-reserved') &&
          transaction.operation !== 'uninstall' && transaction.operation !== 'rollback') {
        await Promise.resolve(this.#options.compatibility({
          operation: transaction.operation, request, release: candidateRelease, old: transaction.old, session,
        }));
      }
      const expectedResource = transaction.transition.platformResourceFingerprint;
      const probe = () => required(driver, 'probe', 'probe_recovery');
      const siblings = platform === 'linux' && typeof session.readSiblingReferences === 'function'
        ? required(session, 'readSiblingReferences', 'read_sibling_references') : [];
      let currentHead = head;
      const refresh = () => {
        const latest = required(session, 'readJournal', 'read_service_journal').entries.at(-1);
        if (plain(latest) && latest.transactionId === transaction.transactionId && validHash(latest.transactionFingerprint)) {
          currentHead = latest;
          transaction = latest;
        }
        return currentHead;
      };
      const append = (phase, substep = 'observed') => {
        const next = this.#append(session, transaction, phase, substep);
        currentHead = next;
        transaction = next;
        return next;
      };
      const stop = async () => {
        if (typeof driver.stopAndQuiesce !== 'function') fail('SERVICE_PENDING', 'recover');
        const observed = probe();
        const fingerprint = observed?.resourceFingerprint;
        if (!validHash(fingerprint) || (transaction.old.disposition !== 'absent' && fingerprint !== transaction.transition.expectedBeforeResourceFingerprint && fingerprint !== expectedResource)) fail('SERVICE_PENDING', 'recover');
        // stopAndQuiesce authenticates the live service resource fingerprint
        // on both drivers. Raw unit/drop-in bytes are reserved for Linux
        // publication/removal CAS below.
        const result = await requiredAsync(driver, 'stopAndQuiesce', 'stop_and_quiesce', { expectedResourceFingerprint: fingerprint });
        refresh();
        return result;
      };
      const publishSuppressed = async () => {
        if (!releaseForDriver || typeof driver.publishSuppressedResource !== 'function') fail('SERVICE_PENDING', 'recover');
        const observed = probe();
        const expectedCurrentResource = transaction.operation === 'install'
          ? null
          : platform === 'linux'
            ? rawResourceSha256(observed, transaction.component)
            : observed?.resourceFingerprint;
        if (transaction.operation !== 'install' && !validHash(expectedCurrentResource)) fail('SERVICE_PENDING', 'recover');
        const input = { phase: 'transition-marker-intent', release: releaseForDriver, expectedCurrentSha256: expectedCurrentResource };
        if (platform === 'linux') input.siblings = siblings;
        const result = await requiredAsync(driver, 'publishSuppressedResource', 'publish_suppressed_resource', input);
        refresh();
        return result;
      };
      const start = async () => {
        if (typeof driver.startTrial !== 'function') fail('SERVICE_PENDING', 'recover');
        const trial = await requiredAsync(driver, 'startTrial', 'start_trial', { expectedResourceFingerprint: expectedResource });
        refresh();
        if (!plain(trial) || trial.resourceFingerprint !== expectedResource) fail('SERVICE_PENDING', 'recover');
        if (typeof driver.runStartupGate !== 'function' || typeof this.#options.observeApplication !== 'function') fail('SERVICE_PENDING', 'recover');
        const result = await requiredAsync(driver, 'runStartupGate', 'run_startup_gate', { trial, observeApplication: this.#options.observeApplication });
        refresh();
        return result;
      };
      const activate = async () => {
        if (typeof driver.armFinalRestart !== 'function' || typeof driver.enableFinal !== 'function') fail('SERVICE_PENDING', 'recover');
        if (platform === 'linux') {
          await requiredAsync(driver, 'armFinalRestart', 'arm_final_restart', { release: releaseForDriver, siblings });
          refresh();
          const result = await requiredAsync(driver, 'enableFinal', 'enable_final', { siblings });
          refresh();
          return result;
        }
        await requiredAsync(driver, 'armFinalRestart', 'arm_final_restart');
        refresh();
        const result = await requiredAsync(driver, 'enableFinal', 'enable_final');
        refresh();
        return result;
      };
      const finishMetadata = async (activation) => {
        // Metadata is committed only after the native final receipt and exact
        // transaction binding are available.  No receipt is synthesized from
        // the classifier alone.
        if (!plain(activation) || !validHash(activation.resourceFingerprint)) fail('SERVICE_PENDING', 'recover');
        const finalResource = activation.resourceFingerprint;
        if (operation === 'uninstall') fail('SERVICE_PENDING', 'recover');
        if (!validHash(finalResource) || finalResource !== transaction.transition.expectedAfterResourceFingerprint) fail('SERVICE_PENDING', 'recover');
        const current = required(session, 'readManifest', 'read_manifest', 'current');
        const currentResource = required(session, 'readResourceProof', 'read_resource_proof', 'current');
        if (typeof session.publishCurrentMetadata !== 'function' || !candidateRelease || !manifest.present) fail('SERVICE_PENDING', 'recover');
        const configuration = manifest.value.configuration;
        const configurationFingerprint = manifest.value.configurationFingerprint;
        const rolesFingerprint = manifest.value.rolesFingerprint;
        const resource = buildServiceResourceProof({
          serviceKey: transaction.serviceKey, component: transaction.component, platform, architecture,
          operation, serviceGeneration: transaction.serviceGeneration,
          applicationManifestFingerprint: transaction.candidate.applicationManifestFingerprint,
          shawlManifestFingerprint: transaction.candidate.shawlManifestFingerprint,
          configurationFingerprint, rolesFingerprint, transactionId: transaction.transactionId,
          transactionNonce: transaction.transactionNonce, predecessorResourceProof: transaction.old.resourceProof,
          platformResourceFingerprint: finalResource, platformState: phaseState(platform, 'final'),
        });
        if (resource.resourceProof !== transaction.final.resourceProof ||
            transaction.final.applicationManifestFingerprint !== transaction.candidate.applicationManifestFingerprint ||
            transaction.final.serviceGeneration !== transaction.serviceGeneration) fail('SERVICE_PENDING', 'recover');
        const nextManifest = buildServiceManifest({
          serviceKey: transaction.serviceKey, component: transaction.component, platform, architecture,
          serviceGeneration: transaction.serviceGeneration,
          applicationManifestFingerprint: transaction.candidate.applicationManifestFingerprint,
          shawlManifestFingerprint: transaction.candidate.shawlManifestFingerprint,
          predecessorManifestFingerprint: operation === 'install' ? null : transaction.old.manifestFingerprint,
          configuration, configurationFingerprint, roles: request.roles, rolesFingerprint,
          resourceProof: resource.resourceProof, platformState: phaseState(platform, 'final'),
        });
        required(session, 'publishCurrentMetadata', 'publish_current_metadata', { transaction, manifest: nextManifest, resource, expectedManifest: current, expectedResource: currentResource });
        const references = required(session, 'readReferences', 'read_references');
        if (typeof session.publishReferences !== 'function') fail('SERVICE_PENDING', 'recover');
        const applicationPublication = typeof session.readPublicationReceipt === 'function'
          ? (() => { try { return session.readPublicationReceipt({ slot: 'provisional', artifactKind: 'application' }); } catch { return null; } })() : null;
        const shawlPublication = platform === 'win32' && typeof session.readPublicationReceipt === 'function'
          ? (() => { try { return session.readPublicationReceipt({ slot: 'provisional', artifactKind: 'shawl' }); } catch { return null; } })() : null;
        const publication = combinePublications(applicationPublication, shawlPublication);
        const previousManifest = operation === 'install' ? null : required(session, 'readManifest', 'read_manifest', 'previous');
        const previousPublication = operation === 'install' ? null : { artifacts: references.value?.current?.artifacts ?? [] };
        const refs = referencesFor(transaction, { value: nextManifest, publication }, operation === 'install' ? null : { value: previousManifest.present ? previousManifest.value : manifest.value, publication: previousPublication });
        required(session, 'publishReferences', 'publish_references', refs, references);
      };
      const completeTrial = async () => {
        await start();
        const activation = await activate();
        await finishMetadata(activation);
        append('committed');
        return Object.freeze({ operation, transactionId: transaction.transactionId, transactionFingerprint: transaction.transactionFingerprint, serviceGeneration: transaction.serviceGeneration, writes: writesOf(session, driver) });
      };
      const transitionObserved = () => currentHead.phase === 'transition-marker-intent' && currentHead.substep === 'observed';

      // The classifier names the only admissible native edge.  Every edge is
      // idempotent in the concrete driver/store and independently rechecks
      // the transaction head, receipts, locks, and platform CAS.
      if (['prepared', 'sequence-reserved'].includes(head.phase)) {
        // Rollback and uninstall have no acquisition edge.  Replaying an
        // install/update acquisition here could reserve or publish a release
        // unrelated to the recorded transition, so refuse before any write.
        if (transaction.operation === 'rollback' || transaction.operation === 'uninstall') {
          fail('SERVICE_PENDING', 'recover');
        }
        try { replayAcquisition = await this.#acquisition(session, recoveryRequest); } catch (error) {
          if (error?.code === 'SERVICE_INVALID' || error?.code === 'SERVICE_ACQUISITION_INVALID') fail('SERVICE_PENDING', 'recover');
          throw error;
        }
        const acquisition = replayAcquisition;
        if (typeof acquisition.reserve !== 'function' || typeof acquisition.publish !== 'function') fail('SERVICE_PENDING', 'recover');
        const appFloor = required(session, 'readApplicationFloor', 'read_application_floor');
        const shawlFloor = platform === 'win32' ? required(session, 'readShawlFloor', 'read_shawl_floor') : null;
        if (head.phase === 'sequence-reserved') {
          const active = appFloor?.floor?.activeReservation;
          if (!plain(active) || active.transactionId !== transaction.transactionId || active.transactionNonce !== transaction.transactionNonce ||
              active.manifestFingerprint !== transaction.candidate.applicationManifestFingerprint || active.sequence !== transaction.candidate.releaseSequence) fail('SERVICE_PENDING', 'recover');
          if (platform === 'win32') {
            const shawlActive = shawlFloor?.floor?.activeReservation;
            if (!plain(shawlActive) || shawlActive.transactionId !== transaction.transactionId || shawlActive.transactionNonce !== transaction.transactionNonce ||
                shawlActive.manifestFingerprint !== transaction.candidate.shawlManifestFingerprint || shawlActive.sequence !== transaction.candidate.releaseSequence) fail('SERVICE_PENDING', 'recover');
          }
        }
        if (head.phase === 'prepared') {
          await requiredAsync(acquisition, 'reserve', 'reserve_service_acquisition', { transaction, currentApplicationSequence: appFloor.floor.committedSequence, currentShawlSequence: platform === 'win32' ? shawlFloor.floor.committedSequence : null });
          append('sequence-reserved');
        }
        if (head.phase === 'prepared' || head.phase === 'sequence-reserved') {
          await requiredAsync(acquisition, 'publish', 'publish_service_acquisition', { transaction: buildServiceTransaction({ ...transaction, phase: 'sequence-reserved', substep: 'observed', previousJournalFingerprint: session.readJournal().entries.at(-1).transactionFingerprint }) });
          append('release-published');
        }
      }
      if (currentHead.phase === 'release-published') {
        const appFloor = required(session, 'readApplicationFloor', 'read_application_floor');
        const floor = appFloor?.floor;
        if (!plain(floor) || floor.committedManifestFingerprint !== transaction.candidate.applicationManifestFingerprint ||
            floor.committedSequence !== transaction.candidate.releaseSequence ||
            floor.committedTransactionId !== transaction.transactionId ||
            floor.committedTransactionNonce !== transaction.transactionNonce ||
            !validHash(floor.committedTransactionFingerprint)) fail('SERVICE_PENDING', 'recover');
        if (platform === 'win32') {
          const shawlFloor = required(session, 'readShawlFloor', 'read_shawl_floor')?.floor;
          if (!plain(shawlFloor) || shawlFloor.committedManifestFingerprint !== transaction.candidate.shawlManifestFingerprint ||
              shawlFloor.committedTransactionId !== transaction.transactionId || shawlFloor.committedTransactionNonce !== transaction.transactionNonce ||
              !validHash(shawlFloor.committedTransactionFingerprint)) fail('SERVICE_PENDING', 'recover');
        }
      }
      if (classifier === 'stop-and-continue') {
        await stop();
        if (!transitionObserved() && (currentHead.phase === 'transition-marker-intent' || currentHead.phase === 'quiescent')) await publishSuppressed();
        if (currentHead.phase === 'resource-published') return await completeTrial();
      } else if (classifier === 'continue' || classifier === 'resume') {
        if (!transitionObserved() && (currentHead.phase === 'transition-marker-intent' || currentHead.phase === 'quiescent')) await publishSuppressed();
        if (currentHead.phase === 'resource-published') return await completeTrial();
      }
      if (currentHead.phase === 'release-published' && operation !== 'uninstall') {
        await publishSuppressed();
        return await completeTrial();
      }
      if (['retrial', 'stop-and-retrial', 'resuppress-and-retrial'].includes(classifier)) {
        if (classifier !== 'retrial') await stop();
        if (classifier === 'resuppress-and-retrial') await publishSuppressed();
        return await completeTrial();
      } else if (classifier === 'resume' && ['trial-start-intent', 'trial-start-observed', 'starting'].includes(head.phase)) {
        return await completeTrial();
      } else if (classifier === 'resume-activation') {
        if (head.phase === 'startup-observed') {
          if (typeof driver.runStartupGate !== 'function' || !classification.trial) fail('SERVICE_PENDING', 'recover');
          await requiredAsync(driver, 'runStartupGate', 'run_startup_gate', { trial: classification.trial, observeApplication: this.#options.observeApplication });
        }
        const activation = await activate();
        await finishMetadata(activation);
        append('committed');
        return Object.freeze({ operation, transactionId: transaction.transactionId, transactionFingerprint: transaction.transactionFingerprint, serviceGeneration: transaction.serviceGeneration, writes: writesOf(session, driver) });
      }
      if (operation !== 'uninstall' && (currentHead.phase === 'stopping' || currentHead.phase === 'quiescent')) {
        if (currentHead.phase === 'stopping') await stop();
        if (!transitionObserved()) await publishSuppressed();
        return await completeTrial();
      }
      if (['stopping', 'quiescent', 'tombstoned', 'resource-removed', 'references-released'].includes(head.phase)) {
        if (head.phase === 'stopping') await stop();
        if (operation === 'uninstall') {
          if (head.phase === 'quiescent' || head.phase === 'stopping') {
            if (typeof session.publishTombstone !== 'function') fail('SERVICE_PENDING', 'recover');
            const appFloor = required(session, 'readApplicationFloor', 'read_application_floor');
            const shawlFloor = platform === 'win32' ? required(session, 'readShawlFloor', 'read_shawl_floor') : null;
            append('tombstoned', 'intent');
            const tombstone = buildServiceTombstone({ component: transaction.component, serviceKey: transaction.serviceKey, platform, architecture, serviceGeneration: transaction.serviceGeneration, transactionId: transaction.transactionId, transactionFingerprint: session.readJournal().entries.at(-1).transactionFingerprint, resourceProof: transaction.old.resourceProof, currentManifestFingerprint: transaction.old.manifestFingerprint, applicationSequenceFloor: appFloor.floor.committedSequence, shawlSequenceFloor: platform === 'win32' ? shawlFloor.floor.committedSequence : null });
            required(session, 'publishTombstone', 'publish_tombstone', tombstone, required(session, 'readTombstone', 'read_tombstone'));
          }
          if (head.phase !== 'resource-removed' && head.phase !== 'references-released') {
            await requiredAsync(driver, 'removeResource', 'remove_resource', platform === 'linux' ? { expectedCurrentSha256: rawResourceSha256(probe(), transaction.component), siblings } : { expectedResourceFingerprint: transaction.transition.platformResourceFingerprint });
            append('resource-removed');
          }
          const startup = typeof session.readStartupProof === 'function' ? required(session, 'readStartupProof', 'read_startup_proof') : { present: false, value: null };
          if (startup.present && typeof session.removeStartupProof === 'function') required(session, 'removeStartupProof', 'remove_startup_proof', startup);
          if (head.phase !== 'references-released') {
            const references = required(session, 'readReferences', 'read_references');
            const empty = buildServiceReferenceRecord({ serviceKey: transaction.serviceKey, component: transaction.component, platform, architecture, serviceGeneration: transaction.serviceGeneration, current: null, previous: null, provisional: null });
            required(session, 'publishReferences', 'publish_references', empty, references); append('references-released');
          }
          for (const slot of ['current', 'previous']) { const m = required(session, 'readManifest', 'read_manifest', slot); const r = required(session, 'readResourceProof', 'read_resource_proof', slot); if (m.present) required(session, 'removeManifest', 'remove_manifest', slot, m); if (r.present) required(session, 'removeResourceProof', 'remove_resource_proof', slot, r); }
          append('committed');
          return Object.freeze({ operation, transactionId: transaction.transactionId, transactionFingerprint: transaction.transactionFingerprint, serviceGeneration: transaction.serviceGeneration, writes: writesOf(session, driver) });
        }
      }
      fail('SERVICE_PENDING', 'recover', writesOf(session, driver));
    } catch (error) {
      if (!classified || error?.name === 'ServiceLifecycleError') throw error;
      const sanitized = new Error('recover failed');
      sanitized.name = 'ServiceLifecycleError';
      sanitized.code = error?.code === 'SERVICE_MANUAL_CLEANUP' ? 'SERVICE_MANUAL_CLEANUP' : 'SERVICE_PENDING';
      sanitized.operation = 'recover';
      sanitized.writes = writesOf(session, driver);
      if (sanitized.code === 'SERVICE_MANUAL_CLEANUP') sanitized.ambiguous = true;
      throw sanitized;
    } finally { try { await replayAcquisition?.close?.(); } finally { required(session, 'close', 'close_service_store'); } }
  }
  async run(operation, request) { if (!SERVICE_OPERATIONS.includes(operation)) fail('SERVICE_INVALID', operation); return this[operation](request); }
}

export function createServiceLifecycle(options) { return new ServiceLifecycle(options); }
export const createLifecycleOrchestrator = createServiceLifecycle;
export default createServiceLifecycle;
