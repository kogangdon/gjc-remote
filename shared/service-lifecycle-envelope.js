import { createHash } from "node:crypto";
import { canonicalJsonBytes, canonicalJsonHash, isHex64, utf8Compare, assertStrictText } from "./strict-json.js";
import { isPrincipal } from "./identity.js";
import { DEPLOYMENT_ENVELOPE_LIMITS, validateDeploymentSource } from "./deployment-envelope.js";

export const SERVICE_LIFECYCLE_LIMITS = Object.freeze({
  requestBytes: 256 * 1024,
  hostIdCodeUnits: 128,
  pathBytes: 4096,
  roleJsonBytes: 32 * 1024,
  principalBytes: 4096,
  servicePasswordBytes: 16 * 1024,
  protectedRecordBytes: 16 * 1024 * 1024,
  startupWindowMs: 60_000,
  expectedHostCount: 100_000,
});

export const SERVICE_OPERATIONS = Object.freeze(["install", "status", "update", "rollback", "uninstall", "recover"]);
export const SERVICE_MUTATION_OPERATIONS = Object.freeze(["install", "update", "rollback", "uninstall"]);
export const SERVICE_TRANSACTION_PHASES = Object.freeze([
  "prepared",
  "sequence-reserved",
  "release-published",
  "transition-marker-intent",
  "stopping",
  "quiescent",
  "resource-published",
  "trial-start-intent",
  "trial-start-observed",
  "starting",
  "startup-observed",
  "activation-observed",
  "tombstoned",
  "resource-removed",
  "references-released",
  "committed",
  "manual-cleanup",
]);
export const SERVICE_STATUS_VALUES = Object.freeze({
  ownership: Object.freeze(["absent", "owned", "foreign", "ambiguous"]),
  service: Object.freeze(["missing", "stopped", "running", "transitioning", "unknown"]),
  activation: Object.freeze(["enabled", "suppressed-controller-startable", "disabled-not-startable", "drifted", "unknown"]),
  tree: Object.freeze(["empty", "exact-current", "ambiguous", "overflow", "unknown"]),
  startupEvidence: Object.freeze(["none", "fresh-current-epoch", "historical-current-epoch", "invalidated", "unavailable"]),
  connectivityObservation: Object.freeze(["last-observed-connected", "last-observed-disconnected", "startup-only", "unknown"]),
  health: Object.freeze(["unknown"]),
  supervisorProvenance: Object.freeze(["not-applicable", "project-attested-unsigned-upstream", "unknown"]),
  recovery: Object.freeze(["clean", "pending", "manual-cleanup"]),
});
export const SERVICE_STORE_NAMESPACES = Object.freeze([
  "transaction",
  "manifest",
  "reference",
  "tombstone",
  "floor",
  "manual",
  "locks",
]);
export const SERVICE_ARTIFACT_SCRATCH_PHASES = Object.freeze([
  "candidate-payload-removing",
  "candidate-inventory-removing",
  "candidate-root-removing",
  "asset-removing",
  "marker-removing",
  "scratch-root-removing",
]);
export const SERVICE_ARTIFACT_CLEANUP_PHASES = Object.freeze([
  "payload-removing",
  "inventory-removing",
  "root-removing",
]);

const PLATFORM_TUPLES = new Set(["linux:x64", "linux:arm64", "win32:x64"]);
const COMPONENTS = new Set(["bot", "daemon"]);
const SAFE_ID = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/;
const NONCE = /^[0-9a-f]{32}$/;
const DAEMON_SERVICE_KEY = /^[a-z0-9](?:[a-z0-9-]{0,30}[a-z0-9])?-[0-9a-f]{64}$/;
const FORBIDDEN_SERVICE_HOST_ID_CHARACTER = /[\p{Cc}\p{Cf}\u2028\u2029]/u;
const ROLE_KEYS = Object.freeze(["management", "bot", "recovery", "daemon", "system"]);
const MUTATION_OPERATION_SET = new Set(SERVICE_MUTATION_OPERATIONS);
const TRANSACTION_PHASE_SET = new Set(SERVICE_TRANSACTION_PHASES);
const MANUAL_REASONS = new Set([
  "foreign-resource",
  "hybrid-proof",
  "recreated-resource",
  "torn-protected-state",
  "activation-drift",
  "ambiguous-process-tree",
  "process-tree-overflow",
  "incompatible-predecessor",
  "platform-evidence-gap",
]);
const MANUAL_ACTIONS = new Set([
  "remove-unmarked-resource",
  "restore-recorded-stable-old",
  "remove-foreign-activation",
  "quiesce-recorded-process-tree",
  "repair-protected-control-store",
  "restore-recorded-predecessor",
]);

const PLATFORM_STATE_TEMPLATES = Object.freeze({
  linux: Object.freeze({
    absent: Object.freeze({ schemaVersion: 1, kind: "linux-service-state", phase: "absent", loaded: false, masked: false, unitFileState: "absent", restartPolicy: "none", inboundActivatorCount: 0, hasStartBlockingCondition: false, activation: "disabled-not-startable" }),
    trial: Object.freeze({ schemaVersion: 1, kind: "linux-service-state", phase: "trial", loaded: true, masked: false, unitFileState: "disabled", restartPolicy: "no", inboundActivatorCount: 0, hasStartBlockingCondition: false, activation: "suppressed-controller-startable" }),
    "final-restart-armed": Object.freeze({ schemaVersion: 1, kind: "linux-service-state", phase: "final-restart-armed", loaded: true, masked: false, unitFileState: "disabled", restartPolicy: "on-failure", inboundActivatorCount: 0, hasStartBlockingCondition: false, activation: "suppressed-controller-startable" }),
    final: Object.freeze({ schemaVersion: 1, kind: "linux-service-state", phase: "final", loaded: true, masked: false, unitFileState: "enabled", restartPolicy: "on-failure", inboundActivatorCount: 0, hasStartBlockingCondition: false, activation: "enabled" }),
  }),
  win32: Object.freeze({
    absent: Object.freeze({ schemaVersion: 1, kind: "windows-service-state", phase: "absent", exists: false, ownershipMarker: "none", startType: "absent", failureActions: "none", failureResetSeconds: 0, failureActionsOnNonCrash: false, activation: "disabled-not-startable" }),
    "created-protected": Object.freeze({ schemaVersion: 1, kind: "windows-service-state", phase: "created-protected", exists: true, ownershipMarker: "transition", startType: "disabled", failureActions: "none", failureResetSeconds: 0, failureActionsOnNonCrash: false, activation: "disabled-not-startable" }),
    trial: Object.freeze({ schemaVersion: 1, kind: "windows-service-state", phase: "trial", exists: true, ownershipMarker: "transition", startType: "demand", failureActions: "none", failureResetSeconds: 0, failureActionsOnNonCrash: false, activation: "suppressed-controller-startable" }),
    "final-auto": Object.freeze({ schemaVersion: 1, kind: "windows-service-state", phase: "final-auto", exists: true, ownershipMarker: "final", startType: "auto", failureActions: "none", failureResetSeconds: 0, failureActionsOnNonCrash: false, activation: "enabled" }),
    final: Object.freeze({ schemaVersion: 1, kind: "windows-service-state", phase: "final", exists: true, ownershipMarker: "final", startType: "auto", failureActions: "restart-10s,restart-10s,restart-10s,none", failureResetSeconds: 600, failureActionsOnNonCrash: false, activation: "enabled" }),
  }),
});

const plain = (value) => value !== null && typeof value === "object" && !Array.isArray(value) && Object.getPrototypeOf(value) === Object.prototype;
const exact = (value, keys) => plain(value) && Object.keys(value).length === keys.length && keys.every((key) => Object.hasOwn(value, key));
const fail = (message) => { throw new TypeError(`SERVICE_LIFECYCLE_ENVELOPE_INVALID: ${message}`); };
const positive = (value) => Number.isSafeInteger(value) && value >= 1;
const nonnegative = (value) => Number.isSafeInteger(value) && value >= 0;
const nullableHash = (value) => value === null || isHex64(value);

function strictText(value, name, maxBytes, { allowEmpty = false } = {}) {
  try { assertStrictText(value, name, maxBytes); } catch { fail(name); }
  if (!allowEmpty && value.length === 0) fail(name);
  return value;
}

function fingerprint(record, field) {
  if (!plain(record) || !Object.hasOwn(record, field)) fail(`${field} preimage`);
  return canonicalJsonHash(Object.fromEntries(Object.entries(record).filter(([key]) => key !== field)));
}

function validateTuple(platform, architecture) {
  if (!PLATFORM_TUPLES.has(`${platform}:${architecture}`)) fail("unsupported platform tuple");
}

function validateComponentAndKey(component, serviceKey) {
  if (!COMPONENTS.has(component)) fail("service identity");
  validateServiceKey(serviceKey, component);
}

function validateSafeId(value, name) {
  if (typeof value !== "string" || !SAFE_ID.test(value)) fail(name);
  return value;
}

function absolutePath(value, platform, name) {
  strictText(value, name, SERVICE_LIFECYCLE_LIMITS.pathBytes);
  const valid = platform === "win32"
    ? /^(?:[A-Za-z]:[\\/]|\\\\[^\\/]+[\\/][^\\/]+)/.test(value)
    : value.startsWith("/");
  if (!valid) fail(name);
  return value;
}

export function validateServiceHostId(hostId) {
  if (typeof hostId !== "string" || hostId.length === 0 || hostId.length > SERVICE_LIFECYCLE_LIMITS.hostIdCodeUnits) fail("HOST_ID length");
  if (FORBIDDEN_SERVICE_HOST_ID_CHARACTER.test(hostId)) fail("HOST_ID forbidden Unicode character");
  for (let index = 0; index < hostId.length; index += 1) {
    const code = hostId.charCodeAt(index);
    if (code >= 0xd800 && code <= 0xdfff) {
      const next = hostId.charCodeAt(index + 1);
      if (code <= 0xdbff && next >= 0xdc00 && next <= 0xdfff) index += 1;
      else fail("HOST_ID unpaired surrogate");
    }
  }
  return hostId;
}

export function deriveServiceInstanceKey(hostId) {
  validateServiceHostId(hostId);
  let slug = hostId.replace(/[^A-Za-z0-9]+/g, "-").toLowerCase().replace(/^-+|-+$/g, "");
  slug = slug.slice(0, 32).replace(/-+$/g, "");
  if (slug.length === 0) slug = "host";
  const digest = createHash("sha256").update(Buffer.from(hostId, "utf8")).digest("hex");
  return `${slug}-${digest}`;
}

export function validateServiceTarget(target) {
  if (!plain(target) || !COMPONENTS.has(target.component)) fail("service target");
  if (target.component === "bot") {
    if (!exact(target, ["component"])) fail("bot target");
  } else {
    if (!exact(target, ["component", "hostId"])) fail("daemon target");
    validateServiceHostId(target.hostId);
  }
  return target;
}

export function serviceKeyForTarget(target) {
  validateServiceTarget(target);
  return target.component === "bot" ? "bot" : deriveServiceInstanceKey(target.hostId);
}

export function validateServiceKey(serviceKey, component = undefined) {
  const inferred = serviceKey === "bot" ? "bot" :
    typeof serviceKey === "string" && DAEMON_SERVICE_KEY.test(serviceKey) ? "daemon" : null;
  if (inferred === null || (component !== undefined && component !== inferred)) fail("service key");
  return serviceKey;
}

export function validateServiceRoles(roles, platform) {
  if (!exact(roles, ROLE_KEYS)) fail("service roles");
  const expectedKind = platform === "linux" ? "uid" : platform === "win32" ? "sid" : null;
  if (expectedKind === null) fail("service role platform");
  const identities = new Set();
  for (const role of ROLE_KEYS) {
    const principal = roles[role];
    if (!isPrincipal(principal) || principal.kind !== expectedKind || Buffer.byteLength(principal.value, "utf8") > SERVICE_LIFECYCLE_LIMITS.principalBytes) fail(`${role} principal`);
    identities.add(`${principal.kind}:${principal.value}`);
  }
  if (identities.size !== ROLE_KEYS.length) fail("service roles must be pairwise distinct");
  const systemValue = platform === "linux" ? "uid:0" : "S-1-5-18";
  if (roles.system.value !== systemValue) fail("SYSTEM principal");
  if (canonicalJsonBytes(roles).byteLength > SERVICE_LIFECYCLE_LIMITS.roleJsonBytes) fail("service role byte limit");
  return roles;
}

export function serviceRolesFingerprint(roles, platform) {
  validateServiceRoles(roles, platform);
  return canonicalJsonHash(roles);
}

function validateConfigurationForComponent(configuration, component, platform) {
  const common = ["runtimePath", "workingDirectory", "homeDirectory", "logDirectory"];
  const keys = component === "bot" ? [...common, "channelsConfig", "expectedHostSetFingerprint", "expectedHostCount"] : common;
  if (!exact(configuration, keys)) fail(`${component} service configuration`);
  for (const field of common) absolutePath(configuration[field], platform, field);
  if (component === "bot") {
    absolutePath(configuration.channelsConfig, platform, "channelsConfig");
    if (!isHex64(configuration.expectedHostSetFingerprint) || !nonnegative(configuration.expectedHostCount) ||
        configuration.expectedHostCount > SERVICE_LIFECYCLE_LIMITS.expectedHostCount) fail("bot expected host set");
  }
  return configuration;
}

export function validateServiceConfiguration(configuration, { target, platform }) {
  validateServiceTarget(target);
  if (!["linux", "win32"].includes(platform)) fail("service configuration platform");
  return validateConfigurationForComponent(configuration, target.component, platform);
}

export function serviceConfigurationFingerprint(configuration, { component, platform }) {
  if (!COMPONENTS.has(component) || !["linux", "win32"].includes(platform)) fail("service configuration identity");
  validateConfigurationForComponent(configuration, component, platform);
  return canonicalJsonHash(configuration);
}

function validateServicePassword(value) {
  if (typeof value !== "string" || value.length === 0 || Buffer.byteLength(value, "utf8") > SERVICE_LIFECYCLE_LIMITS.servicePasswordBytes) fail("service password");
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index);
    if (code === 0) fail("service password NUL");
    if (code >= 0xd800 && code <= 0xdfff) {
      const next = value.charCodeAt(index + 1);
      if (code <= 0xdbff && next >= 0xdc00 && next <= 0xdfff) index += 1;
      else fail("service password unpaired surrogate");
    }
  }
  return value;
}

function validateExpected(operation, expected, platform) {
  const shawl = platform === "win32";
  let keys;
  if (operation === "install") keys = ["serviceGeneration", "resourceProof", "applicationSequenceFloor", ...(shawl ? ["shawlSequenceFloor"] : [])];
  else if (operation === "update") keys = ["serviceGeneration", "resourceProof", "currentManifestFingerprint", "applicationSequenceFloor", ...(shawl ? ["shawlSequenceFloor"] : [])];
  else if (operation === "rollback") keys = ["serviceGeneration", "resourceProof", "currentManifestFingerprint", "predecessorManifestFingerprint"];
  else if (operation === "uninstall") keys = ["serviceGeneration", "resourceProof", "currentManifestFingerprint"];
  else keys = ["transactionId", "journalFingerprint"];
  const floorKeys = ["applicationSequenceFloor", ...(shawl ? ["shawlSequenceFloor"] : [])];
  const hasFloors = floorKeys.every((key) => Object.hasOwn(expected, key));
  if (!exact(expected, hasFloors ? [...new Set([...keys, ...floorKeys])] : keys)) fail(`${operation} expected CAS`);
  if (operation === "recover") {
    validateSafeId(expected.transactionId, "recovery transaction ID");
    if (!isHex64(expected.journalFingerprint)) fail("recovery journal fingerprint");
    return expected;
  }
  if (operation === "install") {
    if (expected.serviceGeneration !== 0 || expected.resourceProof !== null) fail("install expected CAS");
  } else if (!positive(expected.serviceGeneration) || !isHex64(expected.resourceProof)) fail(`${operation} expected CAS`);
  if (Object.hasOwn(expected, "currentManifestFingerprint") && !isHex64(expected.currentManifestFingerprint)) fail(`${operation} current manifest fingerprint`);
  if (Object.hasOwn(expected, "predecessorManifestFingerprint") && !isHex64(expected.predecessorManifestFingerprint)) fail("rollback predecessor fingerprint");
  if (Object.hasOwn(expected, "applicationSequenceFloor") && !nonnegative(expected.applicationSequenceFloor)) fail("application sequence floor CAS");
  if (Object.hasOwn(expected, "shawlSequenceFloor") && !nonnegative(expected.shawlSequenceFloor)) fail("Shawl sequence floor CAS");
  return expected;
}

function assertRequestSize(request) {
  let bytes;
  try { bytes = Buffer.byteLength(JSON.stringify(request), "utf8"); } catch { fail("request JSON"); }
  if (bytes > SERVICE_LIFECYCLE_LIMITS.requestBytes) fail("request byte limit");
}

export function validateServiceLifecycleRequest(operation, request, { platform, architecture }) {
  if (!SERVICE_OPERATIONS.includes(operation) || !plain(request) || request.schemaVersion !== 1) fail("service request");
  validateTuple(platform, architecture);
  let keys;
  if (operation === "status") keys = ["schemaVersion", "target", "roles"];
  else if (operation === "install") keys = ["schemaVersion", "target", "roles", "source", "configuration", "expected", ...(platform === "win32" && Object.hasOwn(request, "servicePassword") ? ["servicePassword"] : [])];
  else if (operation === "update") keys = ["schemaVersion", "target", "roles", "source", "expected", "acceptServiceDisruption"];
  else keys = ["schemaVersion", "target", "roles", "expected", "acceptServiceDisruption"];
  if (!exact(request, keys)) fail(`${operation} request keys`);
  validateServiceTarget(request.target);
  validateServiceRoles(request.roles, platform);
  if (operation === "install" || operation === "update") validateDeploymentSource(request.source, { platform, architecture });
  if (operation === "install") {
    validateServiceConfiguration(request.configuration, { target: request.target, platform });
    if (Object.hasOwn(request, "servicePassword")) validateServicePassword(request.servicePassword);
  }
  if (operation !== "status") validateExpected(operation, request.expected, platform);
  if (["update", "rollback", "uninstall"].includes(operation) && request.acceptServiceDisruption !== true) fail(`${operation} disruption acknowledgement`);
  if (operation === "recover" && typeof request.acceptServiceDisruption !== "boolean") fail("recover disruption acknowledgement");
  assertRequestSize(request);
  return request;
}

export function buildServicePlatformState(platform, phase) {
  const template = PLATFORM_STATE_TEMPLATES[platform]?.[phase];
  if (!template) fail("platform service-state phase");
  return { ...template };
}

export function validateServicePlatformState(state, platform) {
  if (!plain(state) || !PLATFORM_STATE_TEMPLATES[platform]) fail("platform service state");
  const template = PLATFORM_STATE_TEMPLATES[platform][state.phase];
  if (!template || !exact(state, Object.keys(template)) || canonicalJsonHash(state) !== canonicalJsonHash(template)) fail("platform service state relation");
  return state;
}

export function serviceResourceProofFingerprint(record) {
  return fingerprint(record, "resourceProof");
}

export function validateServiceResourceProof(record) {
  const keys = ["schemaVersion", "kind", "serviceKey", "component", "platform", "architecture", "operation", "serviceGeneration", "applicationManifestFingerprint", "shawlManifestFingerprint", "configurationFingerprint", "rolesFingerprint", "transactionId", "transactionNonce", "predecessorResourceProof", "platformResourceFingerprint", "platformState", "resourceProof"];
  if (!exact(record, keys) || record.schemaVersion !== 1 || record.kind !== "service-resource-proof" ||
      !MUTATION_OPERATION_SET.has(record.operation) || !positive(record.serviceGeneration) ||
      !isHex64(record.applicationManifestFingerprint) || !nullableHash(record.shawlManifestFingerprint) ||
      !isHex64(record.configurationFingerprint) || !isHex64(record.rolesFingerprint) ||
      typeof record.transactionId !== "string" || !SAFE_ID.test(record.transactionId) ||
      typeof record.transactionNonce !== "string" || !NONCE.test(record.transactionNonce) ||
      !nullableHash(record.predecessorResourceProof) || !isHex64(record.platformResourceFingerprint) ||
      !isHex64(record.resourceProof)) fail("service resource proof schema");
  validateTuple(record.platform, record.architecture);
  validateComponentAndKey(record.component, record.serviceKey);
  validateServicePlatformState(record.platformState, record.platform);
  if ((record.platform === "win32") !== isHex64(record.shawlManifestFingerprint)) fail("resource proof Shawl relation");
  if (record.operation === "install") {
    if (record.serviceGeneration !== 1 || record.predecessorResourceProof !== null) fail("install resource proof relation");
  } else if (record.serviceGeneration < 2 || !isHex64(record.predecessorResourceProof)) fail("replacement resource proof relation");
  if (serviceResourceProofFingerprint(record) !== record.resourceProof) fail("service resource proof fingerprint");
  return record;
}

export function buildServiceResourceProof(fields) {
  const record = { schemaVersion: 1, kind: "service-resource-proof", ...fields, resourceProof: null };
  record.resourceProof = serviceResourceProofFingerprint(record);
  return validateServiceResourceProof(record);
}

export function serviceManifestFingerprint(manifest) {
  return fingerprint(manifest, "manifestFingerprint");
}

export function validateServiceManifest(manifest) {
  const keys = ["schemaVersion", "kind", "serviceKey", "component", "platform", "architecture", "serviceGeneration", "applicationManifestFingerprint", "shawlManifestFingerprint", "predecessorManifestFingerprint", "configuration", "configurationFingerprint", "roles", "rolesFingerprint", "resourceProof", "platformState", "manifestFingerprint"];
  if (!exact(manifest, keys) || manifest.schemaVersion !== 1 || manifest.kind !== "service-manifest" ||
      !positive(manifest.serviceGeneration) || !isHex64(manifest.applicationManifestFingerprint) ||
      !nullableHash(manifest.shawlManifestFingerprint) || !nullableHash(manifest.predecessorManifestFingerprint) ||
      !isHex64(manifest.configurationFingerprint) || !isHex64(manifest.rolesFingerprint) ||
      !isHex64(manifest.resourceProof) || !isHex64(manifest.manifestFingerprint)) fail("service manifest schema");
  validateTuple(manifest.platform, manifest.architecture);
  validateComponentAndKey(manifest.component, manifest.serviceKey);
  validateConfigurationForComponent(manifest.configuration, manifest.component, manifest.platform);
  validateServiceRoles(manifest.roles, manifest.platform);
  validateServicePlatformState(manifest.platformState, manifest.platform);
  if (manifest.platformState.phase !== "final" || manifest.platformState.activation !== "enabled") fail("service manifest activation");
  if ((manifest.platform === "win32") !== isHex64(manifest.shawlManifestFingerprint)) fail("service manifest Shawl relation");
  if ((manifest.serviceGeneration === 1) !== (manifest.predecessorManifestFingerprint === null)) fail("service manifest predecessor relation");
  if (canonicalJsonHash(manifest.configuration) !== manifest.configurationFingerprint || canonicalJsonHash(manifest.roles) !== manifest.rolesFingerprint) fail("service manifest protected configuration relation");
  if (serviceManifestFingerprint(manifest) !== manifest.manifestFingerprint) fail("service manifest fingerprint");
  return manifest;
}

export function buildServiceManifest(fields) {
  const manifest = { schemaVersion: 1, kind: "service-manifest", ...fields, manifestFingerprint: null };
  manifest.manifestFingerprint = serviceManifestFingerprint(manifest);
  return validateServiceManifest(manifest);
}

function validateStableProof(proof, field, platform) {
  const keys = ["disposition", "manifestFingerprint", "resourceProof", "applicationManifestFingerprint", "shawlManifestFingerprint", "serviceGeneration", "activation", field];
  if (!exact(proof, keys) || !["absent", "stable"].includes(proof.disposition) || !nullableHash(proof.manifestFingerprint) ||
      !nullableHash(proof.resourceProof) || !nullableHash(proof.applicationManifestFingerprint) || !nullableHash(proof.shawlManifestFingerprint) ||
      !nonnegative(proof.serviceGeneration) || !SERVICE_STATUS_VALUES.activation.includes(proof.activation) || !isHex64(proof[field])) fail(`${field} schema`);
  if (proof.disposition === "absent") {
    if ([proof.manifestFingerprint, proof.resourceProof, proof.applicationManifestFingerprint, proof.shawlManifestFingerprint].some((value) => value !== null) ||
        proof.serviceGeneration !== 0 || proof.activation !== "disabled-not-startable") fail(`${field} absent relation`);
  } else {
    if (!isHex64(proof.manifestFingerprint) || !isHex64(proof.resourceProof) || !isHex64(proof.applicationManifestFingerprint) ||
        !positive(proof.serviceGeneration) || proof.activation !== "enabled" || ((platform === "win32") !== isHex64(proof.shawlManifestFingerprint))) fail(`${field} stable relation`);
  }
  if (fingerprint(proof, field) !== proof[field]) fail(`${field} fingerprint`);
  return proof;
}

export function validateServiceOldProof(proof, platform) { return validateStableProof(proof, "oldFingerprint", platform); }
export function validateServiceFinalProof(proof, platform) { return validateStableProof(proof, "finalFingerprint", platform); }

function buildStableProof(fields, field, validator, platform) {
  const proof = { ...fields, [field]: null };
  proof[field] = fingerprint(proof, field);
  return validator(proof, platform);
}

export function buildServiceOldProof(fields, platform) { return buildStableProof(fields, "oldFingerprint", validateServiceOldProof, platform); }
export function buildServiceFinalProof(fields, platform) { return buildStableProof(fields, "finalFingerprint", validateServiceFinalProof, platform); }

export function serviceCandidateFingerprint(candidate) { return fingerprint(candidate, "candidateFingerprint"); }

export function validateServiceCandidateProof(candidate, platform) {
  const keys = ["disposition", "applicationManifestFingerprint", "shawlManifestFingerprint", "releaseSequence", "releaseTreeFingerprint", "compatibilityFingerprint", "candidateFingerprint"];
  if (!exact(candidate, keys) || !["none", "release"].includes(candidate.disposition) ||
      !nullableHash(candidate.applicationManifestFingerprint) || !nullableHash(candidate.shawlManifestFingerprint) ||
      !nonnegative(candidate.releaseSequence) || !nullableHash(candidate.releaseTreeFingerprint) ||
      !nullableHash(candidate.compatibilityFingerprint) || !isHex64(candidate.candidateFingerprint)) fail("candidate proof schema");
  if (candidate.disposition === "none") {
    if ([candidate.applicationManifestFingerprint, candidate.shawlManifestFingerprint, candidate.releaseTreeFingerprint, candidate.compatibilityFingerprint].some((value) => value !== null) || candidate.releaseSequence !== 0) fail("empty candidate proof relation");
  } else if (!isHex64(candidate.applicationManifestFingerprint) || !positive(candidate.releaseSequence) ||
      !isHex64(candidate.releaseTreeFingerprint) || !isHex64(candidate.compatibilityFingerprint) ||
      ((platform === "win32") !== isHex64(candidate.shawlManifestFingerprint))) fail("release candidate proof relation");
  if (serviceCandidateFingerprint(candidate) !== candidate.candidateFingerprint) fail("candidate proof fingerprint");
  return candidate;
}

export function buildServiceCandidateProof(fields, platform) {
  const candidate = { ...fields, candidateFingerprint: null };
  candidate.candidateFingerprint = serviceCandidateFingerprint(candidate);
  return validateServiceCandidateProof(candidate, platform);
}

export function serviceTransitionFingerprint(transition) { return fingerprint(transition, "transitionFingerprint"); }

export function validateServiceTransitionProof(transition, platform) {
  const keys = ["oldFingerprint", "candidateFingerprint", "expectedBeforeResourceFingerprint", "expectedAfterResourceFingerprint", "platformResourceFingerprint", "platformState", "transitionFingerprint"];
  if (!exact(transition, keys) || !isHex64(transition.oldFingerprint) || !isHex64(transition.candidateFingerprint) ||
      !nullableHash(transition.expectedBeforeResourceFingerprint) || !nullableHash(transition.expectedAfterResourceFingerprint) ||
      !isHex64(transition.platformResourceFingerprint) || !isHex64(transition.transitionFingerprint)) fail("transition proof schema");
  validateServicePlatformState(transition.platformState, platform);
  if (serviceTransitionFingerprint(transition) !== transition.transitionFingerprint) fail("transition proof fingerprint");
  return transition;
}

export function buildServiceTransitionProof(fields, platform) {
  const transition = { ...fields, transitionFingerprint: null };
  transition.transitionFingerprint = serviceTransitionFingerprint(transition);
  return validateServiceTransitionProof(transition, platform);
}

export function serviceTransactionFingerprint(transaction) { return fingerprint(transaction, "transactionFingerprint"); }

export function validateServiceTransaction(transaction) {
  const keys = ["schemaVersion", "kind", "transactionId", "transactionNonce", "operation", "component", "serviceKey", "platform", "architecture", "serviceGeneration", "old", "candidate", "transition", "final", "phase", "substep", "previousJournalFingerprint", "transactionFingerprint"];
  if (!exact(transaction, keys) || transaction.schemaVersion !== 1 || transaction.kind !== "service-lifecycle-transaction" ||
      typeof transaction.transactionId !== "string" || !SAFE_ID.test(transaction.transactionId) ||
      typeof transaction.transactionNonce !== "string" || !NONCE.test(transaction.transactionNonce) ||
      !MUTATION_OPERATION_SET.has(transaction.operation) || !positive(transaction.serviceGeneration) ||
      !TRANSACTION_PHASE_SET.has(transaction.phase) || !["none", "intent", "action", "observed"].includes(transaction.substep) ||
      !nullableHash(transaction.previousJournalFingerprint) || !isHex64(transaction.transactionFingerprint)) fail("service transaction schema");
  validateTuple(transaction.platform, transaction.architecture);
  validateComponentAndKey(transaction.component, transaction.serviceKey);
  validateServiceOldProof(transaction.old, transaction.platform);
  validateServiceCandidateProof(transaction.candidate, transaction.platform);
  validateServiceTransitionProof(transaction.transition, transaction.platform);
  validateServiceFinalProof(transaction.final, transaction.platform);
  if (transaction.transition.oldFingerprint !== transaction.old.oldFingerprint || transaction.transition.candidateFingerprint !== transaction.candidate.candidateFingerprint) fail("transaction O/C/T relation");
  const installing = transaction.operation === "install";
  const uninstalling = transaction.operation === "uninstall";
  if (installing !== (transaction.old.disposition === "absent") || uninstalling !== (transaction.candidate.disposition === "none") ||
      uninstalling !== (transaction.final.disposition === "absent")) fail("transaction operation tuple relation");
  if (!installing && transaction.old.disposition !== "stable") fail("transaction old tuple");
  if (!uninstalling && (transaction.candidate.disposition !== "release" || transaction.final.disposition !== "stable")) fail("transaction candidate/final tuple");
  if (transaction.serviceGeneration !== transaction.old.serviceGeneration + 1 ||
      (!uninstalling && transaction.final.serviceGeneration !== transaction.serviceGeneration)) fail("transaction generation relation");
  if (!uninstalling && (transaction.final.applicationManifestFingerprint !== transaction.candidate.applicationManifestFingerprint ||
      transaction.final.shawlManifestFingerprint !== transaction.candidate.shawlManifestFingerprint)) fail("transaction C/F relation");
  if (installing ? transaction.transition.expectedBeforeResourceFingerprint !== null : !isHex64(transaction.transition.expectedBeforeResourceFingerprint)) fail("transaction before-resource relation");
  if (uninstalling ? transaction.transition.expectedAfterResourceFingerprint !== null : !isHex64(transaction.transition.expectedAfterResourceFingerprint)) fail("transaction after-resource relation");
  const initialRecord = transaction.phase === "prepared" && transaction.substep === "none";
  const firstInstallRecord = initialRecord && installing && transaction.serviceGeneration === 1;
  if (firstInstallRecord ? transaction.previousJournalFingerprint !== null : !isHex64(transaction.previousJournalFingerprint)) fail("transaction journal chain");
  if (serviceTransactionFingerprint(transaction) !== transaction.transactionFingerprint) fail("service transaction fingerprint");
  return transaction;
}

export function buildServiceTransaction(fields) {
  const transaction = { schemaVersion: 1, kind: "service-lifecycle-transaction", ...fields, transactionFingerprint: null };
  transaction.transactionFingerprint = serviceTransactionFingerprint(transaction);
  return validateServiceTransaction(transaction);
}

export function serviceStartupProofFingerprint(proof) { return fingerprint(proof, "startupProof"); }

export function validateServiceStartupProof(proof) {
  const keys = ["schemaVersion", "kind", "component", "serviceKey", "platform", "architecture", "serviceGeneration", "transactionId", "resourceProof", "applicationManifestFingerprint", "bootFingerprint", "processEpochFingerprint", "platformEvidenceFingerprint", "applicationEvidenceFingerprint", "platformState", "startBoundaryMs", "observedAtMs", "expiresAtMs", "startupEvidence", "connectivityObservation", "startupProof"];
  if (!exact(proof, keys) || proof.schemaVersion !== 1 || proof.kind !== "service-startup-proof" ||
      !positive(proof.serviceGeneration) || typeof proof.transactionId !== "string" || !SAFE_ID.test(proof.transactionId) ||
      [proof.resourceProof, proof.applicationManifestFingerprint, proof.bootFingerprint, proof.processEpochFingerprint, proof.platformEvidenceFingerprint, proof.applicationEvidenceFingerprint, proof.startupProof].some((value) => !isHex64(value)) ||
      !nonnegative(proof.startBoundaryMs) || !nonnegative(proof.observedAtMs) || !nonnegative(proof.expiresAtMs) ||
      proof.startupEvidence !== "fresh-current-epoch" || !SERVICE_STATUS_VALUES.connectivityObservation.includes(proof.connectivityObservation)) fail("service startup proof schema");
  validateTuple(proof.platform, proof.architecture);
  validateComponentAndKey(proof.component, proof.serviceKey);
  validateServicePlatformState(proof.platformState, proof.platform);
  if (proof.platformState.phase !== "trial" || proof.platformState.activation !== "suppressed-controller-startable") fail("startup proof trial state");
  if (proof.observedAtMs < proof.startBoundaryMs || proof.observedAtMs > proof.expiresAtMs ||
      proof.expiresAtMs <= proof.startBoundaryMs ||
      proof.expiresAtMs - proof.startBoundaryMs > SERVICE_LIFECYCLE_LIMITS.startupWindowMs) fail("startup proof time window");
  if (proof.component === "bot" ? proof.connectivityObservation !== "last-observed-connected" : proof.connectivityObservation !== "startup-only") fail("startup proof application evidence relation");
  if (serviceStartupProofFingerprint(proof) !== proof.startupProof) fail("service startup proof fingerprint");
  return proof;
}

export function buildServiceStartupProof(fields) {
  const proof = { schemaVersion: 1, kind: "service-startup-proof", ...fields, startupProof: null };
  proof.startupProof = serviceStartupProofFingerprint(proof);
  return validateServiceStartupProof(proof);
}

export function serviceTombstoneFingerprint(tombstone) { return fingerprint(tombstone, "tombstoneFingerprint"); }

export function validateServiceTombstone(tombstone) {
  const keys = ["schemaVersion", "kind", "component", "serviceKey", "platform", "architecture", "serviceGeneration", "transactionId", "transactionFingerprint", "resourceProof", "currentManifestFingerprint", "applicationSequenceFloor", "shawlSequenceFloor", "tombstoneFingerprint"];
  if (!exact(tombstone, keys) || tombstone.schemaVersion !== 1 || tombstone.kind !== "service-tombstone" ||
      !positive(tombstone.serviceGeneration) || typeof tombstone.transactionId !== "string" || !SAFE_ID.test(tombstone.transactionId) ||
      !isHex64(tombstone.transactionFingerprint) || !isHex64(tombstone.resourceProof) || !isHex64(tombstone.currentManifestFingerprint) ||
      !nonnegative(tombstone.applicationSequenceFloor) || !isHex64(tombstone.tombstoneFingerprint)) fail("service tombstone schema");
  validateTuple(tombstone.platform, tombstone.architecture);
  validateComponentAndKey(tombstone.component, tombstone.serviceKey);
  if (tombstone.platform === "win32" ? !nonnegative(tombstone.shawlSequenceFloor) : tombstone.shawlSequenceFloor !== null) fail("service tombstone Shawl floor");
  if (serviceTombstoneFingerprint(tombstone) !== tombstone.tombstoneFingerprint) fail("service tombstone fingerprint");
  return tombstone;
}

export function buildServiceTombstone(fields) {
  const tombstone = { schemaVersion: 1, kind: "service-tombstone", ...fields, tombstoneFingerprint: null };
  tombstone.tombstoneFingerprint = serviceTombstoneFingerprint(tombstone);
  return validateServiceTombstone(tombstone);
}

export function serviceManualCleanupFingerprint(record) { return fingerprint(record, "manualCleanupFingerprint"); }

export function validateServiceManualCleanup(record) {
  const keys = ["schemaVersion", "kind", "component", "serviceKey", "platform", "architecture", "serviceGeneration", "transactionId", "journalFingerprint", "phase", "reason", "operatorAction", "expectedDisposition", "expectedOldProofFingerprint", "observedDisposition", "observedFingerprint", "blockedUntilOperatorAction", "manualCleanupFingerprint"];
  if (!exact(record, keys) || record.schemaVersion !== 1 || record.kind !== "service-manual-cleanup" ||
      !nonnegative(record.serviceGeneration) || typeof record.transactionId !== "string" || !SAFE_ID.test(record.transactionId) || !isHex64(record.journalFingerprint) ||
      !TRANSACTION_PHASE_SET.has(record.phase) || !MANUAL_REASONS.has(record.reason) || !MANUAL_ACTIONS.has(record.operatorAction) ||
      !["absent", "stable-old"].includes(record.expectedDisposition) || !isHex64(record.expectedOldProofFingerprint) ||
      !["absent", "stable-old", "foreign", "hybrid", "ambiguous", "survivor", "torn"].includes(record.observedDisposition) ||
      !nullableHash(record.observedFingerprint) || record.blockedUntilOperatorAction !== true ||
      !isHex64(record.manualCleanupFingerprint)) fail("service manual-cleanup schema");
  validateTuple(record.platform, record.architecture);
  validateComponentAndKey(record.component, record.serviceKey);
  if ((record.observedDisposition === "absent" && record.observedFingerprint !== null) ||
      (["stable-old", "hybrid"].includes(record.observedDisposition) && !isHex64(record.observedFingerprint))) fail("service manual-cleanup disposition relation");
  if (serviceManualCleanupFingerprint(record) !== record.manualCleanupFingerprint) fail("service manual-cleanup fingerprint");
  return record;
}

export function buildServiceManualCleanup(fields) {
  const record = { schemaVersion: 1, kind: "service-manual-cleanup", ...fields, manualCleanupFingerprint: null };
  record.manualCleanupFingerprint = serviceManualCleanupFingerprint(record);
  return validateServiceManualCleanup(record);
}

export function serviceStatusFingerprint(status) { return fingerprint(status, "statusFingerprint"); }

export function validateServiceStatusReceipt(status) {
  const keys = ["schemaVersion", "kind", "component", "serviceKey", "platform", "architecture", "serviceGeneration", "manifestFingerprint", "resourceProof", "transactionFingerprint", "ownership", "service", "activation", "tree", "startupEvidence", "connectivityObservation", "providerHealth", "workspaceHealth", "supervisorProvenance", "recovery", "observedAtMs", "statusFingerprint"];
  if (!exact(status, keys) || status.schemaVersion !== 1 || status.kind !== "service-status" ||
      !nonnegative(status.serviceGeneration) || !nullableHash(status.manifestFingerprint) || !nullableHash(status.resourceProof) ||
      !nullableHash(status.transactionFingerprint) || !SERVICE_STATUS_VALUES.ownership.includes(status.ownership) ||
      !SERVICE_STATUS_VALUES.service.includes(status.service) || !SERVICE_STATUS_VALUES.activation.includes(status.activation) ||
      !SERVICE_STATUS_VALUES.tree.includes(status.tree) || !SERVICE_STATUS_VALUES.startupEvidence.includes(status.startupEvidence) ||
      !SERVICE_STATUS_VALUES.connectivityObservation.includes(status.connectivityObservation) || status.providerHealth !== "unknown" ||
      status.workspaceHealth !== "unknown" || !SERVICE_STATUS_VALUES.supervisorProvenance.includes(status.supervisorProvenance) ||
      !SERVICE_STATUS_VALUES.recovery.includes(status.recovery) ||
      !nonnegative(status.observedAtMs) || !isHex64(status.statusFingerprint)) fail("service status schema");
  validateTuple(status.platform, status.architecture);
  validateComponentAndKey(status.component, status.serviceKey);
  if (status.platform === "linux" ? status.supervisorProvenance !== "not-applicable" :
      (status.ownership === "owned" ? status.supervisorProvenance !== "project-attested-unsigned-upstream" :
        status.supervisorProvenance !== "unknown")) fail("status supervisor provenance");
  if (status.ownership === "absent") {
    if (status.serviceGeneration !== 0 || status.manifestFingerprint !== null || status.resourceProof !== null || status.transactionFingerprint !== null ||
        status.service !== "missing" || status.activation !== "disabled-not-startable" || status.tree !== "empty" ||
        status.startupEvidence !== "none" || status.connectivityObservation !== "unknown" || status.recovery !== "clean") fail("absent status relation");
  } else if (status.ownership === "owned") {
    if (!positive(status.serviceGeneration) || !isHex64(status.manifestFingerprint) || !isHex64(status.resourceProof)) fail("owned status proof");
  } else if (status.serviceGeneration !== 0 || status.manifestFingerprint !== null || status.resourceProof !== null) fail("unowned status proof");
  if ((status.recovery === "clean" && status.transactionFingerprint !== null) ||
      (status.recovery === "pending" && !isHex64(status.transactionFingerprint))) fail("status recovery relation");
  if (status.service === "transitioning" && status.recovery === "clean") fail("transitioning status recovery");
  if (status.startupEvidence === "fresh-current-epoch" &&
      (status.ownership !== "owned" || status.service !== "running" || status.tree !== "exact-current")) fail("fresh startup status relation");
  if (status.component === "daemon" && ["last-observed-connected", "last-observed-disconnected"].includes(status.connectivityObservation)) fail("daemon connectivity status relation");
  if (serviceStatusFingerprint(status) !== status.statusFingerprint) fail("service status fingerprint");
  return status;
}

export function buildServiceStatusReceipt(fields) {
  const status = { schemaVersion: 1, kind: "service-status", ...fields, statusFingerprint: null };
  status.statusFingerprint = serviceStatusFingerprint(status);
  return validateServiceStatusReceipt(status);
}

const SERVICE_IDENTITY_PROFILES = new Set([
  "service-control-directory",
  "service-control-file",
  "service-staging-directory",
  "service-staging-file",
  "service-release-directory",
  "service-release-file",
  "service-release-executable",
  "service-bot-log-directory",
  "service-daemon-log-directory",
]);
const FLOOR_SCOPE = /^(?:application:(?:linux:(?:x64|arm64)|win32:x64)|shawl:win32:x64)$/;
const REFERENCE_SLOTS = Object.freeze(["current", "previous", "provisional"]);

function uint64Text(value) {
  if (typeof value !== "string" || !/^(?:0|[1-9][0-9]{0,19})$/.test(value)) return false;
  try { return BigInt(value) <= 18446744073709551615n; } catch { return false; }
}

export function validateServiceNativeIdentity(identity, platform, expectedProfile = undefined) {
  const commonValid = plain(identity) && SERVICE_IDENTITY_PROFILES.has(identity.profile) &&
    (expectedProfile === undefined || identity.profile === expectedProfile) &&
    typeof identity.owner === "string" && identity.owner.length > 0 &&
    Buffer.byteLength(identity.owner, "utf8") <= SERVICE_LIFECYCLE_LIMITS.principalBytes &&
    isHex64(identity.securitySha256);
  if (!commonValid) fail("native service identity");
  strictText(identity.owner, "native service identity owner", SERVICE_LIFECYCLE_LIMITS.principalBytes);
  if (platform === "linux") {
    if (!exact(identity, ["profile", "kind", "device", "inode", "mode", "owner", "securitySha256"]) ||
        identity.kind !== "linux-service-object-v1" || !uint64Text(identity.device) ||
        !uint64Text(identity.inode) || !Number.isSafeInteger(identity.mode) ||
        identity.mode < 0 || identity.mode > 0xffffffff ||
        !isPrincipal({ kind: "uid", value: identity.owner })) fail("Linux native service identity");
  } else if (platform === "win32") {
    if (!exact(identity, ["profile", "kind", "volumeSerial", "fileId", "attributes", "owner", "securitySha256"]) ||
        identity.kind !== "win32-service-object-v1" || !/^[0-9a-f]{16}$/.test(identity.volumeSerial) ||
        !/^[0-9a-f]{32}$/.test(identity.fileId) || !Number.isSafeInteger(identity.attributes) ||
        identity.attributes < 0 || identity.attributes > 0xffffffff ||
        !isPrincipal({ kind: "sid", value: identity.owner })) fail("Windows native service identity");
  } else {
    fail("native service identity platform");
  }
  return identity;
}

export function serviceNativeIdentityFingerprint(identity, platform, expectedProfile = undefined) {
  validateServiceNativeIdentity(identity, platform, expectedProfile);
  return canonicalJsonHash(identity);
}

function validateBoundedServiceFileFacts(facts, platform, maximumBytes) {
  const commonValid = plain(facts) && nonnegative(facts.size) &&
    facts.size <= maximumBytes &&
    typeof facts.owner === "string" &&
    isHex64(facts.sha256) && isHex64(facts.securitySha256);
  if (!commonValid) fail("native service file facts");
  strictText(facts.owner, "native service file owner", SERVICE_LIFECYCLE_LIMITS.principalBytes);
  if (platform === "linux") {
    if (!exact(facts, ["kind", "device", "inode", "size", "sha256", "mode", "owner", "securitySha256"]) ||
        facts.kind !== "linux-file-v1" || !uint64Text(facts.device) || !uint64Text(facts.inode) ||
        !Number.isSafeInteger(facts.mode) || facts.mode < 0 || facts.mode > 0xffffffff ||
        !isPrincipal({ kind: "uid", value: facts.owner })) fail("Linux native service file facts");
  } else if (platform === "win32") {
    if (!exact(facts, ["kind", "volumeSerial", "fileId", "size", "sha256", "attributes", "owner", "securitySha256"]) ||
        facts.kind !== "win32-file-v1" || !/^[0-9a-f]{16}$/.test(facts.volumeSerial) ||
        !/^[0-9a-f]{32}$/.test(facts.fileId) || !Number.isSafeInteger(facts.attributes) ||
        facts.attributes < 0 || facts.attributes > 0xffffffff ||
        !isPrincipal({ kind: "sid", value: facts.owner })) fail("Windows native service file facts");
  } else {
    fail("native service file facts platform");
  }
  return facts;
}

export function validateServiceNativeFileFacts(facts, platform) {
  return validateBoundedServiceFileFacts(facts, platform, SERVICE_LIFECYCLE_LIMITS.protectedRecordBytes);
}

export function validateServiceArtifactFileFacts(facts, platform) {
  return validateBoundedServiceFileFacts(facts, platform, DEPLOYMENT_ENVELOPE_LIMITS.unpackedPayloadBytes);
}

export function serviceNativeFileFactsFingerprint(facts, platform) {
  validateServiceNativeFileFacts(facts, platform);
  return canonicalJsonHash(facts);
}

export function validateServiceControlRootBinding(binding, platform) {
  if (!exact(binding, ["schemaVersion", "rootKind", "rootPath", "rootNonce", "rolesFingerprint", "identity", "directoryIdentities", "bindingFingerprint"]) ||
      binding.schemaVersion !== 1 || binding.rootKind !== "control" ||
      typeof binding.rootNonce !== "string" || !NONCE.test(binding.rootNonce) ||
      !isHex64(binding.rolesFingerprint) || !isHex64(binding.bindingFingerprint) ||
      !exact(binding.directoryIdentities, SERVICE_STORE_NAMESPACES)) fail("service control root binding");
  absolutePath(binding.rootPath, platform, "native service control root path");
  validateServiceNativeIdentity(binding.identity, platform, "service-control-directory");
  for (const namespace of SERVICE_STORE_NAMESPACES) {
    validateServiceNativeIdentity(binding.directoryIdentities[namespace], platform, "service-control-directory");
  }
  return binding;
}

export function serviceStoreRegistrationFingerprint(registration) {
  return fingerprint(registration, "registrationFingerprint");
}

export function validateServiceStoreRegistration(registration) {
  if (!exact(registration, ["schemaVersion", "kind", "platform", "architecture", "roles", "serviceRolesFingerprint", "rootBinding", "historyRootIdentity", "historyRootIdentityFingerprint", "registrationFingerprint"]) ||
      registration.schemaVersion !== 1 || registration.kind !== "service-store-registration" ||
      !isHex64(registration.serviceRolesFingerprint) ||
      !isHex64(registration.historyRootIdentityFingerprint) ||
      !isHex64(registration.registrationFingerprint)) fail("service store registration");
  validateTuple(registration.platform, registration.architecture);
  validateServiceRoles(registration.roles, registration.platform);
  if (serviceRolesFingerprint(registration.roles, registration.platform) !== registration.serviceRolesFingerprint) {
    fail("service store registered role fingerprint");
  }
  validateServiceControlRootBinding(registration.rootBinding, registration.platform);
  validateServiceNativeIdentity(
    registration.historyRootIdentity,
    registration.platform,
    "service-control-directory"
  );
  if (serviceNativeIdentityFingerprint(
    registration.historyRootIdentity,
    registration.platform,
    "service-control-directory"
  ) !== registration.historyRootIdentityFingerprint) {
    fail("service store history root fingerprint");
  }
  if (registration.historyRootIdentity.owner !== registration.roles.management.value) {
    fail("service store history root owner");
  }
  const physicalIdentities = [
    registration.rootBinding.identity,
    ...SERVICE_STORE_NAMESPACES.map((name) =>
      registration.rootBinding.directoryIdentities[name]),
    registration.historyRootIdentity,
  ].map((identity) => serviceNativeIdentityFingerprint(
    identity,
    registration.platform,
    "service-control-directory"
  ));
  if (new Set(physicalIdentities).size !== physicalIdentities.length) {
    fail("service store physical identity collision");
  }
  const managementOwner = registration.roles.management.value;
  if (registration.rootBinding.identity.owner !== managementOwner ||
      SERVICE_STORE_NAMESPACES.some((name) =>
        registration.rootBinding.directoryIdentities[name].owner !== managementOwner) ||
      registration.historyRootIdentity.owner !== managementOwner) {
    fail("service store registered management owner");
  }
  if (serviceStoreRegistrationFingerprint(registration) !== registration.registrationFingerprint) fail("service store registration fingerprint");
  return registration;
}

export function buildServiceStoreRegistration(fields) {
  const registration = { schemaVersion: 1, kind: "service-store-registration", ...fields, registrationFingerprint: null };
  registration.registrationFingerprint = serviceStoreRegistrationFingerprint(registration);
  return validateServiceStoreRegistration(registration);
}

export function serviceStoreRegistrationIncarnationFingerprint(record) {
  return fingerprint(record, "incarnationFingerprint");
}

export function validateServiceStoreRegistrationIncarnation(record) {
  if (!exact(record, ["schemaVersion", "kind", "platform", "architecture", "rootBindingFingerprint", "historyRootIdentityFingerprint", "registrationFingerprint", "registrationRecordSha256", "registrationFileFacts", "incarnationFingerprint"]) ||
      record.schemaVersion !== 1 || record.kind !== "service-store-registration-incarnation" ||
      !isHex64(record.rootBindingFingerprint) || !isHex64(record.historyRootIdentityFingerprint) ||
      !isHex64(record.registrationFingerprint) || !isHex64(record.registrationRecordSha256) ||
      !isHex64(record.incarnationFingerprint)) {
    fail("service store registration incarnation");
  }
  validateTuple(record.platform, record.architecture);
  validateServiceNativeFileFacts(record.registrationFileFacts, record.platform);
  if (record.registrationFileFacts.sha256 !== record.registrationRecordSha256 ||
      serviceStoreRegistrationIncarnationFingerprint(record) !== record.incarnationFingerprint) {
    fail("service store registration incarnation relation");
  }
  return record;
}

export function buildServiceStoreRegistrationIncarnation(fields) {
  const record = {
    schemaVersion: 1,
    kind: "service-store-registration-incarnation",
    ...fields,
    incarnationFingerprint: null,
  };
  record.incarnationFingerprint = serviceStoreRegistrationIncarnationFingerprint(record);
  return validateServiceStoreRegistrationIncarnation(record);
}

function validateFloorReservation(reservation) {
  if (!exact(reservation, ["component", "serviceKey", "transactionId", "transactionNonce", "transactionFingerprint", "sequence", "manifestFingerprint"]) ||
      !COMPONENTS.has(reservation.component) ||
      typeof reservation.transactionId !== "string" || !SAFE_ID.test(reservation.transactionId) ||
      typeof reservation.transactionNonce !== "string" || !NONCE.test(reservation.transactionNonce) ||
      !isHex64(reservation.transactionFingerprint) ||
      !positive(reservation.sequence) || !isHex64(reservation.manifestFingerprint)) fail("service sequence reservation");
  validateComponentAndKey(reservation.component, reservation.serviceKey);
  return reservation;
}

export function serviceSequenceFloorFingerprint(record) {
  return fingerprint(record, "floorFingerprint");
}

export function validateServiceSequenceFloor(record) {
  if (!exact(record, ["schemaVersion", "kind", "scope", "revision", "historyEntryIdentityFingerprint", "previousHistoryStateFingerprint", "highestReservedSequence", "highestReservedManifestFingerprint", "committedSequence", "committedManifestFingerprint", "committedPublicationFingerprint", "committedTransactionId", "committedTransactionNonce", "committedTransactionFingerprint", "activeReservation", "floorFingerprint"]) ||
      record.schemaVersion !== 1 || record.kind !== "service-sequence-floor" ||
      typeof record.scope !== "string" || !FLOOR_SCOPE.test(record.scope) ||
      !nonnegative(record.revision) || !isHex64(record.historyEntryIdentityFingerprint) ||
      !nullableHash(record.previousHistoryStateFingerprint) ||
      !nonnegative(record.highestReservedSequence) ||
      !nullableHash(record.highestReservedManifestFingerprint) || !nonnegative(record.committedSequence) ||
      !nullableHash(record.committedManifestFingerprint) || !nullableHash(record.committedPublicationFingerprint) ||
      (record.activeReservation !== null && !plain(record.activeReservation)) || !isHex64(record.floorFingerprint)) {
    fail("service sequence floor");
  }
  if ((record.highestReservedSequence === 0) !== (record.highestReservedManifestFingerprint === null) ||
      (record.committedSequence === 0) !== (record.committedManifestFingerprint === null) ||
      (record.committedSequence === 0) !== (record.committedPublicationFingerprint === null) ||
      (record.committedSequence === 0) !== (record.committedTransactionId === null) ||
      (record.committedSequence === 0) !== (record.committedTransactionNonce === null) ||
      (record.committedSequence === 0) !== (record.committedTransactionFingerprint === null) ||
      record.committedSequence > record.highestReservedSequence ||
      (record.committedSequence === record.highestReservedSequence && record.committedSequence > 0 &&
       record.committedManifestFingerprint !== record.highestReservedManifestFingerprint)) {
    fail("service sequence floor high-water relation");
  }
  if (record.committedSequence > 0 &&
      (typeof record.committedTransactionId !== "string" || !SAFE_ID.test(record.committedTransactionId) ||
       typeof record.committedTransactionNonce !== "string" || !NONCE.test(record.committedTransactionNonce))) {
    fail("service sequence committed transaction");
  }
  if (record.committedSequence > 0 && !isHex64(record.committedTransactionFingerprint)) {
    fail("service sequence committed transaction fingerprint");
  }
  if (record.revision === 0 && (record.previousHistoryStateFingerprint !== null ||
      record.highestReservedSequence !== 0 || record.committedSequence !== 0 ||
      record.activeReservation !== null)) {
    fail("service sequence floor bootstrap relation");
  }
  if (record.revision > 0 && !isHex64(record.previousHistoryStateFingerprint)) {
    fail("service sequence floor history relation");
  }
  if (record.activeReservation !== null) {
    validateFloorReservation(record.activeReservation);
    if (record.activeReservation.sequence !== record.highestReservedSequence ||
        record.activeReservation.manifestFingerprint !== record.highestReservedManifestFingerprint) {
      fail("service sequence active reservation relation");
    }
  }
  if (serviceSequenceFloorFingerprint(record) !== record.floorFingerprint) fail("service sequence floor fingerprint");
  return record;
}

export function buildServiceSequenceFloor(fields) {
  const record = { schemaVersion: 1, kind: "service-sequence-floor", ...fields, floorFingerprint: null };
  record.floorFingerprint = serviceSequenceFloorFingerprint(record);
  return validateServiceSequenceFloor(record);
}

export function serviceFloorWitnessFingerprint(record) {
  return fingerprint(record, "witnessFingerprint");
}

export function validateServiceFloorWitness(record) {
  if (!exact(record, ["schemaVersion", "kind", "scope", "platform", "architecture", "rootBindingFingerprint", "revision", "historyEntryIdentityFingerprint", "previousHistoryStateFingerprint", "state", "action", "component", "serviceKey", "currentFloorFingerprint", "intendedFloorFingerprint", "transactionId", "transactionNonce", "transactionFingerprint", "witnessFingerprint"]) ||
      record.schemaVersion !== 1 || record.kind !== "service-floor-witness" ||
      typeof record.scope !== "string" || !FLOOR_SCOPE.test(record.scope) ||
      !isHex64(record.rootBindingFingerprint) || !nonnegative(record.revision) ||
      !isHex64(record.historyEntryIdentityFingerprint) ||
      !nullableHash(record.previousHistoryStateFingerprint) ||
      !["stable", "intent"].includes(record.state) || !isHex64(record.currentFloorFingerprint) ||
      !nullableHash(record.intendedFloorFingerprint) || !isHex64(record.witnessFingerprint)) fail("service floor witness");
  validateTuple(record.platform, record.architecture);
  const expectedApplicationScope = `application:${record.platform}:${record.architecture}`;
  if (record.scope !== expectedApplicationScope &&
      !(record.scope === "shawl:win32:x64" && record.platform === "win32" && record.architecture === "x64")) {
    fail("service floor witness tuple relation");
  }
  const intent = record.state === "intent";
  if (intent && !positive(record.revision)) fail("service floor witness intent revision");
  if (intent ? !["reserve", "commit", "abandon"].includes(record.action) : record.action !== null) {
    fail("service floor witness action relation");
  }
  if (intent !== isHex64(record.intendedFloorFingerprint) ||
      intent !== (typeof record.component === "string" && COMPONENTS.has(record.component)) ||
      intent !== (typeof record.serviceKey === "string") ||
      intent !== (typeof record.transactionId === "string" && SAFE_ID.test(record.transactionId)) ||
      intent !== (typeof record.transactionNonce === "string" && NONCE.test(record.transactionNonce)) ||
      intent !== isHex64(record.transactionFingerprint)) {
    fail("service floor witness state relation");
  }
  if (intent) validateComponentAndKey(record.component, record.serviceKey);
  if (!intent && (record.transactionId !== null || record.transactionNonce !== null ||
      record.transactionFingerprint !== null || record.component !== null ||
      record.serviceKey !== null)) fail("stable service floor witness relation");
  if ((record.revision === 0) !== (record.previousHistoryStateFingerprint === null)) {
    fail("service floor witness history relation");
  }
  if (serviceFloorWitnessFingerprint(record) !== record.witnessFingerprint) fail("service floor witness fingerprint");
  return record;
}

export function buildServiceFloorWitness(fields) {
  const record = { schemaVersion: 1, kind: "service-floor-witness", ...fields, witnessFingerprint: null };
  record.witnessFingerprint = serviceFloorWitnessFingerprint(record);
  return validateServiceFloorWitness(record);
}

export function serviceFloorHistoryIntentFingerprint(record) {
  return fingerprint(record, "intentFingerprint");
}

export function validateServiceFloorHistoryIntent(record) {
  const keys = [
    "schemaVersion", "kind", "scope", "platform", "architecture",
    "rootBindingFingerprint", "registrationFingerprint", "revision", "action",
    "component", "serviceKey", "transactionId", "transactionNonce",
    "transactionFingerprint", "historyEntryIdentity",
    "historyEntryIdentityFingerprint", "previousHistoryStateFingerprint",
    "previousFloorFingerprint", "previousWitnessFingerprint",
    "previousFloorRecordSha256", "previousWitnessRecordSha256",
    "previousFloorFileFacts", "previousWitnessFileFacts", "intendedFloor",
    "intendedWitness", "stableWitness", "intentFingerprint",
  ];
  if (!exact(record, keys) || record.schemaVersion !== 1 ||
      record.kind !== "service-floor-history-intent" ||
      typeof record.scope !== "string" || !FLOOR_SCOPE.test(record.scope) ||
      !isHex64(record.rootBindingFingerprint) || !isHex64(record.registrationFingerprint) ||
      !positive(record.revision) || !["reserve", "commit", "abandon"].includes(record.action) ||
      typeof record.component !== "string" || typeof record.serviceKey !== "string" ||
      typeof record.transactionId !== "string" || !SAFE_ID.test(record.transactionId) ||
      typeof record.transactionNonce !== "string" || !NONCE.test(record.transactionNonce) ||
      !isHex64(record.transactionFingerprint) || !isHex64(record.historyEntryIdentityFingerprint) ||
      !isHex64(record.previousHistoryStateFingerprint) ||
      !isHex64(record.previousFloorFingerprint) || !isHex64(record.previousWitnessFingerprint) ||
      !isHex64(record.previousFloorRecordSha256) || !isHex64(record.previousWitnessRecordSha256) ||
      !isHex64(record.intentFingerprint)) {
    fail("service floor history intent");
  }
  validateTuple(record.platform, record.architecture);
  validateComponentAndKey(record.component, record.serviceKey);
  validateServiceNativeIdentity(
    record.historyEntryIdentity,
    record.platform,
    "service-control-directory"
  );
  if (serviceNativeIdentityFingerprint(
    record.historyEntryIdentity,
    record.platform,
    "service-control-directory"
  ) !== record.historyEntryIdentityFingerprint) {
    fail("service floor history intent identity");
  }
  validateServiceNativeFileFacts(record.previousFloorFileFacts, record.platform);
  validateServiceNativeFileFacts(record.previousWitnessFileFacts, record.platform);
  validateServiceSequenceFloor(record.intendedFloor);
  validateServiceFloorWitness(record.intendedWitness);
  validateServiceFloorWitness(record.stableWitness);
  const expectedApplicationScope = `application:${record.platform}:${record.architecture}`;
  if (record.scope !== expectedApplicationScope &&
      !(record.scope === "shawl:win32:x64" && record.platform === "win32" &&
        record.architecture === "x64")) {
    fail("service floor history intent tuple");
  }
  if (record.previousFloorFileFacts.sha256 !== record.previousFloorRecordSha256 ||
      record.previousWitnessFileFacts.sha256 !== record.previousWitnessRecordSha256 ||
      record.intendedFloor.scope !== record.scope ||
      record.intendedFloor.revision !== record.revision ||
      record.intendedFloor.historyEntryIdentityFingerprint !== record.historyEntryIdentityFingerprint ||
      record.intendedFloor.previousHistoryStateFingerprint !== record.previousHistoryStateFingerprint ||
      record.intendedWitness.scope !== record.scope ||
      record.intendedWitness.platform !== record.platform ||
      record.intendedWitness.architecture !== record.architecture ||
      record.intendedWitness.rootBindingFingerprint !== record.rootBindingFingerprint ||
      record.intendedWitness.revision !== record.revision ||
      record.intendedWitness.historyEntryIdentityFingerprint !== record.historyEntryIdentityFingerprint ||
      record.intendedWitness.previousHistoryStateFingerprint !== record.previousHistoryStateFingerprint ||
      record.intendedWitness.state !== "intent" ||
      record.intendedWitness.action !== record.action ||
      record.intendedWitness.component !== record.component ||
      record.intendedWitness.serviceKey !== record.serviceKey ||
      record.intendedWitness.transactionId !== record.transactionId ||
      record.intendedWitness.transactionNonce !== record.transactionNonce ||
      record.intendedWitness.transactionFingerprint !== record.transactionFingerprint ||
      record.intendedWitness.currentFloorFingerprint !== record.previousFloorFingerprint ||
      record.intendedWitness.intendedFloorFingerprint !== record.intendedFloor.floorFingerprint ||
      record.stableWitness.scope !== record.scope ||
      record.stableWitness.platform !== record.platform ||
      record.stableWitness.architecture !== record.architecture ||
      record.stableWitness.rootBindingFingerprint !== record.rootBindingFingerprint ||
      record.stableWitness.revision !== record.revision ||
      record.stableWitness.historyEntryIdentityFingerprint !== record.historyEntryIdentityFingerprint ||
      record.stableWitness.previousHistoryStateFingerprint !== record.previousHistoryStateFingerprint ||
      record.stableWitness.state !== "stable" || record.stableWitness.action !== null ||
      record.stableWitness.currentFloorFingerprint !== record.intendedFloor.floorFingerprint ||
      record.stableWitness.intendedFloorFingerprint !== null) {
    fail("service floor history intent relation");
  }
  const reservation = record.intendedFloor.activeReservation;
  if (record.action === "reserve") {
    if (reservation === null ||
        reservation.component !== record.component ||
        reservation.serviceKey !== record.serviceKey ||
        reservation.transactionId !== record.transactionId ||
        reservation.transactionNonce !== record.transactionNonce ||
        reservation.transactionFingerprint !== record.transactionFingerprint) {
      fail("service floor history reserve relation");
    }
  } else if (reservation !== null) {
    fail("service floor history terminal reservation relation");
  }
  if (record.action === "commit" &&
      (record.intendedFloor.committedTransactionId !== record.transactionId ||
       record.intendedFloor.committedTransactionNonce !== record.transactionNonce ||
       record.intendedFloor.committedTransactionFingerprint !== record.transactionFingerprint)) {
    fail("service floor history commit relation");
  }
  if (serviceFloorHistoryIntentFingerprint(record) !== record.intentFingerprint) {
    fail("service floor history intent fingerprint");
  }
  return record;
}

export function buildServiceFloorHistoryIntent(fields) {
  const record = {
    schemaVersion: 1,
    kind: "service-floor-history-intent",
    ...fields,
    intentFingerprint: null,
  };
  record.intentFingerprint = serviceFloorHistoryIntentFingerprint(record);
  return validateServiceFloorHistoryIntent(record);
}

export function serviceFloorHistoryStateFingerprint(record) {
  return fingerprint(record, "stateFingerprint");
}

export function validateServiceFloorHistoryState(record) {
  const keys = [
    "schemaVersion", "kind", "scope", "platform", "architecture",
    "rootBindingFingerprint", "registrationFingerprint", "revision", "action",
    "component", "serviceKey", "transactionId", "transactionNonce",
    "transactionFingerprint", "historyEntryIdentity",
    "historyEntryIdentityFingerprint", "previousHistoryStateFingerprint",
    "intentFingerprint", "floorFingerprint", "witnessFingerprint",
    "floorRecordSha256", "witnessRecordSha256", "floorFileFacts",
    "witnessFileFacts", "stateFingerprint",
  ];
  if (!exact(record, keys) || record.schemaVersion !== 1 ||
      record.kind !== "service-floor-history-state" ||
      typeof record.scope !== "string" || !FLOOR_SCOPE.test(record.scope) ||
      !isHex64(record.rootBindingFingerprint) || !isHex64(record.registrationFingerprint) ||
      !nonnegative(record.revision) || !isHex64(record.historyEntryIdentityFingerprint) ||
      !nullableHash(record.previousHistoryStateFingerprint) ||
      !nullableHash(record.intentFingerprint) || !isHex64(record.floorFingerprint) ||
      !isHex64(record.witnessFingerprint) || !isHex64(record.floorRecordSha256) ||
      !isHex64(record.witnessRecordSha256) || !isHex64(record.stateFingerprint)) {
    fail("service floor history state");
  }
  validateTuple(record.platform, record.architecture);
  const expectedApplicationScope = `application:${record.platform}:${record.architecture}`;
  if (record.scope !== expectedApplicationScope &&
      !(record.scope === "shawl:win32:x64" && record.platform === "win32" &&
        record.architecture === "x64")) {
    fail("service floor history state tuple");
  }
  validateServiceNativeIdentity(
    record.historyEntryIdentity,
    record.platform,
    "service-control-directory"
  );
  if (serviceNativeIdentityFingerprint(
    record.historyEntryIdentity,
    record.platform,
    "service-control-directory"
  ) !== record.historyEntryIdentityFingerprint) {
    fail("service floor history state identity");
  }
  validateServiceNativeFileFacts(record.floorFileFacts, record.platform);
  validateServiceNativeFileFacts(record.witnessFileFacts, record.platform);
  const initial = record.revision === 0;
  if (initial) {
    if (record.previousHistoryStateFingerprint !== null || record.intentFingerprint !== null ||
        record.action !== null || record.component !== null || record.serviceKey !== null ||
        record.transactionId !== null || record.transactionNonce !== null ||
        record.transactionFingerprint !== null) {
      fail("service floor history bootstrap state");
    }
  } else {
    if (!isHex64(record.previousHistoryStateFingerprint) || !isHex64(record.intentFingerprint) ||
        !["reserve", "commit", "abandon"].includes(record.action) ||
        typeof record.component !== "string" || typeof record.serviceKey !== "string" ||
        typeof record.transactionId !== "string" || !SAFE_ID.test(record.transactionId) ||
        typeof record.transactionNonce !== "string" || !NONCE.test(record.transactionNonce) ||
        !isHex64(record.transactionFingerprint)) {
      fail("service floor history transition state");
    }
    validateComponentAndKey(record.component, record.serviceKey);
  }
  if (record.floorFileFacts.sha256 !== record.floorRecordSha256 ||
      record.witnessFileFacts.sha256 !== record.witnessRecordSha256 ||
      serviceFloorHistoryStateFingerprint(record) !== record.stateFingerprint) {
    fail("service floor history state relation");
  }
  return record;
}

export function buildServiceFloorHistoryState(fields) {
  const record = {
    schemaVersion: 1,
    kind: "service-floor-history-state",
    ...fields,
    stateFingerprint: null,
  };
  record.stateFingerprint = serviceFloorHistoryStateFingerprint(record);
  return validateServiceFloorHistoryState(record);
}

export function serviceArtifactBindingFingerprint(record) {
  return fingerprint(record, "bindingFingerprint");
}

export function validateServiceArtifactBinding(record, platform) {
  if (!exact(record, ["schemaVersion", "kind", "artifactKind", "rootKind", "artifactFingerprint", "manifestFingerprint", "treeFingerprint", "directoryIdentity", "directoryIdentityFingerprint", "bindingFingerprint"]) ||
      record.schemaVersion !== 1 || record.kind !== "service-artifact-binding" ||
      !["application", "shawl", "shared-template"].includes(record.artifactKind) ||
      !isHex64(record.artifactFingerprint) || !nullableHash(record.manifestFingerprint) ||
      !nullableHash(record.treeFingerprint) || !nullableHash(record.directoryIdentityFingerprint) ||
      !isHex64(record.bindingFingerprint)) fail("service artifact binding");
  if (record.artifactKind === "shared-template") {
    if (record.rootKind !== null || record.manifestFingerprint !== null || record.treeFingerprint !== null ||
        record.directoryIdentity !== null || record.directoryIdentityFingerprint !== null) fail("shared-template artifact binding");
  } else {
    const expectedRoot = record.artifactKind === "application" ? "releases" : "shawl";
    if (record.rootKind !== expectedRoot || !isHex64(record.manifestFingerprint) ||
        (record.artifactKind === "application" ? !isHex64(record.treeFingerprint) : record.treeFingerprint !== null) ||
        record.directoryIdentity === null || !isHex64(record.directoryIdentityFingerprint)) fail("immutable artifact binding");
    validateServiceNativeIdentity(record.directoryIdentity, platform, "service-release-directory");
    if (serviceNativeIdentityFingerprint(record.directoryIdentity, platform, "service-release-directory") !== record.directoryIdentityFingerprint) {
      fail("artifact directory identity fingerprint");
    }
  }
  if (record.artifactKind === "shawl" && platform !== "win32") fail("Shawl artifact platform");
  if (serviceArtifactBindingFingerprint(record) !== record.bindingFingerprint) fail("service artifact binding fingerprint");
  return record;
}

export function buildServiceArtifactBinding(fields, platform) {
  const record = { schemaVersion: 1, kind: "service-artifact-binding", ...fields, bindingFingerprint: null };
  record.bindingFingerprint = serviceArtifactBindingFingerprint(record);
  return validateServiceArtifactBinding(record, platform);
}

export function serviceArtifactCleanupFingerprint(record) {
  return fingerprint(record, "cleanupFingerprint");
}

const ARTIFACT_CLEANUP_COMMON_KEYS = [
  "schemaVersion",
  "kind",
  "scope",
  "component",
  "serviceKey",
  "platform",
  "architecture",
  "serviceGeneration",
  "transactionId",
  "transactionNonce",
  "transactionFingerprint",
  "transactionIdentity",
  "purpose",
  "manifestFingerprint",
  "signingKeyId",
  "signingKeyFingerprint",
  "retainedEnvelopeRecordSha256",
  "controlRootBindingFingerprint",
  "roles",
  "rolesFingerprint",
  "artifactLockIdentity",
  "phase",
  "revision",
  "cleanupFingerprint",
];
const ARTIFACT_CLEANUP_PUBLISHED_KEYS = [
  ...ARTIFACT_CLEANUP_COMMON_KEYS,
  "artifactBinding",
  "artifactPhysicalTargetFingerprint",
  "artifactRootBindingFingerprint",
  "artifactRootIdentity",
  "zeroReferenceObservationFingerprint",
];
const ARTIFACT_CLEANUP_SCRATCH_KEYS = [
  ...ARTIFACT_CLEANUP_COMMON_KEYS,
  "stagingRootBindingFingerprint",
  "stagingRootIdentity",
  "scratchName",
  "scratchIdentity",
  "releaseSequence",
  "markerFingerprint",
  "markerFacts",
  "assetName",
  "assetSize",
  "assetSha256",
  "assetFacts",
  "candidateIdentity",
];
const ARTIFACT_CLEANUP_SCOPES = new Set(["published", "scratch"]);
const SCRATCH_SHAWL_PHASES = SERVICE_ARTIFACT_SCRATCH_PHASES.filter(
  (phase) => phase !== "candidate-inventory-removing",
);
// Native staged artifacts are bounded by the fixed two-gibibyte artifact limit.
const ARTIFACT_CLEANUP_ASSET_MAX_BYTES = 2 * 1024 * 1024 * 1024;

function artifactCleanupPhases(scope, purpose) {
  if (scope === "published") return SERVICE_ARTIFACT_CLEANUP_PHASES;
  return purpose === "shawl"
    ? SCRATCH_SHAWL_PHASES
    : SERVICE_ARTIFACT_SCRATCH_PHASES;
}

function validateArtifactCleanupCommon(record, keys) {
  if (!exact(record, keys) ||
      record.schemaVersion !== 1 ||
      record.kind !== "service-artifact-cleanup" ||
      !ARTIFACT_CLEANUP_SCOPES.has(record.scope) ||
      !positive(record.serviceGeneration) ||
      typeof record.transactionId !== "string" ||
      !SAFE_ID.test(record.transactionId) ||
      typeof record.transactionNonce !== "string" ||
      !NONCE.test(record.transactionNonce) ||
      !isHex64(record.transactionFingerprint) ||
      !isHex64(record.transactionIdentity) ||
      !["application", "shawl"].includes(record.purpose) ||
      !isHex64(record.manifestFingerprint) ||
      typeof record.signingKeyId !== "string" ||
      !SAFE_ID.test(record.signingKeyId) ||
      !isHex64(record.signingKeyFingerprint) ||
      !isHex64(record.retainedEnvelopeRecordSha256) ||
      !isHex64(record.controlRootBindingFingerprint) ||
      !isHex64(record.rolesFingerprint) ||
      !nonnegative(record.revision) ||
      !isHex64(record.cleanupFingerprint)) {
    fail("service artifact cleanup schema");
  }
  validateTuple(record.platform, record.architecture);
  validateComponentAndKey(record.component, record.serviceKey);
  if (record.purpose === "shawl" && record.platform !== "win32") {
    fail("service artifact cleanup Shawl tuple");
  }
  validateServiceRoles(record.roles, record.platform);
  if (serviceRolesFingerprint(record.roles, record.platform) !==
      record.rolesFingerprint) {
    fail("service artifact cleanup roles");
  }
  validateServiceNativeIdentity(
    record.artifactLockIdentity,
    record.platform,
    "service-control-file",
  );
  if (record.artifactLockIdentity.owner !== record.roles.management.value) {
    fail("service artifact cleanup ownership");
  }
  const phases = artifactCleanupPhases(record.scope, record.purpose);
  const expectedRevision = phases.indexOf(record.phase);
  if (expectedRevision === -1 || record.revision !== expectedRevision) {
    fail("service artifact cleanup phase");
  }
  if (serviceArtifactCleanupFingerprint(record) !== record.cleanupFingerprint ||
      canonicalJsonBytes(record).byteLength >
        SERVICE_LIFECYCLE_LIMITS.protectedRecordBytes) {
    fail("service artifact cleanup fingerprint");
  }
}

function validatePublishedArtifactCleanup(record) {
  if (!isHex64(record.artifactPhysicalTargetFingerprint) ||
      !isHex64(record.artifactRootBindingFingerprint) ||
      !isHex64(record.zeroReferenceObservationFingerprint)) {
    fail("service artifact cleanup schema");
  }
  validateServiceArtifactBinding(record.artifactBinding, record.platform);
  if (record.artifactBinding.artifactKind !== record.purpose ||
      record.artifactBinding.manifestFingerprint !== record.manifestFingerprint ||
      serviceArtifactPhysicalTargetFingerprint(
        record.artifactBinding,
        record.platform,
      ) !== record.artifactPhysicalTargetFingerprint) {
    fail("service artifact cleanup binding");
  }
  validateServiceNativeIdentity(
    record.artifactRootIdentity,
    record.platform,
    "service-release-directory",
  );
  if (record.artifactRootIdentity.owner !== record.roles.management.value) {
    fail("service artifact cleanup ownership");
  }
}

function validateScratchArtifactCleanup(record) {
  if (!isHex64(record.stagingRootBindingFingerprint) ||
      !isHex64(record.markerFingerprint) ||
      record.scratchName !==
        `${record.serviceKey}-${record.transactionNonce}-${record.purpose}` ||
      record.assetName !==
        (record.purpose === "application" ? "archive" : "raw-shawl") ||
      !positive(record.assetSize) ||
      !positive(record.releaseSequence) ||
      record.assetSize > ARTIFACT_CLEANUP_ASSET_MAX_BYTES ||
      !isHex64(record.assetSha256)) {
    fail("service artifact cleanup schema");
  }
  validateServiceNativeIdentity(
    record.stagingRootIdentity,
    record.platform,
    "service-staging-directory",
  );
  validateServiceNativeIdentity(
    record.scratchIdentity,
    record.platform,
    "service-staging-directory",
  );
  validateServiceArtifactFileFacts(record.markerFacts, record.platform);
  if (record.assetFacts !== null) {
    validateServiceArtifactFileFacts(record.assetFacts, record.platform);
  }
  if (record.candidateIdentity !== null &&
      (validateServiceNativeIdentity(record.candidateIdentity, record.platform),
       !["service-staging-directory", "service-release-directory"].includes(
         record.candidateIdentity.profile))) {
    fail("service artifact cleanup candidate identity");
  }
  const identities = [
    record.stagingRootIdentity,
    record.scratchIdentity,
    ...record.candidateIdentity === null ? [] : [record.candidateIdentity],
  ];
  const factOwners = [
    record.markerFacts,
    ...record.assetFacts === null ? [] : [record.assetFacts],
  ];
  if (identities.some((identity) =>
      identity.owner !== record.roles.management.value) ||
      factOwners.some((facts) =>
        facts.owner !== record.roles.management.value)) {
    fail("service artifact cleanup ownership");
  }
}

export function validateServiceArtifactCleanup(record) {
  const scope = plain(record) ? record.scope : null;
  if (scope === "published") {
    validateArtifactCleanupCommon(record, ARTIFACT_CLEANUP_PUBLISHED_KEYS);
    validatePublishedArtifactCleanup(record);
    return record;
  }
  if (scope === "scratch") {
    validateArtifactCleanupCommon(record, ARTIFACT_CLEANUP_SCRATCH_KEYS);
    validateScratchArtifactCleanup(record);
    return record;
  }
  fail("service artifact cleanup scope");
}

export function buildServiceArtifactCleanup(fields) {
  const record = {
    schemaVersion: 1,
    kind: "service-artifact-cleanup",
    ...fields,
    scope: "published",
    cleanupFingerprint: null,
  };
  record.cleanupFingerprint = serviceArtifactCleanupFingerprint(record);
  return validateServiceArtifactCleanup(record);
}

export function buildServiceArtifactScratchCleanup(fields) {
  const record = {
    schemaVersion: 1,
    kind: "service-artifact-cleanup",
    ...fields,
    scope: "scratch",
    cleanupFingerprint: null,
  };
  record.cleanupFingerprint = serviceArtifactCleanupFingerprint(record);
  return validateServiceArtifactCleanup(record);
}

export function serviceArtifactPhysicalTargetFingerprint(record, platform) {
  validateServiceArtifactBinding(record, platform);
  if (record.artifactKind === "shared-template") fail("shared-template physical artifact target");
  return canonicalJsonHash({
    rootKind: record.rootKind,
    artifactFingerprint: record.artifactFingerprint,
    directoryIdentity: record.directoryIdentity,
    directoryIdentityFingerprint: record.directoryIdentityFingerprint,
  });
}

function validateReferenceSlot(slot, platform, component, expectedGeneration = undefined) {
  if (!exact(slot, ["serviceGeneration", "transactionId", "transactionNonce", "artifacts", "slotFingerprint"]) ||
      !positive(slot.serviceGeneration) || typeof slot.transactionId !== "string" || !SAFE_ID.test(slot.transactionId) ||
      typeof slot.transactionNonce !== "string" || !NONCE.test(slot.transactionNonce) ||
      !Array.isArray(slot.artifacts) || !isHex64(slot.slotFingerprint)) fail("service reference slot");
  if (expectedGeneration !== undefined && slot.serviceGeneration !== expectedGeneration) fail("service reference generation");
  const expectedKinds = platform === "win32" ? ["application", "shawl"] :
    component === "daemon" ? ["application", "shared-template"] : ["application"];
  if (slot.artifacts.length !== expectedKinds.length) fail("service reference artifact set");
  for (let index = 0; index < expectedKinds.length; index += 1) {
    validateServiceArtifactBinding(slot.artifacts[index], platform);
    if (slot.artifacts[index].artifactKind !== expectedKinds[index]) fail("service reference artifact order");
  }
  if (fingerprint(slot, "slotFingerprint") !== slot.slotFingerprint) fail("service reference slot fingerprint");
  return slot;
}

export function buildServiceReferenceSlot(fields, { platform, component }) {
  const slot = { ...fields, slotFingerprint: null };
  slot.slotFingerprint = fingerprint(slot, "slotFingerprint");
  return validateReferenceSlot(slot, platform, component);
}

export function serviceReferenceRecordFingerprint(record) {
  return fingerprint(record, "referenceRecordFingerprint");
}

export function validateServiceReferenceRecord(record) {
  if (!exact(record, ["schemaVersion", "kind", "serviceKey", "component", "platform", "architecture", "serviceGeneration", "current", "previous", "provisional", "referenceRecordFingerprint"]) ||
      record.schemaVersion !== 1 || record.kind !== "service-reference-record" ||
      !nonnegative(record.serviceGeneration) || !isHex64(record.referenceRecordFingerprint)) fail("service reference record");
  validateTuple(record.platform, record.architecture);
  validateComponentAndKey(record.component, record.serviceKey);
  for (const slot of REFERENCE_SLOTS) {
    if (record[slot] !== null) validateReferenceSlot(
      record[slot],
      record.platform,
      record.component,
      slot === "current" ? record.serviceGeneration :
        slot === "provisional" ? record.serviceGeneration + 1 : undefined
    );
  }
  if (record.previous !== null && record.previous.serviceGeneration >= record.serviceGeneration) fail("previous service reference generation");
  const fingerprints = REFERENCE_SLOTS.map((slot) => record[slot]?.slotFingerprint).filter(Boolean);
  if (new Set(fingerprints).size !== fingerprints.length) fail("service reference slot collision");
  const applications = REFERENCE_SLOTS.map((slot) =>
    record[slot]?.artifacts.find((artifact) => artifact.artifactKind === "application")?.bindingFingerprint
  ).filter(Boolean);
  if (new Set(applications).size !== applications.length) fail("service application reference collision");
  if (serviceReferenceRecordFingerprint(record) !== record.referenceRecordFingerprint) fail("service reference record fingerprint");
  return record;
}

export function buildServiceReferenceRecord(fields) {
  const record = { schemaVersion: 1, kind: "service-reference-record", ...fields, referenceRecordFingerprint: null };
  record.referenceRecordFingerprint = serviceReferenceRecordFingerprint(record);
  return validateServiceReferenceRecord(record);
}

export function serviceJournalHeadFingerprint(record) {
  return fingerprint(record, "headFingerprint");
}

export function validateServiceJournalHead(record) {
  if (!exact(record, ["schemaVersion", "kind", "serviceKey", "component", "platform", "architecture", "sequence", "serviceGeneration", "transactionId", "transactionNonce", "transactionFingerprint", "previousJournalFingerprint", "headFingerprint"]) ||
      record.schemaVersion !== 1 || record.kind !== "service-journal-head" ||
      !positive(record.sequence) || !positive(record.serviceGeneration) ||
      typeof record.transactionId !== "string" || !SAFE_ID.test(record.transactionId) ||
      typeof record.transactionNonce !== "string" || !NONCE.test(record.transactionNonce) ||
      !isHex64(record.transactionFingerprint) ||
      !nullableHash(record.previousJournalFingerprint) || !isHex64(record.headFingerprint)) fail("service journal head");
  validateTuple(record.platform, record.architecture);
  validateComponentAndKey(record.component, record.serviceKey);
  if ((record.sequence === 1) !== (record.previousJournalFingerprint === null)) fail("service journal head chain");
  if (serviceJournalHeadFingerprint(record) !== record.headFingerprint) fail("service journal head fingerprint");
  return record;
}

export function buildServiceJournalHead(fields) {
  const record = { schemaVersion: 1, kind: "service-journal-head", ...fields, headFingerprint: null };
  record.headFingerprint = serviceJournalHeadFingerprint(record);
  return validateServiceJournalHead(record);
}

export function serviceZeroReferenceObservationFingerprint(record) {
  return fingerprint(record, "observationFingerprint");
}

export function validateServiceZeroReferenceObservation(record) {
  if (!exact(record, ["schemaVersion", "kind", "platform", "architecture", "artifactBindingFingerprint", "artifactRootKind", "artifactFingerprint", "artifactDirectoryIdentity", "artifactDirectoryIdentityFingerprint", "artifactPhysicalTargetFingerprint", "controlRootBindingFingerprint", "referenceDirectoryIdentity", "artifactLockIdentity", "referenceRecordFingerprints", "observationFingerprint"]) ||
      record.schemaVersion !== 1 || record.kind !== "service-zero-reference-observation" ||
      !isHex64(record.artifactBindingFingerprint) ||
      !["releases", "shawl"].includes(record.artifactRootKind) ||
      !isHex64(record.artifactFingerprint) ||
      !isHex64(record.artifactDirectoryIdentityFingerprint) ||
      !isHex64(record.artifactPhysicalTargetFingerprint) ||
      !isHex64(record.controlRootBindingFingerprint) ||
      !Array.isArray(record.referenceRecordFingerprints) ||
      record.referenceRecordFingerprints.length > SERVICE_LIFECYCLE_LIMITS.expectedHostCount ||
      !isHex64(record.observationFingerprint)) {
    fail("service zero-reference observation");
  }
  validateTuple(record.platform, record.architecture);
  if (record.artifactRootKind === "shawl" && record.platform !== "win32") {
    fail("service zero-reference Shawl target");
  }
  validateServiceNativeIdentity(
    record.artifactDirectoryIdentity,
    record.platform,
    "service-release-directory"
  );
  if (serviceNativeIdentityFingerprint(
    record.artifactDirectoryIdentity,
    record.platform,
    "service-release-directory"
  ) !== record.artifactDirectoryIdentityFingerprint ||
      canonicalJsonHash({
        rootKind: record.artifactRootKind,
        artifactFingerprint: record.artifactFingerprint,
        directoryIdentity: record.artifactDirectoryIdentity,
        directoryIdentityFingerprint: record.artifactDirectoryIdentityFingerprint,
      }) !== record.artifactPhysicalTargetFingerprint) {
    fail("service zero-reference physical target");
  }
  validateServiceNativeIdentity(record.referenceDirectoryIdentity, record.platform, "service-control-directory");
  validateServiceNativeIdentity(record.artifactLockIdentity, record.platform, "service-control-file");
  let previous = null;
  for (const value of record.referenceRecordFingerprints) {
    if (!isHex64(value) || (previous !== null && utf8Compare(previous, value) >= 0)) {
      fail("service zero-reference observation records");
    }
    previous = value;
  }
  if (serviceZeroReferenceObservationFingerprint(record) !== record.observationFingerprint) {
    fail("service zero-reference observation fingerprint");
  }
  return record;
}

export function buildServiceZeroReferenceObservation(fields) {
  const record = { schemaVersion: 1, kind: "service-zero-reference-observation", ...fields, observationFingerprint: null };
  record.observationFingerprint = serviceZeroReferenceObservationFingerprint(record);
  return validateServiceZeroReferenceObservation(record);
}
