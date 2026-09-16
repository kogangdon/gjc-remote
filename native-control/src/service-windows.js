import {
  SERVICE_LIFECYCLE_LIMITS,
  SERVICE_TRANSACTION_PHASES,
  buildServicePlatformState,
  buildServiceStartupProof,
  buildServiceTransaction,
  validateServiceKey,
  validateServiceRoles,
} from '@gjc-remote/shared/service-lifecycle-envelope';
import { canonicalJsonHash } from '@gjc-remote/shared/strict-json';

// Windows Shawl driver (G003 slices 9-10).  The adapter is deliberately closed:
// all operating-system interaction is through the injected native facade and
// store session.  It never opens files, invokes a shell, or accepts caller
// supplied trust/root overrides.
export const WINDOWS_DRIVER_LIMITS = Object.freeze({
  argvElementBytes: 4096,
  outputBytes: 64 * 1024,
  startPollAttempts: 60,
  startPollMs: 250,
  startupWindowMs: 60_000,
  stopWindowMs: 35_000,
  logBytes: 16 * 1024 * 1024,
  logRotateBytes: 2_097_152,
  logRetain: 2,
});

export const WINDOWS_SERVICE_ERROR_CODES = Object.freeze([
  'SERVICE_INVALID', 'SERVICE_UNSUPPORTED', 'SERVICE_ACCESS_DENIED',
  'SERVICE_ALREADY_EXISTS', 'SERVICE_NOT_FOUND', 'SERVICE_STALE',
  'SERVICE_PENDING', 'SERVICE_IO_FAILED', 'SERVICE_TRIAL_NOT_OBSERVED',
  'SERVICE_STARTUP_TIMEOUT', 'SERVICE_MANUAL_CLEANUP', 'SERVICE_AMBIGUOUS',
  'SERVICE_PROCESS_AMBIGUOUS', 'SERVICE_TREE_OVERFLOW',
  'SERVICE_TREE_AMBIGUOUS', 'SERVICE_TREE_SURVIVOR',
]);

export const WINDOWS_DRIVER_REASONS = Object.freeze([
  'resource-drift', 'activation-drift', 'tree-not-quiescent',
  'tree-overflow', 'invocation-not-observed', 'startup-receipt-invalidated',
  'log-epoch-invalid', 'log-offset-gap', 'controller-loss', 'reboot',
  'foreign-resource', 'unmarked-resource', 'process-epoch-changed',
  'ambiguous-process-tree', 'process-tree-overflow', 'tree-survivor',
  'deletion-pending', 'recreated-resource', 'config-drift', 'log-cursor-invalid',
  'stale-epoch',
]);

export function windowsLogEpochFingerprint(epoch) {
  if (!exact(epoch, ['bootId', 'pid', 'startTime', 'files'])) throw new TypeError('invalid Windows log epoch');
  if (typeof epoch.bootId !== 'string' || !Number.isSafeInteger(epoch.pid) || epoch.pid <= 0 || typeof epoch.startTime !== 'string' || !Array.isArray(epoch.files)) throw new TypeError('invalid Windows log epoch');
  return canonicalJsonHash({ kind: 'windows-log-epoch/v1', ...epoch });
}

export function validateWindowsLogEvidence(evidence) {
  if (!exact(evidence, ['epoch', 'cursor', 'records', 'rotationChain'])) throw new TypeError('invalid Windows log evidence');
  const epochFingerprint = windowsLogEpochFingerprint(evidence.epoch);
  if (!Number.isSafeInteger(evidence.cursor) || evidence.cursor < 0 || !Array.isArray(evidence.records) || evidence.records.length === 0 || !Array.isArray(evidence.rotationChain) || evidence.epoch.files.length !== 2 || evidence.epoch.files[0] !== 'stdout' || evidence.epoch.files[1] !== 'stderr') throw new TypeError('invalid Windows log evidence');
  let offset = evidence.cursor;
  for (const record of evidence.records) {
    if (!exact(record, ['offset', 'length', 'epochFingerprint', 'marker'])) throw new TypeError('invalid Windows log record');
    if (!Number.isSafeInteger(record.offset) || !Number.isSafeInteger(record.length) || record.offset !== offset || record.length <= 0 || record.offset > WINDOWS_DRIVER_LIMITS.logBytes || record.length > WINDOWS_DRIVER_LIMITS.logBytes - record.offset || record.epochFingerprint !== epochFingerprint || record.marker !== 'gjc-remote:v1:ready') throw new TypeError('invalid Windows log record');
    offset = record.offset + record.length;
  }
  let previous = null;
  for (const segment of evidence.rotationChain) {
    if (!exact(segment, ['identity', 'startOffset', 'endOffset', 'sha256'])) throw new TypeError('invalid Windows log rotation');
    if (typeof segment.identity !== 'string' || !/^(?:stdout|stderr)\.\d+$/.test(segment.identity) || !Number.isSafeInteger(segment.startOffset) || !Number.isSafeInteger(segment.endOffset) || segment.startOffset < 0 || segment.endOffset < segment.startOffset || segment.endOffset > WINDOWS_DRIVER_LIMITS.logBytes || !validHash(segment.sha256) || (previous !== null && segment.startOffset !== previous)) throw new TypeError('invalid Windows log rotation');
    previous = segment.endOffset;
  }
  return Object.freeze({ epochFingerprint, endOffset: offset });
}

const NATIVE = Object.freeze([
  'open_win32_service', 'close_win32_service', 'query_win32_service',
  'create_win32_service_disabled', 'protect_win32_service',
  'set_win32_service_marker', 'configure_win32_service_launch',
  'set_win32_service_start_type', 'set_win32_service_failure_actions',
  'set_win32_service_failure_actions_flag', 'start_win32_service',
  'stop_win32_service', 'delete_win32_service', 'terminate_win32_service_tree',
  'read_boot_id', 'read_process_facts', 'enumerate_process_tree',
  'read_file_facts_no_follow',
]);
const SESSION_METHODS = Object.freeze(['readJournal', 'appendJournal', 'readStartupProof', 'publishStartupProof', 'readReferences']);
const SERVICE_NAME_BOT = 'GJCRemoteBot';
const MARKER_PREFIX = 'gjc-remote:v1:';
const HEX = /^[0-9a-f]{64}$/;
const START_TYPES = new Set(['disabled', 'demand', 'auto']);
const SERVICE_STATES = new Set(['stopped', 'start-pending', 'running', 'stop-pending', 'continue-pending', 'pause-pending', 'paused']);
const WIN_BOOT = /^win32:[0-9]+$/;
const SNAPSHOT_KEYS = Object.freeze([
  'name', 'serviceRole', 'serviceType', 'startType', 'errorControl', 'tagId',
  'binaryPath', 'loadOrderGroup', 'dependencies', 'accountName',
  'displayName', 'description', 'delayedAutoStart', 'failureResetPeriod',
  'failureRebootMessage', 'failureCommand', 'failureActions',
  'failureActionsOnNonCrashFailures', 'failurePolicy', 'serviceSidType',
  'requiredPrivileges', 'triggerCount', 'preshutdownTimeout', 'securitySha256',
  'aclMatches', 'accountMatchesRole', 'configFingerprint', 'runtime',
]);
const RUNTIME_KEYS = Object.freeze([
  'state', 'controlsAccepted', 'win32ExitCode', 'serviceExitCode',
  'checkpoint', 'waitHint', 'processId', 'serviceFlags', 'fingerprint',
]);

function plain(value) { return value !== null && typeof value === 'object' && !Array.isArray(value) && Object.getPrototypeOf(value) === Object.prototype; }
function exact(value, keys) { return plain(value) && Reflect.ownKeys(value).length === keys.length && keys.every((key) => Object.hasOwn(value, key)); }
function freeze(value) {
  if (Array.isArray(value)) return Object.freeze(value.map(freeze));
  if (plain(value)) {
    const copy = {};
    for (const key of Reflect.ownKeys(value)) copy[key] = freeze(value[key]);
    return Object.freeze(copy);
  }
  return value;
}
function fail(code, operation, writes = 0, ambiguous = false, reason = undefined) { const error = new Error(`${operation} failed`); error.name = 'ServiceWindowsError'; error.code = code; error.operation = operation; error.writes = writes; error.ambiguous = ambiguous; if (reason !== undefined) error.reason = reason; throw error; }
function writesOf(value) { return Number.isSafeInteger(value) && value >= 0 ? value : 0; }
function marker(fingerprint) { return `${MARKER_PREFIX}${fingerprint}`; }
function validMarker(value) { return typeof value === 'string' && value.startsWith(MARKER_PREFIX) && validHash(value.slice(MARKER_PREFIX.length)); }
function validPath(value) { return typeof value === 'string' && value.length > 0 && Buffer.byteLength(value, 'utf8') <= SERVICE_LIFECYCLE_LIMITS.pathBytes && /^(?:[A-Za-z]:[\\/]|\\\\[^\\/]+[\\/]+)/.test(value); }
function validHash(value) { return typeof value === 'string' && HEX.test(value); }
// CommandLineToArgvW-compatible serialization used by addon.cc.  The native
// side quotes every argument (including arguments without whitespace), doubles
// trailing backslashes, and escapes backslashes immediately preceding quotes.
export function serializeWindowsCommandLine(argv) {
  if (!Array.isArray(argv) || argv.length === 0 || argv.some((value) => typeof value !== 'string' || value.length === 0 || Buffer.byteLength(value, 'utf8') > WINDOWS_DRIVER_LIMITS.argvElementBytes)) throw new TypeError('invalid Windows command line');
  return argv.map((argument) => {
    let result = '"'; let backslashes = 0;
    for (const character of argument) {
      if (character === '\\') { backslashes += 1; continue; }
      if (character === '"') { result += '\\'.repeat(backslashes * 2 + 1) + '"'; backslashes = 0; continue; }
      result += '\\'.repeat(backslashes) + character; backslashes = 0;
    }
    return result + '\\'.repeat(backslashes * 2) + '"';
  }).join(' ');
}
function contentAddressedShawlPath(value, digest) {
  if (!validPath(value) || !validHash(digest)) return false;
  const normalized = value.replaceAll('\\', '/').toLowerCase();
  return normalized.endsWith('/shawl.exe') && normalized.includes(`/shawl/${digest}/`);
}
function roleKey(component, serviceKey) { return component === 'bot' ? SERVICE_NAME_BOT : `GJCRemoteDaemon-${serviceKey}`; }
function expectedStopTimeout(component) { return component === 'bot' ? 30000 : 20000; }
function expectedLogAs(component, serviceKey) {
  return component === 'bot' ? 'gjc-remote-bot-wrapper' : `gjc-remote-daemon-${serviceKey}-wrapper`;
}
function expectedLogCmdAs(component, serviceKey) {
  return component === 'bot' ? 'gjc-remote-bot-child' : `gjc-remote-daemon-${serviceKey}-child`;
}
// This is the native ABI's normalized wire value.  Do not use the expanded
// comma representation here: addon.cc accepts exactly this token.
function actionPolicy(final) { return final ? 'restart-3x-10s' : 'none'; }

export function windowsServiceName(component, serviceKey) {
  if (component === 'bot' && serviceKey === 'bot') return SERVICE_NAME_BOT;
  if (component === 'daemon' && typeof serviceKey === 'string' && /^[a-z0-9](?:[a-z0-9-]{0,30}[a-z0-9])?-[0-9a-f]{64}$/.test(serviceKey)) return roleKey(component, serviceKey);
  throw new TypeError('invalid Windows service key');
}

export function buildWindowsShawlArgv(input) {
  if (!exact(input, ['component', 'serviceKey', 'shawlPath', 'workingDirectory', 'homeDirectory', 'runtimePath', 'entrypointPath', 'logDirectory', 'channelsConfig'])) throw new TypeError('invalid Shawl input');
  const { component, serviceKey, shawlPath, workingDirectory, homeDirectory, runtimePath, entrypointPath, logDirectory, channelsConfig } = input;
  windowsServiceName(component, serviceKey);
  for (const value of [shawlPath, workingDirectory, homeDirectory, runtimePath, entrypointPath, logDirectory]) if (!validPath(value)) throw new TypeError('invalid Shawl path');
  if ((component === 'bot' && !validPath(channelsConfig)) || (component === 'daemon' && channelsConfig !== null)) throw new TypeError('invalid channels config');
  const timeout = expectedStopTimeout(component);
  const argv = [
    shawlPath, 'run', '--name', windowsServiceName(component, serviceKey), '--cwd', workingDirectory,
    '--env', `HOME=${homeDirectory}`, '--env', `USERPROFILE=${homeDirectory}`,
    '--kill-process-tree', '--restart-if-not', '0', '--restart-delay', '10000', '--stop-timeout', String(timeout),
    '--log-dir', logDirectory, '--log-as', expectedLogAs(component, serviceKey), '--log-cmd-as', expectedLogCmdAs(component, serviceKey),
    '--log-rotate', `bytes=${WINDOWS_DRIVER_LIMITS.logRotateBytes}`,
    '--log-retain', String(WINDOWS_DRIVER_LIMITS.logRetain),
  ];
  if (component === 'bot') argv.push('--env', `CHANNELS_CONFIG=${channelsConfig}`);
  argv.push('--', runtimePath);
  if (component === 'daemon') argv.push('--no-env-file');
  argv.push(entrypointPath);
  return Object.freeze(argv);
}

export function windowsServiceResourceFingerprint(descriptor) {
  if (!plain(descriptor)) throw new TypeError('invalid Windows resource descriptor');
  // The platform resource CAS covers immutable SCM configuration only.  SCM
  // runtime state (including the wrapper/runtime fingerprint) changes on
  // every start/stop and is proved separately by the process/boot receipts.
  // Normalize this field here as a defensive boundary so callers cannot
  // accidentally fold a dynamic runtime observation into T.
  const identity = { ...descriptor, runtimeFingerprint: null };
  // Accepting a nested runtime object in a caller-provided descriptor must
  // not reintroduce SCM state into the identity hash either.  The driver
  // emits only the flattened descriptor below, but this guard keeps the
  // exported fingerprint boundary unambiguous.
  delete identity.runtime;
  return canonicalJsonHash({ kind: 'windows-service-resource/v1', ...identity });
}

function validateConfiguration(configuration, component) {
  const pathKeys = ['runtimePath', 'workingDirectory', 'homeDirectory', 'logDirectory'];
  const required = component === 'bot' ? [...pathKeys, 'channelsConfig', 'expectedHostSetFingerprint', 'expectedHostCount'] : pathKeys;
  if (!exact(configuration, required) || pathKeys.some((key) => !validPath(configuration[key]))) return false;
  if (component === 'bot' && !validPath(configuration.channelsConfig)) return false;
  if (component === 'bot' && (!validHash(configuration.expectedHostSetFingerprint) || !Number.isSafeInteger(configuration.expectedHostCount) || configuration.expectedHostCount < 0)) return false;
  return true;
}

function validateSnapshot(snapshot, op) {
  // snapshot schema is intentionally closed; native additions must be reviewed
  if (!exact(snapshot, SNAPSHOT_KEYS) || !exact(snapshot.runtime, RUNTIME_KEYS) ||
      typeof snapshot.name !== 'string' || typeof snapshot.serviceRole !== 'string' ||
      !Number.isSafeInteger(snapshot.serviceType) || snapshot.serviceType <= 0 ||
      !START_TYPES.has(snapshot.startType) || !Number.isSafeInteger(snapshot.errorControl) || snapshot.errorControl < 0 ||
      !Number.isSafeInteger(snapshot.tagId) || snapshot.tagId < 0 ||
      !SERVICE_STATES.has(snapshot.runtime.state) || typeof snapshot.binaryPath !== 'string' ||
      typeof snapshot.loadOrderGroup !== 'string' || typeof snapshot.accountName !== 'string' ||
      typeof snapshot.displayName !== 'string' || typeof snapshot.description !== 'string' ||
      typeof snapshot.delayedAutoStart !== 'boolean' || !Number.isSafeInteger(snapshot.failureResetPeriod) || snapshot.failureResetPeriod < 0 ||
      typeof snapshot.failureRebootMessage !== 'string' || typeof snapshot.failureCommand !== 'string' ||
      !Array.isArray(snapshot.failureActions) || !snapshot.failureActions.every((a) => exact(a, ['type', 'delayMs']) && typeof a.type === 'string' && Number.isSafeInteger(a.delayMs) && a.delayMs >= 0) ||
      !['none', 'restart-3x-10s', 'other'].includes(snapshot.failurePolicy) ||
      !Array.isArray(snapshot.dependencies) || !snapshot.dependencies.every((v) => typeof v === 'string') ||
      !Number.isSafeInteger(snapshot.serviceSidType) || snapshot.serviceSidType < 0 ||
      !Array.isArray(snapshot.requiredPrivileges) || !snapshot.requiredPrivileges.every((v) => typeof v === 'string') ||
      !Number.isSafeInteger(snapshot.triggerCount) || snapshot.triggerCount < 0 ||
      !Number.isSafeInteger(snapshot.preshutdownTimeout) || snapshot.preshutdownTimeout < 0 ||
      !validHash(snapshot.securitySha256) || !validHash(snapshot.configFingerprint) || !validHash(snapshot.runtime.fingerprint) ||
      typeof snapshot.runtime.processId !== 'number' || !Number.isSafeInteger(snapshot.runtime.processId) || snapshot.runtime.processId < 0 ||
      !Number.isSafeInteger(snapshot.runtime.controlsAccepted) || snapshot.runtime.controlsAccepted < 0 ||
      !Number.isSafeInteger(snapshot.runtime.win32ExitCode) || snapshot.runtime.win32ExitCode < 0 ||
      !Number.isSafeInteger(snapshot.runtime.serviceExitCode) || snapshot.runtime.serviceExitCode < 0 ||
      !Number.isSafeInteger(snapshot.runtime.checkpoint) || snapshot.runtime.checkpoint < 0 ||
      !Number.isSafeInteger(snapshot.runtime.waitHint) || snapshot.runtime.waitHint < 0 ||
      !Number.isSafeInteger(snapshot.runtime.serviceFlags) || snapshot.runtime.serviceFlags < 0 ||
      typeof snapshot.failureActionsOnNonCrashFailures !== 'boolean' ||
      typeof snapshot.aclMatches !== 'boolean' || typeof snapshot.accountMatchesRole !== 'boolean') fail('SERVICE_INVALID', op, 0, true);
  return snapshot;
}

export function createWindowsServiceDriver(options) {
  const op = 'create_windows_service_driver';
  const optionKeys = ['native', 'session', 'locks', 'roles', 'configuration', 'release', 'shawl', 'clock', 'sleep'];
  const optionalKeys = ['servicePassword', 'servicePasswordRequired'];
  if (!plain(options) || Reflect.ownKeys(options).some((key) => !optionKeys.includes(key) && !optionalKeys.includes(key)) || optionKeys.some((key) => !Object.hasOwn(options, key))) fail('SERVICE_INVALID', op);
  const { native, session, locks, roles, configuration, release, shawl } = options;
  const servicePassword = options.servicePassword;
  const servicePasswordRequired = options.servicePasswordRequired === true;
  const nowMs = options.clock ?? (() => Date.now());
  const sleepMs = options.sleep ?? ((ms) => new Promise((resolve) => setTimeout(resolve, ms)));
  if (typeof nowMs !== 'function' || typeof sleepMs !== 'function') fail('SERVICE_INVALID', op);
  if ((native === null || (typeof native !== 'object' && typeof native !== 'function')) || !plain(session) || !plain(locks) || !plain(release) || !plain(shawl)) fail('SERVICE_INVALID', op);
  for (const method of SESSION_METHODS) if (typeof session[method] !== 'function') fail('SERVICE_INVALID', op);
  if (session.platform !== 'win32' || session.architecture !== 'x64' || (session.component !== 'bot' && session.component !== 'daemon')) fail('SERVICE_INVALID', op);
  const component = session.component; const serviceKey = session.serviceKey;
  try { validateServiceKey(serviceKey, component); validateServiceRoles(roles, 'win32'); } catch { fail('SERVICE_INVALID', op); }
  if (!validateConfiguration(configuration, component) || !exact(release, ['entrypointPath', 'applicationManifestFingerprint']) || !validPath(release.entrypointPath) || !validHash(release.applicationManifestFingerprint)) fail('SERVICE_INVALID', op);
  if (!exact(shawl, ['path', 'sha256', 'runtimeSha256', 'entrypointSha256']) || !contentAddressedShawlPath(shawl.path, shawl.sha256) || !validHash(shawl.runtimeSha256) || !validHash(shawl.entrypointSha256)) fail('SERVICE_INVALID', op);
  if (!exact(locks, ['artifact', 'sharedTemplate', 'serviceKey']) || Object.values(locks).some((v) => v === null || typeof v !== 'object' || Reflect.ownKeys(v).length === 0)) fail('SERVICE_INVALID', op);
  if (servicePassword !== undefined && (typeof servicePassword !== 'string' || servicePassword.length === 0 || Buffer.byteLength(servicePassword, 'utf8') > SERVICE_LIFECYCLE_LIMITS.servicePasswordBytes || servicePassword.includes('\0'))) fail('SERVICE_INVALID', op);
  if (servicePasswordRequired && servicePassword === undefined) fail('SERVICE_INVALID', op, 0, false, 'service-password-required');
  const descriptors = Object.getOwnPropertyDescriptors(native); const calls = Object.create(null);
  for (const name of NATIVE) { const d = descriptors[name]; if (!d || d.get || d.set || !Object.hasOwn(d, 'value') || typeof d.value !== 'function') fail('SERVICE_INVALID', op); calls[name] = d.value; }
  let driverWrites = 0; const name = windowsServiceName(component, serviceKey); const expectedOwner = roles[component].value;
  let activeTrial = null;
  const logFamily = { stdout: `child-${serviceKey}-stdout`, stderr: `child-${serviceKey}-stderr`, wrapper: `shawl-${serviceKey}` };

  function nativeCall(method, ...args) { try { const value = Reflect.apply(calls[method], undefined, args); if (plain(value) && Object.hasOwn(value, 'writes')) driverWrites += writesOf(value.writes); return value; } catch (error) { driverWrites += writesOf(error?.writes); const code = WINDOWS_SERVICE_ERROR_CODES.includes(error?.code) ? error.code : 'SERVICE_IO_FAILED'; fail(code, typeof error?.operation === 'string' ? error.operation : method, driverWrites, error?.ambiguous === true || !Number.isSafeInteger(error?.writes)); } }
  // Keep the Windows journal order identical to the shared envelope.  In
  // particular, stopping/quiescent precede resource-published so an update
  // or rollback cannot publish over a live predecessor.
  const phaseOrder = SERVICE_TRANSACTION_PHASES;
  const substepOrder = Object.freeze({ none: 0, intent: 1, action: 2, observed: 3 });
  function sameJson(left, right) { try { return canonicalJsonHash(left) === canonicalJsonHash(right); } catch { return false; } }
  function journal() {
    const value = session.readJournal();
    if (!plain(value) || !Array.isArray(value.entries) || value.entries.length === 0) fail('SERVICE_PENDING', 'read_service_journal', driverWrites);
    return value;
  }
  // A journal pending record is a prepared transaction edge.  Resolve it from
  // the last committed head before any operation is allowed to inspect or
  // mutate the SCM.  A pending record for another head is deliberately left
  // pending: callers must retry the exact operation after recovery.
  function resolvePending(value, operation, allowed = null) {
    if (value.pending === null || value.pending === undefined) return value.entries.at(-1);
    const pending = value.pending;
    if (!plain(pending) || !['none', 'intent', 'action', 'observed'].includes(pending.substep) ||
        (allowed !== null && !allowed.some((entry) => entry.phase === pending.phase &&
          (entry.substep === undefined || entry.substep === pending.substep)))) {
      fail('SERVICE_PENDING', operation, driverWrites);
    }
    const latest = value.entries.at(-1);
    // The store exposes the uncommitted record as the final journal entry.
    // Never infer a committed head from a different shape: a detached or
    // mismatched pending record is a write-free recovery condition.
    if (!sameJson(latest, pending)) fail('SERVICE_PENDING', operation, driverWrites);
    const committed = value.head?.present === true && plain(value.head.value) && Number.isSafeInteger(value.head.value.sequence)
      ? value.entries[value.head.value.sequence - 1]
      : value.entries.at(-2);
    if (!committed) fail('SERVICE_PENDING', operation, driverWrites);
    let replay;
    try {
      replay = buildServiceTransaction({ ...committed, phase: pending.phase, substep: pending.substep, previousJournalFingerprint: committed.transactionFingerprint });
    } catch {
      fail('SERVICE_PENDING', operation, driverWrites);
    }
    if (!sameJson(replay, pending)) fail('SERVICE_PENDING', operation, driverWrites);
    // If the store already exposes the pending record as its committed tail,
    // there is nothing left to append.  Otherwise append the byte-identical
    // replay; appendJournal is the store's linearization point.
    session.appendJournal(pending);
    return replay;
  }
  function transactionBinding(transaction, operation) {
    if (!plain(transaction) || transaction.component !== component || transaction.serviceKey !== serviceKey || transaction.platform !== 'win32' || transaction.architecture !== 'x64' || !plain(transaction.old) || !plain(transaction.candidate) || !plain(transaction.transition) || !plain(transaction.final) || transaction.transition.oldFingerprint !== transaction.old.oldFingerprint || transaction.transition.candidateFingerprint !== transaction.candidate.candidateFingerprint || !validHash(transaction.transactionFingerprint) || !validHash(transaction.transition.transitionFingerprint)) fail('SERVICE_STALE', operation, driverWrites, true, 'resource-drift');
    return transaction;
  }
  function append(phase, substep) {
    const value = journal();
    if (value.pending !== null && value.pending !== undefined) {
      if (!sameJson(value.entries.at(-1), value.pending)) fail('SERVICE_PENDING', 'append_service_journal', driverWrites);
      const committed = value.head?.present === true && plain(value.head.value) && Number.isSafeInteger(value.head.value.sequence)
        ? value.entries[value.head.value.sequence - 1]
        : value.entries.at(-2);
      if (!plain(value.pending) || value.pending.phase !== phase || value.pending.substep !== substep || !committed) fail('SERVICE_PENDING', 'append_service_journal', driverWrites);
      let replay;
      try { replay = buildServiceTransaction({ ...committed, phase, substep, previousJournalFingerprint: committed.transactionFingerprint }); } catch { fail('SERVICE_PENDING', 'append_service_journal', driverWrites); }
      if (!sameJson(replay, value.pending)) fail('SERVICE_PENDING', 'append_service_journal', driverWrites);
      session.appendJournal(value.pending);
      return value.pending;
    }
    const current = transactionBinding(value.entries.at(-1), 'append_service_journal');
    const previousPhase = phaseOrder.indexOf(current.phase); const nextPhase = phaseOrder.indexOf(phase);
    // A phase may contain more than one independently journaled mutation
    // (for example AUTO then failure-actions).  Repeating a phase is not a
    // rewind; only moving to an earlier lifecycle phase is forbidden.
    // A running trial is stopped as a rollback/uninstall edge after
    // resource-published; the shared order still places stopping before the
    // publish edge so update/rollback can quiesce the old T first.  This is
    // the sole lifecycle back-edge and is only admitted for stop phases.
    const lateStop = (phase === 'stopping' || phase === 'quiescent') && previousPhase >= phaseOrder.indexOf('resource-published');
    if (nextPhase < 0 || (nextPhase < previousPhase && !lateStop)) fail('SERVICE_PENDING', 'append_service_journal', driverWrites);
    let next;
    try { next = buildServiceTransaction({ ...current, phase, substep, previousJournalFingerprint: current.transactionFingerprint }); } catch { fail('SERVICE_INVALID', 'append_service_journal', driverWrites); }
    session.appendJournal(next); return next;
  }
  // `native` is the role-projected public facade. Roles are captured by the
  // factory and injected there; passing them here would shift the ABI and make
  // the real facade reject the call before SCM access.
  function handle(access, operation) { const value = nativeCall('open_win32_service', name, component, access); if (value === null) return null; if (value === undefined || (typeof value !== 'object' && typeof value !== 'function')) fail('SERVICE_INVALID', operation, driverWrites, true); return value; }
  function close(value) { if (value !== null) { try { nativeCall('close_win32_service', value); } catch { /* preserve primary error */ } } }
  function query(service, operation) { if (service === null) return null; return validateSnapshot(nativeCall('query_win32_service', service), operation); }
  function expectedBinary(entrypointPath) { return serializeWindowsCommandLine(buildWindowsShawlArgv({ component, serviceKey, shawlPath: shawl.path, workingDirectory: configuration.workingDirectory, homeDirectory: configuration.homeDirectory, runtimePath: configuration.runtimePath, entrypointPath, logDirectory: configuration.logDirectory, channelsConfig: component === 'bot' ? configuration.channelsConfig : null })); }
  const expectedBinaryFor = expectedBinary;
  function descriptor(snapshot) {
    return { name, component, serviceKey, serviceRole: snapshot?.serviceRole ?? null, serviceType: snapshot?.serviceType ?? null, startType: snapshot?.startType ?? 'absent', errorControl: snapshot?.errorControl ?? null, tagId: snapshot?.tagId ?? null, binaryPath: snapshot?.binaryPath ?? null, loadOrderGroup: snapshot?.loadOrderGroup ?? null, dependencies: snapshot?.dependencies ?? [], accountName: snapshot?.accountName ?? null, displayName: snapshot?.displayName ?? null, description: snapshot?.description ?? null, delayedAutoStart: snapshot?.delayedAutoStart ?? false, failureResetPeriod: snapshot?.failureResetPeriod ?? 0, failureRebootMessage: snapshot?.failureRebootMessage ?? null, failureCommand: snapshot?.failureCommand ?? null, failureActionsOnNonCrashFailures: snapshot?.failureActionsOnNonCrashFailures ?? false, failureActions: snapshot?.failureActions ?? [], failurePolicy: snapshot?.failurePolicy ?? 'none', serviceSidType: snapshot?.serviceSidType ?? null, requiredPrivileges: snapshot?.requiredPrivileges ?? [], triggerCount: snapshot?.triggerCount ?? null, preshutdownTimeout: snapshot?.preshutdownTimeout ?? null, securitySha256: snapshot?.securitySha256 ?? null, aclMatches: snapshot?.aclMatches ?? false, accountMatchesRole: snapshot?.accountMatchesRole ?? false, configFingerprint: snapshot?.configFingerprint ?? null, runtimeFingerprint: null }; }
  function resourceIdentity(value) { if (!plain(value)) return null; const copy = { ...value, runtimeFingerprint: null }; return windowsServiceResourceFingerprint(copy); }
  // SCM stores the complete Shawl command line, including the immutable
  // release entrypoint.  Recover that path from the observed resource rather
  // than trusting the controller constructor release.  The marker and
  // resource CAS together bind the observed path to exactly one declared
  // transaction release.
  function commandLineEntrypoint(binaryPath) {
    if (typeof binaryPath !== 'string' || binaryPath.length === 0) return null;
    const args = []; let index = 0;
    while (index < binaryPath.length) {
      while (index < binaryPath.length && /\s/.test(binaryPath[index])) index += 1;
      if (index >= binaryPath.length) break;
      if (binaryPath[index] !== '"') return null;
      index += 1; let value = '';
      while (index < binaryPath.length) {
        let slashes = 0;
        while (index < binaryPath.length && binaryPath[index] === '\\') { slashes += 1; index += 1; }
        if (index < binaryPath.length && binaryPath[index] === '"') {
          value += '\\'.repeat(Math.floor(slashes / 2));
          if (slashes % 2 === 1) { value += '"'; index += 1; continue; }
          index += 1; break;
        }
        value += '\\'.repeat(slashes);
        if (index >= binaryPath.length) return null;
        value += binaryPath[index++];
      }
      if (index > binaryPath.length || (index === binaryPath.length && binaryPath[index - 1] !== '"')) return null;
      args.push(value);
    }
    const entrypointPath = args.at(-1);
    return validPath(entrypointPath) ? entrypointPath : null;
  }
  function deriveReleaseBinding(transaction, snapshot, operation) {
    if (snapshot === null) return null;
    if (!plain(transaction) || !plain(snapshot) || !validMarker(snapshot.description)) return null;
    const applicationManifestFingerprint = snapshot.description.slice(MARKER_PREFIX.length);
    const candidate = transaction.candidate?.applicationManifestFingerprint ?? null;
    const old = transaction.old?.applicationManifestFingerprint ?? null;
    if (applicationManifestFingerprint !== candidate && applicationManifestFingerprint !== old) {
      fail('SERVICE_MANUAL_CLEANUP', operation, driverWrites, true, 'resource-drift');
    }
    const observedResource = windowsServiceResourceFingerprint(descriptor(snapshot));
    const expectedResources = applicationManifestFingerprint === candidate
      ? [transaction.transition?.platformResourceFingerprint, transaction.transition?.expectedAfterResourceFingerprint, transaction.final?.resourceProof]
      : [transaction.transition?.expectedBeforeResourceFingerprint, transaction.old?.resourceProof];
    const matches = [...new Set(expectedResources.filter((value) => validHash(value)))].filter((value) => value === observedResource);
    if (matches.length !== 1) fail('SERVICE_MANUAL_CLEANUP', operation, driverWrites, true, 'resource-drift');
    const entrypointPath = commandLineEntrypoint(snapshot.binaryPath);
    if (entrypointPath === null) fail('SERVICE_MANUAL_CLEANUP', operation, driverWrites, true, 'resource-drift');
    return Object.freeze({ entrypointPath, applicationManifestFingerprint });
  }
  function evaluate(snapshot, expectedEntrypointPath) {
    if (snapshot === null) return { phase: 'absent', state: buildServicePlatformState('win32', 'absent'), reasons: [] };
    if (snapshot.serviceRole !== component || typeof snapshot.accountName !== 'string' || snapshot.accountName.length === 0 || !validMarker(snapshot.description)) return { phase: null, state: null, reasons: [snapshot.serviceRole === component ? 'unmarked-resource' : 'foreign-resource'] };
    if (!validPath(expectedEntrypointPath)) return { phase: null, state: null, reasons: ['resource-drift'] };
    const noActions = snapshot.failureActions.length === 0 && snapshot.failureResetPeriod === 0 && snapshot.failureRebootMessage === '' && snapshot.failureCommand === '';
    const restartActions = snapshot.failureResetPeriod === 600 && snapshot.failureRebootMessage === '' && snapshot.failureCommand === '' && snapshot.failureActions.length === 4 && snapshot.failureActions[0].type === 'restart' && snapshot.failureActions[1].type === 'restart' && snapshot.failureActions[2].type === 'restart' && snapshot.failureActions[3].type === 'none' && snapshot.failureActions.slice(0, 3).every((a) => a.delayMs === 10000) && snapshot.failureActions[3].delayMs === 0;
    if (!snapshot.aclMatches || !snapshot.accountMatchesRole || snapshot.binaryPath !== expectedBinary(expectedEntrypointPath) || snapshot.failureActionsOnNonCrashFailures || snapshot.dependencies.length !== 0 || (snapshot.failurePolicy === 'none' && !noActions) || (snapshot.failurePolicy === actionPolicy(true) && !restartActions)) return { phase: null, state: null, reasons: ['resource-drift'] };
    const startType = snapshot.startType; const policy = snapshot.failurePolicy;
    const phase = startType === 'disabled' && policy === 'none' ? 'created-protected' : startType === 'demand' && policy === 'none' ? 'trial' : startType === 'auto' && policy === 'none' ? 'final-auto' : startType === 'auto' && policy === actionPolicy(true) ? 'final' : null;
    return phase === null ? { phase: null, state: null, reasons: ['resource-drift'] } : { phase, state: buildServicePlatformState('win32', phase), reasons: [] };
  }
  function processEvidence(snapshot, operation) { const pid = snapshot?.runtime?.processId ?? 0; if (pid === 0) return { pid: 0, tree: null, facts: null }; const facts = nativeCall('read_process_facts', pid); if (!plain(facts) || facts.pid !== pid || typeof facts.startTime !== 'string' || facts.executable !== shawl.path || facts.owner !== expectedOwner) fail('SERVICE_MANUAL_CLEANUP', operation, driverWrites, true, 'resource-drift'); const tree = nativeCall('enumerate_process_tree', pid, facts.startTime, facts.executable, facts.owner); if (!plain(tree) || !Array.isArray(tree.processes) || !Number.isSafeInteger(tree.processCount) || tree.processCount < 1 || tree.processes.length !== tree.processCount || typeof tree.treeFingerprint !== 'string' || !validHash(tree.treeFingerprint)) fail('SERVICE_MANUAL_CLEANUP', operation, driverWrites, true, 'tree-overflow'); return { pid, facts, tree }; }
  function probe(operation = 'probe_windows_service', transaction = null) {
    if (transaction === null) {
      const value = journal();
      transaction = transactionBinding(resolvePending(value, operation), operation);
    }
    const service = handle('query', operation);
    try {
      const snapshot = query(service, operation);
      const binding = deriveReleaseBinding(transaction, snapshot, operation);
      const evaluation = evaluate(snapshot, binding?.entrypointPath ?? null);
      const bootId = nativeCall('read_boot_id'); if (typeof bootId !== 'string' || !WIN_BOOT.test(bootId)) fail('SERVICE_IO_FAILED', 'read_boot_id', driverWrites, true);
      const process = processEvidence(snapshot, operation); const descriptorValue = descriptor(snapshot);
      return freeze({ bootId, service: snapshot, platformState: evaluation.state, platformPhase: evaluation.phase, driftReasons: evaluation.reasons, releaseBinding: binding, resourceDescriptor: descriptorValue, resourceFingerprint: windowsServiceResourceFingerprint(descriptorValue), process, logFamily: { ...logFamily } });
    } finally { close(service); }
  }
  function assertHead(operation, phases) {
    const value = journal();
    const allowed = phases.map((entry) => typeof entry === 'string' ? { phase: entry } : entry);
    const latest = transactionBinding(resolvePending(value, operation, allowed), operation);
    const match = allowed.some((entry) => entry.phase === latest.phase && (entry.substep === undefined || entry.substep === latest.substep));
    if (!match) fail('SERVICE_PENDING', operation, driverWrites);
    return latest;
  }
  function mutation(method, args, operation, options = {}) {
    const result = nativeCall(method, ...args);
    // StopService may return a writes:0 acknowledgement after SCM has already
    // crossed into STOP_PENDING.  That is a valid replay boundary, not a
    // failed mutation; the returned runtime snapshot is the acknowledgement.
    if (!result || (plain(result) && Object.hasOwn(result, 'writes') && result.writes < 1 && options.allowZeroWrites !== true)) fail('SERVICE_INVALID', operation, driverWrites, true);

    // A mutation is observed only after an exact post-action SCM probe.  The
    // native handle is the first argument for every SCM mutation.
    if (args[0] !== undefined && method !== 'delete_win32_service') query(args[0], operation);
    return result;
  }
  function journalMutation(phase, method, args, operation) {
    append(phase, 'intent');
    append(phase, 'action');
    const result = mutation(method, args, operation);
    // mutation() performs an exact SCM query immediately after the native
    // call; only then is the observed edge durable.
    append(phase, 'observed');
    return result;
  }
  // A transition action record does not carry an operation discriminator in
  // the shared envelope.  Recovery therefore reconciles the declared target
  // in a fixed order, using the current SCM snapshot as the CAS witness.  An
  // operation which already has its exact post-state is observed without a
  // second native call; a partial state resumes at the first unmatched edge.
  function reconcileTransition(service, snapshot, input, transaction, operation) {
    let current = snapshot;
    const journalPhase = ['stopping', 'quiescent'].includes(transaction.phase) ? 'resource-published' : 'transition-marker-intent';
    const ensure = (matches, method, args) => {
      if (matches(current)) return;
      journalMutation(journalPhase, method, [service, current.configFingerprint, current.runtime.fingerprint, ...args], operation);
      current = query(service, operation);
    };
    if (current.startType === 'auto') ensure((value) => value.startType === 'demand', 'set_win32_service_start_type', ['demand']);
    if (current.failurePolicy === actionPolicy(true)) {
      ensure((value) => value.failurePolicy === actionPolicy(false), 'set_win32_service_failure_actions', [actionPolicy(false)]);
      ensure((value) => value.failureActionsOnNonCrashFailures === false, 'set_win32_service_failure_actions_flag', [false]);
    }
    const expectedBinary = expectedBinaryFor(input.release.entrypointPath);
    ensure((value) => value.binaryPath === expectedBinary, 'configure_win32_service_launch', [
      shawl.path, shawl.sha256, configuration.workingDirectory, configuration.homeDirectory,
      configuration.runtimePath, shawl.runtimeSha256, input.release.entrypointPath,
      shawl.entrypointSha256, configuration.logDirectory, expectedLogAs(component, serviceKey),
      expectedLogCmdAs(component, serviceKey), component === 'bot' ? configuration.channelsConfig : null,
    ]);
    ensure((value) => value.description === marker(input.release.applicationManifestFingerprint), 'set_win32_service_marker', [marker(input.release.applicationManifestFingerprint)]);
    ensure((value) => value.startType === 'demand', 'set_win32_service_start_type', ['demand']);
    ensure((value) => value.failurePolicy === actionPolicy(false), 'set_win32_service_failure_actions', [actionPolicy(false)]);
    ensure((value) => value.failureActionsOnNonCrashFailures === false, 'set_win32_service_failure_actions_flag', [false]);
    const head = journal().entries.at(-1);
    if (head.phase === 'transition-marker-intent' && head.substep !== 'observed') append('transition-marker-intent', 'observed');
    return current;
  }
  function treeReceipt(value, captured, forced, operation) {
    if (plain(value) && exact(value, ['tree', 'forced', 'terminated', 'writes'])) {
      if (!['empty', 'ambiguous', 'overflow', 'survivor'].includes(value.tree) || typeof value.forced !== 'boolean' || !Number.isSafeInteger(value.terminated) || value.terminated < 0 || !Number.isSafeInteger(value.writes) || value.writes < 0) fail('SERVICE_INVALID', operation, driverWrites, true);
      return value;
    }
    // stop_win32_service returns an SCM snapshot, not a tree receipt. It is
    // only an acknowledgement; callers must obtain an independent post-stop
    // tree probe before certifying quiescence.
    if (plain(value) && plain(value.runtime) && Number.isSafeInteger(value.runtime.processId)) return null;
    fail('SERVICE_PROCESS_AMBIGUOUS', operation, driverWrites, true, 'ambiguous-process-tree');
  }
  function postStopTreeReceipt(captured, forced, operation) {
    if (!captured) fail('SERVICE_PROCESS_AMBIGUOUS', operation, driverWrites, true, 'ambiguous-process-tree');
    const pid = captured.pid > 0 ? captured.facts.pid : 0;
    const startTime = captured.pid > 0 ? captured.facts.startTime : '';
    const executable = captured.pid > 0 ? captured.facts.executable : shawl.path;
    const owner = captured.pid > 0 ? captured.facts.owner : expectedOwner;
    const tree = nativeCall('enumerate_process_tree', pid, startTime, executable, owner);
    if (!plain(tree) || !Array.isArray(tree.processes) || !Number.isSafeInteger(tree.processCount) || tree.processCount !== tree.processes.length || !validHash(tree.treeFingerprint)) fail('SERVICE_TREE_AMBIGUOUS', operation, driverWrites, true, 'ambiguous-process-tree');
    if (tree.processCount !== 0) fail('SERVICE_TREE_SURVIVOR', operation, driverWrites, true, 'tree-survivor');
    return Object.freeze({ tree: 'empty', forced, terminated: captured.tree?.processCount ?? 0, writes: 1 });
  }
  function freshActivationReceipt(service, before, transaction, operation, requireFinal = true) {
    const after = query(service, operation);
    const boot = nativeCall('read_boot_id');
    const live = probe(operation, transaction);
    if (boot === null || typeof boot !== 'string' || boot !== live.bootId || resourceIdentity(live.resourceDescriptor) !== resourceIdentity(descriptor(after))) fail('SERVICE_STARTUP_TIMEOUT', operation, driverWrites, true, 'stale-epoch');
    if (before.runtime.processId > 0) {
      const previous = processEvidence(before, operation);
      const current = processEvidence(after, operation);
      if (current.pid !== previous.pid || current.facts?.startTime !== previous.facts?.startTime || current.tree?.treeFingerprint !== previous.tree?.treeFingerprint) fail('SERVICE_STARTUP_TIMEOUT', operation, driverWrites, true, 'process-epoch-changed');
    }
    if (live.process.pid <= 0 || live.process.facts === null || live.process.tree === null || !validHash(live.process.tree.treeFingerprint)) fail('SERVICE_PENDING', operation, driverWrites, true, 'invocation-not-observed');
    if (live.service?.configFingerprint !== after.configFingerprint || live.service?.runtime?.fingerprint !== after.runtime.fingerprint) fail('SERVICE_STARTUP_TIMEOUT', operation, driverWrites, true, 'activation-drift');
    if (requireFinal && live.resourceFingerprint !== transaction.final.resourceProof) fail('SERVICE_MANUAL_CLEANUP', operation, driverWrites, true, 'resource-drift');
    return live;
  }
  // The Windows facade currently exposes no service-scoped native log cursor
  // or epoch receipt.  A marker-only SCM snapshot cannot prove that the live
  // wrapper emitted a current-run ready record, so final activation remains a
  // recoverable pending/manual state until that ABI exists.
  function requireAuthoritativeLogCursor(operation) {
    fail('SERVICE_PENDING', operation, driverWrites, true, 'log-cursor-invalid');
  }
  function reconstructTrial(transaction, observed, operation) {
    if (!observed || observed.platformPhase !== 'trial' || observed.process.pid <= 0 || observed.process.facts === null || observed.process.tree === null) return null;
    const binding = deriveReleaseBinding(transaction, observed.service, operation);
    if (binding === null || observed.resourceFingerprint !== transaction.transition.platformResourceFingerprint ||
        observed.resourceDescriptor.binaryPath !== expectedBinaryFor(binding.entrypointPath)) return null;
    const releaseFingerprint = binding.applicationManifestFingerprint;
    if (!validHash(releaseFingerprint) || !validHash(observed.resourceFingerprint)) return null;
    const trial = freeze({
      serviceName: name,
      bootId: observed.bootId,
      boundaryMs: nowMs(),
      preStartLogCursor: 0,
      binaryPath: observed.resourceDescriptor.binaryPath,
      resourceFingerprint: observed.resourceFingerprint,
      resourceDescriptor: observed.resourceDescriptor,
      configFingerprint: observed.resourceDescriptor.configFingerprint,
      releaseFingerprint,
      releaseBinding: binding,
      transactionFingerprint: transaction.transactionFingerprint,
      transitionFingerprint: transaction.transition.transitionFingerprint,
      wrapper: { pid: observed.process.pid, fingerprint: observed.service.runtime.fingerprint },
      process: observed.process,
      logFamily,
    });
    activeTrial = trial;
    return trial;
  }
  function publishCas(input, currentFingerprint) {
    const transaction = assertHead('publish_suppressed_resource', [
      { phase: 'prepared', substep: 'none' }, { phase: 'sequence-reserved' },
      { phase: 'release-published' }, { phase: 'transition-marker-intent' },
      { phase: 'stopping' }, { phase: 'quiescent' },
      { phase: 'resource-published' },
    ]);
    const declared = [transaction.candidate.applicationManifestFingerprint, transaction.old.applicationManifestFingerprint].filter((value) => value !== null);
    if (transaction.candidate.shawlManifestFingerprint !== shawl.sha256 || !declared.includes(input.release.applicationManifestFingerprint)) fail('SERVICE_STALE', 'publish_suppressed_resource', driverWrites, true, 'resource-drift');
    const expectedBefore = transaction.transition.expectedBeforeResourceFingerprint;
    if (currentFingerprint === null) {
      if (input.expectedCurrentSha256 !== null || expectedBefore !== null) fail('SERVICE_MANUAL_CLEANUP', 'publish_suppressed_resource', driverWrites, true, 'recreated-resource');
    } else if (!(transaction.phase === 'transition-marker-intent' && ['intent', 'action'].includes(transaction.substep) && input.expectedCurrentSha256 === expectedBefore) &&
               (input.expectedCurrentSha256 !== currentFingerprint || expectedBefore !== currentFingerprint)) {
      fail('SERVICE_MANUAL_CLEANUP', 'publish_suppressed_resource', driverWrites, true, 'resource-drift');
    }
    if (transaction.transition.candidateFingerprint !== transaction.candidate.candidateFingerprint || transaction.transition.oldFingerprint !== transaction.old.oldFingerprint || transaction.final.applicationManifestFingerprint !== transaction.candidate.applicationManifestFingerprint) fail('SERVICE_STALE', 'publish_suppressed_resource', driverWrites, true, 'resource-drift');
    return transaction;
  }

  const api = {
    get writes() { return driverWrites; },
    serviceName: name,
    unitName: name,
    probe() { return probe(); },
    publishSuppressedResource(input) {
      const operation = 'publish_suppressed_resource'; if (!exact(input, ['phase', 'release', 'expectedCurrentSha256'])) fail('SERVICE_INVALID', operation, driverWrites);
      if (!['transition-marker-intent', 'resource-published'].includes(input.phase) || (input.expectedCurrentSha256 !== null && !validHash(input.expectedCurrentSha256)) || !exact(input.release, ['entrypointPath', 'applicationManifestFingerprint']) || !validPath(input.release.entrypointPath) || !validHash(input.release.applicationManifestFingerprint)) fail('SERVICE_INVALID', operation, driverWrites);
      const transaction = assertHead(operation, [
        { phase: 'prepared', substep: 'none' }, { phase: 'sequence-reserved' },
        { phase: 'release-published' }, { phase: 'transition-marker-intent' },
        { phase: 'stopping' }, { phase: 'quiescent' },
        { phase: 'resource-published' },
      ]);
      const transitionReplay = transaction.phase === 'transition-marker-intent' && ['intent', 'action'].includes(transaction.substep) && input.expectedCurrentSha256 === transaction.transition.expectedBeforeResourceFingerprint;
      // The operation's release is authoritative for this transaction.  A
      // fresh controller's constructor release may be a different candidate
      // (notably on rollback), so never use it to reject the recorded old T
      // path before the transaction CAS has been checked.
      const currentProbe = probe(operation, transaction);
      if (transaction.phase === 'resource-published' && transaction.substep === 'observed') {
        if (currentProbe.resourceFingerprint !== transaction.transition.platformResourceFingerprint) fail('SERVICE_MANUAL_CLEANUP', operation, driverWrites, true, 'resource-drift');
        return currentProbe;
      }
      if (currentProbe.service !== null) {
        if (currentProbe.service.serviceRole !== component) fail('SERVICE_ACCESS_DENIED', operation, driverWrites, true, 'foreign-resource');
        if (!validMarker(currentProbe.service.description)) fail('SERVICE_MANUAL_CLEANUP', operation, driverWrites, true, currentProbe.service.description ? 'foreign-resource' : 'unmarked-resource');
        const acceptedMarkers = new Set([transaction.candidate.applicationManifestFingerprint, transaction.old.applicationManifestFingerprint].filter((value) => value !== null).map(marker));
        if (!acceptedMarkers.has(currentProbe.service.description)) fail('SERVICE_ACCESS_DENIED', operation, driverWrites, true, 'foreign-resource');
      }
      publishCas(input, currentProbe.service === null ? null : currentProbe.resourceFingerprint);
      const firstWitness = currentProbe.service === null ? null : Object.freeze({
        resourceFingerprint: currentProbe.resourceFingerprint,
        configFingerprint: currentProbe.service.configFingerprint,
        marker: currentProbe.service.description,
      });
      const expectedBefore = transaction.transition.expectedBeforeResourceFingerprint;
      const expectedAfter = transaction.transition.expectedAfterResourceFingerprint ?? transaction.transition.platformResourceFingerprint;
      if (transitionReplay && currentProbe.service !== null) {
        // A durable action may have completed before the controller vanished.
        // Accept only the exact declared post-state; hybrids are never
        // repaired by guessing which native edge crossed the ABI.
        if (currentProbe.resourceFingerprint === expectedAfter && currentProbe.resourceFingerprint === transaction.transition.platformResourceFingerprint) {
          if (currentProbe.service.description !== marker(transaction.candidate.applicationManifestFingerprint)) fail('SERVICE_MANUAL_CLEANUP', operation, driverWrites, true, 'resource-drift');
          append('transition-marker-intent', 'observed');
          append('resource-published', 'observed');
          return currentProbe;
        }
        if (currentProbe.resourceFingerprint !== expectedBefore || transaction.old.applicationManifestFingerprint === null || currentProbe.service.description !== marker(transaction.old.applicationManifestFingerprint)) fail('SERVICE_MANUAL_CLEANUP', operation, driverWrites, true, 'resource-drift');
      }
      const headBeforePublish = journal().entries.at(-1);
      if (headBeforePublish.phase === 'transition-marker-intent' && substepOrder[headBeforePublish.substep] < substepOrder.intent) append('transition-marker-intent', 'intent');
      const current = handle('mutate', operation); if (current !== null) {
        let existing = query(current, operation);
        // Query and mutate handles are separate native observations.  Refuse
        // any change between them before issuing the first setter; this is
        // the immutable old/T CAS witness for transition replay.
        if (firstWitness !== null && (windowsServiceResourceFingerprint(descriptor(existing)) !== firstWitness.resourceFingerprint || existing.configFingerprint !== firstWitness.configFingerprint || existing.description !== firstWitness.marker)) {
          close(current); fail('SERVICE_MANUAL_CLEANUP', operation, driverWrites, true, 'resource-drift');
        }
        if (!validMarker(existing.description)) { close(current); fail('SERVICE_MANUAL_CLEANUP', operation, driverWrites, true, existing.description ? 'foreign-resource' : 'unmarked-resource'); }
        const acceptedMarkers = new Set([transaction.candidate.applicationManifestFingerprint, transaction.old.applicationManifestFingerprint].filter((value) => value !== null).map(marker));
        if (!acceptedMarkers.has(existing.description)) { close(current); fail('SERVICE_ACCESS_DENIED', operation, driverWrites, true, 'foreign-resource'); }
        const existingFingerprint = windowsServiceResourceFingerprint(descriptor(existing));
        if ((!transitionReplay && input.expectedCurrentSha256 !== null && input.expectedCurrentSha256 !== existingFingerprint) ||
            (input.expectedCurrentSha256 === null && expectedBefore !== null)) { close(current); fail('SERVICE_MANUAL_CLEANUP', operation, driverWrites, true, expectedBefore === null ? 'recreated-resource' : 'resource-drift'); }
        if (existing.serviceType !== 0x10 || existing.errorControl !== 1 || existing.delayedAutoStart || existing.triggerCount !== 0 || existing.dependencies.length !== 0 || !existing.aclMatches || !existing.accountMatchesRole || existing.failureActionsOnNonCrashFailures || existing.loadOrderGroup !== '' || existing.failureRebootMessage !== '' || existing.failureCommand !== '') { close(current); fail('SERVICE_MANUAL_CLEANUP', operation, driverWrites, true, 'config-drift'); }
        if (existing.runtime.processId !== 0) { close(current); fail('SERVICE_MANUAL_CLEANUP', operation, driverWrites, true, 'tree-not-quiescent'); }
        // configure_win32_service_launch is intentionally restricted to a
        // suppressed service.  Recovery of any transition action uses the
        // same ordered CAS operations and skips mutations whose exact target
        // state is already visible after a controller crash.
        existing = reconcileTransition(current, existing, input, transaction, operation);
        close(current);
        append('resource-published', 'observed');
        const published = probe(operation);
        if (published.resourceFingerprint !== transaction.transition.platformResourceFingerprint) fail('SERVICE_MANUAL_CLEANUP', operation, driverWrites, true, 'resource-drift');
        return published;
      }
      const headBeforeCreate = journal().entries.at(-1);
      if (headBeforeCreate.phase !== 'transition-marker-intent' || substepOrder[headBeforeCreate.substep] < substepOrder.action) append('transition-marker-intent', 'action');
      const created = nativeCall('create_win32_service_disabled', name, component, shawl.path, shawl.sha256, configuration.workingDirectory, configuration.homeDirectory, configuration.runtimePath, shawl.runtimeSha256, input.release.entrypointPath, shawl.entrypointSha256, configuration.logDirectory, expectedLogAs(component, serviceKey), expectedLogCmdAs(component, serviceKey), component === 'bot' ? configuration.channelsConfig : null, servicePassword ?? null);
      if (!created) fail('SERVICE_IO_FAILED', operation, driverWrites, true);
      try {
        const initial = query(created, operation);
        append('transition-marker-intent', 'observed');
        journalMutation('transition-marker-intent', 'protect_win32_service', [created, initial.configFingerprint, initial.runtime.fingerprint, marker(input.release.applicationManifestFingerprint)], operation);
        const protectedSnapshot = query(created, operation);
        journalMutation('transition-marker-intent', 'set_win32_service_start_type', [created, protectedSnapshot.configFingerprint, protectedSnapshot.runtime.fingerprint, 'demand'], operation);
        const demandSnapshot = query(created, operation);
        journalMutation('transition-marker-intent', 'set_win32_service_failure_actions', [created, demandSnapshot.configFingerprint, demandSnapshot.runtime.fingerprint, actionPolicy(false)], operation);
        const emptyActions = query(created, operation);
        journalMutation('transition-marker-intent', 'set_win32_service_failure_actions_flag', [created, emptyActions.configFingerprint, emptyActions.runtime.fingerprint, false], operation);
        append('resource-published', 'observed');
        const published = probe(operation);
        if (published.resourceFingerprint !== transaction.transition.platformResourceFingerprint) fail('SERVICE_MANUAL_CLEANUP', operation, driverWrites, true, 'resource-drift');
        return published;
      } finally { close(created); }
    },
    async startTrial(input = {}) {
      const operation = 'start_trial'; if (!plain(input) || Reflect.ownKeys(input).some((key) => key !== 'expectedResourceFingerprint')) fail('SERVICE_INVALID', operation, driverWrites);
      const transaction = assertHead(operation, [
        { phase: 'resource-published', substep: 'observed' },
        { phase: 'trial-start-intent', substep: 'intent' }, { phase: 'trial-start-intent', substep: 'action' },
        { phase: 'trial-start-observed', substep: 'observed' }, { phase: 'starting', substep: 'intent' }, { phase: 'starting', substep: 'action' },
      ]);
      const before = probe(operation, transaction); if (!['trial', 'created-protected'].includes(before.platformPhase)) fail('SERVICE_STALE', operation, driverWrites);
      if (before.platformPhase === 'created-protected') fail('SERVICE_STALE', operation, driverWrites, false, 'activation-drift');
      if (input.expectedResourceFingerprint !== undefined && input.expectedResourceFingerprint !== before.resourceFingerprint) fail('SERVICE_MANUAL_CLEANUP', operation, driverWrites, true, 'resource-drift');
      if (before.resourceFingerprint !== transaction.transition.platformResourceFingerprint) fail('SERVICE_MANUAL_CLEANUP', operation, driverWrites, true, 'resource-drift');
      const service = handle('mutate', operation);
      if (service === null) fail('SERVICE_NOT_FOUND', operation, driverWrites, true);
      try {
        const startHead = journal().entries.at(-1);
        // A fresh controller can recover an already-running wrapper from a
        // durable observed/starting head.  Do not issue StartService again;
        // the process epoch and static resource CAS are the replay witness.
        if (['trial-start-observed', 'starting'].includes(startHead.phase) && before.service.runtime.processId > 0) {
          const recovered = reconstructTrial(transaction, before, operation);
          if (recovered === null) fail('SERVICE_PENDING', operation, driverWrites, true, 'invocation-not-observed');
          return recovered;
        }
        const actionAlreadyJournaled = startHead.phase === 'trial-start-intent' && startHead.substep === 'action';
        const retrialPhase = ['trial-start-observed', 'starting'].includes(startHead.phase);
        const replayStart = actionAlreadyJournaled && before.service.runtime.processId === 0 && before.service.runtime.state === 'stopped';
        if (!actionAlreadyJournaled || replayStart) {
          if (!actionAlreadyJournaled && startHead.phase === 'resource-published') {
            if (startHead.phase !== 'trial-start-intent' || substepOrder[startHead.substep] < substepOrder.intent) append('trial-start-intent', 'intent');
            if (journal().entries.at(-1).phase !== 'trial-start-intent' || substepOrder[journal().entries.at(-1).substep] < substepOrder.action) append('trial-start-intent', 'action');
          }
          if (startHead.phase === 'trial-start-observed' || startHead.phase === 'starting') {
            if (startHead.phase === 'trial-start-observed') append('starting', 'intent');
            if (startHead.phase === 'starting' && substepOrder[startHead.substep] < substepOrder.action) append('starting', 'action');
            if (journal().entries.at(-1).phase !== 'starting' || substepOrder[journal().entries.at(-1).substep] < substepOrder.action) append('starting', 'action');
          }
          mutation('start_win32_service', [service, before.service.configFingerprint, before.service.runtime.fingerprint], operation);
        }
        let observed = null;
        for (let attempt = 0; attempt < WINDOWS_DRIVER_LIMITS.startPollAttempts; attempt += 1) {
          const snapshot = query(service, operation);
          if (snapshot.runtime.state === 'running' && snapshot.runtime.processId > 0 && snapshot.runtime.processId !== before.service.runtime.processId) { observed = snapshot; break; }
          await sleepMs(WINDOWS_DRIVER_LIMITS.startPollMs);
        }
        if (!observed) fail('SERVICE_TRIAL_NOT_OBSERVED', operation, driverWrites, false, 'invocation-not-observed');
        const process = processEvidence(observed, operation);
        const bootId = nativeCall('read_boot_id');
        if (bootId !== before.bootId) fail('SERVICE_TRIAL_NOT_OBSERVED', operation, driverWrites, true, 'reboot');
        if (retrialPhase) {
          if (journal().entries.at(-1).phase === 'starting') append('starting', 'observed');
        } else {
          if (journal().entries.at(-1).phase === 'trial-start-intent') append('trial-start-intent', 'observed');
          append('trial-start-observed', 'observed');
        }
        const observedTransaction = journal().entries.at(-1);
        const trial = freeze({ serviceName: name, bootId, boundaryMs: nowMs(), preStartLogCursor: 0, binaryPath: before.resourceDescriptor.binaryPath, resourceFingerprint: transaction.transition.platformResourceFingerprint, resourceDescriptor: before.resourceDescriptor, configFingerprint: before.resourceDescriptor.configFingerprint, releaseFingerprint: before.releaseBinding.applicationManifestFingerprint, releaseBinding: before.releaseBinding, transactionFingerprint: observedTransaction.transactionFingerprint, transitionFingerprint: observedTransaction.transition.transitionFingerprint, wrapper: { pid: observed.runtime.processId, fingerprint: observed.runtime.fingerprint }, process, logFamily });
        activeTrial = trial;
        return trial;
      } finally { close(service); }
    },
    async runStartupGate(input) {
      const operation = 'run_startup_gate'; if (!exact(input, ['trial', 'observeApplication']) || typeof input.observeApplication !== 'function') fail('SERVICE_INVALID', operation, driverWrites);
      const trial = input.trial; if (!plain(trial) || activeTrial === null || !sameJson(trial, activeTrial) || typeof trial.bootId !== 'string' || !Number.isSafeInteger(trial.preStartLogCursor) || trial.preStartLogCursor < 0 || !plain(trial.process) || !Number.isSafeInteger(trial.process.pid) || !plain(trial.process.facts) || typeof trial.process.facts.startTime !== 'string' || !plain(trial.process.tree) || !validHash(trial.process.tree.treeFingerprint) || !validHash(trial.resourceFingerprint) || !validHash(trial.releaseFingerprint) || !plain(trial.releaseBinding) || !validPath(trial.releaseBinding.entrypointPath) || trial.releaseBinding.applicationManifestFingerprint !== trial.releaseFingerprint || !validHash(trial.transactionFingerprint) || !validHash(trial.transitionFingerprint)) fail('SERVICE_INVALID', operation, driverWrites);
      const trialTransaction = assertHead(operation, [
        { phase: 'trial-start-observed', substep: 'observed' },
        { phase: 'starting', substep: 'intent' }, { phase: 'starting', substep: 'action' }, { phase: 'starting', substep: 'observed' },
      ]);
      const declaredRelease = trialTransaction.candidate.applicationManifestFingerprint === trial.releaseFingerprint || trialTransaction.old.applicationManifestFingerprint === trial.releaseFingerprint;
      if (!declaredRelease || trial.transactionFingerprint !== trialTransaction.transactionFingerprint || trial.transitionFingerprint !== trialTransaction.transition.transitionFingerprint || trial.resourceFingerprint !== trialTransaction.transition.platformResourceFingerprint || trialTransaction.transition.candidateFingerprint !== trialTransaction.candidate.candidateFingerprint || trialTransaction.transition.oldFingerprint !== trialTransaction.old.oldFingerprint) fail('SERVICE_STALE', operation, driverWrites, true, 'resource-drift');
      if (trialTransaction.phase === 'trial-start-observed') append('starting', 'intent');
      const started = nowMs(); let application; while (nowMs() - started <= WINDOWS_DRIVER_LIMITS.startupWindowMs) { application = await input.observeApplication(Object.freeze({ serviceName: name, bootId: trial.bootId, process: trial.process, resourceFingerprint: trial.resourceFingerprint, releaseFingerprint: trial.releaseFingerprint, preStartLogCursor: trial.preStartLogCursor, logFamily })); if (!plain(application) || application.logEvidence === undefined) { await sleepMs(WINDOWS_DRIVER_LIMITS.startPollMs); continue; } try { const log = validateWindowsLogEvidence(application.logEvidence); if (application.logEvidence.epoch.bootId !== trial.bootId || application.logEvidence.epoch.pid !== trial.wrapper.pid || application.logEvidence.epoch.startTime !== trial.process.facts.startTime || application.logEvidence.cursor !== trial.preStartLogCursor) throw new TypeError('epoch mismatch'); if (application.logEvidence.records[0].offset < application.logEvidence.cursor || log.endOffset > WINDOWS_DRIVER_LIMITS.logBytes) throw new TypeError('cursor mismatch'); } catch { fail('SERVICE_STARTUP_TIMEOUT', operation, driverWrites, false, 'log-epoch-invalid'); } if (application.ready === true) break; await sleepMs(WINDOWS_DRIVER_LIMITS.startPollMs); }
      if (!plain(application) || application.ready !== true) fail('SERVICE_STARTUP_TIMEOUT', operation, driverWrites, false, 'startup-receipt-invalidated');
      if (journal().entries.at(-1).phase === 'starting' && substepOrder[journal().entries.at(-1).substep] < substepOrder.action) append('starting', 'action');
      const fresh = probe(operation, trialTransaction); if (fresh.bootId !== trial.bootId || !sameJson(fresh.releaseBinding, trial.releaseBinding) || resourceIdentity(fresh.resourceDescriptor) !== resourceIdentity(trial.resourceDescriptor) || fresh.resourceDescriptor.binaryPath !== trial.binaryPath || fresh.resourceDescriptor.configFingerprint !== trial.configFingerprint || fresh.process.pid !== trial.wrapper.pid || fresh.process.facts?.startTime !== trial.process.facts.startTime || fresh.process.tree?.treeFingerprint !== trial.process.tree.treeFingerprint) fail('SERVICE_STARTUP_TIMEOUT', operation, driverWrites, true, 'startup-receipt-invalidated');
      const transaction = transactionBinding(journal().entries.at(-1), operation);
      const observedAtMs = nowMs();
      let proof;
      try {
        proof = buildServiceStartupProof({
          component, serviceKey, platform: 'win32', architecture: 'x64',
          serviceGeneration: transaction.serviceGeneration,
          transactionId: transaction.transactionId,
          resourceProof: transaction.transition.platformResourceFingerprint,
          applicationManifestFingerprint: trial.releaseFingerprint,
          bootFingerprint: canonicalJsonHash({ kind: 'windows-boot/v1', bootId: trial.bootId }),
          processEpochFingerprint: canonicalJsonHash({ kind: 'windows-process-epoch/v1', wrapper: trial.wrapper, tree: trial.process.tree }),
          platformEvidenceFingerprint: canonicalJsonHash({ kind: 'windows-platform-evidence/v1', serviceName: name, wrapperPid: trial.wrapper.pid, logFamily }),
          applicationEvidenceFingerprint: application.applicationEvidenceFingerprint ?? canonicalJsonHash(application),
          platformState: buildServicePlatformState('win32', 'trial'),
          startBoundaryMs: trial.boundaryMs,
          observedAtMs,
          expiresAtMs: Math.min(started + WINDOWS_DRIVER_LIMITS.startupWindowMs, trial.boundaryMs + WINDOWS_DRIVER_LIMITS.startupWindowMs),
          startupEvidence: 'fresh-current-epoch',
          connectivityObservation: component === 'bot' ? 'last-observed-connected' : 'startup-only',
        });
      } catch { fail('SERVICE_INVALID', operation, driverWrites); }
      session.publishStartupProof(proof, session.readStartupProof()); append('startup-observed', 'observed'); return freeze(proof);
    },
    armFinalRestart() {
      const operation = 'arm_final_restart'; const transaction = assertHead(operation, [{ phase: 'startup-observed', substep: 'observed' }, { phase: 'activation-observed', substep: 'intent' }, { phase: 'activation-observed', substep: 'action' }]);
      if (transaction.phase === 'activation-observed' && transaction.substep === 'action') fail('SERVICE_PENDING', operation, driverWrites, true, 'controller-loss');
      requireAuthoritativeLogCursor(operation);
      const beforeProbe = probe(operation, transaction); const activationMarkers = new Set([transaction.candidate.applicationManifestFingerprint, transaction.old.applicationManifestFingerprint].filter((value) => value !== null).map(marker));
      const declaredResources = [transaction.transition.expectedAfterResourceFingerprint, transaction.transition.expectedBeforeResourceFingerprint].filter((value) => validHash(value));
      if (beforeProbe.resourceFingerprint !== transaction.transition.platformResourceFingerprint || !declaredResources.includes(transaction.final.resourceProof) || beforeProbe.platformPhase !== 'trial' || !beforeProbe.service || !activationMarkers.has(beforeProbe.service.description) || (activeTrial && resourceIdentity(beforeProbe.resourceDescriptor) !== resourceIdentity(activeTrial.resourceDescriptor))) fail('SERVICE_MANUAL_CLEANUP', operation, driverWrites, true, 'resource-drift');
      const service = handle('mutate', operation); if (service === null) fail('SERVICE_NOT_FOUND', operation, driverWrites, true); try {
        const before = query(service, operation);
        if (journal().entries.at(-1).phase !== 'activation-observed' || substepOrder[journal().entries.at(-1).substep] < substepOrder.intent) append('activation-observed', 'intent');
        if (journal().entries.at(-1).phase !== 'activation-observed' || substepOrder[journal().entries.at(-1).substep] < substepOrder.action) append('activation-observed', 'action');
        mutation('set_win32_service_start_type', [service, before.configFingerprint, before.runtime.fingerprint, 'auto'], operation);
        const live = freshActivationReceipt(service, before, transaction, operation, false);
        if (live.platformPhase !== 'final-auto') fail('SERVICE_MANUAL_CLEANUP', operation, driverWrites, true, 'activation-drift');
        append('activation-observed', 'observed'); return live;
      } finally { close(service); }
    },
    enableFinal() {
      const operation = 'enable_final'; const transaction = assertHead(operation, [{ phase: 'activation-observed', substep: 'observed' }]);
      requireAuthoritativeLogCursor(operation);
      const beforeProbe = probe(operation, transaction); const activationMarkers = new Set([transaction.candidate.applicationManifestFingerprint, transaction.old.applicationManifestFingerprint].filter((value) => value !== null).map(marker));
      const declaredResources = [transaction.transition.expectedAfterResourceFingerprint, transaction.transition.expectedBeforeResourceFingerprint].filter((value) => validHash(value));
      if (!declaredResources.includes(beforeProbe.resourceFingerprint) || !declaredResources.includes(transaction.final.resourceProof) || beforeProbe.platformPhase !== 'final-auto' || !beforeProbe.service || !activationMarkers.has(beforeProbe.service.description)) fail('SERVICE_MANUAL_CLEANUP', operation, driverWrites, true, 'resource-drift');
      const service = handle('mutate', operation); if (service === null) fail('SERVICE_NOT_FOUND', operation, driverWrites, true); try {
        const before = query(service, operation);
        append('activation-observed', 'intent'); append('activation-observed', 'action');
        mutation('set_win32_service_failure_actions', [service, before.configFingerprint, before.runtime.fingerprint, actionPolicy(true)], operation);
        const auto = freshActivationReceipt(service, before, transaction, operation, false);
        if (auto.platformPhase !== 'final-auto') fail('SERVICE_MANUAL_CLEANUP', operation, driverWrites, true, 'activation-drift');
        append('activation-observed', 'observed');
        append('activation-observed', 'intent'); append('activation-observed', 'action');
        const after = query(service, operation);
        mutation('set_win32_service_failure_actions_flag', [service, after.configFingerprint, after.runtime.fingerprint, false], operation);
        const live = freshActivationReceipt(service, after, transaction, operation, true);
        if (live.platformPhase !== 'final') fail('SERVICE_MANUAL_CLEANUP', operation, driverWrites, true, 'activation-drift');
        append('activation-observed', 'observed'); return live;
      } finally { close(service); }
    },
    async stopAndQuiesce(input = {}) {
      const operation = 'stop_and_quiesce';
      if (!plain(input) || Reflect.ownKeys(input).some((key) => key !== 'deadlineMs' && key !== 'expectedResourceFingerprint')) fail('SERVICE_INVALID', operation, driverWrites);
      const deadline = input.deadlineMs ?? WINDOWS_DRIVER_LIMITS.stopWindowMs;
      if (!Number.isSafeInteger(deadline) || deadline < 1 || deadline > WINDOWS_DRIVER_LIMITS.stopWindowMs) fail('SERVICE_INVALID', operation, driverWrites);
      const transaction = assertHead(operation, [
        { phase: 'transition-marker-intent' }, { phase: 'stopping' }, { phase: 'quiescent' },
        { phase: 'resource-published', substep: 'observed' }, { phase: 'trial-start-observed' },
        { phase: 'startup-observed' }, { phase: 'activation-observed' }, { phase: 'quiescent' },
        { phase: 'stopping', substep: 'intent' }, { phase: 'stopping', substep: 'action' }, { phase: 'stopping', substep: 'observed' },
      ]);
      const service = handle('mutate', operation);
      if (service === null) {
        // An absent SCM name is not proof that its prior process tree was
        // quiescent.  Even an uninstall transaction whose declared endpoint
        // is absent may have a detached wrapper/child tree; without a
        // service-scoped receipt this remains pending/manual cleanup.
        fail('SERVICE_PENDING', operation, driverWrites, true, 'ambiguous-process-tree');
      }
      try {
        const before = query(service, operation);
        const beforeFingerprint = windowsServiceResourceFingerprint(descriptor(before));
        const pretrial = validHash(transaction.transition.expectedBeforeResourceFingerprint) && ['transition-marker-intent', 'stopping', 'quiescent'].includes(transaction.phase);
        const expectedResource = pretrial ? transaction.transition.expectedBeforeResourceFingerprint : transaction.transition.platformResourceFingerprint;
        const stopMarkers = new Set([(pretrial ? transaction.old.applicationManifestFingerprint : transaction.candidate.applicationManifestFingerprint)].filter((value) => value !== null).map(marker));
        if (!validHash(expectedResource) || beforeFingerprint !== expectedResource || (input.expectedResourceFingerprint !== undefined && (input.expectedResourceFingerprint !== beforeFingerprint || input.expectedResourceFingerprint !== expectedResource)) || !stopMarkers.has(before.description)) fail('SERVICE_MANUAL_CLEANUP', operation, driverWrites, true, 'resource-drift');
        // Recovery from an already acknowledged STOP_PENDING edge must not
        // perform an eager empty-tree probe.  Retain the root facts for the
        // eventual service-scoped receipt and defer enumeration until SCM
        // reports that the root has exited.
        const captured = before.runtime.state === 'stop-pending' && before.runtime.processId > 0
          ? { pid: before.runtime.processId, facts: nativeCall('read_process_facts', before.runtime.processId), tree: null }
          : processEvidence(before, operation);
        if (captured.pid > 0 && (!plain(captured.facts) || captured.facts.pid !== captured.pid || captured.facts.executable !== shawl.path || captured.facts.owner !== expectedOwner)) fail('SERVICE_MANUAL_CLEANUP', operation, driverWrites, true, 'resource-drift');
        if (captured.pid === 0) {
          // PID zero carries no service-scoped lineage.  The current Windows
          // ABI cannot provide a post-stop tree receipt for that case, so do
          // not infer an empty tree or advance the quiescent head.
          fail('SERVICE_PENDING', operation, driverWrites, true, 'ambiguous-process-tree');
        }
        const stopHead = journal().entries.at(-1);
        const stoppingAction = stopHead.phase === 'stopping' && stopHead.substep === 'action';
        if (!stoppingAction && stopHead.phase !== 'stopping') append('stopping', 'intent');
        let stopReceipt = null;
        if (before.runtime.processId > 0) {
          // A stopping/action head is replayed only against the current root
          // lineage and exact config/runtime CAS.  Once SCM reports
          // STOP_PENDING, the native call is known to have crossed the ABI and
          // must not be issued again.
          const callAlreadyCrossed = stoppingAction && before.runtime.state === 'stop-pending';
          if (!callAlreadyCrossed) {
            if (!stoppingAction) { if (stopHead.phase !== 'stopping') append('stopping', 'intent'); append('stopping', 'action'); }
            treeReceipt(mutation('stop_win32_service', [service, before.configFingerprint, before.runtime.fingerprint], operation, { allowZeroWrites: true }), captured, false, operation);
            append('stopping', 'observed');
          }
        }
        const until = nowMs() + deadline;
        while (nowMs() < until) {
          const current = query(service, operation);
          // STOP_PENDING is only an acknowledgement.  Do not ask the generic
          // process-tree enumerator for an empty result while the root is
          // still alive; an empty race would be a false quiescence proof.
          if (current.runtime.processId === 0 && current.runtime.state === 'stopped') {
            stopReceipt = postStopTreeReceipt(captured, false, operation);
            if (!stopReceipt || stopReceipt.tree !== 'empty' || stopReceipt.forced || stopReceipt.terminated < 0) fail('SERVICE_TREE_AMBIGUOUS', operation, driverWrites, true, 'ambiguous-process-tree');
            append('quiescent', 'intent');
            append('quiescent', 'observed');
            return freeze({ serviceName: name, quiescent: true, tree: stopReceipt.tree, forced: stopReceipt.forced, terminated: stopReceipt.terminated, writes: stopReceipt.writes });
          }
          await sleepMs(WINDOWS_DRIVER_LIMITS.startPollMs);
        }
        const residual = query(service, operation);
        if (residual.runtime.processId > 0) {
          const process = processEvidence(residual, operation);
          append('stopping', 'intent'); append('stopping', 'action');
          const forceReceipt = treeReceipt(mutation('terminate_win32_service_tree', [service, residual.configFingerprint, process.facts.pid, process.facts.startTime, process.facts.executable, process.facts.owner, process.tree.treeFingerprint], operation), process, true, operation);
          const freshForceReceipt = postStopTreeReceipt(process, true, operation);
          append('stopping', 'observed');
          const afterForce = query(service, operation);
          if (afterForce.runtime.processId > 0) {
            const remaining = processEvidence(afterForce, operation);
            if (remaining.tree.processCount > 0) fail('SERVICE_MANUAL_CLEANUP', operation, driverWrites, true, 'tree-not-quiescent');
          }
          if (afterForce.runtime.processId === 0 && freshForceReceipt.tree === 'empty' && freshForceReceipt.forced === true && freshForceReceipt.terminated >= 1) {
            append('quiescent', 'intent');
            append('quiescent', 'observed');
            return freeze({ serviceName: name, quiescent: true, tree: freshForceReceipt.tree, forced: freshForceReceipt.forced, terminated: freshForceReceipt.terminated, writes: freshForceReceipt.writes });
          }
        }
        fail('SERVICE_MANUAL_CLEANUP', operation, driverWrites, true, 'tree-not-quiescent');
      } finally { close(service); }
    },
    removeResource(input) {
      const operation = 'remove_windows_resource';
      if (!exact(input, ['expectedResourceFingerprint'])) fail('SERVICE_INVALID', operation, driverWrites);
      const transaction = assertHead(operation, [
        { phase: 'quiescent', substep: 'observed' },
        { phase: 'tombstoned', substep: 'intent' }, { phase: 'tombstoned', substep: 'action' }, { phase: 'tombstoned', substep: 'observed' },
      ]);
      const service = handle('mutate', operation);
      const tombstoneAction = transaction.phase === 'tombstoned' && ['action', 'observed'].includes(transaction.substep);
      if (service === null) {
        // A controller restart after DeleteService can observe an absent SCM
        // name.  Absence is proof only when the tombstoned action is already
        // durable; an intent-only head still requires manual/pending review.
        if (tombstoneAction && input.expectedResourceFingerprint !== transaction.transition.platformResourceFingerprint) fail('SERVICE_MANUAL_CLEANUP', operation, driverWrites, true, 'resource-drift');
        if (tombstoneAction) {
          if (transaction.substep !== 'observed') append('tombstoned', 'observed');
          return freeze({ serviceName: name, removed: true });
        }
        fail('SERVICE_PENDING', operation, driverWrites, true, 'deletion-pending');
      }
      try {
        const current = query(service, operation);
        if (current === null) {
          close(service);
          if (tombstoneAction && input.expectedResourceFingerprint === transaction.transition.platformResourceFingerprint) {
            if (transaction.substep !== 'observed') append('tombstoned', 'observed');
            return freeze({ serviceName: name, removed: true });
          }
          fail('SERVICE_PENDING', operation, driverWrites, true, 'deletion-pending');
        }
        const currentFingerprint = windowsServiceResourceFingerprint(descriptor(current));
        const removalMarkers = new Set([transaction.candidate.applicationManifestFingerprint, transaction.old.applicationManifestFingerprint].filter((value) => value !== null).map(marker));
        if (!removalMarkers.has(current.description) || input.expectedResourceFingerprint !== currentFingerprint || currentFingerprint !== transaction.transition.platformResourceFingerprint) fail('SERVICE_MANUAL_CLEANUP', operation, driverWrites, true, 'resource-drift');
        const alreadyDeleted = tombstoneAction;
        if (!alreadyDeleted) { append('tombstoned', 'intent'); append('tombstoned', 'action'); }
        const receipt = alreadyDeleted ? null : mutation('delete_win32_service', [service, current.configFingerprint, current.runtime.fingerprint], operation);
        close(service);
        for (let attempt = 0; attempt < WINDOWS_DRIVER_LIMITS.startPollAttempts; attempt += 1) {
          const reopened = handle('query', operation);
          if (reopened === null) {
            append('tombstoned', 'observed');
            return freeze({ serviceName: name, removed: true });
          }
          const still = query(reopened, operation); close(reopened);
          if (still === null) {
            append('tombstoned', 'observed');
            return freeze({ serviceName: name, removed: true });
          }
          if (attempt + 1 === WINDOWS_DRIVER_LIMITS.startPollAttempts) fail('SERVICE_PENDING', operation, driverWrites, true, 'deletion-pending');
        }
      } finally { close(service); }
    },
    removeSharedTemplate(input) {
      const operation = 'remove_shared_template';
      if (!exact(input, ['evidence']) || !plain(input.evidence)) fail('SERVICE_INVALID', operation, driverWrites);
      // Windows has no shared unit template.  Keep the Linux-compatible
      // lifecycle seam explicit: only a proof of no shared object is accepted.
      if (input.evidence.present === true) fail('SERVICE_MANUAL_CLEANUP', operation, driverWrites, true, 'resource-drift');
      return freeze({ removed: true, platform: 'win32' });
    },
    recoverTrialState() {
      const operation = 'recover_trial_state';
      const transaction = assertHead(operation, [
        { phase: 'transition-marker-intent' }, { phase: 'stopping' },
        { phase: 'resource-published' }, { phase: 'trial-start-intent' },
        { phase: 'trial-start-observed' }, { phase: 'starting' },
        { phase: 'startup-observed' }, { phase: 'activation-observed' },
        { phase: 'stopping', substep: 'intent' }, { phase: 'stopping', substep: 'action' }, { phase: 'stopping', substep: 'observed' },
        { phase: 'quiescent' }, { phase: 'tombstoned' },
        { phase: 'resource-removed' }, { phase: 'committed' },
      ]);
      // Recovery binds the marker/resource pair observed in SCM.  A newer or
      // undeclared constructor release is never used as an expected path.
      let observed;
      try { observed = probe(operation, transaction); } catch (error) {
        if (error?.code === 'SERVICE_MANUAL_CLEANUP') return freeze({ recovery: 'manual-cleanup', reason: error.reason ?? 'resource-drift' });
        throw error;
      }
      if (observed.platformPhase === null) return freeze({ ...observed, recovery: 'manual-cleanup', reason: observed.driftReasons[0] ?? 'resource-drift' });
      if (observed.platformPhase === 'final') {
        const markerSet = new Set([transaction.candidate.applicationManifestFingerprint, transaction.old.applicationManifestFingerprint].filter((value) => value !== null).map(marker));
        if (transaction.phase !== 'committed' || transaction.final.resourceProof !== observed.resourceFingerprint || !observed.service || !markerSet.has(observed.service.description) || observed.process.pid <= 0 || observed.process.tree === null) return freeze({ ...observed, recovery: 'pending', reason: 'log-cursor-invalid' });
        // No authoritative service-scoped log cursor/epoch exists in this ABI;
        // a final-looking marker is never promoted to stable on that basis.
        return freeze({ ...observed, recovery: 'pending', reason: 'log-cursor-invalid' });
      }
      if (transaction.phase === 'transition-marker-intent') {
        const oldMarker = transaction.old.applicationManifestFingerprint === null ? null : marker(transaction.old.applicationManifestFingerprint);
        if (!validHash(transaction.transition.expectedBeforeResourceFingerprint) || observed.resourceFingerprint !== transaction.transition.expectedBeforeResourceFingerprint || !observed.service || observed.service.description !== oldMarker) return freeze({ ...observed, recovery: 'manual-cleanup', reason: 'resource-drift' });
        if (observed.process.pid === 0) return freeze({ ...observed, recovery: 'pending', reason: 'ambiguous-process-tree' });
        return freeze({ ...observed, recovery: 'resume', reason: 'controller-loss' });
      }
      if (observed.platformPhase !== 'trial') return freeze({ ...observed, recovery: 'pending', reason: 'activation-drift' });
      if (transaction.phase === 'stopping') {
        const markers = new Set([transaction.candidate.applicationManifestFingerprint, transaction.old.applicationManifestFingerprint].filter((value) => value !== null).map(marker));
        if (!observed.service || observed.resourceFingerprint !== transaction.transition.platformResourceFingerprint || !markers.has(observed.service.description)) return freeze({ ...observed, recovery: 'manual-cleanup', reason: 'resource-drift' });
        if (observed.process.pid === 0) return freeze({ ...observed, recovery: 'pending', reason: 'ambiguous-process-tree' });
        // stopAndQuiesce performs the final lineage/CAS check and resumes the
        // exact stop/poll edge; recovery never promotes a stopping head.
        return freeze({ ...observed, recovery: 'resume', reason: 'controller-loss' });
      }
      const proof = session.readStartupProof();
      const latest = journal().entries.at(-1);
      const persistedBoot = proof?.present ? proof.value?.bootFingerprint : null;
      const currentBoot = canonicalJsonHash({ kind: 'windows-boot/v1', bootId: observed.bootId });
      if (persistedBoot !== null && persistedBoot !== currentBoot) return freeze({ ...observed, recovery: 'retrial', reason: 'reboot' });
      if (latest?.phase === 'trial-start-intent') {
        if (latest.substep === 'action' && observed.process.pid > 0) {
          // The native start crossed the ABI before the controller was lost.
          // Promote the durable action to observed only after validating the
          // current process epoch, then reconstruct a callable trial.
          append('trial-start-intent', 'observed');
          const observedTransaction = append('trial-start-observed', 'observed');
          const trial = reconstructTrial(observedTransaction, observed, operation);
          if (trial !== null) return freeze({ ...observed, recovery: 'resume', reason: 'controller-loss', trial });
        }
        // Intent/action with no validated current wrapper is a callable
        // StartService replay; never advertise runStartupGate without a
        // reconstructed activeTrial.
        return freeze({ ...observed, recovery: 'retrial', reason: 'controller-loss' });
      }
      if (latest?.phase === 'trial-start-observed' || latest?.phase === 'starting') {
        if (observed.process.pid > 0) {
          const trial = reconstructTrial(transaction, observed, operation);
          if (trial !== null) return freeze({ ...observed, recovery: 'resume', reason: 'controller-loss', trial });
        }
        return freeze({ ...observed, recovery: 'retrial', reason: 'controller-loss' });
      }
      if (observed.process.pid === 0) return freeze({ ...observed, recovery: 'retrial', reason: 'controller-loss' });
      return freeze({ ...observed, recovery: 'retrial', reason: 'process-epoch-changed' });
    },
  };
  return Object.freeze(api);
}
