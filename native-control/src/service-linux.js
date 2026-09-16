// Issue #240 slice 9: Linux systemd service driver.
//
// This driver implements the Linux half of the approved service-lifecycle
// plan on top of the G001 native facade and the G002 protected store:
//
//   - release-independent true gjc-remote-daemon@.service template plus a
//     proof-owned per-instance drop-in
//     gjc-remote-daemon@<instance-key>.service.d/50-gjc-release.conf
//     (ExecStart= reset, exact absolute runtime + immutable entrypoint,
//     stable external cwd, per-instance HOME, release fingerprint, never a
//     raw HOST_ID);
//   - a byte-exact bot unit carrying its immutable release pin and explicit
//     external cwd/HOME/CHANNELS_CONFIG;
//   - the suppressed-but-controller-startable trial state: the exact unit is
//     loaded, unmasked, disabled, Restart=no, has no false Condition*/Assert*
//     and no owned or foreign inbound activator, so fixed-argv
//     `systemctl start <exact-unit>` is the only activation path;
//   - the post-gate final policy (After/Wants=network-online.target,
//     Restart=on-failure, RestartSec=10s, StartLimitIntervalSec=600s,
//     StartLimitBurst=5, KillSignal=SIGTERM, KillMode=control-group,
//     TimeoutStopSec=35s, UMask=0077), then creation of only the proof-owned
//     multi-user.target.wants link — the boot-activation linearization point;
//   - controller-loss/reboot recovery that never claims controller death
//     stops processes: it revalidates the transition proof, activation graph,
//     boot identity, invocation, and tree; resumes only a fresh same-epoch
//     receipt; otherwise stops an exact lineage, proves quiescence, and
//     retrials.
//
// OS interaction is exclusively (a) native facade primitives for
// unit/drop-in/enablement state (open_linux_service_scope,
// read/publish/remove_linux_service_object) and process/cgroup facts, and
// (b) fixed-argv systemctl/journalctl invocation through the injected runner.
// The driver never builds shell strings and never touches the filesystem
// directly. Every durable intent/action/observed boundary is journaled through
// the store session transaction journal around the OS calls.
//
// Proof preimages stay non-self-referential: published bytes embed only the
// release fingerprint (the signed application manifest never covers unit
// bytes), while the durable binding between bytes and transaction is the
// journal-declared platformResourceFingerprint over the canonical resource
// descriptor. Embedding the transaction or transition fingerprint in the
// bytes would be circular, so it is deliberately absent.
//
// Lock handoff contract: native publish/remove calls require the exclusive
// store lock handles (artifact -> shared-template -> service-key) that the
// open store session already holds. The orchestrator passes those handles in
// as `locks`; this module never acquires or releases them (slice-11 store
// accessor integration point).
//
// The driver never sees a raw HOST_ID: daemon instance identity is the
// derived service key. Runtime binaries, accounts, configuration, homes,
// logs, and env files are preprovisioned external state and are only
// referenced, never created or rewritten here.

import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import {
  canonicalJson,
  canonicalJsonHash,
  isHex64,
} from '@gjc-remote/shared/strict-json';
import {
  SERVICE_LIFECYCLE_LIMITS,
  SERVICE_STATUS_VALUES,
  SERVICE_TRANSACTION_PHASES,
  buildServicePlatformState,
  buildServiceStartupProof,
  buildServiceTransaction,
  validateServiceKey,
  validateServiceRoles,
} from '@gjc-remote/shared/service-lifecycle-envelope';

export const LINUX_DRIVER_LIMITS = Object.freeze({
  showBytes: 64 * 1024,
  journalCursorBytes: 16 * 1024,
  argvElementBytes: 4096,
  startupWindowMs: SERVICE_LIFECYCLE_LIMITS.startupWindowMs,
  stopDeadlineMs: 35_000,
  stopPollMs: 250,
  startPollMs: 100,
  startPollAttempts: 30,
});

// Closed driver error code set. Native codes pass through unchanged; the two
// trial-specific codes name a refused/invalidated trial start and a startup
// gate deadline, neither of which is an I/O, CAS, or ambiguity failure.
export const LINUX_SERVICE_ERROR_CODES = Object.freeze([
  'SERVICE_INVALID',
  'SERVICE_ACCESS_DENIED',
  'SERVICE_ALREADY_EXISTS',
  'SERVICE_IO_FAILED',
  'SERVICE_MANUAL_CLEANUP',
  'SERVICE_PENDING',
  'SERVICE_PROCESS_AMBIGUOUS',
  'SERVICE_REFERENCED',
  'SERVICE_STALE',
  'SERVICE_STARTUP_TIMEOUT',
  'SERVICE_TRIAL_NOT_OBSERVED',
  'SERVICE_TREE_AMBIGUOUS',
  'SERVICE_TREE_OVERFLOW',
  'SERVICE_TREE_SURVIVOR',
]);

// Closed sanitized classification tags. Never raw paths, unit contents,
// environment values, or identity material.
export const LINUX_DRIVER_REASONS = Object.freeze([
  'absent-expected',
  'activation-drift',
  'boot-mismatch',
  'epoch-lost',
  'false-condition',
  'inbound-activator',
  'invocation-not-observed',
  'mask-drift',
  'resource-drift',
  'sibling-drift',
  'startup-receipt-invalidated',
  'template-drift',
  'template-referenced',
  'tree-not-quiescent',
  'recreated-resource',
]);

const SYSTEMCTL = '/usr/bin/systemctl';
const JOURNALCTL = '/usr/bin/journalctl';

const SYSTEMD_ROOT = '/etc/systemd/system';
const BOT_UNIT_FILE = 'gjc-remote-bot.service';
const DAEMON_TEMPLATE_FILE = 'gjc-remote-daemon@.service';
const DAEMON_DROPIN_FILE = '50-gjc-release.conf';
const CGROUP_ROOT = '/sys/fs/cgroup';
const SLICE_NAME = 'system.slice';

const SHOW_PROPERTIES = Object.freeze([
  'LoadState',
  'UnitFileState',
  'Type',
  'User',
  'UID',
  'Description',
  'SyslogIdentifier',
  'ActiveState',
  'SubState',
  'InvocationID',
  'MainPID',
  'ExecMainStartTimestamp',
  'Restart',
  'ConditionResult',
  'AssertResult',
  'Conditions',
  'Asserts',
  'RefuseManualStart',
  'TriggeredBy',
  'WantedBy',
  'RequiredBy',
  'Before',
  'Requires',
  'Requisite',
  'BindsTo',
  'PartOf',
  'Conflicts',
  'Slice',
  'EnvironmentFiles',
  'WorkingDirectory',
  'ControlGroup',
  'FragmentPath',
  'DropInPaths',
  'Environment',
  'ExecStart',
  'RestartUSec',
  'KillSignal',
  'KillMode',
  'TimeoutStopUSec',
  'UMask',
  'After',
  'Wants',
  'StartLimitIntervalUSec',
  'StartLimitBurst',
  'NeedDaemonReload',
]);
const SHOW_PROPERTY_SET = new Set(SHOW_PROPERTIES);

// Manager keys compared across daemon-reload for sibling invariance. Runtime
// fields (active state, invocation, PIDs, timestamps, condition results) are
// deliberately excluded; a reload must never change a sibling's effective
// configuration view.
const SIBLING_STABLE_KEYS = Object.freeze([
  'LoadState',
  'UnitFileState',
  'Restart',
  'FragmentPath',
  'DropInPaths',
  'TriggeredBy',
  'WantedBy',
  'RequiredBy',
  'ExecStart',
  'UID',
  'Description',
  'SyslogIdentifier',
  'Environment',
  'Slice',
]);

// Unit values the driver renders use a closed charset so published bytes
// never need systemd quoting/escaping and compare byte-exact.
const UNIT_VALUE = /^[A-Za-z0-9_./:@+-]+$/;
const RESTART_POLICIES = new Set(['no', 'on-failure']);
const INVOCATION_ID = /^[0-9a-f]{32}$/;
const BOOT_ID = /^linux:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const EXEC_TIMESTAMP = /^[A-Z][a-z]{2} ([0-9]{4})-([0-9]{2})-([0-9]{2}) ([0-9]{2}):([0-9]{2}):([0-9]{2}) UTC$/;
const CURSOR_LINE = /^-- cursor: ([A-Za-z0-9_.:,;+/=-]+)$/;
const FORBIDDEN_UNIT_DIRECTIVE = /^(?:Condition[A-Za-z]*|Assert[A-Za-z]*|RefuseManualStart)\s*=/m;
const SHOW_PID = /^(0|[1-9][0-9]{0,9})$/;
const ARGV_ELEMENT = /^[A-Za-z0-9_./:@+,=-]+$/;

const DRIVER_NATIVE = Object.freeze([
  'open_linux_service_scope',
  'read_linux_service_object',
  'publish_linux_service_object',
  'remove_linux_service_object',
  'close_service_handle',
  'read_boot_id',
  'read_process_facts',
  'enumerate_process_tree',
  'read_linux_service_cgroup',
  'terminate_linux_service_cgroup',
]);

const LOCK_KEYS = Object.freeze(['artifact', 'sharedTemplate', 'serviceKey']);
const SESSION_METHODS = Object.freeze([
  'readJournal',
  'appendJournal',
  'readStartupProof',
  'publishStartupProof',
  'readReferences',
]);
const SNAPSHOT_KEYS = Object.freeze([
  'objectKind',
  'state',
  'parentIdentity',
  'containerIdentity',
  'bytes',
  'facts',
  'target',
]);
const OBJECT_STATES = new Set(['file', 'directory', 'symlink', 'absent', 'parent-absent']);
const PROCESS_FACTS_KEYS = Object.freeze(['pid', 'parentPid', 'startTime', 'executable', 'owner', 'state', 'depth']);
const CGROUP_KEYS = Object.freeze(['identity', 'processes', 'treeFingerprint', 'processCount']);

const TRIAL_KEYS = Object.freeze([
  'unitName',
  'bootId',
  'boundaryMs',
  'preStartCursor',
  'invocationId',
  'mainPid',
  'mainStartTime',
  'executable',
  'owner',
  'cgroupPath',
  'cgroupIdentity',
  'treeFingerprint',
  'cgroupTreeFingerprint',
  'cgroupMemberFingerprint',
  'transactionFingerprint',
  'resourceFingerprint',
  'releaseFingerprint',
]);
const PHASES = Object.freeze(['absent', 'trial', 'final-restart-armed', 'final']);
const STOPPABLE_HEADS = Object.freeze([
  { phase: 'transition-marker-intent', substep: 'observed' },
  { phase: 'resource-published', substep: 'observed' },
  { phase: 'trial-start-observed', substep: 'observed' },
  { phase: 'starting', substep: 'intent' },
  { phase: 'startup-observed', substep: 'observed' },
  { phase: 'activation-observed', substep: 'observed' },
  { phase: 'stopping', substep: 'action' },
  { phase: 'stopping', substep: 'observed' },
]);
const LATE_STOP_PHASES = new Set([
  'resource-published',
  'trial-start-observed',
  'starting',
  'startup-observed',
  'activation-observed',
]);

function fail(code, operation, writes, ambiguous = false, reason = undefined) {
  if (!LINUX_SERVICE_ERROR_CODES.includes(code)) {
    throw new Error(`unknown driver error code: ${code}`);
  }
  if (reason !== undefined && !LINUX_DRIVER_REASONS.includes(reason)) {
    throw new Error(`unknown driver error reason: ${reason}`);
  }
  const error = new Error(`${operation} failed`);
  Object.defineProperties(error, {
    name: { value: 'ServiceLinuxError' },
    code: { value: code, enumerable: true },
    operation: { value: operation, enumerable: true },
    writes: { value: writes, enumerable: true },
    ambiguous: { value: ambiguous, enumerable: true },
    ...(reason === undefined
      ? {}
      : { reason: { value: reason, enumerable: true } }),
  });
  throw error;
}

function validWrites(value) {
  return Number.isSafeInteger(value) && value >= 0;
}

function plain(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value) &&
    Object.getPrototypeOf(value) === Object.prototype;
}

function exactKeys(value, keys) {
  if (!plain(value)) return false;
  const own = Reflect.ownKeys(value);
  return own.length === keys.length &&
    own.every((key) => typeof key === 'string') &&
    keys.every((key) => Object.hasOwn(value, key));
}

function sha256hex(bytes) {
  return createHash('sha256').update(bytes).digest('hex');
}

function freezeDeep(value) {
  if (Buffer.isBuffer(value) || ArrayBuffer.isView(value)) return value;
  if (value !== null && typeof value === 'object') {
    for (const child of Array.isArray(value) ? value : Object.values(value)) {
      freezeDeep(child);
    }
    Object.freeze(value);
  }
  return value;
}

function sameJson(left, right) {
  return canonicalJson(left) === canonicalJson(right);
}

function unitValue(value) {
  return typeof value === 'string' && value.length > 0 &&
    Buffer.byteLength(value, 'utf8') <= SERVICE_LIFECYCLE_LIMITS.pathBytes &&
    UNIT_VALUE.test(value);
}

function absoluteUnitPath(value) {
  return unitValue(value) && value.startsWith('/');
}

/**
 * Reads the two checked-in unit sources. The bot file is a render template
 * carrying @GJC_REMOTE_*@ tokens; the daemon template is the literal
 * invariant unit bytes published verbatim.
 */
export function loadLinuxServiceTemplates() {
  const botUnit = readFileSync(
    new URL('./systemd/gjc-remote-bot.service', import.meta.url),
  );
  const daemonTemplate = readFileSync(
    new URL('./systemd/gjc-remote-daemon@.service', import.meta.url),
  );
  return Object.freeze({ botUnit, daemonTemplate });
}

export function linuxServiceUnitName(component, serviceKey) {
  validateServiceKey(serviceKey, component);
  return component === 'bot'
    ? BOT_UNIT_FILE
    : `gjc-remote-daemon@${serviceKey}.service`;
}

export function linuxDaemonDropinDirectoryName(serviceKey) {
  validateServiceKey(serviceKey, 'daemon');
  return `gjc-remote-daemon@${serviceKey}.service.d`;
}

export function linuxDaemonTemplateFingerprint(templateBytes) {
  if (!Buffer.isBuffer(templateBytes) || templateBytes.length === 0) {
    fail('SERVICE_INVALID', 'linux_daemon_template_fingerprint', 0);
  }
  return sha256hex(templateBytes);
}

function objectNames(component, serviceKey) {
  const unitName = linuxServiceUnitName(component, serviceKey);
  if (component === 'bot') {
    return Object.freeze({
      component,
      serviceKey,
      unitName,
      linkName: BOT_UNIT_FILE,
      linkTarget: `${SYSTEMD_ROOT}/${BOT_UNIT_FILE}`,
      fragmentPath: `${SYSTEMD_ROOT}/${BOT_UNIT_FILE}`,
      dropinPath: null,
      cgroupPath: `${CGROUP_ROOT}/${SLICE_NAME}/${BOT_UNIT_FILE}`,
      controlGroup: `/${SLICE_NAME}/${BOT_UNIT_FILE}`,
    });
  }
  const dropinDirectory = linuxDaemonDropinDirectoryName(serviceKey);
  return Object.freeze({
    component,
    serviceKey,
    unitName,
    linkName: unitName,
    linkTarget: `${SYSTEMD_ROOT}/${DAEMON_TEMPLATE_FILE}`,
    fragmentPath: `${SYSTEMD_ROOT}/${DAEMON_TEMPLATE_FILE}`,
    dropinPath: `${SYSTEMD_ROOT}/${dropinDirectory}/${DAEMON_DROPIN_FILE}`,
    cgroupPath: `${CGROUP_ROOT}/${SLICE_NAME}/${unitName}`,
    controlGroup: `/${SLICE_NAME}/${unitName}`,
  });
}

const BOT_TOKENS = Object.freeze([
  '@GJC_REMOTE_CHANNELS_CONFIG@',
  '@GJC_REMOTE_HOME_DIRECTORY@',
  '@GJC_REMOTE_WORKING_DIRECTORY@',
  '@GJC_REMOTE_RUNTIME_PATH@',
  '@GJC_REMOTE_ENTRYPOINT_PATH@',
  '@GJC_REMOTE_RESTART@',
  '@GJC_REMOTE_RELEASE_FINGERPRINT@',
  '@GJC_REMOTE_PROOF_FINGERPRINT@',
]);

function validateDriverConfiguration(configuration, component) {
  const common = ['runtimePath', 'workingDirectory', 'homeDirectory', 'logDirectory'];
  const keys = component === 'bot'
    ? [...common, 'channelsConfig', 'expectedHostSetFingerprint', 'expectedHostCount']
    : common;
  if (!exactKeys(configuration, keys)) return null;
  for (const field of common) {
    if (!absoluteUnitPath(configuration[field])) return null;
  }
  if (component === 'bot' &&
      (!absoluteUnitPath(configuration.channelsConfig) ||
        !isHex64(configuration.expectedHostSetFingerprint) ||
        !Number.isSafeInteger(configuration.expectedHostCount) ||
        configuration.expectedHostCount < 0 ||
        configuration.expectedHostCount > SERVICE_LIFECYCLE_LIMITS.expectedHostCount)) {
    return null;
  }
  return configuration;
}

/**
 * Renders the proof-owned bot unit bytes from the checked-in template. Every
 * token must be present exactly once in the template and no token may remain
 * in the output; the rendered bytes are deterministic per input.
 */
export function renderLinuxBotUnit(templates, input) {
  const operation = 'render_linux_bot_unit';
  if (!exactKeys(templates, ['botUnit', 'daemonTemplate']) ||
      !Buffer.isBuffer(templates.botUnit)) {
    fail('SERVICE_INVALID', operation, 0);
  }
  if (!exactKeys(input, ['configuration', 'entrypointPath', 'restart', 'releaseFingerprint']) ||
      !validateDriverConfiguration(input.configuration, 'bot') ||
      !absoluteUnitPath(input.entrypointPath) ||
      !RESTART_POLICIES.has(input.restart) ||
      !isHex64(input.releaseFingerprint)) {
    fail('SERVICE_INVALID', operation, 0);
  }
  const values = {
    '@GJC_REMOTE_CHANNELS_CONFIG@': input.configuration.channelsConfig,
    '@GJC_REMOTE_HOME_DIRECTORY@': input.configuration.homeDirectory,
    '@GJC_REMOTE_WORKING_DIRECTORY@': input.configuration.workingDirectory,
    '@GJC_REMOTE_RUNTIME_PATH@': input.configuration.runtimePath,
    '@GJC_REMOTE_ENTRYPOINT_PATH@': input.entrypointPath,
    '@GJC_REMOTE_RESTART@': input.restart,
    '@GJC_REMOTE_RELEASE_FINGERPRINT@': input.releaseFingerprint,
    '@GJC_REMOTE_PROOF_FINGERPRINT@': input.releaseFingerprint,
  };
  let text = templates.botUnit.toString('utf8');
  for (const token of BOT_TOKENS) {
    if (text.split(token).length - 1 !== 1) fail('SERVICE_INVALID', operation, 0);
    text = text.replaceAll(token, values[token]);
  }
  if (/@GJC_REMOTE_[A-Z_*]+@/.test(text) || FORBIDDEN_UNIT_DIRECTIVE.test(text)) {
    fail('SERVICE_INVALID', operation, 0);
  }
  return Buffer.from(text, 'utf8');
}

/**
 * Renders the per-instance daemon drop-in bytes. The layout is canonical:
 * ExecStart= reset, exact absolute runtime + immutable entrypoint, stable
 * external cwd, per-instance HOME, explicit restart policy, and the release
 * fingerprint comment. No raw HOST_ID ever appears.
 */
export function renderLinuxDaemonDropin(input) {
  const operation = 'render_linux_daemon_dropin';
  if (!exactKeys(input, ['configuration', 'entrypointPath', 'restart', 'releaseFingerprint']) ||
      !validateDriverConfiguration(input.configuration, 'daemon') ||
      !absoluteUnitPath(input.entrypointPath) ||
      !RESTART_POLICIES.has(input.restart) ||
      !isHex64(input.releaseFingerprint)) {
    fail('SERVICE_INVALID', operation, 0);
  }
  const configuration = input.configuration;
  const text = [
    '# gjc-remote proof-owned instance release pin; managed only by gjc-remote-service.',
    `# gjc-remote-release: ${input.releaseFingerprint}`,
    '[Service]',
    'ExecStart=',
    `ExecStart=${configuration.runtimePath} ${input.entrypointPath}`,
    `WorkingDirectory=${configuration.workingDirectory}`,
    `Environment=HOME=${configuration.homeDirectory}`,
    `Restart=${input.restart}`,
    '',
  ].join('\n');
  if (FORBIDDEN_UNIT_DIRECTIVE.test(text)) fail('SERVICE_INVALID', operation, 0);
  return Buffer.from(text, 'utf8');
}

/**
 * Canonical OS-resource descriptor behind the transaction's
 * platformResourceFingerprint / expectedBeforeResourceFingerprint /
 * expectedAfterResourceFingerprint values. It binds only durable resource
 * state: owned object bytes and the proof-owned enablement link. Runtime
 * manager state (invocations, PIDs) is startup evidence, never part of this
 * fingerprint.
 */
export function linuxServiceResourceFingerprint(descriptor) {
  const operation = 'linux_service_resource_fingerprint';
  const keys = ['kind', 'component', 'serviceKey', 'botUnitSha256', 'templateSha256', 'dropinSha256', 'enablementLink'];
  if (!exactKeys(descriptor, keys) || descriptor.kind !== 'linux-service-resource/v1') {
    fail('SERVICE_INVALID', operation, 0);
  }
  try {
    validateServiceKey(descriptor.serviceKey, descriptor.component);
  } catch {
    fail('SERVICE_INVALID', operation, 0);
  }
  const hashes = [descriptor.botUnitSha256, descriptor.templateSha256, descriptor.dropinSha256];
  if (hashes.some((value) => value !== null && !isHex64(value)) ||
      (descriptor.enablementLink !== 'absent' && descriptor.enablementLink !== 'owned')) {
    fail('SERVICE_INVALID', operation, 0);
  }
  if (descriptor.component === 'bot'
      ? (descriptor.templateSha256 !== null || descriptor.dropinSha256 !== null)
      : descriptor.botUnitSha256 !== null) {
    fail('SERVICE_INVALID', operation, 0);
  }
  return canonicalJsonHash(descriptor);
}

function parseShowOutput(text, operation, writes) {
  if (typeof text !== 'string' || Buffer.byteLength(text, 'utf8') > LINUX_DRIVER_LIMITS.showBytes) {
    fail('SERVICE_IO_FAILED', operation, writes);
  }
  const result = Object.create(null);
  if (text.length === 0) return result;
  const lines = text.endsWith('\n') ? text.slice(0, -1).split('\n') : text.split('\n');
  for (const line of lines) {
    const separator = line.indexOf('=');
    const key = separator > 0 ? line.slice(0, separator) : '';
    if (!SHOW_PROPERTY_SET.has(key) || Object.hasOwn(result, key)) {
      fail('SERVICE_IO_FAILED', operation, writes);
    }
    result[key] = line.slice(separator + 1);
  }
  // `systemctl show` is a closed observation boundary.  A partial response
  // must never be interpreted through defaults (especially for activation,
  // condition, or reload state), since doing so can certify an unknown unit.
  if (SHOW_PROPERTIES.some((key) => !Object.hasOwn(result, key))) {
    fail('SERVICE_IO_FAILED', operation, writes);
  }
  return result;
}

function showList(value) {
  if (typeof value !== 'string' || value.length === 0) return [];
  return value.trim().split(/\s+/).filter((entry) => entry.length > 0);
}

function cgroupMemberFingerprint(cgroup) {
  if (!exactKeys(cgroup, CGROUP_KEYS) || !Array.isArray(cgroup.processes) ||
      cgroup.processCount !== cgroup.processes.length ||
      !Number.isSafeInteger(cgroup.processCount) || cgroup.processCount < 0 ||
      !exactKeys(cgroup.identity, ['device', 'inode']) ||
      !canonicalUint64(cgroup.identity.device) || !canonicalUint64(cgroup.identity.inode) ||
      !isHex64(cgroup.treeFingerprint)) return null;
  const members = [];
  const pids = new Set();
  for (const process of cgroup.processes) {
    if (!plain(process) || !exactKeys(process, PROCESS_FACTS_KEYS) ||
        !Number.isSafeInteger(process.pid) || process.pid < 1 || pids.has(process.pid) ||
        !Number.isSafeInteger(process.parentPid) || process.parentPid < 0 ||
        typeof process.startTime !== 'string' || process.startTime.length === 0 ||
        typeof process.executable !== 'string' || process.executable.length === 0 ||
        typeof process.owner !== 'string' || process.owner.length === 0 ||
        typeof process.state !== 'string' || process.state.length === 0 ||
        !Number.isSafeInteger(process.depth) || process.depth < 0 || process.depth > 64) {
      return null;
    }
    pids.add(process.pid);
    members.push({ ...process });
  }
  members.sort((left, right) => left.pid - right.pid);
  // The complete fact tuple (including parent/root depth) is the proof.  A
  // PID-only digest permits PID reuse and misses a changed root lineage.
  return canonicalJsonHash({ kind: 'linux-cgroup-members/v2', members });
}

// Linux native receipts carry kernel device/inode values as canonical
// unsigned decimal strings.  Never accept a lossy JS number, a signed value,
// or an alternate spelling (leading zeroes/hex) for a physical identity.
function canonicalUint64(value) {
  if (typeof value !== 'string' || !/^(?:0|[1-9][0-9]*)$/.test(value)) return false;
  try { return BigInt(value) <= 0xffffffffffffffffn; } catch { return false; }
}

function validUid(value) {
  return typeof value === 'string' && /^uid:(?:0|[1-9][0-9]*)$/.test(value) &&
    BigInt(value.slice(4)) <= 0xffffffffn;
}

function validLinuxParentIdentity(value) {
  return plain(value) && exactKeys(value, ['kind', 'device', 'inode', 'mode', 'owner']) &&
    value.kind === 'linux-parent-v1' && canonicalUint64(value.device) &&
    canonicalUint64(value.inode) && Number.isSafeInteger(value.mode) &&
    value.mode >= 0 && value.mode <= 0xffffffff && validUid(value.owner);
}

function validLinuxServiceIdentity(value) {
  const profiles = new Set([
    'service-control-directory', 'service-control-file',
    'service-staging-directory', 'service-staging-file',
    'service-release-directory', 'service-release-file',
    'service-release-executable', 'service-bot-log-directory',
    'service-daemon-log-directory', 'service-internal-container-directory',
    'service-preserved-container-directory',
  ]);
  return plain(value) && exactKeys(value, [
    'profile', 'kind', 'device', 'inode', 'mode', 'owner', 'securitySha256',
  ]) && value.kind === 'linux-service-object-v1' &&
    profiles.has(value.profile) &&
    canonicalUint64(value.device) && canonicalUint64(value.inode) &&
    Number.isSafeInteger(value.mode) && value.mode >= 0 && value.mode <= 0xffffffff &&
    validUid(value.owner) && isHex64(value.securitySha256);
}

function validLinuxContainerIdentity(value) {
  return value === null || validLinuxParentIdentity(value) || validLinuxServiceIdentity(value);
}

function validLinuxFacts(state, value) {
  if (value === null) return state === 'absent' || state === 'parent-absent';
  if (state === 'directory') return validLinuxParentIdentity(value) || validLinuxServiceIdentity(value);
  if (state === 'symlink') {
    return plain(value) && exactKeys(value, ['kind', 'device', 'inode', 'mode', 'owner']) &&
      value.kind === 'linux-symlink-v1' && canonicalUint64(value.device) &&
      canonicalUint64(value.inode) && Number.isSafeInteger(value.mode) &&
      value.mode >= 0 && value.mode <= 0xffffffff && validUid(value.owner);
  }
  if (state !== 'file' || !plain(value) || !exactKeys(value, [
    'kind', 'device', 'inode', 'size', 'sha256', 'mode', 'owner', 'securitySha256',
  ])) return false;
  return value.kind === 'linux-file-v1' && canonicalUint64(value.device) &&
    canonicalUint64(value.inode) && Number.isSafeInteger(value.size) && value.size >= 0 &&
    isHex64(value.sha256) && Number.isSafeInteger(value.mode) && value.mode >= 0 &&
    value.mode <= 0xffffffff && validUid(value.owner) && isHex64(value.securitySha256);
}

function parseShowPid(value) {
  if (typeof value !== 'string' || !SHOW_PID.test(value)) return null;
  const pid = Number(value);
  return pid <= 0x7fffffff ? pid : null;
}

function parseExecTimestamp(value) {
  if (typeof value !== 'string' || value.length === 0) return null;
  const match = EXEC_TIMESTAMP.exec(value);
  if (!match) return null;
  const [, year, month, day, hour, minute, second] = match;
  return Date.UTC(+year, +month - 1, +day, +hour, +minute, +second);
}

function parseJournalCursor(stdout, operation, writes) {
  if (typeof stdout !== 'string' ||
      Buffer.byteLength(stdout, 'utf8') > LINUX_DRIVER_LIMITS.journalCursorBytes) {
    fail('SERVICE_IO_FAILED', operation, writes);
  }
  const lines = stdout.split('\n').filter((line) => line.length > 0);
  // An empty journal has no cursor.  This explicit baseline remains safe
  // because invocation, lineage, and boot checks prove the current run.
  if (lines.length === 0) return '';
  if (lines.length !== 1) fail('SERVICE_IO_FAILED', operation, writes);
  const match = CURSOR_LINE.exec(lines[0]);
  if (!match) fail('SERVICE_IO_FAILED', operation, writes);
  return match[1];
}

function bootFingerprint(bootId) {
  return canonicalJsonHash({ kind: 'linux-boot/v1', bootId });
}

function processEpochFingerprint(epoch) {
  // The epoch binds the exact root lineage only. Tree membership may grow
  // (children) without ending the epoch; tree fingerprints gate stop/force
  // CAS instead.
  return canonicalJsonHash({
    kind: 'linux-process-epoch/v1',
    pid: epoch.mainPid,
    startTime: epoch.mainStartTime,
    executable: epoch.executable,
    owner: epoch.owner,
  });
}

function platformEvidenceFingerprint(evidence) {
  return canonicalJsonHash({ kind: 'linux-platform-evidence/v1', ...evidence });
}

function unitBytesContainForbiddenDirective(bytes) {
  return bytes !== null && FORBIDDEN_UNIT_DIRECTIVE.test(bytes.toString('utf8'));
}

function linkAbsent(snapshot) {
  return snapshot !== null && snapshot !== undefined &&
    (snapshot.state === 'absent' || snapshot.state === 'parent-absent');
}

// The rendered proof-owned bytes carry exactly one release fingerprint
// comment; parsing it back binds a running/observed resource to the release
// it executes without ever embedding a transaction fingerprint (which would
// be a circular preimage).
const RELEASE_COMMENT = /^# gjc-remote-release: ([0-9a-f]{64})$/m;

function parseReleaseFingerprint(objects, component) {
  const file = component === 'bot' ? objects.botUnit : objects.dropin;
  if (file?.state !== 'file') return null;
  const match = RELEASE_COMMENT.exec(file.bytes.toString('utf8'));
  return match === null ? null : match[1];
}

function unitDirective(bytes, name, all = false) {
  if (!Buffer.isBuffer(bytes)) return all ? [] : null;
  const values = [];
  for (const line of bytes.toString('utf8').split('\n')) {
    if (line.startsWith(`${name}=`)) values.push(line.slice(name.length + 1));
  }
  return all ? values : values.at(-1) ?? null;
}

function managerExecArgv(value) {
  if (typeof value !== 'string' || value.length === 0) return null;
  let raw = value.trim();
  if (raw.startsWith('{') && raw.endsWith('}')) {
    const match = /(?:^|;)\s*argv\[\]=([^;]*?)(?:\s*;|$)/.exec(raw.slice(1, -1));
    if (!match) return null;
    raw = match[1].trim();
  }
  const argv = raw.split(/\s+/);
  return argv.length > 0 && argv.every((entry) => ARGV_ELEMENT.test(entry)) ? argv : null;
}

function normalizeSignal(value) {
  if (value === 'SIGTERM' || value === 'TERM' || value === '15') return 'SIGTERM';
  return null;
}

function normalizeUser(value, uid) {
  if (typeof value !== 'string' || !/^[A-Za-z_][A-Za-z0-9_.-]*$/.test(value) ||
      typeof uid !== 'string' || !/^(0|[1-9][0-9]*)$/.test(uid)) return null;
  return { account: value, uid };
}

function canonicalDependencies(value) {
  const list = showList(value);
  if (list.some((entry) => !UNIT_VALUE.test(entry))) return null;
  return [...new Set(list)].sort();
}

function canonicalEnvironment(value) {
  const list = showList(value);
  if (list.some((entry) => !/^[A-Za-z_][A-Za-z0-9_]*=[A-Za-z0-9_./:@+-]+$/.test(entry))) return null;
  return [...new Set(list)].sort();
}

function canonicalEnvironmentFiles(value) {
  if (typeof value !== 'string') return null;
  if (value.length === 0) return [];
  const records = [];
  // EnvironmentFiles is systemd's a(sb) property: each path is paired with
  // ignore_errors metadata. Optional files are not equivalent to required
  // files, so the metadata is parsed and required to be "no".
  const objectPattern = /\{\s*path=([^;\s]+)\s*;\s*ignore_errors=(yes|no)\s*;\s*\}/g;
  let match;
  while ((match = objectPattern.exec(value)) !== null) {
    records.push({ path: match[1], ignoreErrors: match[2] === 'yes' });
  }
  if (records.length === 0) {
    const displayPattern = /(?:^|\s)([^\s()]+)\s+\(ignore_errors=(yes|no)\)/g;
    while ((match = displayPattern.exec(value)) !== null) {
      records.push({ path: match[1], ignoreErrors: match[2] === 'yes' });
    }
  }
  if (records.length === 0) return null;
  const objectWire = records.map(({ path, ignoreErrors }) =>
    `{ path=${path} ; ignore_errors=${ignoreErrors ? 'yes' : 'no'} ; }`).join(' ');
  const displayWire = records.map(({ path, ignoreErrors }) =>
    `${path} (ignore_errors=${ignoreErrors ? 'yes' : 'no'})`).join(' ');
  if (value !== objectWire && value !== displayWire) return null;
  if (records.some(({ path, ignoreErrors }) =>
    ignoreErrors || !/^-?[A-Za-z0-9_./:@+-]+$/.test(path) || path.startsWith('-'))) return null;
  return [...new Set(records.map(({ path }) => path))].sort();
}

function canonicalDuration(value) {
  if (typeof value !== 'string' || !/^[0-9]+(?:us|ms|s|min|m|h|d)?$/.test(value)) return null;
  const match = /^(\d+)(us|ms|s|min|m|h|d)?$/.exec(value);
  const amount = BigInt(match[1]);
  const multiplier = {
    us: 1n, ms: 1_000n, s: 1_000_000n, min: 60_000_000n,
    m: 60_000_000n, h: 3_600_000_000n, d: 86_400_000_000n,
  }[match[2] ?? 'us'];
  const micros = amount * multiplier;
  return micros <= BigInt(Number.MAX_SAFE_INTEGER) ? Number(micros) : null;
}

function normalizeManagerPolicy(manager) {
  const user = normalizeUser(manager.User, manager.UID);
  const execStart = managerExecArgv(manager.ExecStart);
  const dependencies = {};
  for (const key of ['After', 'Wants', 'Before', 'Requires', 'Requisite', 'BindsTo', 'PartOf', 'Conflicts']) {
    dependencies[key] = canonicalDependencies(manager[key]);
    if (dependencies[key] === null) return null;
  }
  const environment = canonicalEnvironment(manager.Environment);
  const environmentFiles = canonicalEnvironmentFiles(manager.EnvironmentFiles);
  const dropInPaths = canonicalDependencies(manager.DropInPaths);
  const killSignal = normalizeSignal(manager.KillSignal);
  if (user === null || execStart === null || environment === null || environmentFiles === null ||
      dropInPaths === null || killSignal === null) return null;
  if (![manager.Type, manager.Slice, manager.WorkingDirectory, manager.ControlGroup,
    manager.FragmentPath, manager.DropInPaths, manager.Description, manager.SyslogIdentifier]
    .every((value) => typeof value === 'string')) return null;
  const restartUsec = canonicalDuration(manager.RestartUSec);
  const timeoutStopUsec = canonicalDuration(manager.TimeoutStopUSec);
  const startLimitIntervalUsec = canonicalDuration(manager.StartLimitIntervalUSec);
  if (!/^(0|[1-9][0-9]*)$/.test(manager.StartLimitBurst) ||
      restartUsec === null || timeoutStopUsec === null || startLimitIntervalUsec === null ||
      !/^[0-7]{3,4}$/.test(manager.UMask)) return null;
  return {
    Type: manager.Type,
    User: user.account,
    UID: user.uid,
    Slice: manager.Slice,
    ControlGroup: manager.ControlGroup,
    FragmentPath: manager.FragmentPath,
    DropInPaths: dropInPaths,
    EnvironmentFiles: environmentFiles,
    WorkingDirectory: manager.WorkingDirectory,
    Environment: environment,
    ExecStart: execStart,
    Restart: manager.Restart,
    RestartUSec: restartUsec,
    KillSignal: killSignal,
    KillMode: manager.KillMode,
    TimeoutStopUSec: timeoutStopUsec,
    UMask: manager.UMask,
    StartLimitIntervalUSec: startLimitIntervalUsec,
    StartLimitBurst: manager.StartLimitBurst,
    Description: manager.Description,
    SyslogIdentifier: manager.SyslogIdentifier,
    Conditions: manager.Conditions,
    Asserts: manager.Asserts,
    ConditionResult: manager.ConditionResult,
    AssertResult: manager.AssertResult,
    RefuseManualStart: manager.RefuseManualStart,
    NeedDaemonReload: manager.NeedDaemonReload,
    ...dependencies,
  };
}

function processFactsFingerprint(processes) {
  if (!Array.isArray(processes)) return null;
  const normalized = [];
  const pids = new Set();
  for (const process of processes) {
    if (!plain(process) || !exactKeys(process, PROCESS_FACTS_KEYS) ||
        !Number.isSafeInteger(process.pid) || process.pid < 1 || pids.has(process.pid) ||
        !Number.isSafeInteger(process.parentPid) || process.parentPid < 0 ||
        typeof process.startTime !== 'string' || process.startTime.length === 0 ||
        typeof process.executable !== 'string' || process.executable.length === 0 ||
        typeof process.owner !== 'string' || process.owner.length === 0 ||
        typeof process.state !== 'string' || process.state.length === 0 ||
        !Number.isSafeInteger(process.depth) || process.depth < 0 || process.depth > 64) return null;
    pids.add(process.pid);
    normalized.push({ ...process });
  }
  normalized.sort((left, right) => left.pid - right.pid);
  return canonicalJsonHash({ kind: 'linux-process-members/v2', members: normalized });
}

function cgroupMatchesTree(cgroup, tree, mainPid) {
  if (cgroupMemberFingerprint(cgroup) === null ||
      !exactKeys(tree, ['processes', 'treeFingerprint', 'processCount']) ||
      tree.processCount !== tree.processes.length || !isHex64(tree.treeFingerprint) ||
      tree.treeFingerprint !== cgroup.treeFingerprint ||
      processFactsFingerprint(cgroup.processes) !== processFactsFingerprint(tree.processes)) return false;
  const roots = cgroup.processes.filter((process) => process.depth === 0);
  const root = cgroup.processes.find((process) => process.pid === mainPid);
  // A cgroup receipt has one and only one root.  Accepting a second depth-0
  // member would allow a replacement tree to be smuggled through a PID-only
  // check even when the member digest happens to match.
  return roots.length === 1 && root !== undefined && root.depth === 0;
}

function effectiveUnitPolicy(names, objects, configuration, expectedOwner) {
  const instanceFile = names.component === 'bot' ? objects.botUnit : objects.dropin;
  const templateFile = names.component === 'daemon' ? objects.template : null;
  const unitBytes = instanceFile?.state === 'file' ? instanceFile.bytes : null;
  const templateBytes = templateFile?.state === 'file' ? templateFile.bytes : null;
  const directive = (name) => unitDirective(unitBytes, name) ?? unitDirective(templateBytes, name);
  const execStart = managerExecArgv(directive('ExecStart'));
  const account = names.component === 'bot' ? 'gjc-bot' : 'gjc-daemon';
  const uid = expectedOwner.startsWith('uid:') ? expectedOwner.slice(4) : '';
  const env = names.component === 'bot'
    ? [`CHANNELS_CONFIG=${configuration.channelsConfig}`, `HOME=${configuration.homeDirectory}`]
    : [`HOME=${configuration.homeDirectory}`];
  const environmentFile = names.component === 'bot'
    ? ['/etc/gjc-remote/bot.env']
    : [`/etc/gjc-remote/daemon-${names.serviceKey}.env`];
  return {
    Type: 'simple',
    User: account,
    UID: uid,
    Slice: SLICE_NAME,
    ControlGroup: names.controlGroup,
    FragmentPath: names.fragmentPath,
    DropInPaths: names.component === 'daemon' ? [names.dropinPath] : [],
    EnvironmentFiles: environmentFile,
    WorkingDirectory: configuration.workingDirectory,
    Environment: env,
    ExecStart: execStart,
    Restart: directive('Restart'),
    RestartUSec: canonicalDuration('10s'),
    KillSignal: 'SIGTERM',
    KillMode: 'control-group',
    TimeoutStopUSec: canonicalDuration('35s'),
    UMask: '0077',
    After: 'network-online.target',
    Wants: 'network-online.target',
    StartLimitIntervalUSec: canonicalDuration('600s'),
    StartLimitBurst: '5',
    Description: directive('Description'),
    SyslogIdentifier: (directive('SyslogIdentifier') ?? '').replaceAll('%i', names.serviceKey),
    Conditions: '',
    Asserts: '',
    ConditionResult: 'yes',
    AssertResult: 'yes',
    RefuseManualStart: 'no',
    NeedDaemonReload: 'no',
    ...Object.fromEntries(['After', 'Wants', 'Before', 'Requires', 'Requisite', 'BindsTo', 'PartOf', 'Conflicts']
      .map((key) => [key, canonicalDependencies(directive(key) ?? '')])),
  };
}

function loadedPolicyMismatch(manager, policy, loaded) {
  if (!loaded) return false;
  if (policy === null || policy.ExecStart === null || Object.values(policy).some((value) => value === null)) return true;
  const normalized = normalizeManagerPolicy(manager);
  if (normalized === null) return true;
  return Object.entries(policy).some(([key, expected]) => !sameJson(normalized[key], expected));
}

/**
 * Maps one observation onto the closed Linux platform-state templates. Every
 * template field must match exactly; anything else is drift (phase null).
 */
function evaluatePlatformState(names, objects, manager, policy) {
  const reasons = [];
  // Keep the manager schema closed.  Unknown values fail closed instead of
  // falling through to the absent/suppressed templates.
  if (!['loaded', 'not-found', 'masked'].includes(manager.LoadState) ||
      !['disabled', 'enabled', 'masked'].includes(manager.UnitFileState) ||
      !['inactive', 'active', 'failed'].includes(manager.ActiveState) ||
      !['dead', 'running'].includes(manager.SubState) ||
      !['', 'no', 'on-failure'].includes(manager.Restart) ||
      !['yes', 'no'].includes(manager.ConditionResult) ||
      !['yes', 'no'].includes(manager.AssertResult) ||
      typeof manager.Conditions !== 'string' ||
      typeof manager.Asserts !== 'string' ||
      !['yes', 'no'].includes(manager.RefuseManualStart) ||
      !['yes', 'no'].includes(manager.NeedDaemonReload) ||
      typeof manager.TriggeredBy !== 'string' ||
      typeof manager.WantedBy !== 'string' ||
      typeof manager.RequiredBy !== 'string') {
    return { phase: null, state: null, reasons: ['resource-drift'] };
  }
  const instanceFile = names.component === 'bot' ? objects.botUnit : objects.dropin;
  const unitBytes = instanceFile?.state === 'file' ? instanceFile.bytes : null;
  const instancePresent = names.component === 'bot'
    ? objects.botUnit?.state === 'file'
    : objects.dropin?.state === 'file';
  const linkOwned = objects.enablementLink?.state === 'symlink' &&
    objects.enablementLink.target === names.linkTarget;
  const linkPresent = objects.enablementLink?.state === 'symlink';
  const loadState = manager.LoadState;
  const loaded = loadState === 'loaded';
  if (loadedPolicyMismatch(manager, policy, loaded)) {
    return { phase: null, state: null, reasons: ['resource-drift'] };
  }
  const masked = loadState === 'masked' || manager.UnitFileState === 'masked';
  if (masked) reasons.push('mask-drift');
  if (loaded && !instancePresent) reasons.push('resource-drift');
  let unitFileState = 'absent';
  if (masked) unitFileState = 'masked';
  else if (manager.UnitFileState === 'enabled') unitFileState = 'enabled';
  else if (manager.UnitFileState === 'disabled') unitFileState = 'disabled';
  else if (manager.UnitFileState !== undefined && manager.UnitFileState !== '') {
    unitFileState = 'other';
  }
  if (loaded && linkPresent !== (unitFileState === 'enabled')) {
    reasons.push('activation-drift');
  }
  if (linkPresent && !linkOwned) reasons.push('activation-drift');
  const restartPolicy = !loaded ? 'none'
    : manager.Restart === 'no' || manager.Restart === 'on-failure' ? manager.Restart
      : 'other';
  if (restartPolicy === 'other') reasons.push('resource-drift');
  const triggeredBy = showList(manager.TriggeredBy);
  const wantedBy = showList(manager.WantedBy);
  const requiredBy = showList(manager.RequiredBy);
  const foreignInbound = wantedBy.filter((name) => name !== 'multi-user.target' || !linkOwned)
    .concat(requiredBy).length;
  const inboundActivatorCount = triggeredBy.length + foreignInbound;
  if (inboundActivatorCount !== 0) reasons.push('inbound-activator');
  const dropInPaths = showList(manager.DropInPaths);
  const dropinDrift = loaded && (names.component === 'bot'
    ? dropInPaths.length !== 0
    : dropInPaths.length !== 1 || dropInPaths[0] !== names.dropinPath);
  const fragmentDrift = loaded && manager.FragmentPath !== names.fragmentPath;
  if (dropinDrift || fragmentDrift) reasons.push('resource-drift');
  const conditionFailed = manager.ConditionResult === 'no' || manager.AssertResult === 'no';
  const forbiddenDirective = unitBytesContainForbiddenDirective(unitBytes);
  const hasStartBlockingCondition = conditionFailed || forbiddenDirective ||
    dropinDrift || fragmentDrift;
  if (conditionFailed || forbiddenDirective) reasons.push('false-condition');
  if (loaded && manager.NeedDaemonReload === 'yes') reasons.push('resource-drift');
  let activation = 'disabled-not-startable';
  if (loaded && !masked && inboundActivatorCount === 0 && !hasStartBlockingCondition) {
    if (unitFileState === 'enabled' && linkOwned) activation = 'enabled';
    else if (unitFileState === 'disabled' && !linkPresent) {
      activation = 'suppressed-controller-startable';
    }
  }
  const observed = {
    loaded,
    masked,
    unitFileState: loaded || masked ? unitFileState : 'absent',
    restartPolicy: loaded || masked ? restartPolicy : 'none',
    inboundActivatorCount,
    hasStartBlockingCondition,
    activation: loaded || masked ? activation : 'disabled-not-startable',
  };
  for (const phase of PHASES) {
    const template = buildServicePlatformState('linux', phase);
    if (template.loaded === observed.loaded &&
        template.masked === observed.masked &&
        template.unitFileState === observed.unitFileState &&
        template.restartPolicy === observed.restartPolicy &&
        template.inboundActivatorCount === observed.inboundActivatorCount &&
        template.hasStartBlockingCondition === observed.hasStartBlockingCondition &&
        template.activation === observed.activation) {
      return { phase, state: template, reasons: [] };
    }
  }
  return { phase: null, state: null, reasons: [...new Set(reasons)] };
}

export function createLinuxServiceDriver(options) {
  const operation = 'create_linux_service_driver';
  if (!exactKeys(options, ['native', 'session', 'locks', 'invoke', 'roles', 'configuration', 'clock', 'sleep', 'templates'])) {
    fail('SERVICE_INVALID', operation, 0);
  }
  const {
    native, session, locks, invoke, roles, configuration,
    clock, sleep, templates,
  } = options;
  if (typeof invoke !== 'function' ||
      (clock !== undefined && typeof clock !== 'function') ||
      (sleep !== undefined && typeof sleep !== 'function')) {
    fail('SERVICE_INVALID', operation, 0);
  }
  const nowMs = clock ?? (() => Date.now());
  const sleepMs = sleep ?? ((ms) => new Promise((resolve) => { setTimeout(resolve, ms); }));
  const suppliedTemplates = templates ?? loadLinuxServiceTemplates();
  const canonicalTemplates = loadLinuxServiceTemplates();
  if (!exactKeys(suppliedTemplates, ['botUnit', 'daemonTemplate']) ||
      !Buffer.isBuffer(suppliedTemplates.botUnit) || suppliedTemplates.botUnit.length === 0 ||
      !Buffer.isBuffer(suppliedTemplates.daemonTemplate) || suppliedTemplates.daemonTemplate.length === 0) {
    fail('SERVICE_INVALID', operation, 0);
  }
  if (!suppliedTemplates.botUnit.equals(canonicalTemplates.botUnit) ||
      !suppliedTemplates.daemonTemplate.equals(canonicalTemplates.daemonTemplate)) {
    fail('SERVICE_INVALID', operation, 0);
  }
  // Native callers may retain and mutate their input buffers after driver
  // construction.  Pin a private byte copy (and its source identity) so all
  // subsequent renders and fingerprints remain bound to construction-time
  // checked-in/template bytes.
  const unitTemplates = Object.freeze({
    botUnit: Buffer.from(suppliedTemplates.botUnit),
    daemonTemplate: Buffer.from(suppliedTemplates.daemonTemplate),
  });
  const templateSourceIdentity = sha256hex(Buffer.concat([
    unitTemplates.botUnit,
    unitTemplates.daemonTemplate,
  ]));
  if (session === null || typeof session !== 'object' || Array.isArray(session)) {
    fail('SERVICE_INVALID', operation, 0);
  }
  for (const method of SESSION_METHODS) {
    if (typeof session[method] !== 'function') fail('SERVICE_INVALID', operation, 0);
  }
  const component = session.component;
  const serviceKey = session.serviceKey;
  const architecture = session.architecture;
  if (session.platform !== 'linux' ||
      (architecture !== 'x64' && architecture !== 'arm64')) {
    fail('SERVICE_INVALID', operation, 0);
  }
  try {
    validateServiceKey(serviceKey, component);
  } catch {
    fail('SERVICE_INVALID', operation, 0);
  }
  try {
    validateServiceRoles(roles, 'linux');
  } catch {
    fail('SERVICE_INVALID', operation, 0);
  }
  if (!validateDriverConfiguration(configuration, component)) {
    fail('SERVICE_INVALID', operation, 0);
  }
  if (!exactKeys(locks, LOCK_KEYS) ||
      LOCK_KEYS.some((key) => locks[key] === null || typeof locks[key] !== 'object')) {
    fail('SERVICE_INVALID', operation, 0);
  }
  if (native === null || (typeof native !== 'object' && typeof native !== 'function')) {
    fail('SERVICE_INVALID', operation, 0);
  }
  const descriptors = Object.getOwnPropertyDescriptors(native);
  const captured = Object.create(null);
  for (const name of DRIVER_NATIVE) {
    const descriptor = descriptors[name];
    if (!descriptor || descriptor.get !== undefined || descriptor.set !== undefined ||
        !Object.hasOwn(descriptor, 'value') || typeof descriptor.value !== 'function') {
      fail('SERVICE_INVALID', operation, 0);
    }
    captured[name] = descriptor.value;
  }
  const nativeCalls = Object.freeze(captured);
  const names = objectNames(component, serviceKey);
  const templateFingerprint = component === 'daemon'
    ? linuxDaemonTemplateFingerprint(unitTemplates.daemonTemplate)
    : null;
  const expectedOwner = roles[component].value;
  let driverWrites = 0;
  // The raw startup epoch is retained only for the lifetime of this driver.
  // The durable receipt intentionally stores fingerprints, not process
  // identity fields; keeping this context lets the final activation boundary
  // compare those fields without widening the shared receipt schema.
  let startupContext = null;
  // Same-content replay is valid only for the exact physical object that
  // this transaction already observed. Bytes alone cannot distinguish a
  // deleted/recreated path, so retain the native identity/container/link
  // receipt for the lifetime of this driver.
  const objectIdentityReceipts = new Map();
  const receiptActionBindings = new Map();
  let activeReceiptDiscriminator = null;
  // Action observations collect candidate identities separately from the
  // retained pre-action receipts.  They are promoted only after the exact
  // postcondition has been observed and immediately before its journal edge.
  const pendingActionReceipts = new Map();
  let removalTombstones = new Map();
  // Action records carry no schema extension. Keep their discriminator in
  // this live controller session so a recreated controller cannot attribute
  // an action head to the wrong native call.
  const actionDiscriminators = new Map();

  function assertTemplateSourceIdentity(op) {
    const current = sha256hex(Buffer.concat([
      unitTemplates.botUnit,
      unitTemplates.daemonTemplate,
    ]));
    if (current !== templateSourceIdentity) fail('SERVICE_INVALID', op, driverWrites);
  }

  function nativeCall(name, ...args) {
    let value;
    try {
      value = Reflect.apply(nativeCalls[name], undefined, args);
    } catch (error) {
      const writes = validWrites(error?.writes) ? error.writes : 0;
      driverWrites += writes;
      const code = typeof error?.code === 'string' && LINUX_SERVICE_ERROR_CODES.includes(error.code)
        ? error.code
        : 'SERVICE_IO_FAILED';
      fail(code, typeof error?.operation === 'string' ? error.operation : name,
        driverWrites, error?.ambiguous === true || !validWrites(error?.writes));
    }
    if (value !== null && typeof value === 'object' && Object.hasOwn(value, 'writes')) {
      if (!validWrites(value.writes)) fail('SERVICE_INVALID', name, driverWrites, driverWrites > 0);
      driverWrites += value.writes;
    }
    return value;
  }

  function identityReceipt(snapshot) {
    if (!plain(snapshot) || snapshot.state === 'absent' || snapshot.state === 'parent-absent') return null;
    if (!validLinuxParentIdentity(snapshot.parentIdentity) ||
        !validLinuxContainerIdentity(snapshot.containerIdentity) ||
        !validLinuxFacts(snapshot.state, snapshot.facts)) return null;
    return canonicalJson({
      parentIdentity: snapshot.parentIdentity,
      containerIdentity: snapshot.containerIdentity,
      facts: snapshot.facts,
      target: snapshot.target,
    });
  }

  // A verified removal has an exact physical post-state even though the
  // object itself no longer carries an identity receipt.  Keep the tombstone
  // through the remainder of that operation so preflight can distinguish the
  // one object just removed from an unrelated disappearance or parent drift.
  function removalTombstone(snapshot) {
    return canonicalJson({
      objectKind: snapshot.objectKind,
      state: snapshot.state,
      parentIdentity: snapshot.parentIdentity,
      containerIdentity: snapshot.containerIdentity,
      bytes: snapshot.bytes,
      facts: snapshot.facts,
      target: snapshot.target,
    });
  }

  function requireIdentityReceipt(objectKind, snapshot, op) {
    const current = identityReceipt(snapshot);
    const recorded = objectIdentityReceipts.get(objectKind);
    const bound = receiptActionBindings.get(objectKind);
    if (current === null || recorded === undefined || current !== recorded ||
        (activeReceiptDiscriminator !== null && bound !== undefined &&
          bound !== activeReceiptDiscriminator)) {
      fail('SERVICE_MANUAL_CLEANUP', op, driverWrites, true, 'recreated-resource');
    }
  }

  // A receipt may be learned from an explicit prepared baseline or from the
  // exact postcondition of an action owned by this controller.  The native
  // post-write return value itself is never authority; promotion happens only
  // after the action's independent observation succeeds.
  function captureBaselineReceipt(objectKind, snapshot, discriminator = null) {
    if (linkAbsent(snapshot)) return;
    const receipt = identityReceipt(snapshot);
    if (receipt === null) return;
    if (!objectIdentityReceipts.has(objectKind)) {
      objectIdentityReceipts.set(objectKind, receipt);
      if (discriminator !== null) receiptActionBindings.set(objectKind, discriminator);
    }
  }

  function captureActionReceipt(objectKind, snapshot) {
    if (activeReceiptDiscriminator === null || linkAbsent(snapshot)) return;
    const receipt = identityReceipt(snapshot);
    if (receipt !== null) pendingActionReceipts.set(objectKind, receipt);
  }

  function promoteActionReceipts(discriminator) {
    for (const [objectKind, receipt] of pendingActionReceipts) {
      objectIdentityReceipts.set(objectKind, receipt);
      receiptActionBindings.set(objectKind, discriminator);
    }
    pendingActionReceipts.clear();
  }

  function clearRemovalReceipt(discriminator) {
    const removed = discriminator.match(/:remove:([a-z-]+)$/)?.[1];
    if (removed !== undefined) {
      objectIdentityReceipts.delete(removed);
      receiptActionBindings.delete(removed);
    }
  }


  function objectReceiptsPresent(objects, objectKeys) {
    const kinds = {
      botUnit: 'bot-unit',
      template: 'daemon-template',
      dropinDirectory: 'daemon-dropin-directory',
      dropin: 'daemon-dropin',
      enablementLink: 'enablement-link',
      enablementDirectory: 'enablement-directory',
    };
    return objectKeys.every((key) => {
      const snapshot = objects[key];
      if (snapshot === undefined || linkAbsent(snapshot)) return true;
      const current = identityReceipt(snapshot);
      return current !== null && objectIdentityReceipts.get(kinds[key]) === current;
    });
  }

  // A mutating boundary may rely only on the complete set of physical
  // receipts retained by this controller.  Bytes and paths are deliberately
  // insufficient: a same-content delete/recreate must stop before the next
  // systemd/native mutation.  The sole absence exception is the install
  // admission boundary (and the prepared transaction admission that precedes
  // it); suppressed trial/final-restart states intentionally have no
  // enablement link, so that optional object is checked only when present.
  function assertCompleteResourceReceipts(componentForAssertion, operationName,
    { capture = false, objects = null, replayTarget = null, resolvedRemoval = null,
      removalTombstones: tombstones = removalTombstones } = {}) {
    if (componentForAssertion !== component) fail('SERVICE_INVALID', operationName, driverWrites);
    const { latest } = journalState();
    if (capture && !(latest.phase === 'prepared' && latest.substep === 'none')) {
      fail('SERVICE_PENDING', operationName, driverWrites);
    }
    const source = objects ?? {};
    const activeAction = latest.substep === 'action'
      ? actionDiscriminators.get(latest.transactionFingerprint)
      : undefined;
    const activeTarget = actionTarget(activeAction);
    const targetOwnsObject = (objectKind) => {
      if (objectKind === 'enablement-link') return activeTarget === 'link-remove' || activeTarget === 'link-publish';
      if (objectKind === 'daemon-template') return activeTarget === 'template';
      if (objectKind === 'daemon-dropin-directory') {
        return activeTarget === 'dropin-directory-publish' || activeTarget === 'dropin-directory-remove';
      }
      if (objectKind === 'daemon-dropin') return activeTarget === 'dropin-publish' || activeTarget === 'dropin-remove';
      if (objectKind === 'bot-unit') return activeTarget === 'bot-unit-publish' || activeTarget === 'bot-unit-remove';
      return false;
    };
    const kinds = component === 'bot'
      ? [['botUnit', 'bot-unit']]
      : [['template', 'daemon-template'], ['dropinDirectory', 'daemon-dropin-directory'],
        ['dropin', 'daemon-dropin']];
    const installAdmission = replayTarget === null && (latest.phase === 'prepared' ||
      (latest.phase === 'transition-marker-intent' && latest.substep === 'observed' &&
        latest.operation === 'install' && latest.transition.expectedBeforeResourceFingerprint === null));
    for (const [key, objectKind] of kinds) {
      const snapshot = source[key];
      if (snapshot === undefined || linkAbsent(snapshot)) {
        if (installAdmission) continue;
        const exactRemoval = resolvedRemoval !== null &&
          resolvedRemoval.objectKind === objectKind && snapshot !== undefined &&
          removalTombstone(snapshot) === resolvedRemoval.tombstone;
        const retainedRemoval = tombstones.get(objectKind);
        const exactRetainedRemoval = retainedRemoval !== undefined && snapshot !== undefined &&
          removalTombstone(snapshot) === retainedRemoval;
        const exactDirectoryPublishGap = replayTarget === 'dropin-directory-publish' &&
          objectKind === 'daemon-dropin' && snapshot !== undefined &&
          linkAbsent(snapshot) && !objectIdentityReceipts.has(objectKind);
        const exactTemplatePublishGap = replayTarget === 'template' && component === 'daemon' &&
          (objectKind === 'daemon-dropin-directory' || objectKind === 'daemon-dropin') &&
          snapshot !== undefined && linkAbsent(snapshot) && !objectIdentityReceipts.has(objectKind);
        if (exactRemoval || exactRetainedRemoval || exactDirectoryPublishGap || exactTemplatePublishGap) continue;
        if (targetOwnsObject(objectKind) && snapshot !== undefined &&
            objectIdentityReceipts.has(objectKind) && activeTarget?.endsWith('-remove')) continue;
        fail('SERVICE_MANUAL_CLEANUP', operationName, driverWrites, true, 'recreated-resource');
      }
      if (capture) captureBaselineReceipt(objectKind, snapshot);
      if (targetOwnsObject(objectKind) && objectIdentityReceipts.has(objectKind) &&
          identityReceipt(snapshot) !== objectIdentityReceipts.get(objectKind)) continue;
      requireIdentityReceipt(objectKind, snapshot, operationName);
    }
    for (const [key, objectKind] of [
      ['enablementDirectory', 'enablement-directory'],
      ['enablementLink', 'enablement-link'],
    ]) {
      const snapshot = source[key];
      if (snapshot === undefined || linkAbsent(snapshot)) continue;
      if (capture) captureBaselineReceipt(objectKind, snapshot);
      if (targetOwnsObject(objectKind) && objectIdentityReceipts.has(objectKind) &&
          identityReceipt(snapshot) !== objectIdentityReceipts.get(objectKind)) continue;
      requireIdentityReceipt(objectKind, snapshot, operationName);
    }
  }

  function requireLiveIdentityReceipts(op) {
    if (objectIdentityReceipts.size === 0) {
      fail('SERVICE_MANUAL_CLEANUP', op, driverWrites, true, 'recreated-resource');
    }
  }

  function assertIntentionalAbsence(objectKind, phase, discriminator, op) {
    if (!objectIdentityReceipts.has(objectKind)) return;
    const latest = journalState().latest;
    const replay = latest.phase === phase && latest.substep === 'action' &&
      actionDiscriminators.get(latest.transactionFingerprint) === discriminator;
    if (!replay) fail('SERVICE_MANUAL_CLEANUP', op, driverWrites, true, 'resource-drift');
  }

  function runArgv(argv, op) {
    if (!Array.isArray(argv) || argv.length === 0 ||
        argv.some((element) => typeof element !== 'string' || element.length === 0 ||
          Buffer.byteLength(element, 'utf8') > LINUX_DRIVER_LIMITS.argvElementBytes ||
          !ARGV_ELEMENT.test(element))) {
      fail('SERVICE_INVALID', op, driverWrites);
    }
    let result;
    try {
      result = invoke(Object.freeze([...argv]));
    } catch {
      fail('SERVICE_IO_FAILED', op, driverWrites, true);
    }
    if (!exactKeys(result, ['code', 'stdout', 'stderr', 'writes']) ||
        !Number.isSafeInteger(result.code) || result.code < 0 || result.code > 255 ||
        typeof result.stdout !== 'string' || typeof result.stderr !== 'string' ||
        !validWrites(result.writes) ||
        Buffer.byteLength(result.stdout, 'utf8') > LINUX_DRIVER_LIMITS.showBytes ||
        Buffer.byteLength(result.stderr, 'utf8') > LINUX_DRIVER_LIMITS.showBytes) {
      fail('SERVICE_IO_FAILED', op, driverWrites, true);
    }
    driverWrites += result.writes;
    return result;
  }

  function openScope(key, access, op) {
    const result = nativeCall('open_linux_service_scope', key, access);
    if (!exactKeys(result, ['handle', 'parentIdentity', 'writes']) ||
        result.handle === null || typeof result.handle !== 'object' || result.writes !== 0 ||
        !validLinuxParentIdentity(result.parentIdentity)) {
      fail('SERVICE_INVALID', 'open_linux_service_scope', driverWrites, true);
    }
    return result.handle;
  }

  function closeScope(handle) {
    try {
      nativeCall('close_service_handle', handle);
    } catch { /* scope close failure never masks the primary failure */ }
  }

  function readObject(scope, objectKind, op) {
    const result = nativeCall('read_linux_service_object', scope, objectKind);
    if (!exactKeys(result, ['snapshot', 'writes']) || result.writes !== 0 ||
        !exactKeys(result.snapshot, SNAPSHOT_KEYS) ||
        result.snapshot.objectKind !== objectKind ||
        !OBJECT_STATES.has(result.snapshot.state) ||
        (result.snapshot.state === 'file' && !Buffer.isBuffer(result.snapshot.bytes)) ||
        (result.snapshot.state !== 'file' && result.snapshot.bytes !== null) ||
        (result.snapshot.state === 'symlink' && typeof result.snapshot.target !== 'string') ||
        !validLinuxParentIdentity(result.snapshot.parentIdentity) ||
        !validLinuxContainerIdentity(result.snapshot.containerIdentity) ||
        !validLinuxFacts(result.snapshot.state, result.snapshot.facts) ||
        (result.snapshot.state !== 'symlink' && result.snapshot.target !== null)) {
      fail('SERVICE_INVALID', op, driverWrites, true);
    }
    if (result.snapshot.state === 'symlink' && objectKind === 'enablement-link' &&
        result.snapshot.target !== names.linkTarget) {
      // A foreign enablement target is inbound-activation drift and is never
      // silently removed or adopted.
      fail('SERVICE_MANUAL_CLEANUP', op, driverWrites, true, 'activation-drift');
    }
    captureActionReceipt(objectKind, result.snapshot);
    if (activeReceiptDiscriminator !== null &&
        activeReceiptDiscriminator.match(/:remove:[a-z-]+$/) && linkAbsent(result.snapshot)) {
      removalTombstones.set(objectKind, removalTombstone(result.snapshot));
    }
    return result.snapshot;
  }

  function lockFor(objectKind) {
    return objectKind === 'daemon-template' || objectKind === 'enablement-directory'
      ? locks.sharedTemplate
      : locks.serviceKey;
  }

  function publishObject(scope, objectKind, bytes, expected, op) {
    const result = nativeCall(
      'publish_linux_service_object', scope, objectKind, bytes, expected, lockFor(objectKind),
    );
    if (!exactKeys(result, ['snapshot', 'writes']) || result.writes < 1) {
      fail('SERVICE_INVALID', op, driverWrites, true);
    }
    // Do not promote the native post-write snapshot to an identity receipt;
    // actionMutation promotes only an independently observed postcondition.
    return result.snapshot;
  }

  function removeObject(scope, objectKind, expected, op) {
    // Removal is authorized only by the live receipt captured for this exact
    // physical object.  A same-content replacement at the same path is not a
    // replay of the current session and must never be deleted.
    requireIdentityReceipt(objectKind, expected, op);
    const result = nativeCall(
      'remove_linux_service_object', scope, objectKind, expected, lockFor(objectKind),
    );
    if (!exactKeys(result, ['snapshot', 'writes']) || result.writes < 1 ||
        (result.snapshot.state !== 'absent' && result.snapshot.state !== 'parent-absent')) {
      fail('SERVICE_INVALID', op, driverWrites, true);
    }
    return result.snapshot;
  }

  function showUnit(unitName, op) {
    const result = runArgv(
      [SYSTEMCTL, 'show', unitName, `--property=${SHOW_PROPERTIES.join(',')}`],
      op,
    );
    if (result.code !== 0 || result.writes !== 0) {
      fail('SERVICE_IO_FAILED', op, driverWrites, true);
    }
    return parseShowOutput(result.stdout, op, driverWrites);
  }

  function daemonReload(op) {
    const result = runArgv([SYSTEMCTL, 'daemon-reload'], op);
    if (result.code !== 0) fail('SERVICE_IO_FAILED', op, driverWrites, true);
  }

  function journalCursor(unitName, op) {
    assertNoPendingTail(op);
    const result = runArgv(
      [JOURNALCTL, '-u', unitName, '-b', '-n', '0', '--quiet', '--show-cursor'],
      op,
    );
    if (result.code !== 0 || result.writes !== 0) {
      fail('SERVICE_IO_FAILED', op, driverWrites, true);
    }
    return parseJournalCursor(result.stdout, op, driverWrites);
  }

  function journalState() {
    const journal = session.readJournal();
    const latest = journal.entries.at(-1);
    if (!latest) fail('SERVICE_PENDING', 'read_service_journal', driverWrites);
    return { journal, latest };
  }

  function assertNoPendingTail(op) {
    const journal = session.readJournal();
    if (!plain(journal) || !Array.isArray(journal.entries) ||
        !Object.hasOwn(journal, 'pending')) {
      fail('SERVICE_INVALID', 'read_service_journal', driverWrites, true);
    }
    if (journal.pending !== null) fail('SERVICE_PENDING', op, driverWrites);
  }

  function assertJournalTransition(previous, phase, substep, op) {
    const previousIndex = SERVICE_TRANSACTION_PHASES.indexOf(previous.phase);
    const nextIndex = SERVICE_TRANSACTION_PHASES.indexOf(phase);
    const lateStop = phase === 'stopping' && substep === 'intent' &&
      LATE_STOP_PHASES.has(previous.phase) &&
      (previous.substep === 'observed' ||
        (previous.phase === 'starting' && previous.substep === 'intent'));
    if (previousIndex < 0 || nextIndex < 0 || (nextIndex < previousIndex && !lateStop)) {
      fail('SERVICE_PENDING', op, driverWrites);
    }
    if (previous.phase !== phase) return;
    if (phase === 'prepared') {
      if (substep !== 'none') fail('SERVICE_PENDING', op, driverWrites);
      return;
    }
    const order = { intent: 0, action: 1, observed: 2 };
    if (!Object.hasOwn(order, previous.substep) || !Object.hasOwn(order, substep)) {
      fail('SERVICE_PENDING', op, driverWrites);
    }
    // Recovery intentionally re-enters an observed phase at intent. Repeated
    // action/observed records are also legal replay edges. Other backward
    // substep transitions are rejected before any native mutation.
    if (substep === previous.substep || (previous.substep === 'observed' && substep === 'intent')) return;
    if (order[substep] < order[previous.substep]) fail('SERVICE_PENDING', op, driverWrites);
  }

  function journalAppend(phase, substep) {
    const op = 'append_service_journal';
    const { journal, latest } = journalState();
    if (journal.pending !== null) {
      // A crash between the journal entry write and the head write completes
      // only by replaying the byte-identical record.
      if (journal.pending.phase !== phase || journal.pending.substep !== substep) {
        fail('SERVICE_PENDING', op, driverWrites);
      }
      const committed = journal.entries.at(-2);
      if (!committed) fail('SERVICE_PENDING', op, driverWrites);
      assertJournalTransition(committed, phase, substep, op);
      let replay;
      try {
        replay = buildServiceTransaction({
          ...committed,
          phase,
          substep,
          previousJournalFingerprint: committed.transactionFingerprint,
        });
      } catch {
        fail('SERVICE_INVALID', op, driverWrites);
      }
      if (!sameJson(replay, journal.pending)) fail('SERVICE_PENDING', op, driverWrites);
      session.appendJournal(replay);
      return replay;
    }
    assertJournalTransition(latest, phase, substep, op);
    let record;
    try {
      record = buildServiceTransaction({
        ...latest,
        phase,
        substep,
        previousJournalFingerprint: latest.transactionFingerprint,
      });
    } catch {
      fail('SERVICE_INVALID', op, driverWrites);
    }
    session.appendJournal(record);
    return record;
  }

  // Every mutating OS call has its own durable edge.  The action record is
  // written before the call, then the exact post-state is read before the
  // observed record is committed.  On restart an action head is reconciled
  // from that post-state; a call is replayed only when the post-state is not
  // present.  Keeping this boundary at one-call granularity prevents a
  // grouped native mutation from becoming an unverifiable hybrid.
  function actionMutation(phase, op, mutate, observe, discriminator = `${phase}:${op}`) {
    let latest = journalState().latest;
    const replaying = latest.phase === phase && latest.substep === 'action';
    if (replaying && actionDiscriminators.get(latest.transactionFingerprint) !== discriminator) {
      fail('SERVICE_PENDING', op, driverWrites);
    }
    if (!(latest.phase === phase && (latest.substep === 'intent' || latest.substep === 'action'))) {
      journalAppend(phase, 'intent');
      latest = journalState().latest;
    }
    if (latest.substep === 'intent') {
      journalAppend(phase, 'action');
      latest = journalState().latest;
      actionDiscriminators.set(latest.transactionFingerprint, discriminator);
    }
    // A completed call may have been interrupted before its observation was
    // journaled.  Reconcile that exact state without issuing a second call.
    let observed = false;
    pendingActionReceipts.clear();
    if (replaying) {
      activeReceiptDiscriminator = discriminator;
      try {
        observed = observe();
      } finally {
        activeReceiptDiscriminator = null;
      }
    }
    if (replaying && observed) {
      promoteActionReceipts(discriminator);
      journalAppend(phase, 'observed');
      clearRemovalReceipt(discriminator);
      return false;
    }
    pendingActionReceipts.clear();
    mutate();
    activeReceiptDiscriminator = discriminator;
    try {
      observed = observe();
    } finally {
      activeReceiptDiscriminator = null;
    }
    if (!observed) fail('SERVICE_MANUAL_CLEANUP', op, driverWrites, true, 'resource-drift');
    promoteActionReceipts(discriminator);
    journalAppend(phase, 'observed');
    clearRemovalReceipt(discriminator);
    return true;
  }

  function reconcilePendingAction(phase, op, observe, discriminator = `${phase}:${op}`) {
    const latest = journalState().latest;
    if (latest.phase === phase && latest.substep === 'action') {
      actionMutation(phase, op, () => {}, observe, discriminator);
      return true;
    }
    return false;
  }

  // Journal action records deliberately omit the discriminator.  It is kept
  // only in this controller, so inspect and validate the exact target before
  // opening a native scope.  A broad phase match is unsafe: a pending link
  // edge must never be replayed as a template, resource, or reload edge.
  function actionTarget(discriminator) {
    if (typeof discriminator !== 'string' || discriminator.length === 0) return null;
    if (discriminator.endsWith(':remove:enablement-link')) return 'link-remove';
    if (discriminator.endsWith(':publish:enablement-link')) return 'link-publish';
    if (discriminator.endsWith(':publish:daemon-dropin-directory')) return 'dropin-directory-publish';
    if (discriminator.endsWith(':remove:daemon-dropin-directory')) return 'dropin-directory-remove';
    if (discriminator.endsWith(':publish:daemon-dropin')) return 'dropin-publish';
    if (discriminator.endsWith(':remove:daemon-dropin')) return 'dropin-remove';
    if (discriminator.endsWith(':publish:bot-unit')) return 'bot-unit-publish';
    if (discriminator.endsWith(':remove:bot-unit')) return 'bot-unit-remove';
    if (discriminator.endsWith(':daemon-reload:arm')) return 'reload-arm';
    if (discriminator.endsWith(':daemon-reload:enable')) return 'reload-enable';
    if (discriminator.endsWith(':daemon-reload')) return 'reload';
    if (discriminator.endsWith(':template')) return 'template';
    return null;
  }

  function pendingAction(op, allowedTargets) {
    const { latest } = journalState();
    if (latest.substep !== 'action') return null;
    const discriminator = actionDiscriminators.get(latest.transactionFingerprint);
    if (typeof discriminator !== 'string' || discriminator.length === 0) {
      fail('SERVICE_MANUAL_CLEANUP', op, driverWrites, true, 'recreated-resource');
    }
    const target = actionTarget(discriminator);
    if (target === null || !allowedTargets.has(target)) fail('SERVICE_PENDING', op, driverWrites);
    return Object.freeze({ discriminator, target });
  }

  // Resolve one and only one pending action before the operation's ordinary
  // resource/CAS helpers run.  The postcondition read is the authority for a
  // replay; the native return value is never adopted directly.
  function dispatchPendingAction(scopes, phase, op, pending, resolution = null) {
    if (pending === null) return null;
    const { discriminator, target } = pending;
    const observeObject = (scope, objectKind, predicate) => actionMutation(
      phase, op, () => {}, () => {
        const snapshot = readObject(scope, objectKind, op);
        const observed = predicate(snapshot);
        if (observed && resolution !== null && target.endsWith('-remove')) {
          resolution.value = Object.freeze({
            objectKind,
            tombstone: removalTombstone(snapshot),
          });
        }
        return observed;
      }, discriminator,
    );
    switch (target) {
      case 'link-remove':
        observeObject(scopes.instanceScope, 'enablement-link', (snapshot) => linkAbsent(snapshot));
        break;
      case 'link-publish':
        observeObject(scopes.instanceScope, 'enablement-link', (snapshot) =>
          snapshot.state === 'symlink' && snapshot.target === names.linkTarget);
        break;
      case 'template':
        observeObject(scopes.sharedScope, 'daemon-template', (snapshot) =>
          snapshot.state === 'file' && snapshot.bytes.equals(unitTemplates.daemonTemplate));
        break;
      case 'dropin-directory-publish':
        observeObject(scopes.instanceScope, 'daemon-dropin-directory', (snapshot) =>
          snapshot.state === 'directory');
        break;
      case 'dropin-directory-remove':
        observeObject(scopes.instanceScope, 'daemon-dropin-directory', (snapshot) =>
          linkAbsent(snapshot));
        break;
      case 'dropin-publish':
      case 'bot-unit-publish':
        // The exact bytes are checked again by the fixed helper after this
        // edge is resolved; this read only establishes the action post-state.
        observeObject(scopes.instanceScope,
          target === 'dropin-publish' ? 'daemon-dropin' : 'bot-unit',
          (snapshot) => snapshot.state === 'file');
        break;
      case 'dropin-remove':
      case 'bot-unit-remove':
        observeObject(scopes.instanceScope,
          target === 'dropin-remove' ? 'daemon-dropin' : 'bot-unit',
          (snapshot) => linkAbsent(snapshot));
        break;
      case 'reload':
      case 'reload-arm':
      case 'reload-enable':
        actionMutation(phase, op, () => {}, () => showUnit(names.unitName, op).NeedDaemonReload === 'no', discriminator);
        break;
      default:
        fail('SERVICE_PENDING', op, driverWrites);
    }
    return target;
  }


  function assertHead(op, allowed, discriminatorMatcher = null) {
    const { journal, latest } = journalState();
    if (journal.pending !== null) fail('SERVICE_PENDING', op, driverWrites);
    const ok = allowed.some((entry) => entry.phase === latest.phase &&
      (entry.substep === undefined || entry.substep === latest.substep));
    if (!ok) fail('SERVICE_PENDING', op, driverWrites);
    if (latest.substep === 'action') {
      // Journal records intentionally carry no operation discriminator.  A
      // fresh controller therefore cannot safely replay an action edge: it
      // must refuse before snapshot/probe/scope/native reads.  The live
      // controller's discriminator is the only authority for this boundary.
      const discriminator = actionDiscriminators.get(latest.transactionFingerprint);
      if (typeof discriminator !== 'string' || discriminator.length === 0) {
        fail('SERVICE_MANUAL_CLEANUP', op, driverWrites, true, 'recreated-resource');
      }
      if (discriminatorMatcher !== null && !discriminatorMatcher(discriminator)) {
        fail('SERVICE_PENDING', op, driverWrites);
      }
    }
    return latest;
  }

  function assertActionReplayGate(op) {
    const { journal, latest } = journalState();
    if (journal.pending !== null) fail('SERVICE_PENDING', op, driverWrites);
    if (latest.substep !== 'action') return latest;
    const discriminator = actionDiscriminators.get(latest.transactionFingerprint);
    if (typeof discriminator !== 'string' || discriminator.length === 0) {
      fail('SERVICE_MANUAL_CLEANUP', op, driverWrites, true, 'recreated-resource');
    }
    return latest;
  }

  function withScopes(access, op, fn) {
    assertNoPendingTail(op);
    const instanceScope = openScope(serviceKey, access, op);
    let sharedScope = null;
    try {
      sharedScope = openScope(null, access, op);
      return fn({ instanceScope, sharedScope });
    } finally {
      if (sharedScope !== null) closeScope(sharedScope);
      closeScope(instanceScope);
    }
  }

  function readAllObjects(scopes, op, capture = false) {
    const objects = {
      botUnit: null,
      template: null,
      dropinDirectory: null,
      dropin: null,
      enablementLink: null,
      enablementDirectory: null,
    };
    if (component === 'bot') {
      objects.botUnit = readObject(scopes.instanceScope, 'bot-unit', op);
    } else {
      objects.template = readObject(scopes.sharedScope, 'daemon-template', op);
      objects.dropinDirectory = readObject(scopes.instanceScope, 'daemon-dropin-directory', op);
      objects.dropin = readObject(scopes.instanceScope, 'daemon-dropin', op);
    }
    objects.enablementLink = readObject(scopes.instanceScope, 'enablement-link', op);
    objects.enablementDirectory = readObject(scopes.sharedScope, 'enablement-directory', op);
    if (capture) {
      captureBaselineReceipt('bot-unit', objects.botUnit);
      captureBaselineReceipt('daemon-template', objects.template);
      captureBaselineReceipt('daemon-dropin-directory', objects.dropinDirectory);
      captureBaselineReceipt('daemon-dropin', objects.dropin);
      captureBaselineReceipt('enablement-link', objects.enablementLink);
      captureBaselineReceipt('enablement-directory', objects.enablementDirectory);
    }
    return objects;
  }

  function observedDescriptor(objects) {
    const link = objects.enablementLink?.state === 'symlink' &&
      objects.enablementLink.target === names.linkTarget ? 'owned' : 'absent';
    return {
      kind: 'linux-service-resource/v1',
      component,
      serviceKey,
      botUnitSha256: objects.botUnit?.state === 'file' ? sha256hex(objects.botUnit.bytes) : null,
      templateSha256: objects.template?.state === 'file' ? sha256hex(objects.template.bytes) : null,
      dropinSha256: objects.dropin?.state === 'file' ? sha256hex(objects.dropin.bytes) : null,
      enablementLink: link,
    };
  }

  // Resolve the resource authority from the durable transaction, not from a
  // caller-supplied hash.  Callers may only confirm the already-resolved
  // state; they can never steer stop/remove/final/recovery onto another
  // fingerprint.  `phase` names the linearization boundary being checked.
  function transactionResourcePredicate(transaction, phase, observedFingerprint,
    callerExpectedFingerprint = undefined, derivedExpectedFingerprint = undefined) {
    if (!plain(transaction) || !plain(transaction.transition)) return false;
    const transition = transaction.transition;
    const declared = [
      transition.platformResourceFingerprint,
      transition.expectedBeforeResourceFingerprint,
      transition.expectedAfterResourceFingerprint,
    ];
    if (declared.some((value) => value !== null && !isHex64(value))) return false;
    const absent = transition.expectedBeforeResourceFingerprint === null;
    let allowed;
    switch (phase) {
      case 'transition-marker-intent':
        allowed = absent ? [null] : [transition.expectedBeforeResourceFingerprint];
        break;
      case 'resource-published':
      case 'trial':
      case 'stopping':
        allowed = [transition.platformResourceFingerprint];
        break;
      case 'resource-removed':
        allowed = [transition.platformResourceFingerprint, transition.expectedBeforeResourceFingerprint,
          transition.expectedAfterResourceFingerprint];
        break;
      case 'final':
      case 'activation-observed':
      case 'recovery':
        allowed = [transition.expectedAfterResourceFingerprint, transition.expectedBeforeResourceFingerprint,
          transition.platformResourceFingerprint];
        break;
      default:
        return false;
    }
    if (callerExpectedFingerprint !== undefined && callerExpectedFingerprint !== null &&
        callerExpectedFingerprint !== observedFingerprint) return false;
    if (derivedExpectedFingerprint !== undefined) allowed.push(derivedExpectedFingerprint);
    return allowed.includes(observedFingerprint);
  }

  function expectedDescriptor(bytes, enablementLink) {
    return {
      kind: 'linux-service-resource/v1',
      component,
      serviceKey,
      botUnitSha256: component === 'bot' ? sha256hex(bytes.unit) : null,
      templateSha256: component === 'daemon' ? sha256hex(bytes.template) : null,
      dropinSha256: component === 'daemon' ? sha256hex(bytes.dropin) : null,
      enablementLink,
    };
  }

  function isAbsentResourceDescriptor(descriptor) {
    return descriptor.botUnitSha256 === null && descriptor.templateSha256 === null &&
      descriptor.dropinSha256 === null && descriptor.enablementLink === 'absent';
  }

  function allDeclaredObjectsAbsent(objects) {
    const keys = component === 'bot'
      ? ['botUnit', 'enablementLink', 'enablementDirectory']
      : ['template', 'dropinDirectory', 'dropin', 'enablementLink', 'enablementDirectory'];
    return keys.every((key) => objects[key] === null || linkAbsent(objects[key]));
  }

  function assertTransactionPreState(transaction, phase, release, expectedCurrentSha256,
    objects, op, replayTarget = null) {
    const descriptor = observedDescriptor(objects);
    const marker = parseReleaseFingerprint(objects, component);
    const transition = transaction.transition;
    if (replayTarget === 'link-remove') {
      // The link edge is independently replayed before the primary resource
      // replacement.  Its exact intermediate CAS is the old primary bytes
      // and marker with only the owned enablement link absent.
      const currentBytes = component === 'bot' ? objects.botUnit?.bytes : objects.dropin?.bytes;
      const oldDescriptor = { ...descriptor, enablementLink: 'owned' };
      if (transition.expectedBeforeResourceFingerprint === null ||
          expectedCurrentSha256 === null ||
          !Buffer.isBuffer(currentBytes) || sha256hex(currentBytes) !== expectedCurrentSha256 ||
          marker !== transaction.old.applicationManifestFingerprint ||
          linuxServiceResourceFingerprint(oldDescriptor) !==
            transition.expectedBeforeResourceFingerprint) {
        fail('SERVICE_STALE', op, driverWrites, false, 'resource-drift');
      }
      return;
    }
    if (replayTarget === 'dropin-directory-publish') {
      // Directory creation precedes the drop-in publish on install.  A crash
      // at this edge is valid only with the invariant template and exact
      // directory present, the primary drop-in still absent, and no link.
      if (component !== 'daemon' || transition.expectedBeforeResourceFingerprint !== null ||
          descriptor.templateSha256 !== templateFingerprint || descriptor.dropinSha256 !== null ||
          descriptor.enablementLink !== 'absent' || expectedCurrentSha256 !== null ||
          objects.dropinDirectory?.state !== 'directory') {
        fail('SERVICE_STALE', op, driverWrites, false, 'resource-drift');
      }
      return;
    }
    // A replayed primary replacement has already crossed the old-byte CAS.
    // Re-evaluate the fresh descriptor against the journal's platform target,
    // not the stale caller hash that authorized the pre-replacement bytes.
    if (replayTarget === 'bot-unit-publish' || replayTarget === 'dropin-publish' ||
        replayTarget === 'reload' || replayTarget === 'reload-arm') {
      const fingerprint = linuxServiceResourceFingerprint(descriptor);
      if (!transactionResourcePredicate(transaction, 'resource-published', fingerprint, undefined) ||
          marker !== release.applicationManifestFingerprint) {
        fail('SERVICE_STALE', op, driverWrites, false, 'resource-drift');
      }
      return;
    }
    if (replayTarget === 'template') {
      // A template publish is only replayable at install admission.  An
      // absent template during an update would imply a hybrid shared/object
      // graph and remains a manual cleanup condition.
      if (component !== 'daemon' || transition.expectedBeforeResourceFingerprint !== null ||
          descriptor.templateSha256 !== templateFingerprint || descriptor.dropinSha256 !== null ||
          descriptor.enablementLink !== 'absent' || expectedCurrentSha256 !== null) {
        fail('SERVICE_STALE', op, driverWrites, false, 'resource-drift');
      }
      return;
    }
    if (phase === 'transition-marker-intent') {
      const observed = isAbsentResourceDescriptor(descriptor) ? null :
        linuxServiceResourceFingerprint(descriptor);
      if (!transactionResourcePredicate(transaction, phase, observed, undefined)) {
        fail('SERVICE_STALE', op, driverWrites, false,
          observed === null ? 'absent-expected' : 'resource-drift');
      }
      if (transition.expectedBeforeResourceFingerprint === null) {
        // Only an install-declared absence may use a null CAS.  A caller hash
        // is not authority for changing that transaction-bound pre-state.
        if (!isAbsentResourceDescriptor(descriptor) || !allDeclaredObjectsAbsent(objects) ||
            expectedCurrentSha256 !== null) {
          fail('SERVICE_STALE', op, driverWrites, false, 'absent-expected');
        }
      } else {
        if (linuxServiceResourceFingerprint(descriptor) !== transition.expectedBeforeResourceFingerprint ||
            marker !== transaction.old.applicationManifestFingerprint ||
            expectedCurrentSha256 === null) {
          fail('SERVICE_STALE', op, driverWrites, false, 'resource-drift');
        }
      }
    } else if (phase === 'resource-published') {
      if (!transactionResourcePredicate(transaction, phase,
        linuxServiceResourceFingerprint(descriptor), undefined)) {
        fail('SERVICE_STALE', op, driverWrites, false, 'resource-drift');
      }
      if (marker !== release.applicationManifestFingerprint || expectedCurrentSha256 !== null) {
        fail('SERVICE_STALE', op, driverWrites, false, 'resource-drift');
      }
    }
    const currentBytes = component === 'bot' ? objects.botUnit?.bytes : objects.dropin?.bytes;
    if (expectedCurrentSha256 !== null &&
        (!Buffer.isBuffer(currentBytes) || sha256hex(currentBytes) !== expectedCurrentSha256)) {
      fail('SERVICE_STALE', op, driverWrites, false, 'resource-drift');
    }
  }

  function probeWith(op, capture = false) {
    // This is deliberately before withScopes/snapshotSiblings and before the
    // first native read.  A fresh controller must never turn an action head
    // into an exploratory probe.
    assertActionReplayGate(op);
    return withScopes('read-existing', op, (scopes) => {
      // Mutating/recovery paths must never mint authority from a fresh
      // controller's first read.  Only an explicitly trusted baseline probe
      // (the initial controller observation) may seed receipts.
      const objects = readAllObjects(scopes, op, capture);
      const manager = showUnit(names.unitName, op);
      const bootId = nativeCall('read_boot_id');
      if (typeof bootId !== 'string' || !BOOT_ID.test(bootId)) {
        fail('SERVICE_IO_FAILED', 'read_boot_id', driverWrites, true);
      }
      const evaluation = evaluatePlatformState(
        names,
        objects,
        manager,
        effectiveUnitPolicy(names, objects, configuration, expectedOwner),
      );
      const descriptor = observedDescriptor(objects);
      return freezeDeep({
        bootId,
        objects,
        manager,
        platformState: evaluation.state,
        platformPhase: evaluation.phase,
        driftReasons: Object.freeze([...evaluation.reasons]),
        resourceFingerprint: linuxServiceResourceFingerprint(descriptor),
        resourceDescriptor: descriptor,
      });
    });
  }

  function renderFor(restart, release, transaction, op) {
    assertTemplateSourceIdentity(op);
    const declared = new Set(
      [transaction.candidate.applicationManifestFingerprint, transaction.old.applicationManifestFingerprint]
        .filter((value) => value !== null),
    );
    if (!declared.has(release.applicationManifestFingerprint)) {
      fail('SERVICE_INVALID', op, driverWrites);
    }
    const input = {
      configuration,
      entrypointPath: release.entrypointPath,
      restart,
      releaseFingerprint: release.applicationManifestFingerprint,
    };
    try {
      return component === 'bot'
        ? { unit: renderLinuxBotUnit(unitTemplates, input) }
        : { dropin: renderLinuxDaemonDropin(input) };
    } catch (error) {
      if (error?.name === 'ServiceLinuxError') {
        fail(error.code, op, driverWrites, error.ambiguous, error.reason);
      }
      throw error;
    }
  }

  function verifyExactState(observation, expectedPhase, declaredFingerprint, op) {
    if (observation.platformPhase === null) {
      fail('SERVICE_MANUAL_CLEANUP', op, driverWrites, true,
        observation.driftReasons[0] ?? 'resource-drift');
    }
    if (observation.platformPhase !== expectedPhase) {
      // A clean but different closed phase is a declared before/after
      // counterpart for replay, never an adoptable state.
      fail('SERVICE_STALE', op, driverWrites, false, 'resource-drift');
    }
    if (declaredFingerprint !== undefined &&
        observation.resourceFingerprint !== declaredFingerprint) {
      fail('SERVICE_MANUAL_CLEANUP', op, driverWrites, true, 'resource-drift');
    }
  }

  function validateSiblings(siblings, op) {
    if (!Array.isArray(siblings)) fail('SERVICE_INVALID', op, driverWrites);
    const seen = new Set();
    for (const sibling of siblings) {
      if (!exactKeys(sibling, ['serviceKey'])) fail('SERVICE_INVALID', op, driverWrites);
      try {
        validateServiceKey(sibling.serviceKey, 'daemon');
      } catch {
        fail('SERVICE_INVALID', op, driverWrites);
      }
      if (sibling.serviceKey === serviceKey || seen.has(sibling.serviceKey)) {
        fail('SERVICE_INVALID', op, driverWrites);
      }
      seen.add(sibling.serviceKey);
    }
    return siblings;
  }

  function snapshotSiblings(siblings, op) {
    const snapshot = new Map();
    for (const sibling of siblings) {
      const siblingNames = objectNames('daemon', sibling.serviceKey);
      const scope = openScope(sibling.serviceKey, 'read-existing', op);
      try {
        const dropin = readObject(scope, 'daemon-dropin', op);
        const manager = showUnit(siblingNames.unitName, op);
        const stable = Object.create(null);
        for (const key of SIBLING_STABLE_KEYS) stable[key] = manager[key] ?? '';
        snapshot.set(sibling.serviceKey, freezeDeep({
          dropinSha256: dropin.state === 'file' ? sha256hex(dropin.bytes) : null,
          manager: stable,
        }));
      } finally {
        closeScope(scope);
      }
    }
    return snapshot;
  }

  function assertSiblingsUnchanged(before, after, op) {
    for (const [key, prior] of before) {
      const current = after.get(key);
      if (!current || current.dropinSha256 !== prior.dropinSha256 ||
          SIBLING_STABLE_KEYS.some((name) => current.manager[name] !== prior.manager[name])) {
        fail('SERVICE_MANUAL_CLEANUP', op, driverWrites, true, 'sibling-drift');
      }
    }
  }

  function assertTemplateReferencedNowhere(op) {
    // A different shared-template fingerprint is refused while any instance
    // reference exists. This driver only ever publishes the invariant
    // checked-in template, so a mismatching reference binding is a
    // generation conflict, never something to repair.
    const references = session.readReferences();
    if (!references.present) return;
    for (const slot of ['current', 'previous', 'provisional']) {
      for (const artifact of references.value[slot]?.artifacts ?? []) {
        if (artifact.artifactKind === 'shared-template' &&
            artifact.artifactFingerprint !== templateFingerprint) {
          fail('SERVICE_REFERENCED', op, driverWrites, false, 'template-referenced');
        }
      }
    }
  }

  function ensureTemplateExact(scopes, phase, op) {
    if (component !== 'daemon') return;
    const before = readObject(scopes.sharedScope, 'daemon-template', op);
    if (before.state === 'file' && before.bytes.equals(unitTemplates.daemonTemplate)) {
      if (!reconcilePendingAction(phase, op, () => {
        const after = readObject(scopes.sharedScope, 'daemon-template', op);
        return after.state === 'file' && after.bytes.equals(unitTemplates.daemonTemplate);
      }, `${phase}:template`)) requireIdentityReceipt('daemon-template', before, op);
      return;
    }
    if (before.state === 'absent') {
      assertIntentionalAbsence(
        'daemon-template', phase, `${phase}:template`, op,
      );
      actionMutation(phase, op,
        () => publishObject(scopes.sharedScope, 'daemon-template', unitTemplates.daemonTemplate, null, op),
        () => {
          const after = readObject(scopes.sharedScope, 'daemon-template', op);
          return after.state === 'file' && after.bytes.equals(unitTemplates.daemonTemplate);
        }, `${phase}:template`);
      return;
    }
    // Foreign or drifted template bytes are never adopted or repaired by name.
    fail('SERVICE_MANUAL_CLEANUP', op, driverWrites, true, 'template-drift');
  }

  function ensureEnablementDirectory(scopes, phase, op) {
    const before = readObject(scopes.sharedScope, 'enablement-directory', op);
    if (before.state === 'directory') {
      if (!reconcilePendingAction(phase, op,
        () => readObject(scopes.sharedScope, 'enablement-directory', op).state === 'directory',
        `${phase}:enablement-directory`)) {
        requireIdentityReceipt('enablement-directory', before, op);
      }
      return;
    }
    if (before.state !== 'absent') {
      fail('SERVICE_MANUAL_CLEANUP', op, driverWrites, true, 'resource-drift');
    }
    assertIntentionalAbsence(
      'enablement-directory', phase, `${phase}:enablement-directory`, op,
    );
    actionMutation(phase, op,
      () => publishObject(scopes.sharedScope, 'enablement-directory', null, null, op),
      () => readObject(scopes.sharedScope, 'enablement-directory', op).state === 'directory',
      `${phase}:enablement-directory`);
  }

  function applyUnitBytes(scope, phase, objectKind, bytes, before, expectedCurrentSha256, op) {
    if (before.state === 'file' && before.bytes.equals(bytes)) {
      if (!reconcilePendingAction(phase, op, () => {
        const after = readObject(scope, objectKind, op);
        return after.state === 'file' && after.bytes.equals(bytes);
      }, `${phase}:publish:${objectKind}`)) requireIdentityReceipt(objectKind, before, op);
      return;
    }
    if (before.state === 'file') {
      if (expectedCurrentSha256 === null || sha256hex(before.bytes) !== expectedCurrentSha256) {
        // On-disk bytes are neither the declared current bytes nor a clean
        // replay of this transaction: hybrid or foreign, never adopted.
        fail('SERVICE_MANUAL_CLEANUP', op, driverWrites, true, 'resource-drift');
      }
      requireIdentityReceipt(objectKind, before, op);
      actionMutation(phase, op,
        () => publishObject(scope, objectKind, bytes, before, op),
        () => {
          const after = readObject(scope, objectKind, op);
          return after.state === 'file' && after.bytes.equals(bytes);
        }, `${phase}:publish:${objectKind}`);
      return;
    }
    if (before.state === 'absent' || before.state === 'parent-absent') {
      assertIntentionalAbsence(objectKind, phase, `${phase}:publish:${objectKind}`, op);
      if (expectedCurrentSha256 !== null) {
        fail('SERVICE_STALE', op, driverWrites, false, 'absent-expected');
      }
      actionMutation(phase, op,
        () => publishObject(scope, objectKind, bytes, null, op),
        () => {
          const after = readObject(scope, objectKind, op);
          return after.state === 'file' && after.bytes.equals(bytes);
        }, `${phase}:publish:${objectKind}`);
      return;
    }
    fail('SERVICE_MANUAL_CLEANUP', op, driverWrites, true, 'resource-drift');
  }

  function removeUnitBytes(scope, phase, objectKind, before, expectedCurrentSha256, op) {
    if (before.state === 'absent' || before.state === 'parent-absent') {
      assertIntentionalAbsence(objectKind, phase, `${phase}:remove:${objectKind}`, op);
      reconcilePendingAction(phase, op, () => linkAbsent(readObject(scope, objectKind, op)),
        `${phase}:remove:${objectKind}`);
      return;
    }
    if (before.state !== 'file') {
      fail('SERVICE_MANUAL_CLEANUP', op, driverWrites, true, 'resource-drift');
    }
    if (expectedCurrentSha256 === null || sha256hex(before.bytes) !== expectedCurrentSha256) {
      // A recreated or different-proof same-name object is never removed.
      fail('SERVICE_MANUAL_CLEANUP', op, driverWrites, true, 'resource-drift');
    }
    requireIdentityReceipt(objectKind, before, op);
    actionMutation(phase, op,
      () => removeObject(scope, objectKind, before, op),
      () => linkAbsent(readObject(scope, objectKind, op)),
      `${phase}:remove:${objectKind}`);
  }

  function validateTrialContext(trial, op) {
    if (!exactKeys(trial, TRIAL_KEYS) || trial.unitName !== names.unitName ||
        !INVOCATION_ID.test(trial.invocationId) ||
        typeof trial.bootId !== 'string' || !BOOT_ID.test(trial.bootId) ||
        !Number.isSafeInteger(trial.mainPid) || trial.mainPid < 1 ||
        !Number.isSafeInteger(trial.boundaryMs) || trial.boundaryMs < 0 ||
        typeof trial.mainStartTime !== 'string' || trial.mainStartTime.length === 0 ||
        trial.executable !== configuration.runtimePath || trial.owner !== expectedOwner ||
        trial.cgroupPath !== names.cgroupPath ||
        !exactKeys(trial.cgroupIdentity, ['device', 'inode']) ||
        !canonicalUint64(trial.cgroupIdentity.device) ||
        !canonicalUint64(trial.cgroupIdentity.inode) ||
        typeof trial.preStartCursor !== 'string' ||
        !isHex64(trial.treeFingerprint) || !isHex64(trial.cgroupTreeFingerprint) ||
        !isHex64(trial.cgroupMemberFingerprint) || !isHex64(trial.transactionFingerprint) ||
        !isHex64(trial.resourceFingerprint) || !isHex64(trial.releaseFingerprint)) {
      fail('SERVICE_INVALID', op, driverWrites);
    }
  }

  // Live epoch query: returns null only for a cleanly absent process (unit
  // inactive, no invocation, or the main PID no longer exists). Ambiguous
  // native evidence propagates as an ambiguous driver error.
  function liveEpoch(op) {
    const manager = showUnit(names.unitName, op);
    const mainPid = parseShowPid(manager.MainPID);
    if (!manager.InvocationID || !INVOCATION_ID.test(manager.InvocationID) ||
        mainPid === null || mainPid === 0 || manager.ActiveState !== 'active') {
      return null;
    }
    const facts = nativeCall('read_process_facts', mainPid);
    if (facts === null) return null;
    if (!exactKeys(facts, PROCESS_FACTS_KEYS) || facts.pid !== mainPid) {
      fail('SERVICE_INVALID', op, driverWrites, true);
    }
    const tree = nativeCall('enumerate_process_tree', mainPid, facts.startTime, facts.executable, facts.owner);
    if (!exactKeys(tree, ['processes', 'treeFingerprint', 'processCount']) ||
        !Array.isArray(tree.processes) || tree.processCount !== tree.processes.length ||
        tree.processes[0]?.pid !== mainPid || !isHex64(tree.treeFingerprint) ||
        processFactsFingerprint(tree.processes) === null) {
      fail('SERVICE_INVALID', op, driverWrites, true);
    }
    return {
      invocationId: manager.InvocationID,
      mainPid,
      mainStartTime: facts.startTime,
      executable: facts.executable,
      owner: facts.owner,
      treeFingerprint: tree.treeFingerprint,
      treeProcesses: tree.processes,
    };
  }

  function lineageMatches(epoch) {
    return epoch !== null &&
      epoch.executable === configuration.runtimePath &&
      epoch.owner === expectedOwner;
  }

  function assertFreshReceipt(op, transaction, expectedResourceFingerprint = undefined) {
    const { latest } = journalState();
    const receiptPhase = latest.phase === 'startup-observed'
      ? latest.substep === 'observed'
      : latest.phase === 'activation-observed' && ['intent', 'action', 'observed'].includes(latest.substep);
    if (transaction === undefined || latest.transactionFingerprint !== transaction.transactionFingerprint ||
        !receiptPhase) {
      fail('SERVICE_STALE', op, driverWrites, false, 'startup-receipt-invalidated');
    }
    const receipt = session.readStartupProof();
    if (!receipt.present) {
      fail('SERVICE_STALE', op, driverWrites, false, 'startup-receipt-invalidated');
    }
    const proof = receipt.value;
    // Recovery may instantiate a fresh driver after a persisted predecessor
    // trial.  Resolve the proof's release against this transaction rather
    // than silently defaulting to the candidate when the in-memory context is
    // absent.
    const expectedApplication = proof?.applicationManifestFingerprint ??
      startupContext?.releaseFingerprint ?? transaction.candidate.applicationManifestFingerprint;
    const bindsCandidate = expectedApplication === transaction.candidate.applicationManifestFingerprint;
    const bindsOld = transaction.old.applicationManifestFingerprint !== null &&
      expectedApplication === transaction.old.applicationManifestFingerprint;
    const expectedResourceProof = expectedApplication === transaction.candidate.applicationManifestFingerprint
      ? transaction.final.resourceProof
      : transaction.old.resourceProof;
    if (!bindsCandidate && !bindsOld) {
      fail('SERVICE_STALE', op, driverWrites, false, 'startup-receipt-invalidated');
    }
    if (!plain(proof) || proof.transactionId !== transaction.transactionId ||
        proof.component !== component || proof.serviceKey !== serviceKey ||
        proof.platform !== 'linux' || proof.architecture !== architecture ||
        proof.serviceGeneration !== transaction.serviceGeneration ||
        proof.applicationManifestFingerprint !== expectedApplication ||
        proof.resourceProof !== expectedResourceProof ||
        proof.platformState?.phase !== 'trial') {
      fail('SERVICE_STALE', op, driverWrites, false, 'startup-receipt-invalidated');
    }
    const live = liveEpoch(op);
    if (live === null || !lineageMatches(live) ||
        proof.processEpochFingerprint !== processEpochFingerprint(live)) {
      fail('SERVICE_STALE', op, driverWrites, false, 'epoch-lost');
    }
    if (proof.bootFingerprint !== bootFingerprint(nativeCall('read_boot_id'))) {
      fail('SERVICE_STALE', op, driverWrites, false, 'boot-mismatch');
    }
    // Recompute the durable platform-evidence preimage from the journaled
    // trial edge and current native epoch.  A fresh controller must not trust
    // a receipt merely because the process still has the same PID.
    const trialEntry = [...session.readJournal().entries].reverse()
      .find((entry) => entry.phase === 'trial-start-observed' && entry.substep === 'observed');
    const currentCgroup = nativeCall('read_linux_service_cgroup', names.cgroupPath);
    const currentTree = {
      processes: live.treeProcesses,
      treeFingerprint: live.treeFingerprint,
      processCount: live.treeProcesses?.length ?? 0,
    };
    const currentCursor = journalCursor(names.unitName, op);
    if (!trialEntry || currentCgroup === null ||
        !cgroupMatchesTree(currentCgroup, currentTree, live.mainPid)) {
      fail('SERVICE_STALE', op, driverWrites, false, 'epoch-lost');
    }
    if (proof.platformEvidenceFingerprint !== platformEvidenceFingerprint({
          unitName: names.unitName,
          transactionFingerprint: trialEntry.transactionFingerprint,
          invocationId: live.invocationId,
          mainPid: live.mainPid,
          cgroupPath: names.cgroupPath,
          cgroupIdentity: currentCgroup.identity,
          cgroupTreeFingerprint: currentCgroup.treeFingerprint,
          cgroupMemberFingerprint: cgroupMemberFingerprint(currentCgroup),
          preStartCursor: currentCursor,
        })) {
      fail('SERVICE_STALE', op, driverWrites, false, 'startup-receipt-invalidated');
    }
    const now = nowMs();
    if (!Number.isSafeInteger(now) || now > proof.expiresAtMs) {
      fail('SERVICE_STALE', op, driverWrites, false, 'startup-receipt-invalidated');
    }
    if (expectedResourceFingerprint !== undefined && latest.phase === 'startup-observed') {
      const observation = probeWith(op, false);
      if (observation.resourceFingerprint !== expectedResourceFingerprint) {
        fail('SERVICE_MANUAL_CLEANUP', op, driverWrites, true, 'resource-drift');
      }
    }
    return proof;
  }

  // Re-read every runtime identity immediately before a durable proof/action
  // observation is published.  This closes the async observer and systemd
  // mutation windows where a reboot/restart could otherwise leave a stale
  // receipt bound to a new epoch.
  function assertFinalEpoch(op, trial, errorCode = 'SERVICE_TRIAL_NOT_OBSERVED', expectedCursor = undefined) {
    validateTrialContext(trial, op);
    if (nativeCall('read_boot_id') !== trial.bootId) {
      fail(errorCode, op, driverWrites, false, 'boot-mismatch');
    }
    const live = liveEpoch(op);
    if (live === null || live.invocationId !== trial.invocationId ||
        live.mainPid !== trial.mainPid || live.mainStartTime !== trial.mainStartTime ||
        live.executable !== trial.executable || live.owner !== trial.owner) {
      fail(errorCode, op, driverWrites, false, 'epoch-lost');
    }
    const cgroup = nativeCall('read_linux_service_cgroup', trial.cgroupPath);
    if (cgroup === null || !exactKeys(cgroup, CGROUP_KEYS) ||
        !exactKeys(cgroup.identity, ['device', 'inode']) ||
        cgroup.identity.device !== trial.cgroupIdentity.device ||
        cgroup.identity.inode !== trial.cgroupIdentity.inode ||
        !Array.isArray(cgroup.processes) ||
        !cgroup.processes.some((process) => process.pid === trial.mainPid) ||
        cgroup.treeFingerprint !== trial.cgroupTreeFingerprint ||
        cgroupMemberFingerprint(cgroup) !== trial.cgroupMemberFingerprint) {
      fail(errorCode, op, driverWrites, false, 'epoch-lost');
    }
    const tree = nativeCall('enumerate_process_tree', trial.mainPid,
      trial.mainStartTime, trial.executable, trial.owner);
    if (!exactKeys(tree, ['processes', 'treeFingerprint', 'processCount']) ||
        !Array.isArray(tree.processes) || tree.processCount !== tree.processes.length ||
        tree.processes[0]?.pid !== trial.mainPid || !isHex64(tree.treeFingerprint) ||
        processFactsFingerprint(tree.processes) === null) {
      fail(errorCode, op, driverWrites, false, 'epoch-lost');
    }
    if (!cgroupMatchesTree(cgroup, tree, trial.mainPid)) {
      fail(errorCode, op, driverWrites, false, 'epoch-lost');
    }
    // Cursor parsing is part of the same final observation boundary.  The
    // cursor is intentionally opaque; its successful bounded re-query proves
    // the log stream is still available without imposing ordering semantics.
    const cursor = journalCursor(names.unitName, op);
    if (expectedCursor !== undefined && cursor !== expectedCursor) {
      fail(errorCode, op, driverWrites, false, 'epoch-lost');
    }
    return cursor;
  }

  function assertFinalActivation(op, expectedPhase, expectedResourceFingerprint) {
    // Linearize on the manager/resource observation first.  Nothing that can
    // publish activation-observed may rely on a manager query made before
    // this probe: a restart between those queries would otherwise permit a
    // stale startup receipt to be journaled as final activation.
    const observation = probeWith(op, false);
    const receipt = session.readStartupProof();
    if (!receipt.present) fail('SERVICE_STALE', op, driverWrites, false, 'startup-receipt-invalidated');
    const manager = observation.manager;
    const mainPid = parseShowPid(manager.MainPID);
    if (!INVOCATION_ID.test(manager.InvocationID) || mainPid === null || mainPid === 0 ||
        manager.ActiveState !== 'active') {
      fail('SERVICE_STALE', op, driverWrites, false, 'epoch-lost');
    }
    const live = liveEpoch(op);
    if (live === null || !lineageMatches(live) || live.invocationId !== manager.InvocationID ||
        live.mainPid !== mainPid) {
      fail('SERVICE_STALE', op, driverWrites, false, 'epoch-lost');
    }
    const facts = nativeCall('read_process_facts', mainPid);
    if (facts === null || !exactKeys(facts, PROCESS_FACTS_KEYS) || facts.pid !== mainPid) {
      fail('SERVICE_STALE', op, driverWrites, true, 'epoch-lost');
    }
    if (live.mainStartTime !== facts.startTime || live.executable !== facts.executable ||
        live.owner !== facts.owner) {
      fail('SERVICE_STALE', op, driverWrites, false, 'epoch-lost');
    }
    const tree = nativeCall('enumerate_process_tree', mainPid, facts.startTime, facts.executable, facts.owner);
    if (!exactKeys(tree, ['processes', 'treeFingerprint', 'processCount']) ||
        !Array.isArray(tree.processes) || tree.processCount !== tree.processes.length ||
        tree.processes[0]?.pid !== mainPid || !isHex64(tree.treeFingerprint)) {
      fail('SERVICE_STALE', op, driverWrites, true, 'epoch-lost');
    }
    if (live.treeFingerprint !== tree.treeFingerprint) {
      fail('SERVICE_STALE', op, driverWrites, false, 'epoch-lost');
    }
    const cgroup = nativeCall('read_linux_service_cgroup', names.cgroupPath);
    if (cgroup === null || !exactKeys(cgroup, CGROUP_KEYS) ||
        !exactKeys(cgroup.identity, ['device', 'inode']) ||
        !Array.isArray(cgroup.processes) ||
        !cgroup.processes.some((process) => process.pid === mainPid) ||
        (startupContext !== null && (cgroup.treeFingerprint !== startupContext.cgroupTreeFingerprint ||
          cgroupMemberFingerprint(cgroup) !== startupContext.cgroupMemberFingerprint)) ||
        !cgroupMatchesTree(cgroup, tree, mainPid)) {
      fail('SERVICE_STALE', op, driverWrites, false, 'epoch-lost');
    }
    const cursor = journalCursor(names.unitName, op);
    const bootId = nativeCall('read_boot_id');
    if (typeof cursor !== 'string' ||
        typeof bootId !== 'string' || !BOOT_ID.test(bootId) ||
        observation.bootId !== bootId) {
      fail('SERVICE_STALE', op, driverWrites, false, 'epoch-lost');
    }
    if (startupContext !== null && observation.bootId !== startupContext.bootId) {
      fail('SERVICE_STALE', op, driverWrites, false, 'boot-mismatch');
    }

    // The receipt's epoch and boot fingerprints must describe the exact live
    // process just compared above.
    const proof = receipt.value;
    if (proof.processEpochFingerprint !== processEpochFingerprint({
      mainPid, mainStartTime: facts.startTime, executable: facts.executable, owner: facts.owner,
    }) || proof.bootFingerprint !== bootFingerprint(bootId)) {
      fail('SERVICE_STALE', op, driverWrites, false, 'epoch-lost');
    }
    const now = nowMs();
    if (!Number.isSafeInteger(now) || now > proof.expiresAtMs) {
      fail('SERVICE_STALE', op, driverWrites, false, 'startup-receipt-invalidated');
    }
    if (startupContext !== null &&
        (manager.InvocationID !== startupContext.invocationId || mainPid !== startupContext.mainPid ||
         facts.startTime !== startupContext.mainStartTime || facts.executable !== startupContext.executable ||
         facts.owner !== startupContext.owner || tree.treeFingerprint !== startupContext.treeFingerprint ||
         cgroup.identity.device !== startupContext.cgroupIdentity.device ||
         cgroup.identity.inode !== startupContext.cgroupIdentity.inode ||
         proof.platformEvidenceFingerprint !== platformEvidenceFingerprint({
           unitName: startupContext.unitName,
           transactionFingerprint: startupContext.transactionFingerprint,
           invocationId: manager.InvocationID,
           mainPid,
           cgroupPath: startupContext.cgroupPath,
           cgroupIdentity: startupContext.cgroupIdentity,
           cgroupTreeFingerprint: cgroup.treeFingerprint,
           cgroupMemberFingerprint: cgroupMemberFingerprint(cgroup),
           preStartCursor: startupContext.preStartCursor,
         }))) {
      fail('SERVICE_STALE', op, driverWrites, false, 'epoch-lost');
    }
    // Epoch checks above intentionally precede this probe. Re-read the full
    // normalized manager/resource view immediately before activation is
    // observed; the initial snapshot must never be reused as proof.
    const finalObservation = probeWith(op, false);
    verifyExactState(finalObservation, expectedPhase, undefined, op);
    if (expectedResourceFingerprint !== undefined &&
        finalObservation.resourceFingerprint !== expectedResourceFingerprint) {
      fail('SERVICE_MANUAL_CLEANUP', op, driverWrites, true, 'resource-drift');
    }
    if (!transactionResourcePredicate(journalState().latest, 'activation-observed',
      finalObservation.resourceFingerprint, undefined, expectedResourceFingerprint)) {
      fail('SERVICE_MANUAL_CLEANUP', op, driverWrites, true, 'resource-drift');
    }
    // The final normalized policy/resource snapshot is only a configuration
    // observation.  Re-read the startup epoch, exact lineage, cgroup/tree
    // membership, and journal cursor after it so a restart during the probe
    // cannot be published as activation-observed.
    const epochContext = startupContext ?? {
      unitName: names.unitName,
      bootId,
      boundaryMs: 0,
      preStartCursor: '',
      invocationId: manager.InvocationID,
      mainPid,
      mainStartTime: facts.startTime,
      executable: facts.executable,
      owner: facts.owner,
      cgroupPath: names.cgroupPath,
      cgroupIdentity: { ...cgroup.identity },
      treeFingerprint: tree.treeFingerprint,
      cgroupTreeFingerprint: cgroup.treeFingerprint,
      cgroupMemberFingerprint: cgroupMemberFingerprint(cgroup),
      transactionFingerprint: journalState().latest.transactionFingerprint,
      resourceFingerprint: finalObservation.resourceFingerprint,
      releaseFingerprint: receipt.value.applicationManifestFingerprint,
    };
    assertFinalEpoch(op, epochContext, 'SERVICE_STALE', cursor);
    return finalObservation;
  }

  function publishResource({ phase, restart, release, expectedCurrentSha256, siblings }, op) {
    removalTombstones = new Map();
    const allowedActionTargets = new Set(['link-remove', 'reload']);
    if (component === 'bot') {
      allowedActionTargets.add('bot-unit-publish');
    } else {
      allowedActionTargets.add('template');
      allowedActionTargets.add('dropin-directory-publish');
      allowedActionTargets.add('dropin-publish');
    }
    const transaction = assertHead(op, [
      { phase: 'prepared', substep: 'none' },
      { phase: 'sequence-reserved' },
      { phase: 'release-published' },
      { phase: 'transition-marker-intent' },
      { phase: 'stopping' },
      { phase: 'quiescent' },
      { phase: 'resource-published' },
      { phase: 'startup-observed' },
      { phase: 'activation-observed' },
    ], (discriminator) => discriminator.startsWith(`${phase}:`) &&
      allowedActionTargets.has(actionTarget(discriminator)));
    const pending = pendingAction(op, allowedActionTargets);
    if (phase === 'transition-marker-intent' && transaction.phase !== 'transition-marker-intent') {
      fail('SERVICE_PENDING', op, driverWrites);
    }
    if (phase === 'resource-published' &&
        transaction.phase !== 'transition-marker-intent' && transaction.phase !== 'resource-published') {
      fail('SERVICE_PENDING', op, driverWrites);
    }
    validateSiblings(siblings, op);
    assertTemplateReferencedNowhere(op);
    const rendered = renderFor(restart, release, transaction, op);
    const siblingBefore = snapshotSiblings(siblings, op);
    let replayTarget = null;
    const resolvedRemoval = { value: null };
    withScopes('mutate', op, (scopes) => {
      replayTarget = dispatchPendingAction(scopes, phase, op, pending, resolvedRemoval);
      // Preflight every existing object that this transition may remove,
      // replace, or reuse.  This keeps a post-restart session fail-closed
      // before any native mutation (including link deletion or template
      // when a same-content object has been recreated.
      const current = readAllObjects(scopes, op);
      assertCompleteResourceReceipts(component, op, {
        objects: current, replayTarget, resolvedRemoval: resolvedRemoval.value,
      });
      assertTransactionPreState(
        transaction, phase, release, expectedCurrentSha256, current, op, replayTarget,
      );
      ensureTemplateExact(scopes, phase, op);
      const link = readObject(scopes.instanceScope, 'enablement-link', op);
      if (link.state === 'symlink') {
        // Remove only the proof-owned multi-user.target.wants link.
        actionMutation(phase, op,
          () => removeObject(scopes.instanceScope, 'enablement-link', link, op),
          () => linkAbsent(readObject(scopes.instanceScope, 'enablement-link', op)),
          `${phase}:remove:enablement-link`);
      } else if (!linkAbsent(link)) {
        fail('SERVICE_MANUAL_CLEANUP', op, driverWrites, true, 'activation-drift');
      } else {
        assertIntentionalAbsence('enablement-link', phase,
          `${phase}:remove:enablement-link`, op);
      }
      if (component === 'bot') {
        const before = readObject(scopes.instanceScope, 'bot-unit', op);
        applyUnitBytes(scopes.instanceScope, phase, 'bot-unit', rendered.unit, before, expectedCurrentSha256, op);
      } else {
        const directory = readObject(scopes.instanceScope, 'daemon-dropin-directory', op);
        if (directory.state === 'absent') {
          assertIntentionalAbsence('daemon-dropin-directory', phase,
            `${phase}:publish:daemon-dropin-directory`, op);
          actionMutation(phase, op,
            () => publishObject(scopes.instanceScope, 'daemon-dropin-directory', null, null, op),
            () => readObject(scopes.instanceScope, 'daemon-dropin-directory', op).state === 'directory',
            `${phase}:publish:daemon-dropin-directory`);
        } else if (directory.state !== 'directory') {
          fail('SERVICE_MANUAL_CLEANUP', op, driverWrites, true, 'resource-drift');
        }
        const before = readObject(scopes.instanceScope, 'daemon-dropin', op);
        applyUnitBytes(scopes.instanceScope, phase, 'daemon-dropin', rendered.dropin, before, expectedCurrentSha256, op);
      }
      if (replayTarget !== 'reload') {
        actionMutation(phase, op,
          () => daemonReload(op),
          () => showUnit(names.unitName, op).NeedDaemonReload === 'no',
          `${phase}:daemon-reload`);
      }
    });
    const siblingAfter = snapshotSiblings(siblings, op);
    assertSiblingsUnchanged(siblingBefore, siblingAfter, op);
    const observation = probeWith(op);
    const descriptor = expectedDescriptor(
      component === 'bot'
        ? { unit: rendered.unit }
        : { template: unitTemplates.daemonTemplate, dropin: rendered.dropin },
      'absent',
    );
    if (observation.resourceFingerprint !== linuxServiceResourceFingerprint(descriptor)) {
      fail('SERVICE_MANUAL_CLEANUP', op, driverWrites, true, 'resource-drift');
    }
    if (restart === 'no') {
      // The journal-declared platformResourceFingerprint pins the candidate's
      // T state. The T-marked old resource is instead pinned by the exact
      // expectedCurrentSha256 CAS chain (plan legal tuple family 2).
      const declared = release.applicationManifestFingerprint ===
        transaction.candidate.applicationManifestFingerprint
        ? transaction.transition.platformResourceFingerprint
        : undefined;
      verifyExactState(observation, 'trial', declared, op);
    } else {
      verifyExactState(observation, 'final-restart-armed', undefined, op);
      const finalFingerprint = linuxServiceResourceFingerprint(expectedDescriptor(
        component === 'bot'
          ? { unit: rendered.unit }
          : { template: unitTemplates.daemonTemplate, dropin: rendered.dropin },
        'owned',
      ));
      // The final enabled endpoint must be one of the two transaction-declared
      // fingerprints: the candidate's (update/install commit) or the exact old
      // one (predecessor restoration).
      const declaredEnds = [
        transaction.transition.expectedAfterResourceFingerprint,
        transaction.transition.expectedBeforeResourceFingerprint,
      ];
      if (!declaredEnds.includes(finalFingerprint)) {
        fail('SERVICE_MANUAL_CLEANUP', op, driverWrites, true, 'resource-drift');
      }
    }
    return observation;
  }

  const api = {
    get writes() { return driverWrites; },
    unitName: names.unitName,
    cgroupPath: names.cgroupPath,

    /**
     * Read-only OS observation: native object snapshots, manager state, boot
     * identity, derived platform state, and the resource fingerprint. No
     * writes, no journal appends.
     */
    probe() {
      const latest = journalState().latest;
      // Only the explicit prepared admission may seed a physical baseline.
      // Once a transaction has crossed its first durable edge, a public probe
      // is observational and must remain capture-free (especially on a fresh
      // controller recovering an active transaction).
      return probeWith('probe_linux_service', latest.phase === 'prepared' && latest.substep === 'none');
    },

    /**
     * Publishes the T-marked suppressed resource: removes only the
     * proof-owned enablement link, independently publishes the Restart=no
     * unit/drop-in carrying the release fingerprint, runs the global
     * daemon-reload as its own action, and revalidates every referenced sibling instance's
     * effective ExecStart/proof before and after. Idempotent across exact
     * crash replay; anything outside the declared before/after pair fails
     * closed.
     */
    publishSuppressedResource(input) {
      const op = 'publish_suppressed_resource';
      if (!exactKeys(input, ['phase', 'release', 'expectedCurrentSha256', 'siblings'])) {
        fail('SERVICE_INVALID', op, driverWrites);
      }
      const { phase, release, expectedCurrentSha256, siblings } = input;
      if ((phase !== 'transition-marker-intent' && phase !== 'resource-published') ||
          (expectedCurrentSha256 !== null && !isHex64(expectedCurrentSha256)) ||
          !exactKeys(release, ['entrypointPath', 'applicationManifestFingerprint']) ||
          !absoluteUnitPath(release.entrypointPath) ||
          !isHex64(release.applicationManifestFingerprint)) {
        fail('SERVICE_INVALID', op, driverWrites);
      }
      return publishResource({ phase, restart: 'no', release, expectedCurrentSha256, siblings }, op);
    },

    /**
     * The executable trial: persists trial-start-intent, invokes fixed-argv
     * `systemctl start <exact-unit>`, then requires a NEW InvocationID plus
     * MainPID/start time, cgroup membership, and exact executable lineage
     * before journaling trial-start-observed. A zero exit without a new
     * invocation fails the trial.
     */
    async startTrial(input = {}) {
      const op = 'start_trial';
      if (!plain(input) ||
          Reflect.ownKeys(input).some((key) => key !== 'expectedResourceFingerprint')) {
        fail('SERVICE_INVALID', op, driverWrites);
      }
      if (Object.hasOwn(input, 'expectedResourceFingerprint') &&
          !isHex64(input.expectedResourceFingerprint)) {
        fail('SERVICE_INVALID', op, driverWrites);
      }
      const transaction = assertHead(op, [
        { phase: 'transition-marker-intent', substep: 'observed' },
        { phase: 'resource-published', substep: 'observed' },
        { phase: 'quiescent', substep: 'observed' },
        { phase: 'trial-start-intent', substep: 'intent' },
        { phase: 'trial-start-intent', substep: 'action' },
      ], (discriminator) => discriminator === 'trial-start-intent:start_trial');
      requireLiveIdentityReceipts(op);
      const pendingStartAction = transaction.phase === 'trial-start-intent' && transaction.substep === 'action';
      if (pendingStartAction &&
          actionDiscriminators.get(transaction.transactionFingerprint) !== 'trial-start-intent:start_trial') {
        fail('SERVICE_PENDING', op, driverWrites);
      }
      const before = probeWith(op);
      assertCompleteResourceReceipts(component, op, { objects: before.objects });
      // The trialed release is proven from the published bytes themselves.
      const releaseFingerprint = parseReleaseFingerprint(before.objects, component);
      if (releaseFingerprint === null ||
          (releaseFingerprint !== transaction.candidate.applicationManifestFingerprint &&
            releaseFingerprint !== transaction.old.applicationManifestFingerprint)) {
        fail('SERVICE_MANUAL_CLEANUP', op, driverWrites, true, 'resource-drift');
      }
      // Candidate trials bind the journal-declared T fingerprint; predecessor
      // restoration trials the old release under the identical suppressed
      // state and the caller pins it with an explicit fingerprint.
      const expectedResource = transaction.transition.platformResourceFingerprint;
      if (releaseFingerprint === transaction.old.applicationManifestFingerprint &&
          releaseFingerprint !== transaction.candidate.applicationManifestFingerprint &&
          !Object.hasOwn(input, 'expectedResourceFingerprint')) {
        fail('SERVICE_INVALID', op, driverWrites);
      }
      if (Object.hasOwn(input, 'expectedResourceFingerprint') &&
          input.expectedResourceFingerprint !== expectedResource) {
        fail('SERVICE_STALE', op, driverWrites, false, 'resource-drift');
      }
      if (!transactionResourcePredicate(transaction, 'trial', before.resourceFingerprint,
        Object.hasOwn(input, 'expectedResourceFingerprint')
          ? input.expectedResourceFingerprint : undefined)) {
        fail('SERVICE_STALE', op, driverWrites, false, 'resource-drift');
      }
      verifyExactState(before, 'trial', expectedResource, op);
      const manager = before.manager;
      const preMainPid = parseShowPid(manager.MainPID);
      if ((!pendingStartAction && manager.ActiveState !== 'inactive' && manager.ActiveState !== 'failed') ||
          (!pendingStartAction && preMainPid !== 0)) {
        fail('SERVICE_MANUAL_CLEANUP', op, driverWrites, true, 'activation-drift');
      }
      const cgroupBefore = nativeCall('read_linux_service_cgroup', names.cgroupPath);
      if (!pendingStartAction && cgroupBefore !== null &&
          (cgroupMemberFingerprint(cgroupBefore) === null || cgroupBefore.processCount !== 0)) {
        fail('SERVICE_MANUAL_CLEANUP', op, driverWrites, true, 'tree-not-quiescent');
      }
      const bootId = before.bootId;
      const cursor = journalCursor(names.unitName, op);
      const preInvocation = pendingStartAction ? '' : (manager.InvocationID ?? '');
      const boundaryMs = nowMs();
      if (!Number.isSafeInteger(boundaryMs) || boundaryMs < 0) {
        fail('SERVICE_INVALID', op, driverWrites);
      }
      if (!(pendingStartAction && manager.ActiveState === 'active' &&
            INVOCATION_ID.test(manager.InvocationID ?? '') && preMainPid > 0)) {
        if (!(journalState().latest.phase === 'trial-start-intent' &&
              (journalState().latest.substep === 'intent' || journalState().latest.substep === 'action'))) {
          journalAppend('trial-start-intent', 'intent');
        }
        if (journalState().latest.substep === 'intent') {
          journalAppend('trial-start-intent', 'action');
          actionDiscriminators.set(
            journalState().latest.transactionFingerprint,
            'trial-start-intent:start_trial',
          );
        }
        const started = runArgv([SYSTEMCTL, 'start', names.unitName], op);
        if (started.code !== 0) {
          fail('SERVICE_IO_FAILED', op, driverWrites, false, 'invocation-not-observed');
        }
      }
      let observed = null;
      for (let attempt = 0; attempt < LINUX_DRIVER_LIMITS.startPollAttempts; attempt += 1) {
        const managerAfter = showUnit(names.unitName, op);
        const pid = parseShowPid(managerAfter.MainPID);
        if (managerAfter.InvocationID !== undefined &&
            INVOCATION_ID.test(managerAfter.InvocationID) &&
            managerAfter.InvocationID !== preInvocation &&
            pid !== null && pid > 0 && managerAfter.ActiveState === 'active') {
          observed = { managerAfter, pid };
          break;
        }
        await sleepMs(LINUX_DRIVER_LIMITS.startPollMs);
      }
      if (observed === null) {
        // Zero exit without a new invocation is a failed trial (for example a
        // skipped condition), never a start receipt.
        fail('SERVICE_TRIAL_NOT_OBSERVED', op, driverWrites, false, 'invocation-not-observed');
      }
      const { managerAfter, pid } = observed;
      if (loadedPolicyMismatch(
        managerAfter,
        effectiveUnitPolicy(names, before.objects, configuration, expectedOwner),
        true,
      )) {
        fail('SERVICE_TRIAL_NOT_OBSERVED', op, driverWrites, false, 'resource-drift');
      }
      if (managerAfter.SubState !== 'running' ||
          managerAfter.Slice !== SLICE_NAME ||
          managerAfter.ControlGroup !== names.controlGroup ||
          managerAfter.NeedDaemonReload !== 'no') {
        fail('SERVICE_TRIAL_NOT_OBSERVED', op, driverWrites, false, 'invocation-not-observed');
      }
      const execTimestamp = parseExecTimestamp(managerAfter.ExecMainStartTimestamp);
      if (execTimestamp === null || execTimestamp + 1000 < boundaryMs) {
        // Second-resolution manager timestamps get one second of quantization
        // allowance against the captured boundary.
        fail('SERVICE_TRIAL_NOT_OBSERVED', op, driverWrites, false, 'invocation-not-observed');
      }
      const facts = nativeCall('read_process_facts', pid);
      if (facts === null || !exactKeys(facts, PROCESS_FACTS_KEYS)) {
        fail('SERVICE_TRIAL_NOT_OBSERVED', op, driverWrites, true, 'invocation-not-observed');
      }
      if (facts.executable !== configuration.runtimePath || facts.owner !== expectedOwner) {
        fail('SERVICE_MANUAL_CLEANUP', op, driverWrites, true, 'resource-drift');
      }
      const tree = nativeCall('enumerate_process_tree', pid, facts.startTime, facts.executable, facts.owner);
      if (!exactKeys(tree, ['processes', 'treeFingerprint', 'processCount']) ||
          !Array.isArray(tree.processes) || tree.processCount !== tree.processes.length ||
          tree.processes[0]?.pid !== pid || !isHex64(tree.treeFingerprint) ||
          processFactsFingerprint(tree.processes) === null) {
        fail('SERVICE_INVALID', op, driverWrites, true);
      }
      const cgroup = nativeCall('read_linux_service_cgroup', names.cgroupPath);
      if (cgroup === null || !exactKeys(cgroup, CGROUP_KEYS) ||
          !exactKeys(cgroup.identity, ['device', 'inode']) ||
          !cgroup.processes.some((process) => process.pid === pid) ||
          cgroupMemberFingerprint(cgroup) === null ||
          !cgroupMatchesTree(cgroup, tree, pid)) {
        fail('SERVICE_TRIAL_NOT_OBSERVED', op, driverWrites, true, 'invocation-not-observed');
      }
      journalAppend('trial-start-observed', 'observed');
      const trialTransactionFingerprint = journalState().latest.transactionFingerprint;
      return freezeDeep({
        unitName: names.unitName,
        bootId,
        boundaryMs,
        preStartCursor: cursor,
        invocationId: managerAfter.InvocationID,
        mainPid: pid,
        mainStartTime: facts.startTime,
        executable: facts.executable,
        owner: facts.owner,
        cgroupPath: names.cgroupPath,
        cgroupIdentity: freezeDeep({ ...cgroup.identity }),
        treeFingerprint: tree.treeFingerprint,
        cgroupTreeFingerprint: cgroup.treeFingerprint,
        cgroupMemberFingerprint: cgroupMemberFingerprint(cgroup),
        transactionFingerprint: trialTransactionFingerprint,
        resourceFingerprint: expectedResource,
        releaseFingerprint,
      });
    },

    /**
     * The 60-second current-run startup gate. Platform epoch revalidation is
     * continuous; application evidence arrives through the injected observer
     * which returns null until its markers exist, or an exact evidence
     * fingerprint plus closed connectivity observation. The proof is persisted
     * before startup-observed is journaled. Startup evidence is current-run
     * only and never a live-health claim.
     */
    async runStartupGate(input) {
      const op = 'run_startup_gate';
      if (!exactKeys(input, ['trial', 'observeApplication'])) {
        fail('SERVICE_INVALID', op, driverWrites);
      }
      const { trial, observeApplication } = input;
      if (typeof observeApplication !== 'function') fail('SERVICE_INVALID', op, driverWrites);
      const transaction = assertHead(op, [
        { phase: 'trial-start-observed', substep: 'observed' },
        { phase: 'starting', substep: 'intent' },
      ]);
      validateTrialContext(trial, op);
      if (trial.transactionFingerprint !== transaction.transactionFingerprint ||
          trial.resourceFingerprint !== transaction.transition.platformResourceFingerprint) {
        fail('SERVICE_STALE', op, driverWrites, false, 'resource-drift');
      }
      journalAppend('starting', 'intent');
      const deadline = trial.boundaryMs + LINUX_DRIVER_LIMITS.startupWindowMs;
      let evidence = null;
      for (;;) {
        const live = liveEpoch(op);
        if (live === null || live.invocationId !== trial.invocationId ||
            live.mainPid !== trial.mainPid || live.mainStartTime !== trial.mainStartTime ||
            live.executable !== trial.executable || live.owner !== trial.owner) {
          fail('SERVICE_TRIAL_NOT_OBSERVED', op, driverWrites, false, 'epoch-lost');
        }
        if (nativeCall('read_boot_id') !== trial.bootId) {
          fail('SERVICE_TRIAL_NOT_OBSERVED', op, driverWrites, false, 'boot-mismatch');
        }
        const cgroup = nativeCall('read_linux_service_cgroup', trial.cgroupPath);
        if (cgroup === null || !exactKeys(cgroup, CGROUP_KEYS) ||
            !exactKeys(cgroup.identity, ['device', 'inode']) ||
            cgroup.identity.device !== trial.cgroupIdentity.device ||
            cgroup.identity.inode !== trial.cgroupIdentity.inode ||
            !cgroup.processes.some((process) => process.pid === trial.mainPid) ||
            cgroup.treeFingerprint !== trial.cgroupTreeFingerprint ||
            cgroupMemberFingerprint(cgroup) !== trial.cgroupMemberFingerprint) {
          fail('SERVICE_TRIAL_NOT_OBSERVED', op, driverWrites, false, 'epoch-lost');
        }
        const tree = nativeCall('enumerate_process_tree', trial.mainPid,
          trial.mainStartTime, trial.executable, trial.owner);
        if (!cgroupMatchesTree(cgroup, tree, trial.mainPid)) {
          fail('SERVICE_TRIAL_NOT_OBSERVED', op, driverWrites, false, 'epoch-lost');
        }
        const observed = await observeApplication(freezeDeep({ ...trial }));
        if (observed !== null) {
          if (!exactKeys(observed, ['applicationEvidenceFingerprint', 'connectivityObservation']) ||
              !isHex64(observed.applicationEvidenceFingerprint) ||
              !SERVICE_STATUS_VALUES.connectivityObservation.includes(observed.connectivityObservation)) {
            fail('SERVICE_INVALID', op, driverWrites);
          }
          evidence = observed;
          break;
        }
        const now = nowMs();
        if (!Number.isSafeInteger(now) || now >= deadline) {
          fail('SERVICE_STARTUP_TIMEOUT', op, driverWrites, false, 'startup-receipt-invalidated');
        }
        await sleepMs(LINUX_DRIVER_LIMITS.stopPollMs);
      }
      const observedAtMs = nowMs();
      if (!Number.isSafeInteger(observedAtMs) || observedAtMs < trial.boundaryMs ||
          observedAtMs > deadline) {
        fail('SERVICE_STARTUP_TIMEOUT', op, driverWrites, false, 'startup-receipt-invalidated');
      }
      // Final linearization check: the observer may have awaited while the
      // service restarted or the host rebooted.  Never publish its evidence
      // until the complete platform epoch and log boundary is re-queried.
      const finalEpochCursor = assertFinalEpoch(op, trial);
      // The epoch checks above intentionally do not carry a manager policy
      // snapshot. Re-read the complete normalized manager view after them so
      // startup-observed cannot certify a restarted or drifted trial unit.
      const finalObservation = probeWith(op);
      verifyExactState(finalObservation, 'trial', transaction.transition.platformResourceFingerprint, op);
      // The normalized manager/resource probe is not itself an epoch proof:
      // systemd may restart the unit while it is being read.  Re-read every
      // runtime identity and the same journal cursor after that probe, and
      // publish no startup receipt unless both boundaries describe one
      // uninterrupted trial epoch.
      assertFinalEpoch(op, trial, 'SERVICE_TRIAL_NOT_OBSERVED', finalEpochCursor);
      let proof;
      try {
        // The startup proof binds the exact release under trial: the
        // candidate's final resource proof, or the exact old resource proof
        // for a predecessor restoration trial.
        const bindsCandidate = trial.releaseFingerprint ===
          transaction.candidate.applicationManifestFingerprint;
        const bindsOld = transaction.old.applicationManifestFingerprint !== null &&
          trial.releaseFingerprint === transaction.old.applicationManifestFingerprint;
        if (!bindsCandidate && !bindsOld) fail('SERVICE_INVALID', op, driverWrites);
        proof = buildServiceStartupProof({
          component,
          serviceKey,
          platform: 'linux',
          architecture,
          serviceGeneration: transaction.serviceGeneration,
          transactionId: transaction.transactionId,
          resourceProof: bindsCandidate
            ? transaction.final.resourceProof
            : transaction.old.resourceProof,
          applicationManifestFingerprint: trial.releaseFingerprint,
          bootFingerprint: bootFingerprint(trial.bootId),
          processEpochFingerprint: processEpochFingerprint(trial),
          platformEvidenceFingerprint: platformEvidenceFingerprint({
            unitName: trial.unitName,
            transactionFingerprint: trial.transactionFingerprint,
            invocationId: trial.invocationId,
            mainPid: trial.mainPid,
            cgroupPath: trial.cgroupPath,
            cgroupIdentity: trial.cgroupIdentity,
            cgroupTreeFingerprint: trial.cgroupTreeFingerprint,
            cgroupMemberFingerprint: trial.cgroupMemberFingerprint,
            preStartCursor: trial.preStartCursor,
          }),
          applicationEvidenceFingerprint: evidence.applicationEvidenceFingerprint,
          platformState: buildServicePlatformState('linux', 'trial'),
          startBoundaryMs: trial.boundaryMs,
          observedAtMs,
          expiresAtMs: deadline,
          startupEvidence: 'fresh-current-epoch',
          connectivityObservation: evidence.connectivityObservation,
        });
      } catch {
        fail('SERVICE_INVALID', op, driverWrites);
      }
      session.publishStartupProof(proof, session.readStartupProof());
      startupContext = freezeDeep({ ...trial });
      journalAppend('startup-observed', 'observed');
      return freezeDeep({ startupProof: proof });
    },

    /**
     * First post-gate activation action: publishes the final
     * Restart=on-failure resource while the enablement link stays absent,
     * reloads, and revalidates siblings. Requires a fresh same-epoch startup
     * receipt; a new process epoch invalidates the receipt and recovery
     * resuppresses/retrials instead.
     */
    armFinalRestart(input) {
      const op = 'arm_final_restart';
      removalTombstones = new Map();
      if (!exactKeys(input, ['release', 'siblings'])) fail('SERVICE_INVALID', op, driverWrites);
      const { release, siblings } = input;
      if (!exactKeys(release, ['entrypointPath', 'applicationManifestFingerprint']) ||
          !absoluteUnitPath(release.entrypointPath) ||
          !isHex64(release.applicationManifestFingerprint)) {
        fail('SERVICE_INVALID', op, driverWrites);
      }
      const allowedActionTargets = new Set(['template',
        component === 'bot' ? 'bot-unit-publish' : 'dropin-publish', 'reload-arm']);
      let transaction = assertHead(op, [
        { phase: 'startup-observed', substep: 'observed' },
        { phase: 'activation-observed', substep: 'intent' },
        { phase: 'activation-observed', substep: 'action' },
      ], (discriminator) => discriminator.startsWith('activation-observed:') &&
        allowedActionTargets.has(actionTarget(discriminator)));
      const pending = pendingAction(op, allowedActionTargets);
      let replayTarget = null;
      if (pending !== null) {
        withScopes('mutate', op, (scopes) => {
          replayTarget = dispatchPendingAction(scopes, 'activation-observed', op, pending);
        });
        transaction = journalState().latest;
      }
      requireLiveIdentityReceipts(op);
      assertFreshReceipt(op, transaction, transaction.transition.platformResourceFingerprint);
      validateSiblings(siblings, op);
      assertTemplateReferencedNowhere(op);
      const rendered = renderFor('on-failure', release, transaction, op);
      const trialRendered = renderFor('no', release, transaction, op);
      const expectedCurrentSha256 = sha256hex(
        component === 'bot' ? trialRendered.unit : trialRendered.dropin,
      );
      const siblingBefore = snapshotSiblings(siblings, op);
      withScopes('mutate', op, (scopes) => {
        const current = readAllObjects(scopes, op);
        assertCompleteResourceReceipts(component, op, { objects: current, replayTarget });
        const currentFingerprint = linuxServiceResourceFingerprint(observedDescriptor(current));
        const trialResource = transactionResourcePredicate(transaction, 'trial', currentFingerprint, undefined);
        const replayedFinalReload = (replayTarget === 'reload-arm') &&
          currentFingerprint === linuxServiceResourceFingerprint(expectedDescriptor(
            component === 'bot'
              ? { unit: rendered.unit }
              : { template: unitTemplates.daemonTemplate, dropin: rendered.dropin },
            'absent',
          ));
        if (!(replayTarget === 'bot-unit-publish' || replayTarget === 'dropin-publish') &&
            !trialResource && !replayedFinalReload) {
          fail('SERVICE_MANUAL_CLEANUP', op, driverWrites, true, 'resource-drift');
        }
        ensureTemplateExact(scopes, 'activation-observed', op);
        const link = readObject(scopes.instanceScope, 'enablement-link', op);
        if (!linkAbsent(link)) {
          fail('SERVICE_MANUAL_CLEANUP', op, driverWrites, true, 'activation-drift');
        }
        if (replayTarget !== 'reload-arm') {
          if (component === 'bot') {
            const before = readObject(scopes.instanceScope, 'bot-unit', op);
            applyUnitBytes(scopes.instanceScope, 'activation-observed', 'bot-unit', rendered.unit, before, expectedCurrentSha256, op);
          } else {
            const before = readObject(scopes.instanceScope, 'daemon-dropin', op);
            applyUnitBytes(scopes.instanceScope, 'activation-observed', 'daemon-dropin', rendered.dropin, before, expectedCurrentSha256, op);
          }
        }
        if (replayTarget !== 'reload-arm') {
          actionMutation('activation-observed', op,
            () => daemonReload(op),
            () => showUnit(names.unitName, op).NeedDaemonReload === 'no',
            'activation-observed:daemon-reload:arm');
        }
      });
      const siblingAfter = snapshotSiblings(siblings, op);
      assertSiblingsUnchanged(siblingBefore, siblingAfter, op);
      const finalFingerprint = linuxServiceResourceFingerprint(expectedDescriptor(
        component === 'bot'
          ? { unit: rendered.unit }
          : { template: unitTemplates.daemonTemplate, dropin: rendered.dropin },
        'owned',
      ));
      if (![
        transaction.transition.expectedAfterResourceFingerprint,
        transaction.transition.expectedBeforeResourceFingerprint,
      ].includes(finalFingerprint)) {
        fail('SERVICE_MANUAL_CLEANUP', op, driverWrites, true, 'resource-drift');
      }
      const finalObservation = assertFinalActivation(
        op, 'final-restart-armed', linuxServiceResourceFingerprint(expectedDescriptor(
          component === 'bot'
            ? { unit: rendered.unit }
            : { template: unitTemplates.daemonTemplate, dropin: rendered.dropin },
          'absent',
        )),
      );
      return finalObservation;
    },

    /**
     * Boot-activation linearization point: creates only the exact proof-owned
     * multi-user.target.wants link, then queries the complete effective unit
     * and requires the declared final resource fingerprint.
     */
    enableFinal() {
      const op = 'enable_final';
      removalTombstones = new Map();
      const allowedActionTargets = new Set(['link-publish', 'reload-enable']);
      let transaction = assertHead(op, [
        { phase: 'activation-observed', substep: 'observed' },
        { phase: 'activation-observed', substep: 'intent' },
        { phase: 'activation-observed', substep: 'action' },
      ], (discriminator) => discriminator.startsWith('activation-observed:') &&
        allowedActionTargets.has(actionTarget(discriminator)));
      const pending = pendingAction(op, allowedActionTargets);
      if (pending !== null) {
        withScopes('mutate', op, (scopes) => {
          dispatchPendingAction(scopes, 'activation-observed', op, pending);
        });
        transaction = journalState().latest;
      }
      requireLiveIdentityReceipts(op);
      assertFreshReceipt(op, transaction);
      // Boot activation requires the armed final resource first; creating the
      // link over a still-trialing Restart=no resource is refused before any
      // mutation.
      const pre = probeWith(op);
      assertCompleteResourceReceipts(component, op, { objects: pre.objects });
      if (pre.platformPhase === null) {
        fail('SERVICE_MANUAL_CLEANUP', op, driverWrites, true,
          pre.driftReasons[0] ?? 'resource-drift');
      }
      if (pre.platformPhase !== 'final-restart-armed' && pre.platformPhase !== 'final') {
        fail('SERVICE_STALE', op, driverWrites, false, 'resource-drift');
      }
      if (!transactionResourcePredicate(transaction, 'final', pre.resourceFingerprint, undefined,
        pre.resourceFingerprint)) {
        fail('SERVICE_MANUAL_CLEANUP', op, driverWrites, true, 'resource-drift');
      }
      withScopes('mutate', op, (scopes) => {
        const current = readAllObjects(scopes, op);
        // This is the fresh in-scope pre-mutation snapshot.  It must be
        // receipt-complete before the directory/link/reload sequence starts;
        // the post-link snapshot below remains mandatory as well.
        assertCompleteResourceReceipts(component, op, { objects: current });
        ensureEnablementDirectory(scopes, 'activation-observed', op);
        const complete = readAllObjects(scopes, op);
        assertCompleteResourceReceipts(component, op, { objects: complete });
        const link = readObject(scopes.instanceScope, 'enablement-link', op);
        if (linkAbsent(link)) {
          assertIntentionalAbsence('enablement-link', 'activation-observed',
            'activation-observed:publish:enablement-link', op);
          actionMutation('activation-observed', op,
            () => publishObject(scopes.instanceScope, 'enablement-link', null, null, op),
            () => {
              const after = readObject(scopes.instanceScope, 'enablement-link', op);
              return after.state === 'symlink' && after.target === names.linkTarget;
            }, 'activation-observed:publish:enablement-link');
        } else if (link.state !== 'symlink') {
          fail('SERVICE_MANUAL_CLEANUP', op, driverWrites, true, 'activation-drift');
        } else {
          // A same-target link is still a physical object. Never treat a
          // recreated link as an idempotent enablement success.
          if (!reconcilePendingAction('activation-observed', op, () => {
            const after = readObject(scopes.instanceScope, 'enablement-link', op);
            return after.state === 'symlink' && after.target === names.linkTarget;
          }, 'activation-observed:publish:enablement-link')) requireIdentityReceipt('enablement-link', link, op);
        }
        const postLink = readAllObjects(scopes, op);
        assertCompleteResourceReceipts(component, op, { objects: postLink });
        if (pending === null || actionTarget(pending.discriminator) !== 'reload-enable') {
          actionMutation('activation-observed', op,
            () => daemonReload(op),
            () => showUnit(names.unitName, op).NeedDaemonReload === 'no',
            'activation-observed:daemon-reload:enable');
        }
      });
      const observation = assertFinalActivation(op, 'final', undefined);
      // The committed endpoint must be exactly one of the two
      // transaction-declared resource fingerprints (candidate final, or the
      // exact old final on a predecessor restoration path).
      const declaredEnds = [
        transaction.transition.expectedAfterResourceFingerprint,
        transaction.transition.expectedBeforeResourceFingerprint,
      ].filter((value) => isHex64(value));
      if (!declaredEnds.includes(observation.resourceFingerprint)) {
        fail('SERVICE_MANUAL_CLEANUP', op, driverWrites, true, 'resource-drift');
      }
      return observation;
    },

    /**
     * Supervisor-first exact stop with bounded lineage proof. Never kills by
     * image name; force is limited to the revalidated systemd cgroup with the
     * exact device/inode/tree CAS. Survivors or ambiguity stay suppressed and
     * surface as manual-cleanup-class failures.
     */
    async stopAndQuiesce(input = {}) {
      const op = 'stop_and_quiesce';
      removalTombstones = new Map();
      if (!plain(input) ||
          Reflect.ownKeys(input).some((key) => key !== 'deadlineMs' && key !== 'expectedResourceFingerprint')) {
        fail('SERVICE_INVALID', op, driverWrites);
      }
      const deadlineMs = input.deadlineMs ?? LINUX_DRIVER_LIMITS.stopDeadlineMs;
      if (!Number.isSafeInteger(deadlineMs) || deadlineMs < 1 ||
          deadlineMs > LINUX_DRIVER_LIMITS.stopDeadlineMs ||
          (Object.hasOwn(input, 'expectedResourceFingerprint') &&
            !isHex64(input.expectedResourceFingerprint))) {
        fail('SERVICE_INVALID', op, driverWrites);
      }
      const transaction = assertHead(op, STOPPABLE_HEADS,
        (discriminator) => discriminator.startsWith('stopping:'));
      requireLiveIdentityReceipts(op);
      const pendingStopAction = transaction.phase === 'stopping' && transaction.substep === 'action';
      const pendingStopDiscriminator = pendingStopAction
        ? actionDiscriminators.get(transaction.transactionFingerprint)
        : null;
      if (pendingStopAction &&
          pendingStopDiscriminator !== 'stopping:stop_and_quiesce' &&
          pendingStopDiscriminator !== 'stopping:terminate-cgroup') {
        fail('SERVICE_PENDING', op, driverWrites);
      }
      if (!pendingStopAction) journalAppend('stopping', 'intent');
      const before = probeWith(op);
      assertCompleteResourceReceipts(component, op, { objects: before.objects });
      if (before.platformPhase === null) {
        fail('SERVICE_MANUAL_CLEANUP', op, driverWrites, true,
          before.driftReasons[0] ?? 'resource-drift');
      }
      // The stopped resource must be the exact T state: the
      // journal-declared candidate fingerprint by default, or the
      // caller-pinned exact old T fingerprint when stopping a restored
      // predecessor.
      const expectedResource = transaction.transition.platformResourceFingerprint;
      if (!transactionResourcePredicate(transaction, 'stopping', before.resourceFingerprint,
        Object.hasOwn(input, 'expectedResourceFingerprint')
          ? input.expectedResourceFingerprint : undefined)) {
        fail('SERVICE_MANUAL_CLEANUP', op, driverWrites, true, 'resource-drift');
      }
      const live = liveEpoch(op);
      // A stopping/action head means systemctl stop may already have run.
      // Never issue a second stop when the post-stop state is not provably
      // quiescent; the current root is an unresolved crash boundary.
      const pendingCgroup = pendingStopAction
        ? nativeCall('read_linux_service_cgroup', names.cgroupPath)
        : null;
      if (pendingStopAction && pendingCgroup !== null &&
          cgroupMemberFingerprint(pendingCgroup) === null) {
        fail('SERVICE_PENDING', op, driverWrites, true, 'tree-not-quiescent');
      }
      if (pendingStopAction &&
          (live !== null || before.manager.ActiveState === 'active' ||
            parseShowPid(before.manager.MainPID) > 0 ||
            (pendingCgroup !== null && pendingCgroup.processCount > 0))) {
        fail('SERVICE_PENDING', op, driverWrites, true, 'tree-not-quiescent');
      }
      if (live !== null && !lineageMatches(live)) {
        // Never stop a tree that is not the exact T-bound lineage.
        fail('SERVICE_MANUAL_CLEANUP', op, driverWrites, true, 'resource-drift');
      }
      const beforeCgroup = live === null
        ? pendingCgroup
        : nativeCall('read_linux_service_cgroup', names.cgroupPath);
      if (live !== null && (beforeCgroup === null || cgroupMemberFingerprint(beforeCgroup) === null ||
          !beforeCgroup.processes.some((process) => process.pid === live.mainPid) ||
          processFactsFingerprint(live.treeProcesses ?? []) !== processFactsFingerprint(beforeCgroup.processes))) {
        fail('SERVICE_MANUAL_CLEANUP', op, driverWrites, true, 'resource-drift');
      }
      let forced = false;
      let terminated = 0;
      if (pendingStopDiscriminator === 'stopping:terminate-cgroup') {
        // A crash after the force action has a distinct replay edge.  Only an
        // exact empty post-state may advance it; never issue a second force or
        // supervisor stop from this head.
        const killedNow = actionMutation('stopping', op, () => {}, () => {
          const after = nativeCall('read_linux_service_cgroup', names.cgroupPath);
          return after === null || (
            cgroupMemberFingerprint(after) !== null && after.processCount === 0
          );
        }, 'stopping:terminate-cgroup');
        if (!killedNow) {
          forced = true;
          terminated = 0;
        }
      } else if (live !== null) {
        if (journalState().latest.substep === 'intent') {
          journalAppend('stopping', 'action');
          actionDiscriminators.set(
            journalState().latest.transactionFingerprint,
            'stopping:stop_and_quiesce',
          );
        }
        const stopped = runArgv([SYSTEMCTL, 'stop', names.unitName], op);
        if (stopped.code !== 0) fail('SERVICE_IO_FAILED', op, driverWrites, true);
        const start = nowMs();
        for (;;) {
          const manager = showUnit(names.unitName, op);
          const cgroup = nativeCall('read_linux_service_cgroup', names.cgroupPath);
          if (cgroup !== null && cgroupMemberFingerprint(cgroup) === null) {
            fail('SERVICE_MANUAL_CLEANUP', op, driverWrites, true, 'tree-not-quiescent');
          }
          if (cgroup !== null && cgroup.processCount > 0 && beforeCgroup !== null &&
              cgroupMemberFingerprint(cgroup) !== cgroupMemberFingerprint(beforeCgroup)) {
            fail('SERVICE_MANUAL_CLEANUP', op, driverWrites, true, 'tree-not-quiescent');
          }
          const quiet = (manager.ActiveState === 'inactive' || manager.ActiveState === 'failed') &&
            (cgroup === null || cgroup.processCount === 0);
          if (quiet) break;
          if (nowMs() - start >= deadlineMs) {
            const exact = nativeCall('read_linux_service_cgroup', names.cgroupPath);
            if (exact === null) break;
            if (cgroupMemberFingerprint(exact) === null) {
              fail('SERVICE_MANUAL_CLEANUP', op, driverWrites, true, 'tree-not-quiescent');
            }
            if (exact.processCount === 0) break;
            if (!exactKeys(exact, CGROUP_KEYS) ||
                !exactKeys(exact.identity, ['device', 'inode']) ||
                !isHex64(exact.treeFingerprint) || cgroupMemberFingerprint(exact) === null ||
                (beforeCgroup !== null && cgroupMemberFingerprint(exact) !== cgroupMemberFingerprint(beforeCgroup))) {
              fail('SERVICE_MANUAL_CLEANUP', op, driverWrites, true, 'tree-not-quiescent');
            }
            // The stop action has an exact (still-live) observation.  Force
            // termination is a separate native action, never grouped under
            // the systemctl stop edge.
            withScopes('mutate', op, (scopes) => {
              const current = readAllObjects(scopes, op);
              assertCompleteResourceReceipts(component, op, { objects: current });
            });
            journalAppend('stopping', 'observed');
            let killed;
            const killedNow = actionMutation('stopping', op,
              () => {
                killed = nativeCall(
                  'terminate_linux_service_cgroup',
                  names.cgroupPath,
                  exact.identity.device,
                  exact.identity.inode,
                  exact.treeFingerprint,
                );
              },
              () => {
                const after = nativeCall('read_linux_service_cgroup', names.cgroupPath);
                return after === null || after.processCount === 0;
              }, 'stopping:terminate-cgroup');
            if (!killedNow) killed = { tree: 'empty', forced: true, terminated: 0, writes: 0 };
            if (!exactKeys(killed, ['tree', 'forced', 'terminated', 'writes']) ||
                killed.tree !== 'empty' || killed.forced !== true ||
                !Number.isSafeInteger(killed.terminated) || killed.terminated < 0 ||
                killed.terminated > exact.processCount) {
              fail('SERVICE_MANUAL_CLEANUP', op, driverWrites, true, 'tree-not-quiescent');
            }
            forced = true;
            terminated = killed.terminated;
            break;
          }
          await sleepMs(LINUX_DRIVER_LIMITS.stopPollMs);
        }
      }
      const finalManager = showUnit(names.unitName, op);
      const finalCgroup = nativeCall('read_linux_service_cgroup', names.cgroupPath);
      if (finalCgroup !== null && cgroupMemberFingerprint(finalCgroup) === null) {
        fail('SERVICE_TREE_SURVIVOR', op, driverWrites, true, 'tree-not-quiescent');
      }
      if ((finalManager.ActiveState !== 'inactive' && finalManager.ActiveState !== 'failed') ||
          (finalCgroup !== null && finalCgroup.processCount !== 0)) {
        fail('SERVICE_TREE_SURVIVOR', op, driverWrites, true, 'tree-not-quiescent');
      }
      journalAppend('stopping', 'observed');
      journalAppend('quiescent', 'intent');
      journalAppend('quiescent', 'observed');
      return freezeDeep({ forced, terminated });
    },

    /**
     * Removes the exact owned unit/drop-in/enablement objects after
     * quiescence. The shared daemon template itself is never removed here;
     * see removeSharedTemplate.
     */
    removeResource(input) {
      const op = 'remove_linux_resource';
      if (!exactKeys(input, ['expectedCurrentSha256', 'siblings'])) {
        fail('SERVICE_INVALID', op, driverWrites);
      }
      const removalHead = journalState().latest;
      if (!(removalHead.phase === 'resource-removed' && removalHead.substep === 'action')) {
        removalTombstones = new Map();
      }
      const { expectedCurrentSha256, siblings } = input;
      if (expectedCurrentSha256 !== null && !isHex64(expectedCurrentSha256)) {
        fail('SERVICE_INVALID', op, driverWrites);
      }
      const allowedActionTargets = new Set(['link-remove',
        component === 'bot' ? 'bot-unit-remove' : 'dropin-remove',
        ...(component === 'daemon' ? ['dropin-directory-remove'] : []), 'reload']);
      assertHead(op, [
        { phase: 'quiescent', substep: 'observed' },
        { phase: 'tombstoned', substep: 'observed' },
        { phase: 'resource-removed' },
      ], (discriminator) => discriminator.startsWith('resource-removed:') &&
        allowedActionTargets.has(actionTarget(discriminator)));
      const pending = pendingAction(op, allowedActionTargets);
      requireLiveIdentityReceipts(op);
      validateSiblings(siblings, op);
      const siblingBefore = snapshotSiblings(siblings, op);
      let replayTarget = null;
      const resolvedRemoval = { value: null };
      withScopes('mutate', op, (scopes) => {
        replayTarget = dispatchPendingAction(scopes, 'resource-removed', op, pending, resolvedRemoval);
        const current = readAllObjects(scopes, op);
        assertCompleteResourceReceipts(component, op, {
          objects: current, replayTarget, resolvedRemoval: resolvedRemoval.value,
        });
        const currentFingerprint = linuxServiceResourceFingerprint(observedDescriptor(current));
        const removalReplayState = replayTarget === 'bot-unit-remove'
          ? component === 'bot' && linkAbsent(current.botUnit) && linkAbsent(current.enablementLink)
          : replayTarget === 'dropin-remove'
            ? component === 'daemon' && current.template?.state === 'file' &&
              current.template.bytes.equals(unitTemplates.daemonTemplate) &&
              linkAbsent(current.dropin) && current.dropinDirectory?.state === 'directory' &&
              linkAbsent(current.enablementLink)
            : replayTarget === 'dropin-directory-remove'
              ? component === 'daemon' && current.template?.state === 'file' &&
                current.template.bytes.equals(unitTemplates.daemonTemplate) &&
                linkAbsent(current.dropin) && linkAbsent(current.dropinDirectory) &&
                linkAbsent(current.enablementLink)
              : false;
        if (!transactionResourcePredicate(journalState().latest, 'resource-removed',
          currentFingerprint, undefined) && !removalReplayState) {
          fail('SERVICE_MANUAL_CLEANUP', op, driverWrites, true, 'resource-drift');
        }
        const link = readObject(scopes.instanceScope, 'enablement-link', op);
        if (link.state === 'symlink') {
          actionMutation('resource-removed', op,
            () => removeObject(scopes.instanceScope, 'enablement-link', link, op),
            () => linkAbsent(readObject(scopes.instanceScope, 'enablement-link', op)),
            'resource-removed:remove:enablement-link');
        } else if (!linkAbsent(link)) {
          fail('SERVICE_MANUAL_CLEANUP', op, driverWrites, true, 'activation-drift');
        } else {
          assertIntentionalAbsence('enablement-link', 'resource-removed',
            'resource-removed:remove:enablement-link', op);
          reconcilePendingAction('resource-removed', op,
            () => linkAbsent(readObject(scopes.instanceScope, 'enablement-link', op)),
            'resource-removed:remove:enablement-link');
        }
        if (component === 'bot') {
          const before = readObject(scopes.instanceScope, 'bot-unit', op);
          removeUnitBytes(scopes.instanceScope, 'resource-removed', 'bot-unit', before, expectedCurrentSha256, op);
        } else {
          const before = readObject(scopes.instanceScope, 'daemon-dropin', op);
          removeUnitBytes(scopes.instanceScope, 'resource-removed', 'daemon-dropin', before, expectedCurrentSha256, op);
          const directory = readObject(scopes.instanceScope, 'daemon-dropin-directory', op);
          if (directory.state === 'directory') {
            actionMutation('resource-removed', op,
              () => removeObject(scopes.instanceScope, 'daemon-dropin-directory', directory, op),
              () => linkAbsent(readObject(scopes.instanceScope, 'daemon-dropin-directory', op)),
              'resource-removed:remove:daemon-dropin-directory');
          } else if (directory.state !== 'absent') {
            fail('SERVICE_MANUAL_CLEANUP', op, driverWrites, true, 'resource-drift');
        } else {
            reconcilePendingAction('resource-removed', op,
              () => linkAbsent(readObject(scopes.instanceScope, 'daemon-dropin-directory', op)),
              'resource-removed:remove:daemon-dropin-directory');
          }
        }
        if (replayTarget !== 'reload') {
          actionMutation('resource-removed', op,
            () => daemonReload(op),
            () => showUnit(names.unitName, op).NeedDaemonReload === 'no',
            'resource-removed:daemon-reload');
        }
      });
      const siblingAfter = snapshotSiblings(siblings, op);
      assertSiblingsUnchanged(siblingBefore, siblingAfter, op);
      const observation = probeWith(op);
      verifyExactState(observation, 'absent', undefined, op);
      return observation;
    },

    /**
     * Removes the exact invariant daemon template only after the last
     * instance reference is gone. Requires the caller's zero-reference
     * evidence binding the exact on-disk template fingerprint; this service's
     * own reference record must no longer carry a shared-template binding.
     * Drifted or foreign template bytes are never removed. Cross-instance
     * reference enumeration is a confirmed slice-11 store gap; the evidence
     * object is the integration seam for it.
     */
    removeSharedTemplate(input) {
      const op = 'remove_shared_template';
      if (!exactKeys(input, ['evidence'])) fail('SERVICE_INVALID', op, driverWrites);
      // G004 integration seam: this slice has no store-issued opaque
      // zero-reference receipt/revision.  A caller-shaped {kind,
      // templateFingerprint} object is not authority and must never authorize
      // deleting the shared template.  Keep the operation pending/manual
      // until the store accessor supplies that opaque receipt.
      if (component !== 'daemon') {
        fail('SERVICE_INVALID', op, driverWrites);
      }
      fail('SERVICE_PENDING', op, driverWrites, false, 'template-referenced');
    },

    /**
     * Read-only controller-loss/reboot recovery classification. Revalidates
     * the transition proof, activation graph, boot identity, invocation, and
     * tree against the durable journal head and returns the closed recovery
     * classification. It never stops anything by itself and never claims a
     * dead controller stopped a process.
     */
    recoverTrialState() {
      const op = 'recover_trial_state';
      assertActionReplayGate(op);
      const { latest } = journalState();
      const trialPhases = ['trial-start-intent', 'trial-start-observed', 'starting'];
      const preTrialPhases = ['transition-marker-intent', 'quiescent', 'resource-published'];
      const activationPhases = ['startup-observed', 'activation-observed'];
      if (![...trialPhases, ...preTrialPhases, ...activationPhases].includes(latest.phase)) {
        return freezeDeep({ classification: 'not-in-trial', phase: latest.phase });
      }
      // A fresh controller has no trusted physical baseline.  Do not probe
      // native objects and accidentally mint one while classifying recovery.
      if (objectIdentityReceipts.size === 0) {
        return freezeDeep({
          classification: 'manual-cleanup',
          phase: latest.phase,
          reason: 'recreated-resource',
        });
      }
      const observation = probeWith(op, false);
      if (!transactionResourcePredicate(latest, 'recovery',
        observation.platformPhase === 'absent' ? null : observation.resourceFingerprint, undefined)) {
        return freezeDeep({
          classification: 'manual-cleanup',
          phase: latest.phase,
          reason: 'resource-drift',
        });
      }
      // T/activation-graph revalidation: the observed resource must be a
      // closed exact state carrying a release fingerprint this transaction
      // declares (candidate or old); anything else is drift.
      const parsedRelease = parseReleaseFingerprint(observation.objects, component);
      const declaredRelease = parsedRelease !== null &&
        (parsedRelease === latest.candidate.applicationManifestFingerprint ||
          (latest.old.applicationManifestFingerprint !== null &&
            parsedRelease === latest.old.applicationManifestFingerprint));
      const absentResource = observation.platformPhase === 'absent';
      const trialResource = latest.transition.platformResourceFingerprint;
      const predecessorResource = latest.operation !== 'install' &&
        latest.operation !== 'uninstall' &&
        isHex64(latest.transition.expectedBeforeResourceFingerprint) &&
        latest.old.applicationManifestFingerprint !== null &&
        parsedRelease === latest.old.applicationManifestFingerprint &&
        observation.resourceFingerprint === latest.transition.expectedBeforeResourceFingerprint &&
        observation.platformPhase === 'final';
      const declaredResources = new Set([
        trialResource,
        latest.transition.expectedBeforeResourceFingerprint,
        latest.transition.expectedAfterResourceFingerprint,
      ].filter((value) => isHex64(value)));
      const activationResource = latest.phase === 'activation-observed' &&
        declaredResources.has(observation.resourceFingerprint);
      const exactResource = latest.phase === 'activation-observed'
        ? declaredRelease && activationResource &&
          (observation.platformPhase === 'trial' ||
            observation.platformPhase === 'final-restart-armed' ||
            observation.platformPhase === 'final')
        : latest.phase === 'transition-marker-intent' || latest.phase === 'quiescent'
          ? absentResource || predecessorResource
          : declaredRelease && observation.resourceFingerprint === trialResource &&
            observation.platformPhase === 'trial';
      if (!exactResource) {
        return freezeDeep({
          classification: 'manual-cleanup',
          phase: latest.phase,
          reason: 'resource-drift',
        });
      }
      // A predecessor continuation is safe only when this live session has
      // already observed every object it would rely on.  Durable journal
      // bytes and fresh same-content objects are insufficient authority after
      // a restart; return without mutation and require manual cleanup.
      if (predecessorResource && !objectReceiptsPresent(observation.objects,
        component === 'bot'
          ? ['botUnit', 'enablementLink']
          : ['template', 'dropinDirectory', 'dropin', 'enablementLink'])) {
        return freezeDeep({
          classification: 'manual-cleanup',
          phase: latest.phase,
          reason: 'recreated-resource',
        });
      }
      const live = liveEpoch(op);
      let lineage = lineageMatches(live);
      if (lineage && live !== null) {
        const cgroup = nativeCall('read_linux_service_cgroup', names.cgroupPath);
        lineage = cgroup !== null && cgroupMatchesTree(cgroup, {
          processes: live.treeProcesses,
          treeFingerprint: live.treeFingerprint,
          processCount: live.treeProcesses?.length ?? 0,
        }, live.mainPid);
      }
      if (absentResource && live !== null) {
        return freezeDeep({
          classification: 'manual-cleanup',
          phase: latest.phase,
          reason: 'resource-drift',
        });
      }
      if (latest.phase === 'startup-observed' || latest.phase === 'activation-observed') {
        const receipt = session.readStartupProof();
        if (!receipt.present) {
          return freezeDeep({
            classification: 'manual-cleanup',
            phase: latest.phase,
            reason: 'startup-receipt-invalidated',
          });
        }
        const proof = receipt.value;
        const expectedApplication = proof?.applicationManifestFingerprint;
        const expectedResourceProof = expectedApplication === latest.candidate.applicationManifestFingerprint
          ? latest.final.resourceProof
          : expectedApplication === latest.old.applicationManifestFingerprint
            ? latest.old.resourceProof
            : null;
        if (!plain(proof) || proof.transactionId !== latest.transactionId ||
            proof.component !== component || proof.serviceKey !== serviceKey ||
            proof.platform !== 'linux' || proof.architecture !== architecture ||
            proof.serviceGeneration !== latest.serviceGeneration ||
            !isHex64(expectedResourceProof) || proof.resourceProof !== expectedResourceProof ||
            proof.platformState?.phase !== 'trial') {
          return freezeDeep({
            classification: 'manual-cleanup',
            phase: latest.phase,
            reason: 'startup-receipt-invalidated',
          });
        }
        let evidenceOk = true;
        if (live !== null && lineage) {
          const trialEntry = [...session.readJournal().entries]
            .reverse().find((entry) => entry.phase === 'trial-start-observed' &&
              entry.substep === 'observed');
          if (!trialEntry) {
            evidenceOk = false;
          } else {
            const currentCgroup = nativeCall('read_linux_service_cgroup', names.cgroupPath);
            const currentTree = {
              processes: live.treeProcesses,
              treeFingerprint: live.treeFingerprint,
              processCount: live.treeProcesses?.length ?? 0,
            };
            const currentCursor = journalCursor(names.unitName, op);
            evidenceOk = cgroupMatchesTree(currentCgroup, currentTree, live.mainPid) &&
              proof.platformEvidenceFingerprint === platformEvidenceFingerprint({
                unitName: names.unitName,
                transactionFingerprint: trialEntry.transactionFingerprint,
                invocationId: live.invocationId,
                mainPid: live.mainPid,
                cgroupPath: names.cgroupPath,
                cgroupIdentity: currentCgroup.identity,
                cgroupTreeFingerprint: currentCgroup.treeFingerprint,
                cgroupMemberFingerprint: cgroupMemberFingerprint(currentCgroup),
                // The cursor is the only durable log boundary available to a
                // fresh controller; a changed cursor therefore invalidates
                // the persisted platform-evidence fingerprint.
                preStartCursor: currentCursor,
              });
          }
        }
        const epochOk = live !== null && lineage && evidenceOk &&
          proof.processEpochFingerprint === processEpochFingerprint(live) &&
          proof.bootFingerprint === bootFingerprint(observation.bootId);
        const now = nowMs();
        const fresh = epochOk && Number.isSafeInteger(now) && now <= proof.expiresAtMs;
        if (fresh) {
          return freezeDeep({ classification: 'resume-activation', phase: latest.phase });
        }
        // Reboot, a new invocation, or an expired receipt invalidates the
        // startup evidence; recovery resuppresses, stops the exact tree when
        // provable, and retrials rather than declaring readiness
        // retrospectively.
        if (live === null) {
          return freezeDeep({ classification: 'resuppress-and-retrial', phase: latest.phase });
        }
        return freezeDeep({
          classification: lineage ? 'resuppress-and-retrial' : 'manual-cleanup',
          phase: latest.phase,
          ...(lineage ? {} : { reason: 'resource-drift' }),
        });
      }
      if (preTrialPhases.includes(latest.phase)) {
        // No trial intent was journaled yet: a running tree is unexpected
        // activation that may be stopped only with exact T-bound lineage.
        if (live === null) {
          return freezeDeep({ classification: 'continue', phase: latest.phase });
        }
        return freezeDeep({
          classification: lineage ? 'stop-and-continue' : 'manual-cleanup',
          phase: latest.phase,
          ...(lineage ? {} : { reason: 'resource-drift' }),
        });
      }
      // trial-start-intent / trial-start-observed / starting: no durable gate
      // boundary exists, so a running tree is unexpected activation that may
      // be stopped only with the exact T-bound lineage.
      if (live === null) {
        return freezeDeep({ classification: 'retrial', phase: latest.phase });
      }
      return freezeDeep({
        classification: lineage ? 'stop-and-retrial' : 'manual-cleanup',
        phase: latest.phase,
        ...(lineage ? {} : { reason: 'resource-drift' }),
      });
    },
  };

  return Object.freeze(api);
}
