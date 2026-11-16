import assert from 'node:assert/strict';
import { setTimeout as delay } from 'node:timers/promises';
import { isCanonicalWindowsSid } from '@gjc-remote/shared/identity';
import { validateServiceRoles, SERVICE_LIFECYCLE_LIMITS } from '@gjc-remote/shared/service-lifecycle-envelope';
import { assertStrictText, parseStrictJsonBytes } from '@gjc-remote/shared/strict-json';
import {
  WINDOWS_SERVICE_ERROR_CODES, buildWindowsShawlArgv, serializeWindowsCommandLine, windowsServiceLaunchFingerprint,
  windowsServiceName,
} from '../src/service-windows.js';

export const SCM_POLICY = Object.freeze({ timeoutMs: 5000, pollMs: 50, maxPollAttempts: 101 });
export const SCM_CHANGE_SCOPE = Object.freeze([
  'create-disabled', 'protect', 'demand', 'disable', 'delete', 'observe-absence',
]);
export const SCM_APPROVALS = Object.freeze({
  'general-host': 'authorize-current-host-scm-primitives',
  'disposable-host': 'authorize-disposable-host-scm-primitives',
});
const prepared = new WeakSet();
const hex = /^[0-9a-f]{64}$/;
const passwordControlCodes = new Set([
  ...Array.from({ length: 31 }, (_, index) => index + 1),
  ...Array.from({ length: 33 }, (_, index) => index + 0x7f),
  0x2028, 0x2029,
]);
const keys = ['schemaVersion', 'hostMode', 'acknowledgement', 'platform', 'evidenceKind',
  'serviceName', 'serviceRole', 'roles', 'launch', 'servicePassword', 'transitionProof', 'changeScope'];

export function parseScmArguments(argv) {
  if (argv.length !== 4 || argv[0] !== '--host-mode' || !Object.hasOwn(SCM_APPROVALS, argv[1]) ||
      argv[2] !== '--fixture' || typeof argv[3] !== 'string' || argv[3].length === 0) {
    throw new Error('usage: node native-control/test-fixtures/service-scm.mjs --host-mode <general-host|disposable-host> --fixture <protected-fixture.json>');
  }
  return Object.freeze({ hostMode: argv[1], fixturePath: argv[3] });
}

function freeze(value) {
  if (value && typeof value === 'object') {
    for (const entry of Object.values(value)) freeze(entry);
    Object.freeze(value);
  }
  return value;
}

function assertStrictStrings(value) {
  if (typeof value === 'string') assertStrictText(value);
  else if (value && typeof value === 'object') {
    for (const entry of Object.values(value)) assertStrictStrings(entry);
  }
}

// Capture bytes once; strict parsing also rejects duplicate keys and excessive input.
// This private test seam does not load native code or make any trust decision.
export function prepareScmFixture(bytes, hostMode) {
  // Native passwords permit non-NUL controls. Parsing still validates scalar
  // strings and strict keys; every other field regains strict text below.
  const fixture = parseStrictJsonBytes(bytes, { maxBytes: 128 * 1024, maxDepth: 8, maxNodes: 512 }, {
    allowedValueControlCodes: passwordControlCodes,
  });
  assert.deepEqual(Object.keys(fixture).sort(), [...keys].sort());
  for (const [key, value] of Object.entries(fixture)) {
    if (key !== 'servicePassword') assertStrictStrings(value);
  }
  assert.equal(fixture.schemaVersion, 1);
  assert.equal(Object.hasOwn(SCM_APPROVALS, hostMode), true);
  assert.equal(fixture.hostMode, hostMode);
  assert.equal(fixture.acknowledgement, SCM_APPROVALS[hostMode]);
  assert.equal(fixture.platform, 'win32-x64');
  assert.equal(fixture.evidenceKind, `real-${hostMode}`);
  assert.deepEqual(fixture.changeScope, SCM_CHANGE_SCOPE);
  assert.equal(typeof fixture.transitionProof, 'string');
  assert.match(fixture.transitionProof, hex);
  validateServiceRoles(fixture.roles, 'win32');
  for (const role of Object.values(fixture.roles)) assert.equal(isCanonicalWindowsSid(role.value), true);
  const serviceKey = fixture.serviceRole === 'bot' ? 'bot'
    : typeof fixture.serviceName === 'string' && fixture.serviceName.startsWith('GJCRemoteDaemon-')
      ? fixture.serviceName.slice('GJCRemoteDaemon-'.length) : null;
  assert.equal(fixture.serviceName, windowsServiceName(fixture.serviceRole, serviceKey));
  if (fixture.servicePassword !== null) {
    assert.equal(typeof fixture.servicePassword, 'string');
    assert.notEqual(fixture.servicePassword.length, 0);
    assert.equal(Buffer.byteLength(fixture.servicePassword, 'utf8') <= SERVICE_LIFECYCLE_LIMITS.servicePasswordBytes, true);
    // The strict parser rejects unpaired surrogates even with allowed controls;
    // this byte bound also bounds UTF-16 units as required by Win32PasswordArg.
    assert.equal(fixture.servicePassword.includes('\0'), false);
  }
  // The exported builder enforces exact current Launch keys, runtime pins, role
  // topology and the derived runtimePolicyFingerprint before any native writes.
  const binaryPath = serializeWindowsCommandLine(buildWindowsShawlArgv({
    component: fixture.serviceRole, serviceKey, launch: fixture.launch,
  }));
  assert.equal(binaryPath.length <= 32767, true, 'Windows command line exceeds the native ABI bound');
  const result = freeze({ ...fixture, serviceKey, binaryPath,
    launchFingerprint: windowsServiceLaunchFingerprint(fixture.launch, fixture.serviceRole, serviceKey) });
  prepared.add(result);
  return result;
}

export async function runScmScenario(fixture, native, evidence = {}, timing = {}) {
  assert.equal(prepared.has(fixture), true, 'fixture must be captured and validated');
  const now = timing.now ?? (() => performance.now());
  const wait = timing.wait ?? delay;
  let handle = null;
  let retained = null;
  let mutationAttempted = false;
  let deletionAccepted = false;
  let absenceObserved = false;
  let step = 'preflight-absence';
  let failure = null;
  let closeFailed = false;
  let pendingObservation = null;
  let absenceAttempts = 0;
  const close = (value) => {
    if (value === null) return;
    try { native.close_win32_service(value); } catch { closeFailed = true; }
  };
  const open = () => native.open_win32_service(fixture.serviceName, fixture.serviceRole, fixture.roles, 'query');
  const marker = `gjc-remote:v1:${fixture.transitionProof}`;
  const check = (snapshot, startType, description, protectedAcl) => {
    assert.equal(snapshot.name, fixture.serviceName);
    assert.equal(snapshot.serviceRole, fixture.serviceRole);
    assert.equal(snapshot.startType, startType);
    assert.equal(snapshot.runtime.state, 'stopped');
    assert.equal(snapshot.runtime.processId, 0);
    assert.equal(snapshot.description, description);
    assert.equal(snapshot.accountMatchesRole, true);
    if (protectedAcl) assert.equal(snapshot.aclMatches, true);
    assert.equal(snapshot.binaryPath, fixture.binaryPath);
    assert.equal(snapshot.failurePolicy, 'none');
    assert.equal(snapshot.failureActionsOnNonCrashFailures, false);
    assert.match(snapshot.configFingerprint, hex);
    assert.match(snapshot.runtime.fingerprint, hex);
  };
  try {
    const existing = open();
    if (existing !== null) {
      close(existing);
      const error = new Error('collision');
      error.code = 'SERVICE_ALREADY_EXISTS';
      throw error;
    }
    step = 'create-disabled';
    mutationAttempted = true;
    // Current ABI: one exact Launch record, never the obsolete spread tuple.
    handle = native.create_win32_service_disabled(fixture.serviceName, fixture.serviceRole,
      fixture.launch, fixture.servicePassword, fixture.roles);
    assert.notEqual(handle, null);
    let snapshot = native.query_win32_service(handle);
    check(snapshot, 'disabled', '', false);
    step = 'protect';
    snapshot = native.protect_win32_service(handle, snapshot.configFingerprint, snapshot.runtime.fingerprint, marker);
    check(snapshot, 'disabled', marker, true);
    step = 'demand';
    snapshot = native.set_win32_service_start_type(handle, snapshot.configFingerprint, snapshot.runtime.fingerprint, 'demand');
    check(snapshot, 'demand', marker, true);
    step = 'disable';
    snapshot = native.set_win32_service_start_type(handle, snapshot.configFingerprint, snapshot.runtime.fingerprint, 'disabled');
    check(snapshot, 'disabled', marker, true);
    step = 'retain-query';
    retained = open();
    assert.notEqual(retained, null);
    step = 'delete';
    const result = native.delete_win32_service(handle, snapshot.configFingerprint, snapshot.runtime.fingerprint);
    // Successful native deletion consumes/closes the mutable handle.
    handle = null;
    deletionAccepted = true;
    assert.deepEqual(result, { deletionPending: true, writes: 1 });
    step = 'observe-pending';
    try {
      const pending = open();
      if (pending !== null) close(pending);
      assert.notEqual(pending, null, 'retained query must prevent proven absence');
      pendingObservation = 'query-handle';
    } catch (error) {
      if (error.code !== 'SERVICE_PENDING' || error.writes !== 0) throw error;
      pendingObservation = 'SERVICE_PENDING';
    }
    close(retained);
    retained = null;
    assert.equal(closeFailed, false);
    step = 'observe-absence';
    const deadline = now() + SCM_POLICY.timeoutMs;
    for (; absenceAttempts < SCM_POLICY.maxPollAttempts && now() <= deadline;) {
      absenceAttempts += 1;
      try {
        const observed = open();
        if (observed === null) { absenceObserved = true; break; }
        close(observed);
        assert.equal(closeFailed, false);
      } catch (error) {
        if (error.code !== 'SERVICE_PENDING' || error.writes !== 0) throw error;
      }
      if (absenceAttempts < SCM_POLICY.maxPollAttempts && now() < deadline) await wait(SCM_POLICY.pollMs);
    }
    assert.equal(absenceObserved, true, 'delete acceptance is not proof of absence');
  } catch (error) {
    // Never serialize native messages, assertions, paths, principals or passwords.
    failure = { step, code: WINDOWS_SERVICE_ERROR_CODES.includes(error?.code) ? error.code : 'SCM_SCENARIO_FAILED' };
  } finally {
    // No fresh snapshots, adopted mutable handles or cleanup mutations on failure.
    close(retained);
    close(handle);
  }
  if (closeFailed && !failure) failure = { step: 'close-handle', code: 'SCM_CLOSE_FAILED' };
  return {
    schemaVersion: 1, evidenceKind: fixture.evidenceKind, hostMode: fixture.hostMode,
    serviceName: fixture.serviceName, serviceRole: fixture.serviceRole,
    scope: 'native-scm-primitives-only', productionProvenance: 'not-verified',
    scenario: 'scm-create-protect-demand-disable-delete', platform: fixture.platform,
    result: failure ? 'failed' : 'passed', changeScope: [...SCM_CHANGE_SCOPE],
    launchFingerprint: fixture.launchFingerprint, transitionProof: fixture.transitionProof,
    mutationAttempted, deletionAccepted, absenceObserved, pendingObservation, absenceAttempts,
    cleanup: absenceObserved && !closeFailed ? 'absence-proven'
      : mutationAttempted || closeFailed ? 'uncertain-manual-reconciliation-required' : 'no-mutation',
    policy: SCM_POLICY, evidence, failure,
  };
}
