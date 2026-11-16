import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import {
  SCM_APPROVALS, SCM_CHANGE_SCOPE, SCM_POLICY, parseScmArguments, prepareScmFixture, runScmScenario,
} from '../test-fixtures/service-scm-scenario.mjs';
import { windowsServiceRuntimePolicyFingerprint } from '../src/service-windows.js';

const hex = (character) => character.repeat(64);
const roles = {
  management: { kind: 'sid', value: 'S-1-5-21-111-222-333-1001' },
  bot: { kind: 'sid', value: 'S-1-5-21-111-222-333-1002' },
  recovery: { kind: 'sid', value: 'S-1-5-21-111-222-333-1003' },
  daemon: { kind: 'sid', value: 'S-1-5-21-111-222-333-1004' },
  system: { kind: 'sid', value: 'S-1-5-18' },
};

function input(hostMode = 'general-host', component = 'bot') {
  const key = component === 'bot' ? 'bot' : `host-${hex('1')}`;
  const daemon = component === 'daemon';
  const launch = {
    supervisorPath: `C:\\GJC\\shawl\\${hex('a')}\\shawl.exe`, supervisorSha256: hex('a'),
    workingDirectory: `C:\\GJC\\${component}`, homeDirectory: `C:\\GJC\\home\\${component}`,
    runtimePath: daemon ? 'C:\\GJC\\bun.exe' : 'C:\\GJC\\node.exe', runtimeSha256: hex('b'),
    runtimeVersion: daemon ? '1.4.2' : '26.7.0',
    runtimeSourceRevision: daemon ? '744846f844374847c902b5e7fd59b4342a51ef99' : 'b4f23d3619c98bed09af93a21192f6080197a8c6',
    entrypointPath: `C:\\GJC\\release\\${component}.js`, entrypointSha256: hex('c'),
    bootstrapPath: 'C:\\GJC\\service-bootstrap.js', bootstrapSha256: hex('d'),
    bootstrapClosureFingerprint: hex('e'),
    runtimeConfigRoot: daemon ? 'C:\\GJC\\daemon\\runtime-config' : null,
    runtimeConfigRootIdentityFingerprint: daemon ? hex('2') : null,
    runtimeConfigPath: daemon ? 'C:\\GJC\\daemon\\runtime-config\\.bunfig.toml' : null,
    runtimeConfigSha256: daemon ? 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855' : null,
    runtimeConfigIdentityFingerprint: daemon ? hex('3') : null,
    sdkProfilePath: daemon ? 'C:\\GJC\\profile' : null,
    scopeFingerprint: hex('4'), logDirectory: `C:\\GJC\\logs\\${component}`,
    logAs: daemon ? `gjc-remote-daemon-${key}-wrapper` : 'gjc-remote-bot-wrapper',
    logCmdAs: daemon ? `gjc-remote-daemon-${key}-child` : 'gjc-remote-bot-child',
    channelsConfig: daemon ? null : 'C:\\GJC\\channels.json',
    effectiveConfigFingerprint: hex('5'), configSourceIdentityFingerprint: hex('6'),
  };
  launch.runtimePolicyFingerprint = windowsServiceRuntimePolicyFingerprint(launch, component, key);
  return {
    schemaVersion: 1, hostMode, acknowledgement: SCM_APPROVALS[hostMode], platform: 'win32-x64',
    evidenceKind: `real-${hostMode}`, serviceName: daemon ? `GJCRemoteDaemon-${key}` : 'GJCRemoteBot',
    serviceRole: component, roles: structuredClone(roles), launch, servicePassword: 'private-password',
    transitionProof: hex('7'), changeScope: [...SCM_CHANGE_SCOPE],
  };
}
const bytes = (value) => Buffer.from(JSON.stringify(value));
const prepare = (value = input(), mode = value.hostMode) => prepareScmFixture(bytes(value), mode);
const nativeError = (code, writes = 0, message = 'private-password C:\\private\\secret') => Object.assign(new Error(message), { code, writes, ambiguous: true });

function fake(fixture, options = {}) {
  const calls = [];
  const created = {};
  const query = {};
  let exists = options.collision ?? false;
  let deleted = false;
  let retained = false;
  let config = 0;
  let snapshot;
  let pendingCalls = 0;
  const record = (name, args) => {
    calls.push({ name, args });
    if (options.fail === name) throw nativeError(options.code ?? 'SERVICE_STALE', options.writes ?? 0);
  };
  const change = (startType, description, aclMatches) => {
    config += 1;
    snapshot = {
      name: fixture.serviceName, serviceRole: fixture.serviceRole, startType, description, aclMatches,
      accountMatchesRole: true, binaryPath: fixture.binaryPath, failurePolicy: 'none',
      failureActionsOnNonCrashFailures: false, configFingerprint: config.toString(16).padStart(64, '0'),
      runtime: { state: 'stopped', processId: 0, fingerprint: hex('9') },
    };
    if (options.driftAt === startType && description) snapshot.binaryPath = 'foreign command';
    return structuredClone(snapshot);
  };
  const cas = (handle, configFingerprint, runtimeFingerprint) => {
    assert.equal(handle, created, 'mutations must only use the handle created by this invocation');
    assert.equal(configFingerprint, snapshot.configFingerprint);
    assert.equal(runtimeFingerprint, snapshot.runtime.fingerprint);
  };
  const native = {
    open_win32_service(...args) {
      record('open', args);
      assert.deepEqual(args, [fixture.serviceName, fixture.serviceRole, fixture.roles, 'query']);
      if (!exists) return null;
      if (deleted) {
        pendingCalls += 1;
        if (retained && options.prematureAbsence) return null;
        if (retained || options.neverAbsent || pendingCalls <= (options.pendingPolls ?? 0)) {
          if (options.pendingHandle) return query;
          throw nativeError('SERVICE_PENDING');
        }
        exists = false;
        return null;
      }
      retained = true;
      return query;
    },
    close_win32_service(...args) {
      record('close', args);
      if (args[0] === query) retained = false;
    },
    create_win32_service_disabled(...args) {
      record('create', args);
      assert.equal(args.length, 5);
      assert.equal(args[0], fixture.serviceName);
      assert.equal(args[1], fixture.serviceRole);
      assert.equal(args[2], fixture.launch, 'Launch is the current single captured object');
      assert.equal(args[3], fixture.servicePassword);
      assert.equal(args[4], fixture.roles);
      exists = true;
      change('disabled', '', false);
      return created;
    },
    query_win32_service(...args) { record('query', args); assert.equal(args[0], created); return structuredClone(snapshot); },
    protect_win32_service(...args) {
      record('protect', args); cas(...args.slice(0, 3));
      assert.equal(args[3], `gjc-remote:v1:${fixture.transitionProof}`);
      return change('disabled', args[3], true);
    },
    set_win32_service_start_type(...args) {
      record(args[3], args); cas(...args.slice(0, 3));
      return change(args[3], snapshot.description, true);
    },
    delete_win32_service(...args) {
      record('delete', args); cas(...args);
      deleted = true;
      return options.badDeleteResult ? { deletionPending: false, writes: 1 } : { deletionPending: true, writes: 1 };
    },
    start_win32_service() { assert.fail('must never start'); },
    stop_win32_service() { assert.fail('must never stop'); },
  };
  return { native, calls, created, query };
}

async function run(fixture, options) {
  const context = fake(fixture, options);
  let elapsed = 0;
  const waits = [];
  const receipt = await runScmScenario(fixture, context.native, { fixtureSha256: hex('f') }, {
    now: () => elapsed, wait: async (ms) => { elapsed += ms; waits.push(ms); },
  });
  return { ...context, receipt, waits };
}

test('CLI requires explicit closed host-mode and fixture flags, without trust overrides', () => {
  assert.deepEqual(parseScmArguments(['--host-mode', 'general-host', '--fixture', 'protected.json']), {
    hostMode: 'general-host', fixturePath: 'protected.json',
  });
  for (const argv of [[], ['--ack-disposable-host', '--fixture', 'f'],
    ['--host-mode', 'shared', '--fixture', 'f'], ['--host-mode', 'general-host', '--fixture', ''],
    ['--host-mode', 'general-host', '--fixture', 'f', '--skip-signature']]) {
    assert.throws(() => parseScmArguments(argv));
  }
});

test('current Launch ABI, CAS chain, ordering and absence evidence for both host categories and roles', async () => {
  for (const mode of Object.keys(SCM_APPROVALS)) for (const component of ['bot', 'daemon']) {
    const fixture = prepare(input(mode, component));
    const { receipt, calls } = await run(fixture);
    assert.equal(receipt.result, 'passed');
    assert.equal(receipt.evidenceKind, `real-${mode}`);
    assert.equal(receipt.productionProvenance, 'not-verified');
    assert.equal(receipt.scope, 'native-scm-primitives-only');
    assert.equal(receipt.absenceObserved, true);
    assert.equal(receipt.deletionAccepted, true);
    assert.equal(receipt.cleanup, 'absence-proven');
    assert.equal(receipt.pendingObservation, 'SERVICE_PENDING');
    assert.equal(receipt.failure, null);
    assert.deepEqual(calls.map((call) => call.name), [
      'open', 'create', 'query', 'protect', 'demand', 'disabled', 'open', 'delete', 'open', 'close', 'open',
    ]);
  }
});

test('approval mismatch, exact schema, SID authority, topology, Launch and policy are rejected before native access', () => {
  const changes = [
    (value) => { value.hostMode = 'disposable-host'; },
    (value) => { value.acknowledgement = SCM_APPROVALS['disposable-host']; },
    (value) => { value.evidenceKind = 'real-disposable-host'; },
    (value) => { value.accountName = 'administrator'; },
    (value) => { value.extra = true; },
    (value) => { delete value.servicePassword; },
    (value) => { value.transitionProof = '7'.repeat(63); },
    (value) => { value.changeScope.push('start'); },
    (value) => { value.serviceName = 'GJCRemoteBot-extra'; },
    (value) => { value.serviceRole = 'management'; },
    (value) => { value.roles.bot = value.roles.management; },
    (value) => { value.roles.bot.value = 'S-1-5-21-01'; },
    (value) => { value.roles.system.value = 'S-1-5-19'; },
    (value) => { value.roles.bot.extra = true; },
    (value) => { value.launch.accountName = 'bad'; },
    (value) => { delete value.launch.bootstrapPath; },
    (value) => { value.launch.runtimePolicyFingerprint = hex('0'); },
    (value) => { value.launch.runtimeVersion = 'old'; },
    (value) => { value.launch.runtimePath = 'C:\\GJC\\wrong.exe'; },
    (value) => { value.launch.workingDirectory = 'C:\\GJC\\..\\foreign'; },
    (value) => { value.servicePassword = 'secret\0suffix'; },
    (value) => { value.servicePassword = '\ud800'; },
    (value) => { value.servicePassword = ''; },
    (value) => { value.servicePassword = 'p'.repeat(16 * 1024 + 1); },
  ];
  for (const change of changes) {
    const value = input(); change(value);
    assert.throws(() => prepare(value, 'general-host'));
  }
  for (const malformed of ['null', '[]', '{"schemaVersion":1,"schemaVersion":1}', '{', ' '.repeat(128 * 1024 + 1)]) {
    assert.throws(() => prepareScmFixture(Buffer.from(malformed), 'general-host'));
  }
});

test('captured fixture is immutable and never rereads mutable caller configuration', async () => {
  const value = input();
  const originalBytes = bytes(value);
  const fixture = prepareScmFixture(originalBytes, 'general-host');
  originalBytes.fill(0);
  value.serviceName = 'foreign';
  value.roles.bot.value = 'S-1-5-19';
  value.launch.runtimePath = 'foreign';
  assert.equal(Object.isFrozen(fixture.launch), true);
  assert.equal(Object.isFrozen(fixture.roles.bot), true);
  assert.throws(() => { fixture.launch.runtimePath = 'foreign'; });
  assert.equal((await run(fixture)).receipt.result, 'passed');
  await assert.rejects(() => runScmScenario(value, {}));
});

test('password null and maximum UTF-8 byte length stay within the native ABI bounds', () => {
  for (const password of [null, 'p', 'p'.repeat(16 * 1024)]) {
    const value = input(); value.servicePassword = password;
    assert.equal(prepare(value).servicePassword, password);
  }
  const value = input(); value.servicePassword = '한'.repeat(5462);
  assert.throws(() => prepare(value));
});

test('native-valid password controls and Unicode separators are preserved without disclosure', async () => {
  const controls = [
    ...Array.from({ length: 31 }, (_, index) => String.fromCharCode(index + 1)),
    ...Array.from({ length: 33 }, (_, index) => String.fromCharCode(index + 0x7f)),
    String.fromCharCode(0x2028), String.fromCharCode(0x2029),
  ].join('');
  const password = `private-prefix${controls}😀private-suffix`;
  const value = input(); value.servicePassword = password;
  const fixture = prepare(value);
  assert.equal(fixture.servicePassword, password);
  const { receipt, calls } = await run(fixture);
  assert.equal(receipt.result, 'passed');
  assert.equal(calls.find((call) => call.name === 'create').args[3], password);
  assert.equal(JSON.stringify(receipt).includes('private-prefix'), false);
});

test('password-only control allowance does not weaken any other fixture values or keys', () => {
  for (const code of [1, 9, 10, 31, 0x7f, 0x85, 0x9f, 0x2028, 0x2029]) {
    const control = String.fromCharCode(code);
    for (const change of [
      (value) => { value.serviceName += control; },
      (value) => { value.roles.bot.value += control; },
      (value) => { value.launch.homeDirectory += control; },
      (value) => { value.launch.runtimePolicyFingerprint += control; },
      (value) => { value.changeScope[0] += control; },
      (value) => { value.launch[`servicePassword${control}`] = 'value'; },
      (value) => { value.servicePassword = { nested: control }; },
    ]) {
      const value = input(); change(value);
      assert.throws(() => prepare(value));
    }
  }
  for (const password of ['prefix\0suffix', '\ud800', '\udc00']) {
    const value = input(); value.servicePassword = password;
    assert.throws(() => prepare(value));
  }
});

test('preexisting service is closed and refused without any mutation', async () => {
  const { receipt, calls } = await run(prepare(), { collision: true });
  assert.equal(receipt.result, 'failed');
  assert.equal(receipt.failure.code, 'SERVICE_ALREADY_EXISTS');
  assert.equal(receipt.mutationAttempted, false);
  assert.equal(receipt.cleanup, 'no-mutation');
  assert.deepEqual(calls.map((call) => call.name), ['open', 'close']);
});

test('native errors and CAS drift close only existing handles; never adopt or auto-delete', async () => {
  for (const fail of ['create', 'query', 'protect', 'demand', 'disabled', 'delete']) {
    const { receipt, calls, created } = await run(prepare(), { fail });
    assert.equal(receipt.result, 'failed');
    assert.equal(receipt.failure.code, 'SERVICE_STALE');
    assert.equal(receipt.cleanup, 'uncertain-manual-reconciliation-required');
    assert.equal(receipt.absenceObserved, false);
    const failIndex = calls.findIndex((call) => call.name === fail);
    assert.equal(calls.slice(failIndex + 1).every((call) => call.name === 'close'), true);
    assert.equal(calls.filter((call) => call.name === 'query').length <= 1, true);
    if (fail !== 'create') assert.equal(calls.at(-1).args[0], created);
    const serialized = JSON.stringify(receipt);
    for (const secret of ['private-password', 'C:\\\\private', roles.bot.value, 'foreign command']) {
      assert.equal(serialized.includes(secret), false);
    }
  }
  const drift = await run(prepare(), { driftAt: 'demand' });
  assert.equal(drift.receipt.result, 'failed');
  assert.equal(drift.receipt.failure.step, 'demand');
  assert.equal(drift.calls.some((call) => call.name === 'delete'), false);
  assert.equal(drift.calls.at(-1).name, 'close');
});

test('partial native creation failure cannot be interpreted as absence or trigger cleanup', async () => {
  const { receipt, calls } = await run(prepare(), { fail: 'create', code: 'SERVICE_MANUAL_CLEANUP', writes: 1 });
  assert.equal(receipt.failure.code, 'SERVICE_MANUAL_CLEANUP');
  assert.equal(receipt.serviceName, 'GJCRemoteBot');
  assert.equal(receipt.cleanup, 'uncertain-manual-reconciliation-required');
  assert.equal(receipt.absenceObserved, false);
  assert.deepEqual(calls.map((call) => call.name), ['open', 'create']);
});

test('pending deletion is not absence; polling is bounded and never mutates', async () => {
  const pending = await run(prepare(), { pendingPolls: 3 });
  assert.equal(pending.receipt.result, 'passed');
  assert.equal(pending.receipt.absenceAttempts, 3);
  assert.deepEqual(pending.waits, [SCM_POLICY.pollMs, SCM_POLICY.pollMs]);
  const timeout = await run(prepare(), { neverAbsent: true });
  assert.equal(timeout.receipt.result, 'failed');
  assert.equal(timeout.receipt.deletionAccepted, true);
  assert.equal(timeout.receipt.absenceObserved, false);
  assert.equal(timeout.receipt.failure.step, 'observe-absence');
  assert.equal(timeout.receipt.cleanup, 'uncertain-manual-reconciliation-required');
  assert.equal(timeout.receipt.absenceAttempts <= SCM_POLICY.maxPollAttempts, true);
  assert.equal(timeout.waits.length * SCM_POLICY.pollMs <= SCM_POLICY.timeoutMs, true);
  assert.equal(timeout.calls.filter((call) => call.name === 'delete').length, 1);
  const handles = await run(prepare(), { pendingHandle: true });
  assert.equal(handles.receipt.result, 'passed');
  assert.equal(handles.receipt.pendingObservation, 'query-handle');
});

test('invalid deletion receipts and premature absence while retained fail closed without re-deleting', async () => {
  for (const options of [{ badDeleteResult: true }, { prematureAbsence: true }]) {
    const { receipt, calls } = await run(prepare(), options);
    assert.equal(receipt.result, 'failed');
    assert.equal(receipt.absenceObserved, false);
    assert.equal(receipt.cleanup, 'uncertain-manual-reconciliation-required');
    assert.equal(calls.filter((call) => call.name === 'delete').length, 1);
    assert.equal(calls.at(-1).name, 'close');
  }
});

test('close failures remain explicit uncertainty and native diagnostics are redacted', async () => {
  const { receipt } = await run(prepare(), { fail: 'close', code: 'PRIVATE_PASSWORD_IS_NOT_AN_ERROR_CODE' });
  assert.equal(receipt.result, 'failed');
  assert.equal(receipt.cleanup, 'uncertain-manual-reconciliation-required');
  assert.equal(JSON.stringify(receipt).includes('private-password'), false);
  assert.equal(JSON.stringify(receipt).includes('PRIVATE_PASSWORD'), false);
});

test('production CLI pins signatures before verified load and cannot inject a fake native loader', () => {
  const source = readFileSync(new URL('../test-fixtures/service-scm.mjs', import.meta.url), 'utf8');
  const signatureIndex = source.indexOf('const signature = evaluateRequiredSignature(manifestBytes)');
  const loadIndex = source.indexOf('const native = loadVerifiedAddon(');
  const runIndex = source.indexOf('await runScmScenario(');
  assert.equal(signatureIndex >= 0 && loadIndex > signatureIndex && runIndex > loadIndex, true);
  assert.match(source, /if \(!signature\.ok\) throw/);
  assert.equal(source.includes('createRequire'), false);
  assert.equal(source.includes('local-dev'), false);
  assert.equal(source.includes('process.env'), false);
  assert.equal(source.includes('JSON.stringify(fixture)'), false);
});
