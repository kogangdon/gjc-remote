import test from 'node:test';
import assert from 'node:assert/strict';
import { canonicalJsonBytes } from '@gjc-remote/shared/strict-json';
import { buildServiceStatusReceipt } from '@gjc-remote/shared/service-lifecycle-envelope';
import {
  parseServiceArgv,
  parseServiceRequest,
  runServiceCli,
} from '../src/service-cli.js';

const roles = {
  management: { kind: 'uid', value: 'uid:1000' },
  bot: { kind: 'uid', value: 'uid:1001' },
  recovery: { kind: 'uid', value: 'uid:1002' },
  daemon: { kind: 'uid', value: 'uid:1003' },
  system: { kind: 'uid', value: 'uid:0' },
};
const statusRequest = { schemaVersion: 1, target: { component: 'bot' }, roles };
const bytes = (value) => canonicalJsonBytes(value);
const transaction = (operation, writes = 0) => ({
  operation,
  transactionId: 'tx-1',
  transactionFingerprint: 'a'.repeat(64),
  ...(operation === 'recover' ? {} : { serviceGeneration: 1 }),
  writes,
});
const absentStatus = () => ({
  ...buildServiceStatusReceipt({
    component: 'bot', serviceKey: 'bot', platform: 'linux', architecture: 'x64',
    serviceGeneration: 0, manifestFingerprint: null, resourceProof: null, transactionFingerprint: null,
    ownership: 'absent', service: 'missing', activation: 'disabled-not-startable', tree: 'empty',
    startupEvidence: 'none', connectivityObservation: 'unknown', providerHealth: 'unknown', workspaceHealth: 'unknown',
    supervisorProvenance: 'not-applicable', recovery: 'clean', observedAtMs: 1,
  }),
  writes: 0,
});

for (const operation of ['install', 'status', 'update', 'rollback', 'uninstall', 'recover']) {
  test(`argv admits only ${operation}`, () => assert.equal(parseServiceArgv([operation]), operation));
}

test('argv rejects unknown operations and flags', () => {
  assert.throws(() => parseServiceArgv(['shell']));
  assert.throws(() => parseServiceArgv(['status', '--json']));
});

test('status request validates closed schema and canonical bytes', () => {
  assert.deepEqual(parseServiceRequest(bytes(statusRequest), 'status', { platform: 'linux', architecture: 'x64' }), statusRequest);
  assert.throws(() => parseServiceRequest(Buffer.from('{"target":{},"schemaVersion":1,"roles":{}}'), 'status', { platform: 'linux', architecture: 'x64' }));
  assert.throws(() => parseServiceRequest(bytes({ ...statusRequest, extra: true }), 'status', { platform: 'linux', architecture: 'x64' }));
});

test('TTY is refused before lifecycle dispatch', async () => {
  let calls = 0;
  const receipt = await runServiceCli({
    argv: ['status'], input: bytes(statusRequest), stdinIsTTY: true,
    lifecycle: { status: async () => { calls += 1; return {}; } },
    platform: 'linux', architecture: 'x64',
  });
  assert.equal(receipt.status, 'refused');
  assert.equal(receipt.code, 'SERVICE_INVALID');
  assert.equal(calls, 0);
});

test('status routes read-only and normalizes writes to zero', async () => {
  let seen;
  const receipt = await runServiceCli({
    argv: ['status'], input: bytes(statusRequest),
    lifecycle: { status: async (request) => { seen = request; return absentStatus(); } },
    platform: 'linux', architecture: 'x64',
  });
  assert.equal(receipt.status, 'ok');
  assert.equal(receipt.writes, 0);
  assert.deepEqual(seen, statusRequest);
});

test('lifecycle refusal is sanitized and preserves cumulative writes', async () => {
  const hash = 'a'.repeat(64);
  const request = {
    schemaVersion: 1, target: { component: 'bot' }, roles,
    source: { kind: 'github-release', tag: 'v1.0.0' },
    expected: { serviceGeneration: 1, resourceProof: hash, currentManifestFingerprint: hash, applicationSequenceFloor: 1 },
    acceptServiceDisruption: true,
  };
  const receipt = await runServiceCli({
    argv: ['update'], input: bytes(request),
    lifecycle: { update: async () => { const error = new Error('password=secret'); error.code = 'SERVICE_STALE'; error.writes = 3; throw error; } },
    platform: 'linux', architecture: 'x64',
  });
  assert.equal(receipt.status, 'refused');
  assert.equal(receipt.code, 'SERVICE_STALE');
  assert.equal(receipt.writes, 3);
  assert.doesNotMatch(JSON.stringify(receipt), /secret/);
});

test('arbitrary mutation return schemas and unknown write counts are refused', async () => {
  const hash = 'a'.repeat(64);
  const request = {
    schemaVersion: 1, target: { component: 'bot' }, roles,
    source: { kind: 'github-release', tag: 'v1.0.0' },
    expected: { serviceGeneration: 1, resourceProof: hash, currentManifestFingerprint: hash, applicationSequenceFloor: 1 },
    acceptServiceDisruption: true,
  };
  const malformed = await runServiceCli({ argv: ['update'], input: bytes(request), platform: 'linux', architecture: 'x64', lifecycle: {
    update: async () => ({ operation: 'update', transactionId: 'tx-1', transactionFingerprint: hash, serviceGeneration: 2, writes: 'unknown' }),
  } });
  assert.equal(malformed.status, 'refused');
  assert.equal(malformed.code, 'SERVICE_INVALID');
  assert.equal(malformed.writes, 0);
});

test('a signal observed after a settled mutation does not fabricate an interruption', async () => {
  const hash = 'a'.repeat(64);
  const request = {
    schemaVersion: 1, target: { component: 'bot' }, roles,
    source: { kind: 'github-release', tag: 'v1.0.0' },
    expected: { serviceGeneration: 1, resourceProof: hash, currentManifestFingerprint: hash, applicationSequenceFloor: 1 },
    acceptServiceDisruption: true,
  };
  const controller = new AbortController();
  const receipt = await runServiceCli({ argv: ['update'], input: bytes(request), platform: 'linux', architecture: 'x64', signal: controller.signal, lifecycle: {
    update: async () => { controller.abort(); return transaction('update', 2); },
  } });
  assert.equal(receipt.status, 'ok');
  assert.equal(receipt.writes, 2);
});

test('effective configuration preflight runs before lifecycle dispatch', async () => {
  let dispatched = false;
  const hash = 'a'.repeat(64);
  const request = {
    schemaVersion: 1, target: { component: 'bot' }, roles,
    source: { kind: 'github-release', tag: 'v1.0.0' },
    expected: { serviceGeneration: 1, resourceProof: hash, currentManifestFingerprint: hash, applicationSequenceFloor: 1 },
    acceptServiceDisruption: true,
  };
  const receipt = await runServiceCli({ argv: ['update'], input: bytes(request), platform: 'linux', architecture: 'x64',
    effectiveConfigPreflight: async () => { const error = new Error('configuration unavailable'); error.code = 'SERVICE_ACCESS_DENIED'; error.writes = 0; throw error; },
    lifecycle: { update: async () => { dispatched = true; return transaction('update'); } },
  });
  assert.equal(receipt.status, 'refused');
  assert.equal(receipt.code, 'SERVICE_ACCESS_DENIED');
  assert.equal(receipt.writes, 0);
  assert.equal(dispatched, false);
});

test('configuration preflight is mutation-scoped and an abort is rechecked before dispatch', async () => {
  let preflightCalls = 0;
  let factoryCalls = 0;
  let dispatched = false;
  const controller = new AbortController();
  const statusReceipt = await runServiceCli({
    argv: ['status'], input: bytes(statusRequest), platform: 'linux', architecture: 'x64',
    effectiveConfigPreflight: async () => { preflightCalls += 1; },
    lifecycle: { status: async () => { dispatched = true; return absentStatus(); } },
  });
  assert.equal(statusReceipt.status, 'ok');
  assert.equal(preflightCalls, 0);
  assert.equal(dispatched, true);
  const updateRequest = {
    schemaVersion: 1, target: { component: 'bot' }, roles,
    source: { kind: 'github-release', tag: 'v1.0.0' },
    expected: { serviceGeneration: 1, resourceProof: 'a'.repeat(64), currentManifestFingerprint: 'a'.repeat(64), applicationSequenceFloor: 1 },
    acceptServiceDisruption: true,
  };
  const aborted = await runServiceCli({
    argv: ['update'], input: bytes(updateRequest), platform: 'linux', architecture: 'x64', signal: controller.signal,
    lifecycleFactory: async () => { factoryCalls += 1; controller.abort(); return { update: async () => { throw new Error('must not dispatch'); } }; },
  });
  assert.equal(factoryCalls, 1);
  assert.equal(aborted.code, 'SERVICE_ABORTED');
  assert.equal(aborted.writes, 0);
});

test('unknown lifecycle write counts become an explicit ambiguous refusal', async () => {
  const hash = 'a'.repeat(64);
  const updateRequest = {
    schemaVersion: 1, target: { component: 'bot' }, roles,
    source: { kind: 'github-release', tag: 'v1.0.0' },
    expected: { serviceGeneration: 1, resourceProof: hash, currentManifestFingerprint: hash, applicationSequenceFloor: 1 },
    acceptServiceDisruption: true,
  };
  const receipt = await runServiceCli({
    argv: ['update'], input: bytes(updateRequest), platform: 'linux', architecture: 'x64',
    lifecycle: { update: async () => { throw Object.assign(new Error('unknown'), { code: 'SERVICE_STALE', writes: 'unknown' }); } },
  });
  assert.deepEqual(receipt, { status: 'refused', operation: 'update', code: 'SERVICE_INVALID', message: 'service request is invalid', writes: 0, ambiguous: true });
});

test('all six operations route only after schema validation', async () => {
  const hash = 'a'.repeat(64);
  const common = { schemaVersion: 1, target: { component: 'bot' }, roles };
  const requests = {
    install: { ...common, source: { kind: 'github-release', tag: 'v1.0.0' }, configuration: {
      runtimePath: '/opt/gjc/node', workingDirectory: '/var/lib/gjc', homeDirectory: '/var/lib/gjc-home',
      logDirectory: '/var/log/gjc', channelsConfig: '/etc/gjc/channels.json', expectedHostSetFingerprint: hash, expectedHostCount: 1,
    }, expected: { serviceGeneration: 0, resourceProof: null, applicationSequenceFloor: 0 } },
    status: common,
    update: { ...common, source: { kind: 'github-release', tag: 'v1.0.0' }, expected: { serviceGeneration: 1, resourceProof: hash, currentManifestFingerprint: hash, applicationSequenceFloor: 1 }, acceptServiceDisruption: true },
    rollback: { ...common, expected: { serviceGeneration: 1, resourceProof: hash, currentManifestFingerprint: hash, predecessorManifestFingerprint: hash }, acceptServiceDisruption: true },
    uninstall: { ...common, expected: { serviceGeneration: 1, resourceProof: hash, currentManifestFingerprint: hash }, acceptServiceDisruption: true },
    recover: { ...common, expected: { transactionId: 'tx-1', journalFingerprint: hash }, acceptServiceDisruption: false },
  };
  const seen = [];
  const lifecycle = Object.fromEntries(Object.keys(requests).map((operation) => [operation, async () => {
    seen.push(operation);
    return operation === 'status' ? absentStatus() : transaction(operation);
  }]));
  for (const operation of Object.keys(requests)) {
    const receipt = await runServiceCli({ argv: [operation], input: bytes(requests[operation]), lifecycle, platform: 'linux', architecture: 'x64' });
    assert.equal(receipt.status, 'ok', `${operation} should validate`);
  }
  assert.deepEqual(seen, Object.keys(requests));
});

test('Windows service password is transient and never appears in output', async () => {
  const windowsRoles = {
    management: { kind: 'sid', value: 'S-1-5-21-1' },
    bot: { kind: 'sid', value: 'S-1-5-21-2' },
    recovery: { kind: 'sid', value: 'S-1-5-21-3' },
    daemon: { kind: 'sid', value: 'S-1-5-21-4' },
    system: { kind: 'sid', value: 'S-1-5-18' },
  };
  const request = {
    schemaVersion: 1, target: { component: 'bot' }, roles: windowsRoles,
    source: { kind: 'github-release', tag: 'v1.0.0' },
    configuration: {
      runtimePath: 'C:/gjc/node.exe', workingDirectory: 'C:/gjc', homeDirectory: 'C:/gjc-home',
      logDirectory: 'C:/gjc/log', channelsConfig: 'C:/gjc/channels.json', expectedHostSetFingerprint: 'a'.repeat(64), expectedHostCount: 1,
    },
    expected: { serviceGeneration: 0, resourceProof: null, applicationSequenceFloor: 0, shawlSequenceFloor: 0 },
    servicePassword: 'not-a-receipt-value',
  };
  let seen;
  const receipt = await runServiceCli({ argv: ['install'], input: bytes(request), platform: 'win32', architecture: 'x64', lifecycle: {
    install: async (value) => { seen = value; return transaction('install', 1); },
  } });
  assert.equal(receipt.status, 'ok');
  assert.equal(seen.servicePassword, undefined);
  assert.doesNotMatch(JSON.stringify(receipt), /not-a-receipt-value/);
});
