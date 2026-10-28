import test from 'node:test';
import assert from 'node:assert/strict';
import { canonicalJson, canonicalJsonBytes } from '@gjc-remote/shared/strict-json';
import { buildServiceStatusReceipt } from '@gjc-remote/shared/service-lifecycle-envelope';
import { REQUEST_LIMITS, serviceReceiptBytes } from '../src/service-cli.js';
import { EXIT_CODES, readBoundedStdin, runServiceEntrypoint } from '../src/service-entrypoint.js';

const roles = {
  management: { kind: 'uid', value: 'uid:1000' },
  bot: { kind: 'uid', value: 'uid:1001' },
  recovery: { kind: 'uid', value: 'uid:1002' },
  daemon: { kind: 'uid', value: 'uid:1003' },
  system: { kind: 'uid', value: 'uid:0' },
};
const request = { schemaVersion: 1, target: { component: 'bot' }, roles };
const status = {
  ...buildServiceStatusReceipt({
    component: 'bot', serviceKey: 'bot', platform: 'linux', architecture: 'x64',
    serviceGeneration: 0, manifestFingerprint: null, resourceProof: null, transactionFingerprint: null,
    ownership: 'absent', service: 'missing', activation: 'disabled-not-startable', tree: 'empty',
    startupEvidence: 'none', connectivityObservation: 'unknown', providerHealth: 'unknown', workspaceHealth: 'unknown',
    supervisorProvenance: 'not-applicable', recovery: 'clean', observedAtMs: 1,
  }),
  writes: 0,
};
const capture = () => {
  const chunks = [];
  return { stream: { write: (chunk) => { chunks.push(Buffer.from(chunk)); } }, output: () => Buffer.concat(chunks).toString('utf8') };
};

test('entrypoint emits one canonical bounded receipt and routes operation', async () => {
  const captured = capture();
  let calls = 0;
  const result = await runServiceEntrypoint({
    argv: ['status'], input: canonicalJsonBytes(request), stdout: captured.stream,
    platform: 'linux', architecture: 'x64',
    lifecycle: { status: async () => { calls += 1; return status; } },
  });
  assert.equal(result.exitCode, EXIT_CODES.ok);
  assert.equal(calls, 1);
  const text = captured.output();
  assert.equal(text.split('\n').filter(Boolean).length, 1);
  assert.equal(text, `${canonicalJson(result.receipt)}\n`);
});

test('TTY input refuses without dispatch', async () => {
  const captured = capture();
  let calls = 0;
  const result = await runServiceEntrypoint({
    argv: ['status'], stdin: { isTTY: true }, stdout: captured.stream,
    platform: 'linux', architecture: 'x64',
    lifecycle: { status: async () => { calls += 1; return {}; } },
  });
  assert.equal(result.exitCode, EXIT_CODES.usage);
  assert.equal(calls, 0);
  assert.match(captured.output(), /SERVICE_INVALID/);
});

test('oversized stdin is refused before lifecycle construction', async () => {
  const captured = capture();
  let constructed = false;
  const result = await runServiceEntrypoint({
    argv: ['install'], input: Buffer.alloc(256 * 1024 + 1), stdout: captured.stream,
    lifecycle: new Proxy({}, { get() { constructed = true; return undefined; } }),
    platform: 'linux', architecture: 'x64',
  });
  assert.equal(result.exitCode, EXIT_CODES.usage);
  assert.equal(constructed, false);
  assert.match(captured.output(), /SERVICE_INVALID/);
});

for (const [name, chunks] of [
  ['one chunk', [Buffer.alloc(REQUEST_LIMITS.maxBytes + 1, 'x')]],
  ['multiple chunks', [Buffer.alloc(REQUEST_LIMITS.maxBytes - 1, 'x'), Buffer.from('x'), Buffer.from('x')]],
  ['multibyte string chunk', [Buffer.alloc(REQUEST_LIMITS.maxBytes - 1, 'x'), 'é']],
]) {
  test(`streamed oversized stdin (${name}) emits one canonical refusal before dispatch`, async () => {
    const captured = capture();
    const secret = 'servicePassword=streamed-secret';
    chunks[0].write(secret);
    let reads = 0;
    let closed = false;
    let authorityReads = 0;
    const sentinel = new Proxy({}, { get() { authorityReads += 1; throw new Error('authority must not be read'); } });
    async function* stdin() {
      try {
        for (const chunk of chunks) {
          reads += 1;
          yield chunk;
        }
        throw new Error('oversized stdin must not be drained');
      } finally {
        closed = true;
      }
    }
    const result = await runServiceEntrypoint({
      argv: ['install'], stdin: stdin(), stdout: captured.stream,
      lifecycle: sentinel, lifecycleOptions: sentinel, platform: 'win32', architecture: 'x64',
    });
    const expected = {
      status: 'refused', operation: 'service', code: 'SERVICE_INVALID',
      message: 'service request is invalid', writes: 0, ambiguous: false,
    };
    assert.equal(result.exitCode, 64);
    assert.deepEqual(result.receipt, expected);
    assert.equal(captured.output(), `${canonicalJson(expected)}\n`);
    assert.equal(captured.output().includes(secret), false);
    assert.equal(reads, chunks.length);
    assert.equal(closed, true);
    assert.equal(authorityReads, 0);
    assert.throws(() => serviceReceiptBytes({ ...expected, message: 'service operation failed' }), { code: 'SERVICE_INVALID' });
  });
}

for (const size of [REQUEST_LIMITS.maxBytes - 1, REQUEST_LIMITS.maxBytes]) {
  test(`streamed stdin preserves all ${size} bytes at the request boundary`, async () => {
    const bytes = Buffer.alloc(size, 'x');
    async function* stdin() {
      yield bytes.subarray(0, size - 1);
      yield bytes.subarray(size - 1);
    }
    const result = await readBoundedStdin(stdin());
    assert.deepEqual(result, { bytes, isTTY: false });
  });
}

for (const partial of [false, true]) {
  test(`stdin read error ${partial ? 'after a chunk' : 'before any chunk'} emits a canonical IO refusal`, async () => {
    const captured = capture();
    const secret = 'servicePassword=unreadable-secret';
    let authorityReads = 0;
    const sentinel = new Proxy({}, { get() { authorityReads += 1; throw new Error('authority must not be read'); } });
    async function* stdin() {
      if (partial) yield Buffer.from(secret);
      throw new Error(secret);
    }
    const result = await runServiceEntrypoint({
      argv: ['install'], stdin: stdin(), stdout: captured.stream,
      lifecycle: sentinel, lifecycleOptions: sentinel, platform: 'win32', architecture: 'x64',
    });
    const expected = {
      status: 'refused', operation: 'service', code: 'SERVICE_IO_FAILED',
      message: 'service operation failed', writes: 0, ambiguous: false,
    };
    assert.equal(result.exitCode, EXIT_CODES.refused);
    assert.deepEqual(result.receipt, expected);
    assert.equal(captured.output(), `${canonicalJson(expected)}\n`);
    assert.equal(captured.output().includes(secret), false);
    assert.equal(authorityReads, 0);
  });
}

test('invalid request does not construct the lifecycle facade', async () => {
  const captured = capture();
  let constructed = false;
  const result = await runServiceEntrypoint({
    argv: ['status'], input: Buffer.from('{}'), stdout: captured.stream,
    lifecycleOptions: { get marker() { constructed = true; return undefined; } },
    platform: 'linux', architecture: 'x64',
  });
  assert.equal(result.exitCode, EXIT_CODES.usage);
  assert.equal(constructed, false);
});

test('invalid win32 request composes the host producer without touching native authority', async () => {
  const captured = capture();
  const result = await runServiceEntrypoint({
    argv: ['install'], input: Buffer.from('{}'), stdout: captured.stream,
    platform: 'win32', architecture: 'x64',
  });
  assert.equal(result.exitCode, EXIT_CODES.usage);
  assert.equal(result.receipt.status, 'refused');
  assert.equal(result.receipt.writes, 0);
});

test('production composition refuses before mutation when authoritative dependencies are unavailable', async () => {
  const captured = capture();
  const result = await runServiceEntrypoint({
    argv: ['install'], input: canonicalJsonBytes({
      ...request,
      source: { kind: 'github-release', tag: 'v1.0.0' },
      configuration: {
        runtimePath: '/opt/gjc/node', workingDirectory: '/var/lib/gjc', homeDirectory: '/var/lib/gjc-home',
        logDirectory: '/var/log/gjc', channelsConfig: '/etc/gjc/channels.json', expectedHostSetFingerprint: 'a'.repeat(64), expectedHostCount: 1,
      },
      expected: { serviceGeneration: 0, resourceProof: null, applicationSequenceFloor: 0 },
    }), stdout: captured.stream, lifecycleOptions: {}, platform: 'linux', architecture: 'x64',
  });
  assert.equal(result.exitCode, EXIT_CODES.usage);
  assert.equal(result.receipt.status, 'refused');
  assert.equal(result.receipt.writes, 0);
  assert.match(captured.output(), /SERVICE_INVALID/);
});

test('production mutation requires effective configuration preflight before native/store composition', async () => {
  const captured = capture();
  let nativeRead = false;
  const lifecycleOptions = new Proxy({
    roles: request.roles,
    target: request.target,
    native: {},
    observeApplication: () => {},
    compatibility: () => {},
    planResource: () => {},
    shawl: {},
  }, {
    get(target, key, receiver) {
      if (key === 'native') nativeRead = true;
      return Reflect.get(target, key, receiver);
    },
  });
  const result = await runServiceEntrypoint({
    argv: ['install'], input: canonicalJsonBytes({
      ...request,
      source: { kind: 'github-release', tag: 'v1.0.0' },
      configuration: {
        runtimePath: '/opt/gjc/node', workingDirectory: '/var/lib/gjc', homeDirectory: '/var/lib/gjc-home',
        logDirectory: '/var/log/gjc', channelsConfig: '/etc/gjc/channels.json', expectedHostSetFingerprint: 'a'.repeat(64), expectedHostCount: 1,
      },
      expected: { serviceGeneration: 0, resourceProof: null, applicationSequenceFloor: 0 },
    }), stdout: captured.stream, lifecycleOptions, platform: 'linux', architecture: 'x64',
  });
  assert.equal(result.exitCode, EXIT_CODES.usage);
  assert.equal(result.receipt.status, 'refused');
  assert.equal(result.receipt.code, 'SERVICE_INVALID');
  assert.equal(nativeRead, false);
  assert.match(captured.output(), /SERVICE_INVALID/);
});
