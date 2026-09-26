import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { EventEmitter } from 'node:events';
import { readFileSync } from 'node:fs';
import https from 'node:https';
import { Readable } from 'node:stream';
import test, { after } from 'node:test';
import { checkServerIdentity, rootCertificates } from 'node:tls';
import {
  DEPLOYMENT_ENVELOPE_LIMITS,
  buildApplicationDeploymentManifest,
  buildDeploymentCompatibility,
  buildShawlDeploymentManifest,
} from '@gjc-remote/shared/deployment-envelope';
import * as publicApi from '../src/public.js';
import { createGithubReleaseTransport as createProductionTransport } from '../src/service-transport.js';
import { createPinnedDeploymentInstallation } from '../test-fixtures/pinned-deployment-installation.mjs';

// Every network result in this file is a deterministic modeled-protocol result.
// It is not evidence of actual TLS, GitHub behavior, DNS, proxy policy, or Internet reachability.
const installation = await createPinnedDeploymentInstallation({
  keyIds: ['deployment-test'],
  includeTransport: true,
});
after(() => installation.dispose());

const sha256 = (bytes) => createHash('sha256').update(bytes).digest('hex');

function compatibility() {
  return buildDeploymentCompatibility({
    bot: {
      domains: [{ domain: 'bot-mapping-reader', readableFormats: ['mapping-v1'], writableFormats: ['mapping-v1'] }],
    },
    daemon: {
      domains: [
        { domain: 'daemon-app-session', readableFormats: ['session-v1'], writableFormats: ['session-v1'] },
        { domain: 'workspace-lifecycle', readableFormats: ['workspace-v1'], writableFormats: ['workspace-v1'] },
      ],
      sdkExternalStateContractFingerprint: '8'.repeat(64),
    },
  });
}

function applicationManifest(bytes, {
  platform = 'linux',
  architecture = 'x64',
  releaseVersion = '1.2.3',
} = {}) {
  const tag = `v${releaseVersion}`;
  return buildApplicationDeploymentManifest({
    signingKeyId: 'deployment-test',
    releaseId: tag,
    releaseVersion,
    releaseSequence: 9,
    source: {
      repository: 'kogangdon/gjc-remote',
      tag,
      commit: 'a'.repeat(40),
      tree: 'b'.repeat(40),
      bunLockSha256: 'c'.repeat(64),
    },
    target: { platform, architecture },
    archive: {
      name: `gjc-remote-service-${releaseVersion}-${platform}-${architecture}.tar.gz`,
      mediaType: 'application/gzip',
      byteLength: bytes.byteLength,
      sha256: sha256(bytes),
      entryCount: 1,
    },
    inventory: {
      path: 'bundle-files.json',
      byteLength: 2,
      sha256: 'd'.repeat(64),
      payloadEntryCount: 0,
      unpackedPayloadBytes: 0,
      treeFingerprint: 'e'.repeat(64),
    },
    entrypoints: { bot: 'bot/src/bot.js', daemon: 'daemon/src/daemon.js' },
    runtimes: { node: { minimumVersion: '26.0.0' }, bun: { minimumVersion: '1.4.0' } },
    nativeControl: {
      manifestPath: 'native-control/build/Release/native-control.manifest.json',
      manifestFingerprint: 'f'.repeat(64),
      contractVersion: 5,
      contractRevision: 1,
    },
    wireCapabilities: ['gate_presentation_v1'],
    compatibility: compatibility(),
  });
}

function shawlManifest(bytes, { tag = 'v1.2.3' } = {}) {
  return buildShawlDeploymentManifest({
    signingKeyId: 'deployment-test',
    releaseSequence: 4,
    target: { platform: 'win32', architecture: 'x64' },
    upstream: {
      repository: 'mtkennerly/shawl',
      tag: 'v1.9.0',
      commit: 'dbc4014c6d67027dc75a565d79fe9f493e897eb2',
      assetId: 410957225,
      assetName: 'shawl-v1.9.0-win64.zip',
      zipSha256: '1'.repeat(64),
    },
    executable: {
      name: 'shawl.exe',
      byteLength: bytes.byteLength,
      sha256: sha256(bytes),
      version: '1.9.0',
      versionOutput: 'shawl 1.9.0',
      authenticode: 'unsigned',
    },
    projectAsset: {
      repository: 'kogangdon/gjc-remote',
      tag,
      name: 'gjc-remote-shawl-win32-x64.exe',
    },
  });
}

function rawHeaders(headers = {}) {
  const result = [];
  for (const [name, rawValue] of Object.entries(headers)) {
    const values = Array.isArray(rawValue) ? rawValue : [rawValue];
    for (const value of values) result.push(name, String(value));
  }
  return result;
}

class ModeledResponse extends Readable {
  constructor(spec = {}) {
    super({ highWaterMark: 16 * 1024 });
    this.statusCode = spec.statusCode ?? 200;
    this.rawHeaders = spec.rawHeaders ? [...spec.rawHeaders] : rawHeaders(spec.headers);
    this.complete = false;
    this.destroyCalls = 0;
    this.pulls = 0;
    this.idleMilliseconds = null;
    this.idleCallback = null;
    this._chunks = (spec.chunks ?? [spec.body ?? Buffer.alloc(0)]).map((chunk) => Buffer.from(chunk));
    this._index = 0;
    this._scheduled = false;
    this._hang = spec.hang === true;
    this._completeAtEnd = spec.complete !== false;
    this._abortAt = spec.abortAt ?? null;
    this._errorAt = spec.errorAt ?? null;
    this._rawError = spec.rawError ?? 'MODELED_RAW_NETWORK_SECRET';
  }

  _read() {
    this.pulls += 1;
    if (this._hang || this._scheduled || this.destroyed) return;
    this._scheduled = true;
    queueMicrotask(() => {
      this._scheduled = false;
      if (this.destroyed) return;
      if (this._abortAt === this._index) {
        this.emit('aborted');
        return;
      }
      if (this._errorAt === this._index) {
        this.destroy(new Error(this._rawError));
        return;
      }
      if (this._index < this._chunks.length) {
        this.push(this._chunks[this._index]);
        this._index += 1;
        return;
      }
      this.complete = this._completeAtEnd;
      this.push(null);
    });
  }

  setTimeout(milliseconds, callback) {
    this.idleMilliseconds = milliseconds;
    this.idleCallback = milliseconds === 0 ? null : callback;
    return this;
  }

  fireIdleTimeout() {
    this.idleCallback?.();
  }

  destroy(error) {
    this.destroyCalls += 1;
    return super.destroy(error);
  }
}

class ModeledRequest extends EventEmitter {
  constructor(spec, options, responses) {
    super();
    this.spec = spec;
    this.options = options;
    this.responses = responses;
    this.destroyed = false;
    this.destroyCalls = 0;
    this.ended = false;
    this.maxHeadersCount = undefined;
  }

  end() {
    this.ended = true;
    if (this.spec.throwOnEnd) throw new Error(this.spec.rawError ?? 'MODELED_RAW_END_SECRET');
    if (this.spec.noResponse) return;
    queueMicrotask(() => {
      if (this.destroyed) return;
      if (this.spec.requestError) {
        this.emit('error', new Error(this.spec.rawError ?? 'MODELED_RAW_REQUEST_SECRET'));
        return;
      }
      const response = new ModeledResponse(this.spec);
      this.responses.push(response);
      this.emit('response', response);
    });
  }

  destroy() {
    this.destroyCalls += 1;
    this.destroyed = true;
    return this;
  }
}

function installNetworkModel(t, script) {
  const remaining = [...script];
  const calls = [];
  const requests = [];
  const responses = [];
  t.mock.method(https, 'request', (options) => {
    const spec = remaining.shift() ?? { requestError: true, rawError: 'UNEXPECTED_MODELED_REQUEST' };
    calls.push(options);
    const request = new ModeledRequest(spec, options, responses);
    requests.push(request);
    return request;
  });
  return { calls, requests, responses, remaining };
}

function installTimerModel(t) {
  const handles = [];
  t.mock.method(globalThis, 'setTimeout', (callback, milliseconds, ...args) => {
    const handle = {
      callback,
      milliseconds,
      args,
      cleared: false,
      unrefCalled: false,
      unref() {
        this.unrefCalled = true;
        return this;
      },
      fire() {
        if (!this.cleared) this.callback(...this.args);
      },
    };
    handles.push(handle);
    return handle;
  });
  t.mock.method(globalThis, 'clearTimeout', (handle) => {
    if (handle && typeof handle === 'object') handle.cleared = true;
  });
  return handles;
}

function fixtureTransport(t, options = { tag: 'v1.2.3', platform: 'linux', architecture: 'x64' }) {
  const transport = installation.transport.createGithubReleaseTransport(options);
  t.after(() => transport.close());
  return transport;
}

function errorIs(code, operation) {
  return (error) => {
    assert.equal(error?.name, 'ServiceTransportError');
    assert.equal(error?.code, code);
    assert.equal(error?.operation, operation);
    assert.equal(error?.writes, 0);
    assert.equal(error?.message, code);
    assert.equal(error?.cause, undefined);
    assert.ok(Buffer.byteLength(error.message, 'utf8') < 128);
    assert.doesNotMatch(error.message, /https?:|github|token|secret/i);
    return true;
  };
}

async function consume(chunks) {
  const values = [];
  let length = 0;
  for await (const chunk of chunks) {
    values.push(Buffer.from(chunk));
    length += chunk.byteLength;
  }
  return Buffer.concat(values, length);
}

function assertFixedRequest(options, hostname = 'github.com') {
  assert.equal(options.protocol, 'https:');
  assert.equal(options.hostname, hostname);
  assert.equal(options.port, 443);
  assert.equal(options.method, 'GET');
  assert.equal(options.rejectUnauthorized, true);
  assert.equal(options.checkServerIdentity, checkServerIdentity);
  assert.equal(options.servername, hostname);
  assert.equal(options.ca, rootCertificates);
  assert.equal(options.maxHeaderSize, 16 * 1024);
  assert.equal(options.joinDuplicateHeaders, false);
  assert.equal(options.setHost, true);
  assert.notEqual(options.agent, https.globalAgent);
  assert.equal(options.agent.options.rejectUnauthorized, true);
  assert.equal(options.agent.options.checkServerIdentity, checkServerIdentity);
  assert.equal(options.agent.options.ca, rootCertificates);
  assert.equal(options.agent.options.keepAlive, false);
  assert.equal(options.agent.options.maxSockets, 1);
  assert.deepEqual(options.headers, {
    accept: 'application/octet-stream',
    'accept-encoding': 'identity',
    connection: 'close',
    'user-agent': 'gjc-remote-native-control/1',
  });
  for (const forbidden of ['auth', 'authorization', 'cookie', 'lookup', 'proxy', 'signal', 'timeout']) {
    assert.equal(Object.hasOwn(options, forbidden), false);
  }
}

test('transport is internal, frozen, closed-option-only and tuple/selector bounded', () => {
  const packageJson = JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8'));
  assert.equal(Object.hasOwn(publicApi, 'createGithubReleaseTransport'), false);
  assert.equal(Object.hasOwn(packageJson.exports, './service-transport'), false);
  const transport = createProductionTransport({ tag: 'v1.2.3', platform: 'linux', architecture: 'x64' });
  try {
    assert.equal(Object.isFrozen(transport), true);
    assert.deepEqual(Object.keys(transport), ['readBootstrap', 'openApplication', 'openShawl', 'close']);
    assert.throws(() => transport.close('extra'), errorIs('SERVICE_TRANSPORT_INVALID', 'close_github_release_transport'));
  } finally {
    transport.close();
  }

  for (const invoke of [
    () => createProductionTransport(),
    () => createProductionTransport({ tag: 'v1.2.3', platform: 'linux', architecture: 'x64' }, null),
    () => createProductionTransport({ tag: '', platform: 'linux', architecture: 'x64' }),
    () => createProductionTransport({ tag: '../latest', platform: 'linux', architecture: 'x64' }),
    () => createProductionTransport({ tag: 'v1.2.3', platform: 'darwin', architecture: 'x64' }),
    () => createProductionTransport({ tag: 'v1.2.3', platform: 'win32', architecture: 'arm64' }),
    () => createProductionTransport({ tag: 'v1.2.3', platform: 'linux', architecture: 'x64', url: 'https://example.test' }),
    () => createProductionTransport({ tag: 'v1.2.3', platform: 'linux', architecture: 'x64', headers: {} }),
    ...['agent', 'ca', 'proxy', 'timeout', 'rejectUnauthorized'].map((key) => () =>
      createProductionTransport({ tag: 'v1.2.3', platform: 'linux', architecture: 'x64', [key]: true })),
    () => createProductionTransport(Object.defineProperty(
      { platform: 'linux', architecture: 'x64' },
      'tag',
      { enumerable: true, get: () => 'v1.2.3' },
    )),
    () => createProductionTransport(new Proxy({}, {
      getPrototypeOf() { throw new Error('MODELED_RAW_OPTIONS_SECRET'); },
    })),
  ]) {
    assert.throws(invoke, errorIs('SERVICE_TRANSPORT_INVALID', 'create_github_release_transport'));
  }
});

test('fixed application bootstrap routes use modeled GETs with explicit bundled trust and identity encoding', async (t) => {
  const manifestBytes = Buffer.from('{"modeled":"manifest"}');
  const signatureBytes = Buffer.from('{"modeled":"signature"}');
  const model = installNetworkModel(t, [
    { headers: { 'Content-Length': manifestBytes.length }, chunks: [manifestBytes.subarray(0, 3), manifestBytes.subarray(3)] },
    { headers: { 'Content-Encoding': 'identity' }, body: signatureBytes },
  ]);
  const transport = fixtureTransport(t);
  const result = await transport.readBootstrap('application');
  assert.equal(Object.isFrozen(result), true);
  assert.deepEqual(result.manifestBytes, manifestBytes);
  assert.deepEqual(result.signatureBytes, signatureBytes);
  assert.deepEqual(model.calls.map((call) => call.path), [
    '/kogangdon/gjc-remote/releases/download/v1.2.3/gjc-remote-service-linux-x64.manifest.json',
    '/kogangdon/gjc-remote/releases/download/v1.2.3/gjc-remote-service-linux-x64.manifest.json.sig',
  ]);
  assert.equal(model.calls[0].agent, model.calls[1].agent);
  for (const call of model.calls) assertFixedRequest(call);
  assert.equal(model.remaining.length, 0);
});

test('fixed Windows Shawl bootstrap names are selected only for the Windows tuple', async (t) => {
  const model = installNetworkModel(t, [
    { body: Buffer.from('shawl manifest') },
    { body: Buffer.from('shawl signature') },
  ]);
  const transport = fixtureTransport(t, { tag: 'v1.2.3', platform: 'win32', architecture: 'x64' });
  const result = await transport.readBootstrap('shawl');
  assert.equal(result.manifestBytes.toString(), 'shawl manifest');
  assert.equal(result.signatureBytes.toString(), 'shawl signature');
  assert.deepEqual(model.calls.map((call) => call.path), [
    '/kogangdon/gjc-remote/releases/download/v1.2.3/gjc-remote-shawl-win32-x64.manifest.json',
    '/kogangdon/gjc-remote/releases/download/v1.2.3/gjc-remote-shawl-win32-x64.manifest.json.sig',
  ]);

  const linux = fixtureTransport(t);
  await assert.rejects(linux.readBootstrap('shawl'), errorIs('SERVICE_TRANSPORT_INVALID', 'read_bootstrap'));
  assert.equal(model.calls.length, 2);
});

test('manual safe redirects are followed only through exact release asset hosts', async (t) => {
  const manifestBytes = Buffer.from('manifest');
  const signatureBytes = Buffer.from('signature');
  const model = installNetworkModel(t, [
    { statusCode: 302, headers: { Location: 'https://release-assets.githubusercontent.com:443/a/manifest?sig=one' } },
    { statusCode: 307, headers: { Location: '/a/manifest-final?sig=two' } },
    { body: manifestBytes },
    { statusCode: 301, headers: { Location: 'https://objects.githubusercontent.com/a/signature?sig=three' } },
    { body: signatureBytes },
  ]);
  const transport = fixtureTransport(t);
  const result = await transport.readBootstrap('application');
  assert.deepEqual(result.manifestBytes, manifestBytes);
  assert.deepEqual(result.signatureBytes, signatureBytes);
  assert.deepEqual(model.calls.map((call) => call.hostname), [
    'github.com',
    'release-assets.githubusercontent.com',
    'release-assets.githubusercontent.com',
    'github.com',
    'objects.githubusercontent.com',
  ]);
  assertFixedRequest(model.calls[1], 'release-assets.githubusercontent.com');
  assertFixedRequest(model.calls[4], 'objects.githubusercontent.com');
  assert.ok(model.responses.slice(0, 3).every((response) => response.destroyCalls >= 1));
});

test('the exact initial GitHub asset URL may be a redirect target, but arbitrary GitHub paths may not', async (t) => {
  const initial = 'https://github.com/kogangdon/gjc-remote/releases/download/v1.2.3/gjc-remote-service-linux-x64.manifest.json';
  const model = installNetworkModel(t, [
    { statusCode: 302, headers: { Location: initial } },
    { statusCode: 302, headers: { Location: 'https://release-assets.githubusercontent.com/final' } },
    { body: Buffer.from('manifest') },
    { body: Buffer.from('signature') },
  ]);
  const transport = fixtureTransport(t);
  await transport.readBootstrap('application');
  assert.equal(model.calls[1].hostname, 'github.com');
  assert.equal(model.calls[1].path, new URL(initial).pathname);
});

test('redirect exhaustion stops after three followed redirects for one request', async (t) => {
  const model = installNetworkModel(t, [
    { statusCode: 302, headers: { Location: 'https://release-assets.githubusercontent.com/one' } },
    { statusCode: 302, headers: { Location: 'https://objects.githubusercontent.com/two' } },
    { statusCode: 307, headers: { Location: 'https://release-assets.githubusercontent.com/three' } },
    { statusCode: 308, headers: { Location: 'https://objects.githubusercontent.com/four' } },
  ]);
  const transport = fixtureTransport(t);
  await assert.rejects(
    transport.readBootstrap('application'),
    errorIs('SERVICE_TRANSPORT_REDIRECT_LIMIT', 'read_bootstrap'),
  );
  assert.equal(model.calls.length, 4);
  assert.ok(model.requests.every((request) => request.destroyCalls >= 1));
  assert.ok(model.responses.every((response) => response.destroyCalls >= 1));
});

test('forbidden redirect classes and ambiguous Location fields fail closed', async (t) => {
  const initial = 'https://github.com/kogangdon/gjc-remote/releases/download/v1.2.3/gjc-remote-service-linux-x64.manifest.json';
  const cases = [
    ['non-HTTPS', 'http://release-assets.githubusercontent.com/asset'],
    ['non-443 port', 'https://release-assets.githubusercontent.com:444/asset'],
    ['userinfo', 'https://user:password@release-assets.githubusercontent.com/asset'],
    ['fragment', 'https://release-assets.githubusercontent.com/asset#fragment'],
    ['IPv4 literal', 'https://127.0.0.1/asset'],
    ['IPv6 literal', 'https://[::1]/asset'],
    ['arbitrary GitHub path', 'https://github.com/kogangdon/gjc-remote/releases/latest'],
    ['GitHub subdomain', 'https://assets.github.com/asset'],
    ['GitHub lookalike', 'https://github.com.example.test/asset'],
    ['release asset subdomain', 'https://x.release-assets.githubusercontent.com/asset'],
    ['object host lookalike', 'https://objects.githubusercontent.com.example.test/asset'],
    ['unrelated host', 'https://example.test/asset'],
    ['backslash normalization', 'https://release-assets.githubusercontent.com\\@example.test/asset'],
    ['relative arbitrary GitHub path', '/kogangdon/gjc-remote/releases/latest'],
    ['query mutation of initial GitHub URL', `${initial}?redirected=true`],
    ['overlong Location', `https://release-assets.githubusercontent.com/${'x'.repeat(4097)}`],
  ];
  for (const [name, location] of cases) {
    await t.test(name, async (t) => {
      const model = installNetworkModel(t, [{ statusCode: 302, headers: { Location: location } }]);
      const transport = fixtureTransport(t);
      await assert.rejects(
        transport.readBootstrap('application'),
        errorIs('SERVICE_TRANSPORT_REDIRECT_INVALID', 'read_bootstrap'),
      );
      assert.equal(model.calls.length, 1);
      assert.ok(model.requests[0].destroyCalls >= 1);
      assert.ok(model.responses[0].destroyCalls >= 1);
    });
  }

  await t.test('missing Location', async (t) => {
    const model = installNetworkModel(t, [{ statusCode: 302 }]);
    const transport = fixtureTransport(t);
    await assert.rejects(transport.readBootstrap('application'), errorIs('SERVICE_TRANSPORT_REDIRECT_INVALID', 'read_bootstrap'));
    assert.equal(model.calls.length, 1);
  });

  await t.test('duplicate Location', async (t) => {
    const model = installNetworkModel(t, [{
      statusCode: 302,
      rawHeaders: [
        'Location', 'https://release-assets.githubusercontent.com/one',
        'Location', 'https://objects.githubusercontent.com/two',
      ],
    }]);
    const transport = fixtureTransport(t);
    await assert.rejects(transport.readBootstrap('application'), errorIs('SERVICE_TRANSPORT_REDIRECT_INVALID', 'read_bootstrap'));
    assert.equal(model.calls.length, 1);
  });
});

test('bootstrap response bounds, encodings and Content-Length syntax are enforced', async (t) => {
  const tooManyHeaders = [];
  for (let index = 0; index < 65; index += 1) tooManyHeaders.push(`X-Modeled-${index}`, 'x');
  const cases = [
    ['encoded gzip', { headers: { 'Content-Encoding': 'gzip' }, body: Buffer.from('x') }, 'SERVICE_TRANSPORT_RESPONSE_INVALID'],
    ['multiple encodings', { rawHeaders: ['Content-Encoding', 'identity', 'Content-Encoding', 'identity'], body: Buffer.from('x') }, 'SERVICE_TRANSPORT_RESPONSE_INVALID'],
    ['invalid length', { headers: { 'Content-Length': '1x' }, body: Buffer.from('x') }, 'SERVICE_TRANSPORT_SIZE_INVALID'],
    ['conflicting lengths', { rawHeaders: ['Content-Length', '1', 'Content-Length', '2'], body: Buffer.from('x') }, 'SERVICE_TRANSPORT_SIZE_INVALID'],
    ['length beyond manifest cap', { headers: { 'Content-Length': String(DEPLOYMENT_ENVELOPE_LIMITS.manifestBytes + 1) } }, 'SERVICE_TRANSPORT_SIZE_INVALID'],
    ['length plus transfer encoding', { headers: { 'Content-Length': '1', 'Transfer-Encoding': 'chunked' }, body: Buffer.from('x') }, 'SERVICE_TRANSPORT_RESPONSE_INVALID'],
    ['aggregate headers too large', { rawHeaders: ['X-Modeled', 'x'.repeat(16 * 1024)] }, 'SERVICE_TRANSPORT_RESPONSE_INVALID'],
    ['too many headers', { rawHeaders: tooManyHeaders }, 'SERVICE_TRANSPORT_RESPONSE_INVALID'],
    ['body beyond manifest cap', { body: Buffer.alloc(DEPLOYMENT_ENVELOPE_LIMITS.manifestBytes + 1) }, 'SERVICE_TRANSPORT_SIZE_INVALID'],
    ['declared and actual mismatch', { headers: { 'Content-Length': '2' }, body: Buffer.from('x') }, 'SERVICE_TRANSPORT_SIZE_INVALID'],
    ['incomplete HTTP body', { body: Buffer.from('x'), complete: false }, 'SERVICE_TRANSPORT_INCOMPLETE'],
    ['non-success response', { statusCode: 404, body: Buffer.from('not found') }, 'SERVICE_TRANSPORT_RESPONSE_INVALID'],
  ];
  for (const [name, response, code] of cases) {
    await t.test(name, async (t) => {
      const model = installNetworkModel(t, [response]);
      const transport = fixtureTransport(t);
      await assert.rejects(transport.readBootstrap('application'), errorIs(code, 'read_bootstrap'));
      assert.equal(model.calls.length, 1);
      assert.ok(model.requests[0].destroyCalls >= 1);
      assert.ok(model.responses[0].destroyCalls >= 1);
    });
  }
});

test('bootstrap manifest and signature accept their exact caps and reject signature cap plus one', async (t) => {
  await t.test('exact caps', async (t) => {
    const manifestBytes = Buffer.alloc(DEPLOYMENT_ENVELOPE_LIMITS.manifestBytes, 0x6d);
    const signatureBytes = Buffer.alloc(DEPLOYMENT_ENVELOPE_LIMITS.signatureBytes, 0x73);
    installNetworkModel(t, [
      { headers: { 'Content-Length': String(manifestBytes.length) }, body: manifestBytes },
      { headers: { 'Content-Length': String(signatureBytes.length) }, body: signatureBytes },
    ]);
    const transport = fixtureTransport(t);
    const result = await transport.readBootstrap('application');
    assert.equal(result.manifestBytes.length, DEPLOYMENT_ENVELOPE_LIMITS.manifestBytes);
    assert.equal(result.signatureBytes.length, DEPLOYMENT_ENVELOPE_LIMITS.signatureBytes);
  });

  await t.test('signature cap plus one', async (t) => {
    const model = installNetworkModel(t, [
      { body: Buffer.from('manifest') },
      { headers: { 'Content-Length': String(DEPLOYMENT_ENVELOPE_LIMITS.signatureBytes + 1) } },
    ]);
    const transport = fixtureTransport(t);
    await assert.rejects(
      transport.readBootstrap('application'),
      errorIs('SERVICE_TRANSPORT_SIZE_INVALID', 'read_bootstrap'),
    );
    assert.equal(model.calls.length, 2);
  });
});

test('unbranded, wrong-purpose, wrong-tuple and wrong-tag manifests refuse before any request', async (t) => {
  const applicationBytes = Buffer.from('signed application archive');
  const shawlBytes = Buffer.from('signed shawl executable');
  const pinnedApplication = installation.verifyManifest(applicationManifest(applicationBytes));
  const pinnedShawl = installation.verifyManifest(shawlManifest(shawlBytes));
  const model = installNetworkModel(t, []);

  const transport = fixtureTransport(t);
  await assert.rejects(
    transport.openApplication(JSON.parse(JSON.stringify(pinnedApplication))),
    errorIs('DEPLOYMENT_PINNED_PROVENANCE_REQUIRED', 'open_application'),
  );
  await assert.rejects(
    transport.openApplication(pinnedShawl),
    errorIs('DEPLOYMENT_PINNED_PROVENANCE_REQUIRED', 'open_application'),
  );

  const wrongTuple = fixtureTransport(t, { tag: 'v1.2.3', platform: 'linux', architecture: 'arm64' });
  await assert.rejects(
    wrongTuple.openApplication(pinnedApplication),
    errorIs('SERVICE_TRANSPORT_MANIFEST_MISMATCH', 'open_application'),
  );

  const wrongTag = fixtureTransport(t, { tag: 'v1.2.4', platform: 'linux', architecture: 'x64' });
  await assert.rejects(
    wrongTag.openApplication(pinnedApplication),
    errorIs('SERVICE_TRANSPORT_MANIFEST_MISMATCH', 'open_application'),
  );

  const linux = fixtureTransport(t);
  await assert.rejects(
    linux.openShawl(pinnedShawl),
    errorIs('SERVICE_TRANSPORT_MANIFEST_MISMATCH', 'open_shawl'),
  );
  assert.equal(model.calls.length, 0);
});

test('genuinely verified pinned application fields select and verify the streamed asset', async (t) => {
  const archiveBytes = Buffer.from('genuine pinned application archive bytes');
  const manifest = installation.verifyManifest(applicationManifest(archiveBytes));
  assert.equal(installation.provenance.assertPinnedDeploymentManifest(manifest, 'application'), manifest);
  const model = installNetworkModel(t, [{
    headers: { 'Content-Length': archiveBytes.length, 'Content-Encoding': 'identity' },
    chunks: [archiveBytes.subarray(0, 1), archiveBytes.subarray(1, 9), archiveBytes.subarray(9)],
  }]);
  const transport = fixtureTransport(t);
  const asset = await transport.openApplication(manifest);
  assert.equal(Object.isFrozen(asset), true);
  assert.equal(Object.isFrozen(asset.chunks), true);
  assert.deepEqual(Object.keys(asset), ['chunks', 'close']);
  assert.equal(model.responses[0].pulls, 0, 'open leaves the archive response paused instead of buffering it');
  assert.deepEqual(await consume(asset.chunks), archiveBytes);
  assert.equal(model.calls[0].path, '/kogangdon/gjc-remote/releases/download/v1.2.3/gjc-remote-service-1.2.3-linux-x64.tar.gz');
  assertFixedRequest(model.calls[0]);
  assert.ok(model.requests[0].destroyCalls >= 1);
  assert.ok(model.responses[0].destroyCalls >= 1);
  asset.close();
});

test('genuinely verified pinned Shawl fields select and verify the streamed project asset', async (t) => {
  const executableBytes = Buffer.from('genuine pinned shawl executable bytes');
  const manifest = installation.verifyManifest(shawlManifest(executableBytes));
  assert.equal(installation.provenance.assertPinnedDeploymentManifest(manifest, 'shawl'), manifest);
  const model = installNetworkModel(t, [{ body: executableBytes }]);
  const transport = fixtureTransport(t, { tag: 'v1.2.3', platform: 'win32', architecture: 'x64' });
  const asset = await transport.openShawl(manifest);
  assert.deepEqual(await consume(asset.chunks), executableBytes);
  assert.equal(model.calls[0].path, '/kogangdon/gjc-remote/releases/download/v1.2.3/gjc-remote-shawl-win32-x64.exe');
});

test('signed length, HTTP completeness and SHA-256 are checked at stream EOF', async (t) => {
  const expected = Buffer.from('signed archive body');
  const corrupted = Buffer.from(expected);
  corrupted[0] ^= 0xff;
  const pinned = installation.verifyManifest(applicationManifest(expected));
  const cases = [
    ['short body', Buffer.from('short'), true, 'SERVICE_TRANSPORT_SIZE_INVALID'],
    ['long body', Buffer.concat([expected, Buffer.from('x')]), true, 'SERVICE_TRANSPORT_SIZE_INVALID'],
    ['truncated HTTP message', expected, false, 'SERVICE_TRANSPORT_INCOMPLETE'],
    ['same-length corruption', corrupted, true, 'SERVICE_TRANSPORT_HASH_INVALID'],
  ];
  for (const [name, body, complete, code] of cases) {
    await t.test(name, async (t) => {
      const model = installNetworkModel(t, [{ body, complete }]);
      const transport = fixtureTransport(t);
      const asset = await transport.openApplication(pinned);
      await assert.rejects(consume(asset.chunks), errorIs(code, 'open_application'));
      assert.ok(model.requests[0].destroyCalls >= 1);
      assert.ok(model.responses[0].destroyCalls >= 1);
    });
  }

  await t.test('signed Content-Length mismatch refuses before exposing chunks', async (t) => {
    const model = installNetworkModel(t, [{ headers: { 'Content-Length': String(expected.length - 1) }, body: expected }]);
    const transport = fixtureTransport(t);
    await assert.rejects(transport.openApplication(pinned), errorIs('SERVICE_TRANSPORT_SIZE_INVALID', 'open_application'));
    assert.equal(model.calls.length, 1);
  });
});

test('asset chunks permit one consumer and early abandonment fails closed', async (t) => {
  const bytes = Buffer.from('two modeled chunks');
  const pinned = installation.verifyManifest(applicationManifest(bytes));

  await t.test('second iterator is refused after verified completion', async (t) => {
    installNetworkModel(t, [{ chunks: [bytes.subarray(0, 4), bytes.subarray(4)] }]);
    const transport = fixtureTransport(t);
    const asset = await transport.openApplication(pinned);
    assert.deepEqual(await consume(asset.chunks), bytes);
    assert.throws(
      () => asset.chunks[Symbol.asyncIterator](),
      errorIs('SERVICE_TRANSPORT_ALREADY_CONSUMED', 'open_application'),
    );
  });

  await t.test('for-await break destroys the response and reports incomplete consumption', async (t) => {
    const model = installNetworkModel(t, [{ chunks: [bytes.subarray(0, 4), bytes.subarray(4)] }]);
    const transport = fixtureTransport(t);
    const asset = await transport.openApplication(pinned);
    await assert.rejects(async () => {
      for await (const chunk of asset.chunks) break;
    }, errorIs('SERVICE_TRANSPORT_INCOMPLETE', 'open_application'));
    assert.ok(model.requests[0].destroyCalls >= 1);
    assert.ok(model.responses[0].destroyCalls >= 1);
  });

  await t.test('return before first next and explicit asset close both fail closed', async (t) => {
    const model = installNetworkModel(t, [{ body: bytes }, { body: bytes }]);
    const transport = fixtureTransport(t);
    const first = await transport.openApplication(pinned);
    const iterator = first.chunks[Symbol.asyncIterator]();
    await assert.rejects(iterator.return(), errorIs('SERVICE_TRANSPORT_INCOMPLETE', 'open_application'));

    const second = await transport.openApplication(pinned);
    assert.throws(() => second.close('extra'), errorIs('SERVICE_TRANSPORT_INVALID', 'open_application'));
    second.close();
    const closedIterator = second.chunks[Symbol.asyncIterator]();
    await assert.rejects(closedIterator.next(), errorIs('SERVICE_TRANSPORT_INCOMPLETE', 'open_application'));
    assert.ok(model.requests.every((request) => request.destroyCalls >= 1));
    assert.ok(model.responses.every((response) => response.destroyCalls >= 1));
  });
});

test('connect timeout destroys a pending request with no raw cause', async (t) => {
  const timers = installTimerModel(t);
  const model = installNetworkModel(t, [{ noResponse: true }]);
  const transport = fixtureTransport(t);
  const pending = transport.readBootstrap('application');
  const connect = timers.find((timer) => timer.milliseconds === DEPLOYMENT_ENVELOPE_LIMITS.connectTimeoutMs);
  assert.ok(connect);
  assert.equal(connect.unrefCalled, true);
  connect.fire();
  await assert.rejects(pending, errorIs('SERVICE_TRANSPORT_CONNECT_TIMEOUT', 'read_bootstrap'));
  assert.ok(model.requests[0].destroyCalls >= 1);
  transport.close();
});

test('one shared lifetime deadline aborts work, destroys the dedicated agent and prevents later requests', async (t) => {
  const timers = installTimerModel(t);
  const model = installNetworkModel(t, [{ noResponse: true }]);
  const transport = fixtureTransport(t);
  const pending = transport.readBootstrap('application');
  const deadlines = timers.filter((timer) => timer.milliseconds === DEPLOYMENT_ENVELOPE_LIMITS.acquisitionTimeoutMs);
  assert.equal(deadlines.length, 1);
  assert.equal(deadlines[0].unrefCalled, true);

  const agent = model.calls[0].agent;
  const originalDestroy = agent.destroy.bind(agent);
  let agentDestroyCalls = 0;
  t.mock.method(agent, 'destroy', () => {
    agentDestroyCalls += 1;
    return originalDestroy();
  });
  deadlines[0].fire();
  await assert.rejects(pending, errorIs('SERVICE_TRANSPORT_DEADLINE_EXCEEDED', 'read_bootstrap'));
  assert.equal(agentDestroyCalls, 1);
  assert.ok(model.requests[0].destroyCalls >= 1);
  await assert.rejects(
    transport.readBootstrap('application'),
    errorIs('SERVICE_TRANSPORT_DEADLINE_EXCEEDED', 'read_bootstrap'),
  );
  assert.equal(model.calls.length, 1);
});

test('the shared lifetime deadline also aborts an already-open response stream', async (t) => {
  const bytes = Buffer.from('deadline response body');
  const pinned = installation.verifyManifest(applicationManifest(bytes));
  const timers = installTimerModel(t);
  const model = installNetworkModel(t, [{ hang: true }]);
  const transport = fixtureTransport(t);
  const asset = await transport.openApplication(pinned);
  const iterator = asset.chunks[Symbol.asyncIterator]();
  const next = iterator.next();
  const deadlines = timers.filter((timer) => timer.milliseconds === DEPLOYMENT_ENVELOPE_LIMITS.acquisitionTimeoutMs);
  assert.equal(deadlines.length, 1);
  deadlines[0].fire();
  await assert.rejects(next, errorIs('SERVICE_TRANSPORT_DEADLINE_EXCEEDED', 'open_application'));
  assert.ok(model.requests[0].destroyCalls >= 1);
  assert.ok(model.responses[0].destroyCalls >= 1);
});

test('idle timeout and response abort/error paths destroy both sides and redact raw failures', async (t) => {
  const bytes = Buffer.from('idle response body');
  const pinned = installation.verifyManifest(applicationManifest(bytes));

  await t.test('idle timeout', async (t) => {
    const model = installNetworkModel(t, [{ hang: true }]);
    const transport = fixtureTransport(t);
    const asset = await transport.openApplication(pinned);
    const iterator = asset.chunks[Symbol.asyncIterator]();
    const next = iterator.next();
    assert.equal(model.responses[0].idleMilliseconds, DEPLOYMENT_ENVELOPE_LIMITS.idleTimeoutMs);
    model.responses[0].fireIdleTimeout();
    await assert.rejects(next, errorIs('SERVICE_TRANSPORT_IDLE_TIMEOUT', 'open_application'));
    assert.ok(model.requests[0].destroyCalls >= 1);
    assert.ok(model.responses[0].destroyCalls >= 1);
  });

  await t.test('response abort', async (t) => {
    const model = installNetworkModel(t, [{ chunks: [bytes], abortAt: 0 }]);
    const transport = fixtureTransport(t);
    const asset = await transport.openApplication(pinned);
    await assert.rejects(consume(asset.chunks), errorIs('SERVICE_TRANSPORT_INCOMPLETE', 'open_application'));
    assert.ok(model.requests[0].destroyCalls >= 1);
    assert.ok(model.responses[0].destroyCalls >= 1);
  });

  await t.test('response error', async (t) => {
    const model = installNetworkModel(t, [{ chunks: [bytes], errorAt: 0, rawError: 'https://secret.example/?token=raw' }]);
    const transport = fixtureTransport(t);
    const asset = await transport.openApplication(pinned);
    await assert.rejects(consume(asset.chunks), errorIs('SERVICE_TRANSPORT_NETWORK_FAILED', 'open_application'));
    assert.ok(model.requests[0].destroyCalls >= 1);
    assert.ok(model.responses[0].destroyCalls >= 1);
  });

  await t.test('request error', async (t) => {
    const model = installNetworkModel(t, [{ requestError: true, rawError: 'https://secret.example/?token=raw' }]);
    const transport = fixtureTransport(t);
    await assert.rejects(transport.openApplication(pinned), errorIs('SERVICE_TRANSPORT_NETWORK_FAILED', 'open_application'));
    assert.ok(model.requests[0].destroyCalls >= 1);
  });
});

test('transport close aborts pending and open streams, is idempotent, and prevents all later requests', async (t) => {
  const bytes = Buffer.from('close response bytes');
  const pinned = installation.verifyManifest(applicationManifest(bytes));

  await t.test('pending request', async (t) => {
    const model = installNetworkModel(t, [{ noResponse: true }]);
    const transport = fixtureTransport(t);
    const pending = transport.readBootstrap('application');
    transport.close();
    transport.close();
    await assert.rejects(pending, errorIs('SERVICE_TRANSPORT_CLOSED', 'read_bootstrap'));
    await assert.rejects(transport.readBootstrap('application'), errorIs('SERVICE_TRANSPORT_CLOSED', 'read_bootstrap'));
    assert.equal(model.calls.length, 1);
    assert.ok(model.requests[0].destroyCalls >= 1);
  });

  await t.test('open response', async (t) => {
    const model = installNetworkModel(t, [{ hang: true }]);
    const transport = fixtureTransport(t);
    const asset = await transport.openApplication(pinned);
    const iterator = asset.chunks[Symbol.asyncIterator]();
    const next = iterator.next();
    transport.close();
    await assert.rejects(next, errorIs('SERVICE_TRANSPORT_CLOSED', 'open_application'));
    assert.ok(model.requests[0].destroyCalls >= 1);
    assert.ok(model.responses[0].destroyCalls >= 1);
  });
});
