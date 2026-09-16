import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import test from 'node:test';
import { buildShawlDeploymentManifest, SHAWL_UPSTREAM } from '@gjc-remote/shared/deployment-envelope';
import { createOfflineDeploymentSource } from '../src/service-offline-source.js';
import { createPinnedDeploymentInstallation } from '../test-fixtures/pinned-deployment-installation.mjs';

const digest = (bytes) => createHash('sha256').update(bytes).digest('hex');
const source = Object.freeze({
  kind: 'offline',
  applicationManifestPath: 'C:\\fixture\\app.json',
  applicationSignaturePath: 'C:\\fixture\\app.sig',
  applicationArchivePath: 'C:\\fixture\\app.tar.gz',
  shawlManifestPath: 'C:\\fixture\\shawl.json',
  shawlSignaturePath: 'C:\\fixture\\shawl.sig',
  shawlExecutablePath: 'C:\\fixture\\shawl.exe',
});
const options = (native) => ({ native, source, platform: 'win32', architecture: 'x64' });

function modelNative(files, { chunkSize = 7, corrupt = false, wrongOffset = false, excessiveFacts = false } = {}) {
  const handles = new Set();
  const opened = [];
  const native = {
    open_service_artifact_source(path, maximum, expected) {
      assert.equal(expected, null);
      opened.push(path);
      const bytes = files.get(path);
      if (bytes === undefined) return null;
      assert.ok(bytes.length <= maximum);
      const handle = { path, bytes };
      handles.add(handle);
      return {
        handle,
        facts: {
          kind: 'win32-file-v1', volumeSerial: '1'.repeat(16), fileId: digest(path).slice(0, 32),
          size: excessiveFacts ? maximum + 1 : bytes.length,
          sha256: digest(bytes), attributes: 32,
          owner: 'S-1-5-21-1-2-3-1000', securitySha256: 'b'.repeat(64),
        },
        writes: 0,
      };
    },
    read_service_artifact_chunk(handle, offset, maximum) {
      assert.ok(handles.has(handle));
      assert.ok(maximum <= 1024 * 1024);
      const bytes = Buffer.from(handle.bytes.subarray(offset, offset + Math.min(maximum, chunkSize)));
      if (corrupt && bytes.length) bytes[0] ^= 1;
      const nextOffset = offset + bytes.length;
      return { bytes, nextOffset: wrongOffset ? nextOffset + 1 : nextOffset, eof: nextOffset === handle.bytes.length, writes: 0 };
    },
    close_service_handle(handle) {
      assert.ok(handles.delete(handle));
      return { writes: 0 };
    },
  };
  return { native, handles, opened };
}

async function collect(chunks) {
  const parts = [];
  for await (const bytes of chunks) parts.push(bytes);
  return Buffer.concat(parts);
}

test('model: bounded offline bootstrap uses captured native methods and closes every reader', async () => {
  const files = new Map([
    [source.applicationManifestPath, Buffer.from('manifest bytes')],
    [source.applicationSignaturePath, Buffer.alloc(0)],
  ]);
  const model = modelNative(files);
  const offline = createOfflineDeploymentSource(options(model.native));
  model.native.open_service_artifact_source = () => { throw new Error('mutated facade'); };
  const result = await offline.readBootstrap('application');
  assert.deepEqual(result.manifestBytes, files.get(source.applicationManifestPath));
  assert.equal(result.signatureBytes.length, 0);
  assert.equal(model.handles.size, 0);
  assert.deepEqual(model.opened, [source.applicationManifestPath, source.applicationSignaturePath]);
  offline.close();
  await assert.rejects(offline.readBootstrap('application'), { code: 'DEPLOYMENT_SOURCE_CLOSED', writes: 0 });
});

test('model: failed native close retains ownership until a successful source-close retry', async () => {
  const model = modelNative(new Map([
    [source.applicationManifestPath, Buffer.from('manifest bytes')],
  ]));
  const originalClose = model.native.close_service_handle;
  let failClose = true;
  let attempts = 0;
  model.native.close_service_handle = (handle) => {
    attempts += 1;
    if (failClose) throw Object.assign(new Error('private close failure'), { writes: 0 });
    return originalClose(handle);
  };
  const offline = createOfflineDeploymentSource(options(model.native));
  await assert.rejects(offline.readBootstrap('application'), {
    code: 'DEPLOYMENT_SOURCE_NATIVE_FAILED',
    message: 'DEPLOYMENT_SOURCE_NATIVE_FAILED',
    writes: 0,
  });
  assert.equal(model.handles.size, 1);
  assert.throws(() => offline.close(), { code: 'DEPLOYMENT_SOURCE_NATIVE_FAILED', writes: 0 });
  assert.equal(model.handles.size, 1);
  const failedAttempts = attempts;
  failClose = false;
  offline.close();
  assert.equal(attempts, failedAttempts + 1);
  assert.equal(model.handles.size, 0);
  offline.close();
  assert.equal(attempts, failedAttempts + 1);
  await assert.rejects(offline.readBootstrap('application'), { code: 'DEPLOYMENT_SOURCE_CLOSED', writes: 0 });
});

test('model: offline source rejects invalid receipts, changed bytes and missing inputs without leaked handles', async () => {
  for (const fault of [{ corrupt: true }, { wrongOffset: true }, { excessiveFacts: true }, {}]) {
    const files = new Map([[source.applicationManifestPath, Buffer.from('private input')]]);
    const model = modelNative(files, fault);
    const offline = createOfflineDeploymentSource(options(model.native));
    await assert.rejects(offline.readBootstrap('application'), (error) => {
      assert.equal(error.writes, 0);
      assert.match(error.code, /^DEPLOYMENT_SOURCE_/);
      assert.equal(error.message, error.code);
      assert.equal(error.cause, undefined);
      assert.ok(!JSON.stringify(error).includes('private input'));
      assert.ok(!JSON.stringify(error).includes('fixture'));
      return true;
    });
    assert.equal(model.handles.size, 0);
    offline.close();
  }
});

test('model: genuine fixture-pinned offline Shawl streams are single-use and abortable', async () => {
  const fixture = await createPinnedDeploymentInstallation({ keyIds: ['deployment-test'], includeOffline: true });
  try {
    const bytes = Buffer.from('fixture executable bytes');
    const manifest = fixture.verifyManifest(buildShawlDeploymentManifest({
      signingKeyId: 'deployment-test', releaseSequence: 1,
      target: { platform: 'win32', architecture: 'x64' },
      upstream: { repository: SHAWL_UPSTREAM.repository, tag: SHAWL_UPSTREAM.tag, commit: SHAWL_UPSTREAM.commit, assetId: 1, assetName: 'shawl.zip', zipSha256: 'a'.repeat(64) },
      executable: { name: 'shawl.exe', byteLength: bytes.length, sha256: digest(bytes), version: '1.9.0', versionOutput: 'shawl 1.9.0', authenticode: 'unsigned' },
      projectAsset: { repository: 'kogangdon/gjc-remote', tag: 'v1.0.0', name: 'gjc-remote-shawl-win32-x64.exe' },
    }));
    const model = modelNative(new Map([[source.shawlExecutablePath, bytes]]));
    const offline = fixture.offline.createOfflineDeploymentSource(options(model.native));
    assert.throws(() => offline.openShawl(structuredClone(manifest)), { code: 'DEPLOYMENT_SOURCE_PINNED_PROVENANCE_REQUIRED' });
    assert.throws(() => offline.openApplication(manifest), { code: 'DEPLOYMENT_SOURCE_PINNED_PROVENANCE_REQUIRED' });
    const foreignTarget = fixture.offline.createOfflineDeploymentSource({
      native: model.native, platform: 'linux', architecture: 'x64',
      source: { kind: 'offline', applicationManifestPath: '/fixture/app.json', applicationSignaturePath: '/fixture/app.sig', applicationArchivePath: '/fixture/app.tar.gz' },
    });
    assert.throws(() => foreignTarget.openShawl(manifest), { code: 'DEPLOYMENT_SOURCE_TARGET_MISMATCH' });
    foreignTarget.close();
    assert.equal(model.opened.length, 0);
    assert.throws(() => createOfflineDeploymentSource(options(model.native)).openShawl(manifest), { code: 'DEPLOYMENT_SOURCE_PINNED_PROVENANCE_REQUIRED' });
    assert.equal(model.opened.length, 0);
    const opened = offline.openShawl(manifest);
    assert.ok(Object.isFrozen(opened.facts));
    assert.deepEqual(await collect(opened.chunks), bytes);
    assert.throws(() => opened.chunks[Symbol.asyncIterator](), { code: 'DEPLOYMENT_SOURCE_ALREADY_CONSUMED' });
    assert.equal(model.handles.size, 0);
    const mismatchModel = modelNative(new Map([[source.shawlExecutablePath, Buffer.alloc(bytes.length, 0)]]));
    const mismatch = fixture.offline.createOfflineDeploymentSource(options(mismatchModel.native));
    assert.throws(() => mismatch.openShawl(manifest), { code: 'DEPLOYMENT_SOURCE_IDENTITY_MISMATCH' });
    assert.equal(mismatchModel.handles.size, 0);
    mismatch.close();
    for (const method of ['return', 'throw']) {
      const unstarted = offline.openShawl(manifest).chunks[Symbol.asyncIterator]();
      assert.equal(model.handles.size, 1);
      await assert.rejects(unstarted[method](new Error('private cancellation')), {
        code: 'DEPLOYMENT_SOURCE_INCOMPLETE', writes: 0,
      });
      assert.equal(model.handles.size, 0);
    }
    const incomplete = offline.openShawl(manifest);
    const iterator = incomplete.chunks[Symbol.asyncIterator]();
    await iterator.next();
    await assert.rejects(iterator.return(), { code: 'DEPLOYMENT_SOURCE_INCOMPLETE' });
    assert.equal(model.handles.size, 0);
    const interrupted = offline.openShawl(manifest);
    offline.close();
    assert.equal(model.handles.size, 0);
    await assert.rejects(collect(interrupted.chunks), { code: 'DEPLOYMENT_SOURCE_CLOSED' });
  } finally {
    fixture.dispose();
  }
});

test('offline options and source paths refuse before any native call', () => {
  const model = modelNative(new Map());
  const input = options(model.native);
  assert.throws(() => createOfflineDeploymentSource({ ...input, extra: true }));
  assert.throws(() => createOfflineDeploymentSource({ ...input, source: { ...source, applicationArchivePath: source.applicationManifestPath } }));
  let evaluated = false;
  Object.defineProperty(input, 'source', { get() { evaluated = true; return source; } });
  assert.throws(() => createOfflineDeploymentSource(input));
  assert.equal(evaluated, false);
  assert.equal(model.opened.length, 0);
});
