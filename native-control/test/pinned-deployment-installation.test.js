import assert from 'node:assert/strict';
import fs from 'node:fs';
import { syncBuiltinESMExports } from 'node:module';
import { join, sep } from 'node:path';
import test from 'node:test';
import { createPinnedDeploymentInstallation } from '../test-fixtures/pinned-deployment-installation.mjs';

const CLEANUP_FAILURE = 'PINNED_DEPLOYMENT_FIXTURE_CLEANUP_FAILED';

function missing(path, lstat = fs.lstatSync) {
  try {
    Reflect.apply(lstat, fs, [path]);
    return false;
  } catch (error) {
    if (error?.code === 'ENOENT') return true;
    throw error;
  }
}

function assertCleanupFailure(error) {
  assert.equal(error?.code, CLEANUP_FAILURE);
  assert.equal(error?.message, CLEANUP_FAILURE);
  assert.equal(Object.hasOwn(error, 'writes'), false);
  assert.equal(error?.cause, undefined);
  assert.ok(error.message.length < 128);
  return true;
}

function installRootCapture(t) {
  const original = fs.mkdtempSync;
  let createdPath = null;
  t.mock.method(fs, 'mkdtempSync', (...args) => {
    const path = Reflect.apply(original, fs, args);
    createdPath = path;
    return path;
  });
  syncBuiltinESMExports();
  return {
    original,
    get createdPath() {
      assert.notEqual(createdPath, null);
      return createdPath;
    },
  };
}

function restoreFsMocks(t) {
  t.mock.restoreAll();
  syncBuiltinESMExports();
}

test('verified fixture disposal removes its captured directory and is idempotent', async (t) => {
  const originalLstat = fs.lstatSync;
  const capture = installRootCapture(t);
  let fixture;
  let root;
  try {
    fixture = await createPinnedDeploymentInstallation({
      keyIds: ['fixture-dispose-key'],
    });
    root = fs.realpathSync(capture.createdPath);
    assert.equal(fs.lstatSync(root).isDirectory(), true);
    assert.equal(fixture.releaseBuilderUrl, null);
    const applicationTrustA = fixture.bundledApplicationTrustBytes;
    const applicationTrustB = fixture.bundledApplicationTrustBytes;
    const shawlTrustA = fixture.bundledShawlTrustBytes;
    const shawlTrustB = fixture.bundledShawlTrustBytes;
    assert.ok(applicationTrustA.length > 0);
    assert.ok(shawlTrustA.length > 0);
    assert.notEqual(applicationTrustA, applicationTrustB);
    assert.notEqual(shawlTrustA, shawlTrustB);
    applicationTrustA.fill(0);
    shawlTrustA.fill(0);
    assert.notDeepEqual(applicationTrustA, applicationTrustB);
    assert.notDeepEqual(shawlTrustA, shawlTrustB);

    fixture.dispose();
    assert.equal(missing(root, originalLstat), true);
    assert.doesNotThrow(() => fixture.dispose());
  } finally {
    restoreFsMocks(t);
    if (root && !missing(root, originalLstat)) {
      fs.rmSync(root, { recursive: true, force: true });
    }
  }
});

test('dispose rejects a renamed fixture root and preserves replacement contents', async (t) => {
  const originalLstat = fs.lstatSync;
  const capture = installRootCapture(t);
  let fixture;
  let root;
  let moved;
  try {
    fixture = await createPinnedDeploymentInstallation({
      keyIds: ['fixture-replacement-key'],
      includeReleaseBuilder: true,
    });
    root = fs.realpathSync(capture.createdPath);
    moved = `${root}-renamed`;
    fs.renameSync(root, moved);
    fs.mkdirSync(root);
    const sentinel = join(root, 'replacement-sentinel.txt');
    fs.writeFileSync(sentinel, 'replacement must survive\n');

    assert.throws(() => fixture.dispose(), assertCleanupFailure);
    assert.equal(fs.readFileSync(sentinel, 'utf8'), 'replacement must survive\n');
    assert.equal(fs.lstatSync(moved).isDirectory(), true);
    assert.equal(missing(join(moved, 'native-control', 'deployment-keys', 'application-trusted.json'), originalLstat), false);
    assert.equal(missing(join(moved, 'native-control', 'deployment-keys', 'shawl-trusted.json'), originalLstat), false);
    assert.match(fixture.releaseBuilderUrl, /^file:/);
  } finally {
    restoreFsMocks(t);
    for (const path of [root, moved]) {
      if (path && !missing(path, originalLstat)) {
        fs.rmSync(path, { recursive: true, force: true });
      }
    }
  }
});

test('construction failure after identity capture preserves a replacement and returns only the bounded cleanup failure', async (t) => {
  const originalMkdtemp = fs.mkdtempSync;
  const originalMkdir = fs.mkdirSync;
  const originalRename = fs.renameSync;
  const originalWrite = fs.writeFileSync;
  const originalRealpath = fs.realpathSync;
  const originalLstat = fs.lstatSync;
  let createdPath = null;
  let canonicalRoot = null;
  let moved = null;
  let replaced = false;

  t.mock.method(fs, 'mkdtempSync', (...args) => {
    createdPath = Reflect.apply(originalMkdtemp, fs, args);
    canonicalRoot = Reflect.apply(originalRealpath, fs, [createdPath]);
    moved = `${canonicalRoot}-constructor-renamed`;
    return createdPath;
  });
  t.mock.method(fs, 'mkdirSync', (path, ...args) => {
    if (!replaced && canonicalRoot !== null &&
        typeof path === 'string' && path.startsWith(`${canonicalRoot}${sep}`)) {
      replaced = true;
      Reflect.apply(originalRename, fs, [canonicalRoot, moved]);
      Reflect.apply(originalMkdir, fs, [canonicalRoot]);
      Reflect.apply(originalWrite, fs, [
        join(canonicalRoot, 'replacement-sentinel.txt'),
        'constructor replacement must survive\n',
      ]);
      throw new Error(`untrusted constructor failure at ${path}`);
    }
    return Reflect.apply(originalMkdir, fs, [path, ...args]);
  });
  syncBuiltinESMExports();

  try {
    await assert.rejects(
      createPinnedDeploymentInstallation({
        keyIds: ['fixture-constructor-failure-key'],
      }),
      assertCleanupFailure,
    );
    assert.equal(replaced, true);
    assert.equal(
      fs.readFileSync(join(canonicalRoot, 'replacement-sentinel.txt'), 'utf8'),
      'constructor replacement must survive\n',
    );
    assert.equal(fs.lstatSync(moved).isDirectory(), true);
  } finally {
    restoreFsMocks(t);
    for (const path of [canonicalRoot, moved]) {
      if (path && !missing(path, originalLstat)) {
        fs.rmSync(path, { recursive: true, force: true });
      }
    }
  }
});

test('includeStore installations copy the archive parser and link the tar dependency', async (t) => {
  const originalLstat = fs.lstatSync;
  const capture = installRootCapture(t);
  let root;
  try {
    const fixture = await createPinnedDeploymentInstallation({
      keyIds: ['fixture-store-archive-key'],
      includeStore: true,
    });
    root = fs.realpathSync(capture.createdPath);
    const parserPath = join(root, 'native-control', 'src', 'service-archive.js');
    assert.equal(fs.lstatSync(parserPath).isFile(), true);
    assert.equal(
      fs.statSync(join(root, 'node_modules', 'tar')).isDirectory(),
      true,
    );
    const parser = await import(`file://${parserPath.replaceAll(sep, '/')}`);
    assert.equal(typeof parser.inspectApplicationArchive, 'function');
    assert.equal(typeof parser.consumeApplicationArchive, 'function');
    fixture.dispose();
  } finally {
    restoreFsMocks(t);
    if (root && !missing(root, originalLstat)) {
      fs.rmSync(root, { recursive: true, force: true });
    }
  }
});
