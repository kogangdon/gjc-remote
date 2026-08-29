import test from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { existsSync, readFileSync } from 'node:fs';
import { mkdtemp, rm, realpath } from 'node:fs/promises';
import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { validateBuildManifest } from '../src/index.js';

const require = createRequire(import.meta.url);
const addonPath = fileURLToPath(new URL('../build/Release/native_control.node', import.meta.url));
const manifestPath = fileURLToPath(new URL('../build/Release/native-control.manifest.json', import.meta.url));
const packagePath = fileURLToPath(new URL('../package.json', import.meta.url));

// Loads the real, manifest-validated native addon or registers a skip. Unlike
// the pure-JS binding unit test, this exercises the actual native
// enumerate_workspace_process_holders implementation.
function loadAddonOrSkip(t) {
  if (!existsSync(addonPath) || !existsSync(manifestPath)) {
    t.skip('verified native addon is not built for this checkout');
    return null;
  }
  const addonBytes = readFileSync(addonPath);
  const manifest = JSON.parse(readFileSync(manifestPath, 'utf8'));
  const packageJson = JSON.parse(readFileSync(packagePath, 'utf8'));
  if (!validateBuildManifest(manifest, packageJson, addonBytes, process.platform, process.arch)) {
    t.skip('native build belongs to a different platform or architecture');
    return null;
  }
  return require(addonPath);
}

test('enumerate_workspace_process_holders rejects malformed arguments', (t) => {
  const addon = loadAddonOrSkip(t);
  if (!addon) return;
  assert.throws(() => addon.enumerate_workspace_process_holders('', 'posix'), { code: 'INVENTORY_INVALID' });
  assert.throws(() => addon.enumerate_workspace_process_holders('/srv/ws'), /.*/); // arity
  assert.throws(() => addon.enumerate_workspace_process_holders(42, 'posix'), /.*/);
});

test('enumerate_workspace_process_holders is unsupported off Linux', (t) => {
  if (process.platform === 'linux') {
    t.skip('linux performs a real scan; unsupported behavior is for other platforms');
    return;
  }
  const addon = loadAddonOrSkip(t);
  if (!addon) return;
  // On windows-drive the posix branch is compiled out; the native call fails
  // closed with CONTAINMENT_UNSUPPORTED (Windows handle-scan is slice S7.2b).
  assert.throws(
    () => addon.enumerate_workspace_process_holders('C:\\workspace', 'windows-drive'),
    (error) => error.code === 'CONTAINMENT_UNSUPPORTED' || error.code === 'INVENTORY_INVALID',
  );
});

test('linux scan returns [] for a workspace no process holds, and finds a holder by cwd', async (t) => {
  if (process.platform !== 'linux') {
    t.skip('the real /proc scan only runs on linux');
    return;
  }
  const addon = loadAddonOrSkip(t);
  if (!addon) return;

  const dir = await realpath(await mkdtemp(join(tmpdir(), 'residual-')));
  try {
    // No process holds the fresh workspace open.
    const empty = addon.enumerate_workspace_process_holders(dir, 'posix');
    assert.deepEqual(empty, []);

    // Spawn a child whose current working directory is inside the workspace.
    const child = spawn(process.execPath, ['-e', 'setInterval(() => {}, 1000)'], {
      cwd: dir,
      stdio: 'ignore',
    });
    try {
      await new Promise((resolve, reject) => {
        child.once('spawn', resolve);
        child.once('error', reject);
      });
      // Give the child a moment for /proc/<pid>/cwd to be observable.
      await new Promise((resolve) => setTimeout(resolve, 100));
      const held = addon.enumerate_workspace_process_holders(dir, 'posix');
      assert.ok(Array.isArray(held));
      assert.ok(
        held.some((descriptor) => descriptor.pid === child.pid),
        `expected holder set ${JSON.stringify(held)} to include child pid ${child.pid}`,
      );
      for (const descriptor of held) {
        assert.equal(typeof descriptor.pid, 'number');
        assert.ok(Number.isSafeInteger(descriptor.pid) && descriptor.pid >= 1);
      }
    } finally {
      child.kill('SIGKILL');
      await new Promise((resolve) => child.once('exit', resolve));
    }
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});
