import test from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { existsSync, readFileSync } from 'node:fs';
import { mkdtemp, rm, realpath, writeFile } from 'node:fs/promises';
import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';
import { tmpdir } from 'node:os';
import { mkdir } from 'node:fs/promises';
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

// Spawns a long-lived child, awaits its spawn, and returns it. `setup` is inline
// node source that establishes the residual hold (cwd via spawn options, or an
// open fd). Callers must kill the returned child.
async function spawnHolder({ cwd, source }) {
  const child = spawn(process.execPath, ['-e', source], { cwd, stdio: 'ignore' });
  await new Promise((resolve, reject) => {
    child.once('spawn', resolve);
    child.once('error', reject);
  });
  // Give /proc/<pid>/{cwd,fd} a moment to become observable.
  await new Promise((resolve) => setTimeout(resolve, 120));
  return child;
}

async function killHolder(child) {
  child.kill('SIGKILL');
  await new Promise((resolve) => child.once('exit', resolve));
}

test('enumerate_workspace_process_holders rejects malformed arguments', (t) => {
  const addon = loadAddonOrSkip(t);
  if (!addon) return;
  // Argument-shape validation runs before any platform branch, so these fail
  // closed identically on every OS.
  assert.throws(() => addon.enumerate_workspace_process_holders('', 'posix'), { code: 'INVENTORY_INVALID' });
  assert.throws(() => addon.enumerate_workspace_process_holders('/srv/ws'), { code: 'INVENTORY_INVALID' });
  assert.throws(() => addon.enumerate_workspace_process_holders(42, 'posix'), { code: 'INVENTORY_INVALID' });
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

test('linux scan rejects non-canonical workspace roots', (t) => {
  if (process.platform !== 'linux') {
    t.skip('canonicality enforcement is compiled only on linux');
    return;
  }
  const addon = loadAddonOrSkip(t);
  if (!addon) return;
  for (const bad of ['/srv/ws/../ws', '/srv//ws', '/srv/./ws', '/srv/ws/.', '/srv/ws/..']) {
    assert.throws(() => addon.enumerate_workspace_process_holders(bad, 'posix'), { code: 'INVENTORY_INVALID' }, bad);
  }
});

test('linux scan returns [] for an unheld workspace and finds cwd, fd, and boundary holders', async (t) => {
  if (process.platform !== 'linux') {
    t.skip('the real /proc scan only runs on linux');
    return;
  }
  const addon = loadAddonOrSkip(t);
  if (!addon) return;

  const parent = await realpath(await mkdtemp(join(tmpdir(), 'residual-')));
  const dir = join(parent, 'ws');
  const sibling = join(parent, 'wsX'); // prefix of `dir` but NOT a path-boundary child
  const outside = await realpath(tmpdir());
  const children = [];
  try {
    // mkdtemp gave us `parent`; create ws and its prefix-sibling wsX under it.
    await mkdir(dir, { recursive: true });
    await mkdir(sibling, { recursive: true });
    const held = join(dir, 'held.txt');
    await writeFile(held, 'x');

    // No process holds the fresh workspace open.
    assert.deepEqual(addon.enumerate_workspace_process_holders(dir, 'posix'), []);

    // Holder A: cwd inside the workspace.
    const cwdChild = await spawnHolder({ cwd: dir, source: 'setInterval(() => {}, 1000)' });
    children.push(cwdChild);
    // Holder B: an open fd on a workspace file, with cwd OUTSIDE the workspace
    // so only the fd path can match (isolates the fd-scan branch).
    const fdChild = await spawnHolder({
      cwd: outside,
      source: `require('fs').openSync(${JSON.stringify(held)}, 'r'); setInterval(() => {}, 1000);`,
    });
    children.push(fdChild);
    // Negative: cwd in the sibling '.../wsX' must NOT count as a holder of '.../ws'.
    const siblingChild = await spawnHolder({ cwd: sibling, source: 'setInterval(() => {}, 1000)' });
    children.push(siblingChild);

    const pids = addon.enumerate_workspace_process_holders(dir, 'posix').map((d) => d.pid);
    for (const d of addon.enumerate_workspace_process_holders(dir, 'posix')) {
      assert.equal(typeof d.pid, 'number');
      assert.ok(Number.isSafeInteger(d.pid) && d.pid >= 1);
    }
    assert.ok(pids.includes(cwdChild.pid), `cwd holder ${cwdChild.pid} missing from ${JSON.stringify(pids)}`);
    assert.ok(pids.includes(fdChild.pid), `fd holder ${fdChild.pid} missing from ${JSON.stringify(pids)}`);
    assert.ok(
      !pids.includes(siblingChild.pid),
      `sibling '.../wsX' pid ${siblingChild.pid} was wrongly counted as a '.../ws' holder`,
    );
    // Every reported pid appears once.
    assert.equal(new Set(pids).size, pids.length);
  } finally {
    for (const child of children) await killHolder(child);
    await rm(parent, { recursive: true, force: true });
  }
});
