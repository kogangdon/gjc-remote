// Exact-runtime canary for the signed service bootstrap guard. Runs the guard
// under the real Node 26.7.0 / Bun 1.4.2 executables (skipped, never passed,
// when the local runtimes are not the exact pinned builds). It never creates
// services, changes ACLs, reads credentials or signs anything: every child
// gets a minimal explicit environment and a temporary entrypoint that only
// prints a marker, so the observable claim is "the guard stops a refused
// launch before the entrypoint runs and is inert outside a service launch".
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { SERVICE_BOOTSTRAP_RUNTIMES } from '../src/service-bootstrap-policy.js';

const GUARD = fileURLToPath(new URL('../src/service-bootstrap.js', import.meta.url));
const MARKER = 'GJC_ENTRYPOINT_RAN';

function probe(command, args) {
  const result = spawnSync(command, args, { encoding: 'utf8', windowsHide: true, timeout: 30_000 });
  return result.status === 0 ? result.stdout.trim() : null;
}
const nodeVersion = process.versions.node;
const bunPath = process.platform === 'win32' ? 'bun.exe' : 'bun';
const bunIdentity = probe(bunPath, ['-e', 'console.log(Bun.version + " " + Bun.revision)']);
const exactNode = nodeVersion === SERVICE_BOOTSTRAP_RUNTIMES.bot.version;
const exactBun = bunIdentity === `${SERVICE_BOOTSTRAP_RUNTIMES.daemon.version} ${SERVICE_BOOTSTRAP_RUNTIMES.daemon.sourceRevision}`;

function baseEnv(extra = {}) {
  return {
    SystemRoot: process.env.SystemRoot ?? '',
    PATH: process.env.PATH ?? '',
    TEMP: process.env.TEMP ?? tmpdir(),
    TMP: process.env.TMP ?? tmpdir(),
    ...extra,
  };
}

function withEntrypoint(source, run) {
  const directory = mkdtempSync(join(tmpdir(), 'gjc-guard-canary-'));
  try {
    const entry = join(directory, 'entry.mjs');
    writeFileSync(entry, source);
    return run(entry);
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
}

const importingEntry = `import { consumeServiceBootstrapContext } from ${JSON.stringify(pathToFileURL(GUARD).href)};\n` +
  `const context = consumeServiceBootstrapContext();\nconsole.log('${MARKER} ' + JSON.stringify(context));\n`;

test('Node: guard is inert outside a service launch and yields a null context', { skip: !exactNode && 'local Node is not the exact pinned runtime' }, () => {
  withEntrypoint(importingEntry, (entry) => {
    const result = spawnSync(process.execPath, [entry], { encoding: 'utf8', env: baseEnv(), windowsHide: true, timeout: 60_000 });
    assert.equal(result.status, 0, result.stderr);
    assert.match(result.stdout, new RegExp(`${MARKER} null`));
  });
});

test('Node: a service-marked launch without verified authority stops before the entrypoint', { skip: !exactNode && 'local Node is not the exact pinned runtime' }, () => {
  withEntrypoint(importingEntry, (entry) => {
    const result = spawnSync(process.execPath, [entry], {
      encoding: 'utf8', env: baseEnv({ GJC_REMOTE_SERVICE_COMPONENT: 'bot' }), windowsHide: true, timeout: 60_000,
    });
    assert.notEqual(result.status, 0);
    assert.doesNotMatch(result.stdout, new RegExp(MARKER));
    assert.match(result.stderr, /service-bootstrap(-native)?\.js/, 'refusal must originate in the guard');
  });
});

test('Bun: BUN_INSPECT_PRELOAD guard is inert outside a service launch', { skip: !exactBun && 'local Bun is not the exact pinned runtime' }, () => {
  withEntrypoint(`console.log('${MARKER}');\n`, (entry) => {
    const result = spawnSync(bunPath, [entry], {
      encoding: 'utf8', env: baseEnv({ BUN_INSPECT_PRELOAD: GUARD }), windowsHide: true, timeout: 60_000,
    });
    assert.equal(result.status, 0, result.stderr);
    assert.match(result.stdout, new RegExp(MARKER));
  });
});

test('Bun: BUN_INSPECT_PRELOAD guard refusal stops the entrypoint', { skip: !exactBun && 'local Bun is not the exact pinned runtime' }, () => {
  withEntrypoint(`console.log('${MARKER}');\n`, (entry) => {
    const result = spawnSync(bunPath, [entry], {
      encoding: 'utf8',
      env: baseEnv({ BUN_INSPECT_PRELOAD: GUARD, GJC_REMOTE_SERVICE_COMPONENT: 'daemon' }),
      windowsHide: true, timeout: 60_000,
    });
    assert.notEqual(result.status, 0);
    assert.doesNotMatch(result.stdout, new RegExp(MARKER));
    assert.match(result.stderr, /service-bootstrap(-native)?\.js/, 'refusal must originate in the guard');
  });
});
