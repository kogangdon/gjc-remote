import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFileSync, realpathSync } from 'node:fs';
import { builtinModules, createRequire } from 'node:module';
import { dirname, join, relative, sep } from 'node:path';
import test from 'node:test';
import { fileURLToPath, pathToFileURL } from 'node:url';
import {
  SERVICE_BOOTSTRAP_CLOSURE_DOMAIN,
  SERVICE_BOOTSTRAP_STATIC_CLOSURE,
  serviceBootstrapClosureFingerprint,
} from '../src/service-bootstrap-policy.js';
import { windowsServiceBootstrapClosureFingerprint } from '@gjc-remote/shared/deployment-envelope';
import { windowsServiceBootstrapMetadata } from '../scripts/build-service-release.mjs';

const repoRoot = realpathSync(dirname(dirname(dirname(fileURLToPath(import.meta.url)))));
const guardPath = join(repoRoot, 'native-control', 'src', 'service-bootstrap.js');
const builtins = new Set(builtinModules);
const ESM_SPECIFIER = /^\s*(?:import|export)\s[^'"]*?from\s*['"]([^'"]+)['"]|^\s*import\s*['"]([^'"]+)['"]/gm;
const CJS_SPECIFIER = /\brequire\(\s*['"]([^'"]+)['"]\s*\)/g;
const repoRelative = (path) => relative(repoRoot, realpathSync(path)).split(sep).join('/');

function packageJsonFor(file) {
  let directory = dirname(file);
  for (;;) {
    try {
      const candidate = join(directory, 'package.json');
      readFileSync(candidate);
      return candidate;
    } catch {
      const parent = dirname(directory);
      if (parent === directory) throw new Error('package.json not found');
      directory = parent;
    }
  }
}

function staticClosure() {
  const files = new Set();
  const specifiers = [];
  const queue = [guardPath];
  while (queue.length > 0) {
    const file = realpathSync(queue.pop());
    const key = repoRelative(file);
    if (files.has(key)) continue;
    files.add(key);
    files.add(repoRelative(packageJsonFor(file)));
    const source = readFileSync(file, 'utf8');
    const esm = file.endsWith('.js') && !file.includes(`${sep}node_modules${sep}`);
    const found = esm
      ? [...source.matchAll(ESM_SPECIFIER)].map((match) => match[1] ?? match[2])
      : [...source.matchAll(CJS_SPECIFIER)].map((match) => match[1]);
    const require = createRequire(file);
    for (const specifier of found) {
      specifiers.push([key, specifier]);
      if (specifier.startsWith('node:') || builtins.has(specifier)) continue;
      const resolved = esm && !specifier.startsWith('.')
        ? fileURLToPath(import.meta.resolve(specifier, pathToFileURL(file).href))
        : require.resolve(specifier);
      if (resolved.endsWith('.json')) files.add(repoRelative(resolved));
      else queue.push(resolved);
    }
  }
  return {
    files: [...files].sort((a, b) => Buffer.compare(Buffer.from(a), Buffer.from(b))),
    specifiers,
  };
}

test('declared static closure equals the recomputed guard import and resolution closure', () => {
  assert.deepEqual(staticClosure().files, [...SERVICE_BOOTSTRAP_STATIC_CLOSURE]);
  assert.equal(Object.isFrozen(SERVICE_BOOTSTRAP_STATIC_CLOSURE), true);
});

test('guard closure has no application, SDK, broad public, dotenv-config or dynamic imports', () => {
  const { specifiers } = staticClosure();
  const forbidden = /^(?:dotenv\/config|@gjc-remote\/shared$|@gjc-remote\/native-control$|\.\/(?:public|index|service-cli|service-entrypoint)\.js$|discord\.js|@oh-my-pi|@anthropic|@earendil|gajae)/;
  for (const [file, specifier] of specifiers) assert.equal(forbidden.test(specifier), false, `${file} -> ${specifier}`);
  for (const file of SERVICE_BOOTSTRAP_STATIC_CLOSURE.filter((path) => path.endsWith('.js'))) {
    const source = readFileSync(join(repoRoot, ...file.split('/')), 'utf8');
    assert.equal(/\bimport\s*\(/.test(source), false, `${file} has a dynamic import`);
    assert.equal(/\beval\s*\(|new Function\s*\(/.test(source), false, `${file} evaluates code`);
  }
  const guard = readFileSync(guardPath, 'utf8');
  assert.equal(guard.match(/createServiceBootstrapNative\(\)/g).length, 1);
  assert.equal(guard.match(/evaluateServiceBootstrap\(/g).length, 1);
});

test('closure fingerprint is domain-separated and binds every path and hash in order', () => {
  const entries = SERVICE_BOOTSTRAP_STATIC_CLOSURE.map((relativePath) => ({
    relativePath,
    sha256: createHash('sha256').update(readFileSync(join(repoRoot, ...relativePath.split('/')))).digest('hex'),
  }));
  const fingerprint = serviceBootstrapClosureFingerprint(entries);
  const expected = createHash('sha256').update(`${SERVICE_BOOTSTRAP_CLOSURE_DOMAIN}\n${JSON.stringify(
    entries.map(({ relativePath, sha256 }) => [relativePath, sha256]))}`).digest('hex');
  assert.equal(fingerprint, expected);
  const alteredHash = entries.map((entry, index) => index === 3 ? { ...entry, sha256: '0'.repeat(64) } : entry);
  assert.notEqual(serviceBootstrapClosureFingerprint(alteredHash), fingerprint);
  const alteredPath = entries.map((entry, index) => index === entries.length - 1
    ? { ...entry, relativePath: `${entry.relativePath}x` } : entry);
  assert.notEqual(serviceBootstrapClosureFingerprint(alteredPath), fingerprint);
  assert.throws(() => serviceBootstrapClosureFingerprint([entries[1], entries[0]]), TypeError);
  assert.throws(() => serviceBootstrapClosureFingerprint([...entries, entries.at(-1)]), TypeError);
  assert.throws(() => serviceBootstrapClosureFingerprint([{ ...entries[0], extra: true }]), TypeError);
  assert.throws(() => serviceBootstrapClosureFingerprint([{ relativePath: 'a', sha256: 'A'.repeat(64) }]), TypeError);
  assert.throws(() => serviceBootstrapClosureFingerprint([]), TypeError);
});

test('Windows Launch validation requires the guard leaf that the closure declares', () => {
  const windows = readFileSync(join(repoRoot, 'native-control', 'src', 'service-windows.js'), 'utf8');
  assert.match(windows, /validWin32Leaf\(fields\.bootstrapPath, 'service-bootstrap\.js'\)/);
  assert.match(windows, /\['BUN_INSPECT_PRELOAD', launch\.bootstrapPath\]/);
  assert.equal(SERVICE_BOOTSTRAP_STATIC_CLOSURE.includes('native-control/src/service-bootstrap.js'), true);
});

function releasePayload(extra = []) {
  const map = (sourcePath) => sourcePath.startsWith('native-control/')
    ? `node_modules/@gjc-remote/${sourcePath}`
    : sourcePath.startsWith('shared/') ? `node_modules/@gjc-remote/${sourcePath}` : sourcePath;
  return [...SERVICE_BOOTSTRAP_STATIC_CLOSURE.map((sourcePath, index) => ({
    path: map(sourcePath), size: 1, sha256: String(index % 10).repeat(64), executablePolicy: 'forbidden',
  })), ...extra.map((path) => ({ path, size: 1, sha256: 'f'.repeat(64), executablePolicy: 'forbidden' }))];
}

test('release builder maps the guard closure to release-resolved package aliases', () => {
  const metadata = windowsServiceBootstrapMetadata(releasePayload());
  assert.equal(metadata.guardPath, 'node_modules/@gjc-remote/native-control/src/service-bootstrap.js');
  assert.equal(metadata.staticClosure.length, SERVICE_BOOTSTRAP_STATIC_CLOSURE.length);
  assert.ok(metadata.staticClosure.some((entry) => entry.relativePath === 'node_modules/@gjc-remote/shared/strict-json.js'));
  assert.ok(metadata.staticClosure.some((entry) => entry.relativePath === 'node_modules/dotenv/lib/main.js'));
  // Shared and native-control compute one fingerprint over the same closure.
  assert.equal(metadata.staticClosureFingerprint, serviceBootstrapClosureFingerprint(metadata.staticClosure));
  assert.equal(metadata.staticClosureFingerprint, windowsServiceBootstrapClosureFingerprint(metadata.staticClosure));
  assert.deepEqual(metadata.externalBunConfig, { relativePath: 'runtime-config/.bunfig.toml', sha256: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855', byteLength: 0 });
  assert.deepEqual(Object.keys(metadata.runtimePolicies), ['bot', 'daemon']);
});

test('release builder resolves nested package copies and refuses shadowing or missing closure files', () => {
  const nested = releasePayload(['node_modules/@gjc-remote/native-control/node_modules/dotenv/package.json', 'node_modules/@gjc-remote/native-control/node_modules/dotenv/lib/main.js']);
  const metadata = windowsServiceBootstrapMetadata(nested);
  assert.ok(metadata.staticClosure.some((entry) => entry.relativePath === 'node_modules/@gjc-remote/native-control/node_modules/dotenv/lib/main.js'));
  assert.equal(metadata.staticClosure.some((entry) => entry.relativePath === 'node_modules/dotenv/lib/main.js'), false);
  for (const shadow of ['bot/node_modules/@gjc-remote/native-control/package.json', 'daemon/node_modules/dotenv/package.json']) {
    assert.throws(() => windowsServiceBootstrapMetadata(releasePayload([shadow])));
  }
  assert.throws(() => windowsServiceBootstrapMetadata(releasePayload().filter((entry) => !entry.path.endsWith('service-bootstrap.js'))));
});
