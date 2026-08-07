import assert from 'node:assert/strict';
import { execFile as execFileCallback } from 'node:child_process';
import { createHash, generateKeyPairSync, sign as cryptoSign } from 'node:crypto';
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';

import { evaluateRequiredSignature } from '../scripts/verify-build.mjs';
import { capabilities, capabilitySignatures, loadVerifiedAddon, verifyManifestSignature } from '../src/index.js';

const packageRoot = fileURLToPath(new URL('..', import.meta.url));
const realAddonPath = join(packageRoot, 'build', 'Release', 'native_control.node');
const realPackageJsonPath = join(packageRoot, 'package.json');
const realAddonAvailable = existsSync(realAddonPath);

function generateEd25519() {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519');
  return { publicKeyPem: publicKey.export({ type: 'spki', format: 'pem' }).toString(), sign: (bytes) => cryptoSign(null, bytes, privateKey) };
}

function generateP256() {
  const { publicKey, privateKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
  return { publicKeyPem: publicKey.export({ type: 'spki', format: 'pem' }).toString(), sign: (bytes) => cryptoSign('sha256', bytes, privateKey) };
}

function sidecarFor(key, algorithm, keyId, manifestBytes) {
  return { keyId, algorithm, signature: key.sign(manifestBytes).toString('base64') };
}

// --- Pure verifyManifestSignature coverage -------------------------------------------------

test('verifyManifestSignature: valid ed25519 signature verifies against the pinned key', () => {
  const key = generateEd25519();
  const manifestBytes = Buffer.from('{"a":1}');
  const trustStore = { version: 1, keys: [{ keyId: 'k1', algorithm: 'ed25519', publicKeyPem: key.publicKeyPem }] };
  const sidecar = sidecarFor(key, 'ed25519', 'k1', manifestBytes);
  const result = verifyManifestSignature(manifestBytes, sidecar, trustStore);
  assert.deepEqual(result, { ok: true, keyId: 'k1', algorithm: 'ed25519' });
});

test('verifyManifestSignature: valid P-256 signature verifies against the pinned key', () => {
  const key = generateP256();
  const manifestBytes = Buffer.from('{"a":1}');
  const trustStore = { version: 1, keys: [{ keyId: 'k1', algorithm: 'p256', publicKeyPem: key.publicKeyPem }] };
  const sidecar = sidecarFor(key, 'p256', 'k1', manifestBytes);
  const result = verifyManifestSignature(manifestBytes, sidecar, trustStore);
  assert.deepEqual(result, { ok: true, keyId: 'k1', algorithm: 'p256' });
});

test('verifyManifestSignature: unknown keyId refuses', () => {
  const key = generateEd25519();
  const manifestBytes = Buffer.from('{"a":1}');
  const trustStore = { version: 1, keys: [{ keyId: 'k1', algorithm: 'ed25519', publicKeyPem: key.publicKeyPem }] };
  const sidecar = sidecarFor(key, 'ed25519', 'not-pinned', manifestBytes);
  const result = verifyManifestSignature(manifestBytes, sidecar, trustStore);
  assert.equal(result.ok, false);
  assert.match(result.reason, /unknown signing keyId/);
});

test('verifyManifestSignature: signature made with a different key refuses', () => {
  const pinned = generateEd25519();
  const impostor = generateEd25519();
  const manifestBytes = Buffer.from('{"a":1}');
  const trustStore = { version: 1, keys: [{ keyId: 'k1', algorithm: 'ed25519', publicKeyPem: pinned.publicKeyPem }] };
  // signed by a different private key, but claims the pinned keyId
  const sidecar = sidecarFor(impostor, 'ed25519', 'k1', manifestBytes);
  const result = verifyManifestSignature(manifestBytes, sidecar, trustStore);
  assert.equal(result.ok, false);
  assert.match(result.reason, /signature verification failed/);
});

test('verifyManifestSignature: tampered manifest bytes refuse even with a valid keyId/algorithm', () => {
  const key = generateEd25519();
  const signedBytes = Buffer.from('{"a":1}');
  const tamperedBytes = Buffer.from('{"a":2}');
  const trustStore = { version: 1, keys: [{ keyId: 'k1', algorithm: 'ed25519', publicKeyPem: key.publicKeyPem }] };
  const sidecar = sidecarFor(key, 'ed25519', 'k1', signedBytes);
  const result = verifyManifestSignature(tamperedBytes, sidecar, trustStore);
  assert.equal(result.ok, false);
  assert.match(result.reason, /signature verification failed/);
});

test('verifyManifestSignature: algorithm mismatch against the pinned key refuses', () => {
  const key = generateEd25519();
  const manifestBytes = Buffer.from('{"a":1}');
  const trustStore = { version: 1, keys: [{ keyId: 'k1', algorithm: 'ed25519', publicKeyPem: key.publicKeyPem }] };
  const sidecar = { keyId: 'k1', algorithm: 'p256', signature: key.sign(manifestBytes).toString('base64') };
  const result = verifyManifestSignature(manifestBytes, sidecar, trustStore);
  assert.equal(result.ok, false);
  assert.match(result.reason, /does not match the pinned key/);
});

test('verifyManifestSignature: malformed sidecar shapes refuse', () => {
  const manifestBytes = Buffer.from('{"a":1}');
  const trustStore = { version: 1, keys: [] };
  for (const sidecar of [null, undefined, {}, { keyId: 'k1' }, { keyId: 'k1', algorithm: 'ed25519' }, { keyId: '', algorithm: 'ed25519', signature: 'x' }]) {
    const result = verifyManifestSignature(manifestBytes, sidecar, trustStore);
    assert.equal(result.ok, false, JSON.stringify(sidecar));
  }
});

// --- loadVerifiedAddon wiring coverage ------------------------------------------------------

function withFixtureDir(fn) {
  const dir = mkdtempSync(join(tmpdir(), 'native-control-provenance-'));
  try { return fn(dir); } finally { rmSync(dir, { recursive: true, force: true }); }
}

function writeManifestFixture(dir, { addonBytes, packageJson, copyAddon = false }) {
  const releaseDir = join(dir, 'release');
  const releaseKeysDir = join(dir, 'release-keys');
  writeFileSync(join(dir, '.keep'), '');
  // The real .node file stays locked by the OS for as long as this process has required it, so
  // tests that will actually load it (require()) point straight at the real build output instead
  // of copying it into a temp dir that later needs to be removed. Tests that expect a refusal
  // before require() is ever called (e.g. tampering) copy it so they can safely mutate the bytes.
  const addonPath = copyAddon ? join(releaseDir, 'native_control.node') : realAddonPath;
  const manifestPath = join(releaseDir, 'native-control.manifest.json');
  const packageJsonPath = join(dir, 'package.json');
  mkdirSync(releaseDir, { recursive: true });
  mkdirSync(releaseKeysDir, { recursive: true });
  if (copyAddon) writeFileSync(addonPath, addonBytes);
  writeFileSync(packageJsonPath, JSON.stringify(packageJson));
  const manifest = {
    contractVersion: 3, package: packageJson.name, version: packageJson.version, napi: 8,
    platform: process.platform, arch: process.arch, addon: 'native_control.node',
    sha256: createHash('sha256').update(addonBytes).digest('hex'),
    capabilities, capabilitySignatures,
  };
  const manifestBytes = Buffer.from(`${JSON.stringify(manifest, null, 2)}\n`, 'utf8');
  writeFileSync(manifestPath, manifestBytes);
  return {
    releaseDir, releaseKeysDir, addonPath, manifestPath, packageJsonPath, manifestBytes,
    sidecarPath: `${manifestPath}.sig`,
    trustedKeysPath: join(releaseKeysDir, 'trusted.json'),
    devKeysPath: join(releaseKeysDir, 'local-dev.json'),
  };
}

function loadOptions(fixture, extra) {
  return {
    manifestPath: fixture.manifestPath,
    addonPath: fixture.addonPath,
    packageJsonPath: fixture.packageJsonPath,
    sidecarPath: fixture.sidecarPath,
    trustedKeysPath: fixture.trustedKeysPath,
    devKeysPath: fixture.devKeysPath,
    warn: extra?.warn ?? (() => {}),
    ...extra,
  };
}

test('loadVerifiedAddon: missing sidecar refuses when a key is pinned', (t) => {
  if (!realAddonAvailable) { t.skip('real native addon build is not present on this checkout'); return; }
  withFixtureDir((dir) => {
    const packageJson = JSON.parse(readFileSync(realPackageJsonPath, 'utf8'));
    const fixture = writeManifestFixture(dir, { addonBytes: readFileSync(realAddonPath), packageJson });
    const key = generateEd25519();
    writeFileSync(fixture.trustedKeysPath, JSON.stringify({ version: 1, keys: [{ keyId: 'k1', algorithm: 'ed25519', publicKeyPem: key.publicKeyPem }] }));
    // deliberately do not write fixture.sidecarPath
    assert.throws(() => loadVerifiedAddon(loadOptions(fixture)), /ERR_NATIVE_CONTROL_REFUSED|sidecar is missing/);
  });
});

test('loadVerifiedAddon: tampered addon bytes still refuse via the existing hash check (not weakened)', (t) => {
  if (!realAddonAvailable) { t.skip('real native addon build is not present on this checkout'); return; }
  withFixtureDir((dir) => {
    const packageJson = JSON.parse(readFileSync(realPackageJsonPath, 'utf8'));
    const fixture = writeManifestFixture(dir, { addonBytes: readFileSync(realAddonPath), packageJson, copyAddon: true });
    // tamper the addon bytes on disk after the manifest sha256 was computed from the original bytes
    writeFileSync(fixture.addonPath, Buffer.concat([readFileSync(fixture.addonPath), Buffer.from('x')]));
    assert.throws(() => loadVerifiedAddon(loadOptions(fixture)), (error) => {
      assert.equal(error.code, 'ERR_NATIVE_CONTROL_REFUSED');
      assert.match(error.reason, /build manifest verification failed/);
      return true;
    });
  });
});

test('loadVerifiedAddon: zero-pinned-keys path warns exactly once and does not accept a malformed sidecar', (t) => {
  if (!realAddonAvailable) { t.skip('real native addon build is not present on this checkout'); return; }
  withFixtureDir((dir) => {
    const packageJson = JSON.parse(readFileSync(realPackageJsonPath, 'utf8'));
    const fixture = writeManifestFixture(dir, { addonBytes: readFileSync(realAddonPath), packageJson });
    writeFileSync(fixture.trustedKeysPath, JSON.stringify({ version: 1, keys: [] }));
    writeFileSync(fixture.sidecarPath, 'not even json');
    const warnings = [];
    const addon = loadVerifiedAddon(loadOptions(fixture, { warn: (message) => warnings.push(message) }));
    assert.equal(typeof addon.native_control_contract, 'function');
    assert.equal(warnings.length, 1);
    assert.match(warnings[0], /UNVERIFIED/);
  });
});

test('loadVerifiedAddon: dev-key acceptance only when the gitignored dev trust file exists', (t) => {
  if (!realAddonAvailable) { t.skip('real native addon build is not present on this checkout'); return; }
  withFixtureDir((dir) => {
    const packageJson = JSON.parse(readFileSync(realPackageJsonPath, 'utf8'));
    const fixture = writeManifestFixture(dir, { addonBytes: readFileSync(realAddonPath), packageJson });
    writeFileSync(fixture.trustedKeysPath, JSON.stringify({ version: 1, keys: [] }));
    const devKey = generateEd25519();
    const sidecar = sidecarFor(devKey, 'ed25519', 'dev-1', fixture.manifestBytes);
    writeFileSync(fixture.sidecarPath, JSON.stringify(sidecar));

    // without the dev trust file present: falls back to the zero-pinned-keys UNVERIFIED path
    const warningsWithoutDevFile = [];
    const addonWithoutDevFile = loadVerifiedAddon(loadOptions(fixture, { warn: (message) => warningsWithoutDevFile.push(message) }));
    assert.equal(typeof addonWithoutDevFile.native_control_contract, 'function');
    assert.equal(warningsWithoutDevFile.length, 1);
    assert.match(warningsWithoutDevFile[0], /UNVERIFIED/);

    // with the dev trust file present: the dev key is accepted and a distinct warning names it
    writeFileSync(fixture.devKeysPath, JSON.stringify({ version: 1, keys: [{ keyId: 'dev-1', algorithm: 'ed25519', publicKeyPem: devKey.publicKeyPem }] }));
    const warningsWithDevFile = [];
    const addonWithDevFile = loadVerifiedAddon(loadOptions(fixture, { warn: (message) => warningsWithDevFile.push(message) }));
    assert.equal(typeof addonWithDevFile.native_control_contract, 'function');
    assert.equal(warningsWithDevFile.length, 1);
    assert.match(warningsWithDevFile[0], /development key/);
    assert.match(warningsWithDevFile[0], /dev-1/);
  });
});

test('loadVerifiedAddon: a pinned trusted key loads without any dev-key warning', (t) => {
  if (!realAddonAvailable) { t.skip('real native addon build is not present on this checkout'); return; }
  withFixtureDir((dir) => {
    const packageJson = JSON.parse(readFileSync(realPackageJsonPath, 'utf8'));
    const fixture = writeManifestFixture(dir, { addonBytes: readFileSync(realAddonPath), packageJson });
    const key = generateP256();
    writeFileSync(fixture.trustedKeysPath, JSON.stringify({ version: 1, keys: [{ keyId: 'prod-1', algorithm: 'p256', publicKeyPem: key.publicKeyPem }] }));
    writeFileSync(fixture.sidecarPath, JSON.stringify(sidecarFor(key, 'p256', 'prod-1', fixture.manifestBytes)));
    const warnings = [];
    const addon = loadVerifiedAddon(loadOptions(fixture, { warn: (message) => warnings.push(message) }));
    assert.equal(typeof addon.native_control_contract, 'function');
    assert.equal(warnings.length, 0);
  });
});

const execFile = promisify(execFileCallback);
const realManifestPath = join(packageRoot, 'build', 'Release', 'native-control.manifest.json');
const realSidecarPath = `${realManifestPath}.sig`;

// --- Dev keys are honoured only in the trusted.json zero-key bootstrap state ---------------

test('loadVerifiedAddon: a dev-signed manifest is ignored (fails closed) once a production key is pinned', (t) => {
  if (!realAddonAvailable) { t.skip('real native addon build is not present on this checkout'); return; }
  withFixtureDir((dir) => {
    const packageJson = JSON.parse(readFileSync(realPackageJsonPath, 'utf8'));
    const fixture = writeManifestFixture(dir, { addonBytes: readFileSync(realAddonPath), packageJson });
    const prodKey = generateP256();
    const devKey = generateEd25519();
    writeFileSync(fixture.trustedKeysPath, JSON.stringify({ version: 1, keys: [{ keyId: 'prod-1', algorithm: 'p256', publicKeyPem: prodKey.publicKeyPem }] }));
    writeFileSync(fixture.devKeysPath, JSON.stringify({ version: 1, keys: [{ keyId: 'dev-1', algorithm: 'ed25519', publicKeyPem: devKey.publicKeyPem }] }));
    // sidecar is signed only by the dev key — never by the pinned production key
    writeFileSync(fixture.sidecarPath, JSON.stringify(sidecarFor(devKey, 'ed25519', 'dev-1', fixture.manifestBytes)));
    assert.throws(() => loadVerifiedAddon(loadOptions(fixture)), (error) => {
      assert.equal(error.code, 'ERR_NATIVE_CONTROL_REFUSED');
      assert.match(error.reason, /unknown signing keyId/);
      return true;
    });
  });
});

test('loadVerifiedAddon: the same dev key is honoured while trusted.json is still zero-key, then refused the instant a production key is pinned', (t) => {
  if (!realAddonAvailable) { t.skip('real native addon build is not present on this checkout'); return; }
  withFixtureDir((dir) => {
    const packageJson = JSON.parse(readFileSync(realPackageJsonPath, 'utf8'));
    const fixture = writeManifestFixture(dir, { addonBytes: readFileSync(realAddonPath), packageJson });
    const devKey = generateEd25519();
    writeFileSync(fixture.trustedKeysPath, JSON.stringify({ version: 1, keys: [] }));
    writeFileSync(fixture.devKeysPath, JSON.stringify({ version: 1, keys: [{ keyId: 'dev-1', algorithm: 'ed25519', publicKeyPem: devKey.publicKeyPem }] }));
    writeFileSync(fixture.sidecarPath, JSON.stringify(sidecarFor(devKey, 'ed25519', 'dev-1', fixture.manifestBytes)));

    // zero-key bootstrap state: the dev key is honoured
    const addon = loadVerifiedAddon(loadOptions(fixture));
    assert.equal(typeof addon.native_control_contract, 'function');

    // pin a production key: the same dev-signed sidecar now fails closed, no downgrade path remains
    const prodKey = generateP256();
    writeFileSync(fixture.trustedKeysPath, JSON.stringify({ version: 1, keys: [{ keyId: 'prod-1', algorithm: 'p256', publicKeyPem: prodKey.publicKeyPem }] }));
    assert.throws(() => loadVerifiedAddon(loadOptions(fixture)), (error) => {
      assert.equal(error.code, 'ERR_NATIVE_CONTROL_REFUSED');
      assert.match(error.reason, /unknown signing keyId/);
      return true;
    });
  });
});

// --- Duplicate keyId entries are rejected fail-closed, never silently shadowed -------------

test('loadVerifiedAddon: a trusted.json with duplicate keyIds refuses to load instead of silently shadowing', (t) => {
  if (!realAddonAvailable) { t.skip('real native addon build is not present on this checkout'); return; }
  withFixtureDir((dir) => {
    const packageJson = JSON.parse(readFileSync(realPackageJsonPath, 'utf8'));
    const fixture = writeManifestFixture(dir, { addonBytes: readFileSync(realAddonPath), packageJson });
    const first = generateEd25519();
    const second = generateP256();
    writeFileSync(fixture.trustedKeysPath, JSON.stringify({
      version: 1,
      keys: [
        { keyId: 'dup-1', algorithm: 'ed25519', publicKeyPem: first.publicKeyPem },
        { keyId: 'dup-1', algorithm: 'p256', publicKeyPem: second.publicKeyPem },
      ],
    }));
    writeFileSync(fixture.sidecarPath, JSON.stringify(sidecarFor(second, 'p256', 'dup-1', fixture.manifestBytes)));
    assert.throws(() => loadVerifiedAddon(loadOptions(fixture)), (error) => {
      assert.equal(error.code, 'ERR_NATIVE_CONTROL_REFUSED');
      assert.match(error.reason, /trust store is invalid/);
      assert.match(error.reason, /duplicate keyId/);
      return true;
    });
  });
});

test('loadVerifiedAddon: a local-dev.json with duplicate keyIds refuses to load instead of silently shadowing', (t) => {
  if (!realAddonAvailable) { t.skip('real native addon build is not present on this checkout'); return; }
  withFixtureDir((dir) => {
    const packageJson = JSON.parse(readFileSync(realPackageJsonPath, 'utf8'));
    const fixture = writeManifestFixture(dir, { addonBytes: readFileSync(realAddonPath), packageJson });
    writeFileSync(fixture.trustedKeysPath, JSON.stringify({ version: 1, keys: [] }));
    const first = generateEd25519();
    const second = generateEd25519();
    writeFileSync(fixture.devKeysPath, JSON.stringify({
      version: 1,
      keys: [
        { keyId: 'dup-dev', algorithm: 'ed25519', publicKeyPem: first.publicKeyPem },
        { keyId: 'dup-dev', algorithm: 'ed25519', publicKeyPem: second.publicKeyPem },
      ],
    }));
    writeFileSync(fixture.sidecarPath, JSON.stringify(sidecarFor(second, 'ed25519', 'dup-dev', fixture.manifestBytes)));
    assert.throws(() => loadVerifiedAddon(loadOptions(fixture)), (error) => {
      assert.equal(error.code, 'ERR_NATIVE_CONTROL_REFUSED');
      assert.match(error.reason, /trust store is invalid/);
      assert.match(error.reason, /duplicate keyId/);
      return true;
    });
  });
});

// --- verify-build.mjs --require-signature verifies strictly against trusted.json only ------

test('evaluateRequiredSignature: a dev-key-only signature is rejected even when the dev key is otherwise valid', () => {
  const devKey = generateEd25519();
  const manifestBytes = Buffer.from('{"a":1}');
  withFixtureDir((dir) => {
    const trustedKeysPath = join(dir, 'trusted.json');
    const sidecarPath = join(dir, 'manifest.json.sig');
    writeFileSync(trustedKeysPath, JSON.stringify({ version: 1, keys: [] }));
    writeFileSync(sidecarPath, JSON.stringify(sidecarFor(devKey, 'ed25519', 'dev-1', manifestBytes)));
    const result = evaluateRequiredSignature(manifestBytes, { sidecarPath, trustedKeysPath });
    assert.equal(result.ok, false);
    assert.match(result.reason, /unknown signing keyId/);
  });
});

test('evaluateRequiredSignature: a signature from a pinned trusted.json key verifies', () => {
  const prodKey = generateP256();
  const manifestBytes = Buffer.from('{"a":1}');
  withFixtureDir((dir) => {
    const trustedKeysPath = join(dir, 'trusted.json');
    const sidecarPath = join(dir, 'manifest.json.sig');
    writeFileSync(trustedKeysPath, JSON.stringify({ version: 1, keys: [{ keyId: 'prod-1', algorithm: 'p256', publicKeyPem: prodKey.publicKeyPem }] }));
    writeFileSync(sidecarPath, JSON.stringify(sidecarFor(prodKey, 'p256', 'prod-1', manifestBytes)));
    const result = evaluateRequiredSignature(manifestBytes, { sidecarPath, trustedKeysPath });
    assert.deepEqual(result, { ok: true, keyId: 'prod-1', algorithm: 'p256' });
  });
});

// --- Regenerating the manifest deletes any stale sidecar left over from a prior build ------

test('verify-build.mjs --write-manifest deletes a stale sidecar so it can never appear valid or linger', async (t) => {
  if (!realAddonAvailable) { t.skip('real native addon build is not present on this checkout'); return; }
  writeFileSync(realSidecarPath, JSON.stringify({ keyId: 'stale', algorithm: 'ed25519', signature: 'not-a-real-signature' }));
  assert.ok(existsSync(realSidecarPath), 'fixture setup: stale sidecar must exist before regeneration');
  try {
    await execFile(process.execPath, [join(packageRoot, 'scripts', 'verify-build.mjs'), '--write-manifest'], { cwd: packageRoot });
  } finally {
    assert.equal(existsSync(realSidecarPath), false, 'manifest regeneration must delete the stale sidecar');
  }
});
