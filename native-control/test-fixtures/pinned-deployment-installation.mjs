import { generateKeyPairSync, sign } from 'node:crypto';
import {
  copyFileSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  realpathSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from 'node:fs';
import { createRequire } from 'node:module';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { canonicalJsonBytes } from '@gjc-remote/shared/strict-json';
import { deploymentSignaturePreimage, DEPLOYMENT_SIGNATURE_DOMAINS } from '@gjc-remote/shared/deployment-envelope';

const require = createRequire(import.meta.url);
const cleanupFailureCode = 'PINNED_DEPLOYMENT_FIXTURE_CLEANUP_FAILED';
const nativePackageBytes = readFileSync(
  fileURLToPath(new URL('../package.json', import.meta.url)),
);

function cleanupFailure() {
  const error = new Error(cleanupFailureCode);
  error.code = cleanupFailureCode;
  return error;
}

function captureFixtureRoot(createdPath) {
  try {
    const created = lstatSync(createdPath, { bigint: true });
    const canonicalPath = realpathSync(createdPath);
    const canonical = lstatSync(canonicalPath, { bigint: true });
    if (!created.isDirectory() || created.isSymbolicLink() ||
        !canonical.isDirectory() || canonical.isSymbolicLink() ||
        created.dev !== canonical.dev || created.ino !== canonical.ino) {
      throw cleanupFailure();
    }
    return Object.freeze({
      path: canonicalPath,
      dev: canonical.dev,
      ino: canonical.ino,
    });
  } catch {
    throw cleanupFailure();
  }
}

function rootStillMatches(identity) {
  try {
    const named = lstatSync(identity.path, { bigint: true });
    return named.isDirectory() && !named.isSymbolicLink() &&
      realpathSync(identity.path) === identity.path &&
      named.dev === identity.dev && named.ino === identity.ino;
  } catch {
    return false;
  }
}

// A separate temporary installation of the exact source under test. Its keys
// and module-local brands are fixture-only, never accepted by the real module.
// There is no production reader/verifier override or exported branding seam.
export async function createPinnedDeploymentInstallation({
  keyIds,
  includeStore = false,
  includeTransport = false,
  includeOffline = false,
  includeNativeProvenance = false,
  includeAcquisition = false,
  includeReleaseBuilder = false,
}) {
  if (includeAcquisition) {
    includeTransport = true;
    includeOffline = true;
    includeNativeProvenance = true;
  }
  if (includeReleaseBuilder) includeNativeProvenance = true;
  if (!Array.isArray(keyIds) || keyIds.length === 0 || keyIds.length > 32 ||
      new Set(keyIds).size !== keyIds.length || keyIds.some((key) =>
        typeof key !== 'string' || !/^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/.test(key))) {
    throw new TypeError('Invalid fixture signing key IDs');
  }
  let rootIdentity;
  try {
    const createdRoot = mkdtempSync(
      join(tmpdir(), 'gjc-pinned-deployment-fixture-'),
    );
    rootIdentity = captureFixtureRoot(createdRoot);
  } catch {
    throw cleanupFailure();
  }
  const root = rootIdentity.path;
  let disposed = false;
  const dispose = () => {
    if (disposed) return;
    // This is an intentionally conservative named-path check, not an atomic
    // handle-bound deletion claim. A mismatch retains both names for the test
    // owner to inspect and clean explicitly.
    if (!rootStillMatches(rootIdentity)) throw cleanupFailure();
    try {
      rmSync(root, { recursive: true, force: false });
      try {
        lstatSync(root);
      } catch (error) {
        if (error?.code === 'ENOENT') {
          disposed = true;
          return;
        }
      }
    } catch {
      // A failed or ambiguous named cleanup must never fall through as success.
    }
    throw cleanupFailure();
  };
  try {
    const source = join(root, 'native-control', 'src');
    const shared = join(root, 'node_modules', '@gjc-remote', 'shared');
    mkdirSync(source, { recursive: true });
    mkdirSync(shared, { recursive: true });
    if (includeStore || includeAcquisition || includeReleaseBuilder) {
      symlinkSync(
        dirname(require.resolve('tar/package.json')),
        join(root, 'node_modules', 'tar'),
        process.platform === 'win32' ? 'junction' : 'dir',
      );
    }
    if (includeReleaseBuilder) {
      for (const dependency of ['jsonc-parser', 'semver']) {
        symlinkSync(
          dirname(require.resolve(`${dependency}/package.json`)),
          join(root, 'node_modules', dependency),
          process.platform === 'win32' ? 'junction' : 'dir',
        );
      }
      const scripts = join(root, 'native-control', 'scripts');
      const contract = join(root, 'deploy', 'native');
      mkdirSync(scripts, { recursive: true });
      mkdirSync(contract, { recursive: true });
      copyFileSync(
        fileURLToPath(new URL('../scripts/build-service-release.mjs', import.meta.url)),
        join(scripts, 'build-service-release.mjs'),
      );
      copyFileSync(
        fileURLToPath(new URL('../../deploy/native/release-contract.json', import.meta.url)),
        join(contract, 'release-contract.json'),
      );
    }
    writeFileSync(join(root, 'package.json'), JSON.stringify({ private: true, type: 'module' }));
    for (const name of [
      'package.json', 'strict-json.js', 'identity.js', 'deployment-envelope.js',
      'deployment-format-registry.js', 'service-lifecycle-envelope.js',
    ]) {
      copyFileSync(fileURLToPath(new URL(`../../shared/${name}`, import.meta.url)), join(shared, name));
    }
    for (const name of [
      'deployment-provenance.js',
      ...(includeStore ? ['service-artifacts.js', 'service-store.js'] : []),
      ...(includeTransport ? ['service-transport.js'] : []),
      ...(includeOffline ? ['service-offline-source.js'] : []),
      ...(includeReleaseBuilder ? ['service-sdk-contract.js', 'service-production-closure.js', 'service-bootstrap-policy.js'] : []),
      ...(includeStore || includeAcquisition || includeReleaseBuilder ? ['service-archive.js'] : []),
      ...(includeAcquisition ? ['service-acquisition.js'] : []),
      ...(includeNativeProvenance
        ? ['capabilities.js', 'native-provenance.js']
        : []),
    ]) {
      copyFileSync(fileURLToPath(new URL(`../src/${name}`, import.meta.url)), join(source, name));
    }
    const applicationKeys = new Map(keyIds.map((keyId) => [keyId, generateKeyPairSync('ed25519')]));
    const shawlKeys = new Map(keyIds.map((keyId) => [keyId, generateKeyPairSync('ed25519')]));
    const entry = (keyId, key) => ({
      keyId, algorithm: 'ed25519',
      publicKeyPem: key.publicKey.export({ type: 'spki', format: 'pem' }),
    });
    let nativeKeyId = 'fixture-native-key';
    while (applicationKeys.has(nativeKeyId) || shawlKeys.has(nativeKeyId)) nativeKeyId += '-native';
    const nativeKey = generateKeyPairSync('ed25519');
    let bundledApplicationTrustBytes;
    let bundledShawlTrustBytes;
    let bundledNativeTrustBytes;
    for (const [directory, fileName, entries] of [
      ['deployment-keys', 'application-trusted.json', [...applicationKeys].map(([keyId, key]) => entry(keyId, key))],
      ['deployment-keys', 'shawl-trusted.json', [...shawlKeys].map(([keyId, key]) => entry(keyId, key))],
      ['release-keys', 'trusted.json', [entry(nativeKeyId, nativeKey)]],
    ]) {
      const path = join(root, 'native-control', directory);
      mkdirSync(path, { recursive: true });
      const trustBytes = Buffer.from(JSON.stringify({ version: 1, keys: entries }));
      writeFileSync(join(path, fileName), trustBytes);
      if (fileName === 'application-trusted.json') bundledApplicationTrustBytes = trustBytes;
      if (fileName === 'shawl-trusted.json') bundledShawlTrustBytes = trustBytes;
      if (directory === 'release-keys') bundledNativeTrustBytes = trustBytes;
    }
    const provenance = await import(pathToFileURL(join(source, 'deployment-provenance.js')).href);
    const store = includeStore ? await import(pathToFileURL(join(source, 'service-store.js')).href) : null;
    const transport = includeTransport ? await import(pathToFileURL(join(source, 'service-transport.js')).href) : null;
    const offline = includeOffline ? await import(pathToFileURL(join(source, 'service-offline-source.js')).href) : null;
    const nativeProvenance = includeNativeProvenance
      ? await import(pathToFileURL(join(source, 'native-provenance.js')).href)
      : null;
    const acquisition = includeAcquisition
      ? await import(pathToFileURL(join(source, 'service-acquisition.js')).href)
      : null;
    const releaseBuilderUrl = includeReleaseBuilder
      ? pathToFileURL(join(root, 'native-control', 'scripts', 'build-service-release.mjs')).href
      : null;
    const releaseBuilder = releaseBuilderUrl !== null
      ? await import(releaseBuilderUrl)
      : null;
    const signManifest = (manifest) => {
      const purpose = manifest.kind === 'application-deployment-manifest' ? 'application'
        : manifest.kind === 'shawl-deployment-manifest' ? 'shawl' : null;
      const key = (purpose === 'application' ? applicationKeys : shawlKeys).get(manifest.signingKeyId);
      if (!purpose || !key) throw new TypeError('Unknown fixture manifest kind or signing key');
      const manifestBytes = canonicalJsonBytes(
        manifest,
        { maxBytes: 1024 * 1024, maxDepth: 32, maxNodes: 100_000 },
      );
      const signature = {
        schemaVersion: 1,
        kind: `${purpose}-deployment-signature`,
        domain: DEPLOYMENT_SIGNATURE_DOMAINS[purpose],
        keyId: manifest.signingKeyId,
        algorithm: 'ed25519',
        manifestFingerprint: manifest.manifestFingerprint,
        signature: sign(
          null,
          deploymentSignaturePreimage(purpose, manifest),
          key.privateKey,
        ).toString('base64'),
      };
      return Object.freeze({
        manifestBytes,
        signatureBytes: canonicalJsonBytes(signature),
      });
    };
    const signNativeManifest = includeNativeProvenance ? (manifestBytes) => {
      if (!Buffer.isBuffer(manifestBytes) || manifestBytes.length === 0) {
        throw new TypeError('Invalid fixture native manifest bytes');
      }
      return canonicalJsonBytes({
        keyId: nativeKeyId,
        algorithm: 'ed25519',
        signature: sign(
          null,
          manifestBytes,
          nativeKey.privateKey,
        ).toString('base64'),
      });
    } : null;
    return Object.freeze({
      provenance,
      store,
      transport,
      offline,
      nativeProvenance,
      acquisition,
      releaseBuilder,
      releaseBuilderUrl,
      get bundledApplicationTrustBytes() {
        return Buffer.from(bundledApplicationTrustBytes);
      },
      get bundledShawlTrustBytes() {
        return Buffer.from(bundledShawlTrustBytes);
      },
      bundledNativeTrustBytes: includeNativeProvenance
        ? Buffer.from(bundledNativeTrustBytes)
        : null,
      get nativePackageBytes() {
        return includeNativeProvenance ? Buffer.from(nativePackageBytes) : null;
      },
      dispose,
      signManifest,
      signNativeManifest,
      verifyManifest(manifest) {
        const purpose = manifest.kind === 'application-deployment-manifest' ? 'application'
          : manifest.kind === 'shawl-deployment-manifest' ? 'shawl' : null;
        const signed = signManifest(manifest);
        return provenance.verifyPinnedDeploymentProvenance({
          purpose,
          manifestBytes: signed.manifestBytes,
          signatureBytes: signed.signatureBytes,
          platform: manifest.target.platform,
          architecture: manifest.target.architecture,
        }).manifest;
      },
    });
  } catch (error) {
    try {
      dispose();
    } catch {
      throw cleanupFailure();
    }
    throw error;
  }
}
