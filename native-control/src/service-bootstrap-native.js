import {
  closeSync,
  constants,
  fstatSync,
  lstatSync,
  openSync,
  readSync,
} from 'node:fs';
import { createRequire } from 'node:module';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { capabilities } from './capabilities.js';
import {
  nativeFingerprint,
  validateNativeAddonContract,
  verifyPinnedNativeBuildManifest,
} from './native-provenance.js';

const packageRoot = dirname(dirname(fileURLToPath(import.meta.url)));
const releaseDirectory = join(packageRoot, 'build', 'Release');
const addonPath = join(releaseDirectory, 'native_control.node');
const manifestPath = join(releaseDirectory, 'native-control.manifest.json');
const signaturePath = `${manifestPath}.sig`;
const packagePath = join(packageRoot, 'package.json');
const trustPath = join(packageRoot, 'release-keys', 'trusted.json');
const requireFromPackage = createRequire(import.meta.url);
const manifestLimit = 1024 * 1024;
const signatureLimit = 16 * 1024;
const trustLimit = 64 * 1024;
const packageLimit = 1024 * 1024;
const addonLimit = 256 * 1024 * 1024;

function refuse() {
  const error = new Error('create_service_bootstrap_native refused');
  error.code = 'ERR_NATIVE_CONTROL_REFUSED';
  error.operation = 'create_service_bootstrap_native';
  error.reason = 'production-native-addon-unverified';
  error.writes = 0;
  error.ambiguous = false;
  throw error;
}

function sameFileState(left, right) {
  return left.isFile() && right.isFile() &&
    left.dev === right.dev && left.ino === right.ino &&
    left.size === right.size && left.mtimeNs === right.mtimeNs &&
    left.ctimeNs === right.ctimeNs;
}

function readStableBytes(path, maximumBytes) {
  let descriptor;
  try {
    const namedBefore = lstatSync(path, { bigint: true });
    if (!namedBefore.isFile() || namedBefore.size < 1n ||
        namedBefore.size > BigInt(maximumBytes)) refuse();
    const flags = process.platform === 'win32'
      ? constants.O_RDONLY
      : constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK;
    descriptor = openSync(path, flags);
    const before = fstatSync(descriptor, { bigint: true });
    if (!sameFileState(namedBefore, before)) refuse();
    const buffer = Buffer.alloc(Number(before.size));
    let offset = 0;
    while (offset < buffer.length) {
      const count = readSync(
        descriptor, buffer, offset, buffer.length - offset, null,
      );
      if (count === 0) refuse();
      offset += count;
    }
    const after = fstatSync(descriptor, { bigint: true });
    const namedAfter = lstatSync(path, { bigint: true });
    if (!sameFileState(before, after) ||
        !sameFileState(before, namedAfter)) refuse();
    return Object.freeze({
      bytes: buffer,
      state: Object.freeze({
        dev: before.dev,
        ino: before.ino,
        size: before.size,
        mtimeNs: before.mtimeNs,
        ctimeNs: before.ctimeNs,
      }),
    });
  } catch {
    refuse();
  } finally {
    if (descriptor !== undefined) {
      try {
        closeSync(descriptor);
      } catch {
        refuse();
      }
    }
  }
}

function assertAddonFileStillPinned(expected) {
  try {
    const current = lstatSync(addonPath, { bigint: true });
    if (!current.isFile() || current.dev !== expected.dev ||
        current.ino !== expected.ino || current.size !== expected.size ||
        current.mtimeNs !== expected.mtimeNs ||
        current.ctimeNs !== expected.ctimeNs) refuse();
  } catch {
    refuse();
  }
}

function loadProductionAddon() {
  if (process.platform !== 'win32' || process.arch !== 'x64') refuse();
  const manifest = readStableBytes(manifestPath, manifestLimit);
  const signature = readStableBytes(signaturePath, signatureLimit);
  const packageJson = readStableBytes(packagePath, packageLimit);
  const trusted = readStableBytes(trustPath, trustLimit);
  const addon = readStableBytes(addonPath, addonLimit);
  let receipt;
  try {
    receipt = verifyPinnedNativeBuildManifest({
      manifestBytes: manifest.bytes,
      signatureBytes: signature.bytes,
      packageBytes: packageJson.bytes,
      bundledTrustBytes: trusted.bytes,
      platform: process.platform,
      architecture: process.arch,
    });
  } catch {
    refuse();
  }
  if (receipt.platform !== 'win32' || receipt.architecture !== 'x64' ||
      receipt.addonSha256 !== nativeFingerprint(addon.bytes)) refuse();

  assertAddonFileStillPinned(addon.state);
  let nativeAddon;
  try {
    nativeAddon = requireFromPackage(addonPath);
  } catch {
    refuse();
  }
  assertAddonFileStillPinned(addon.state);
  try {
    if (nativeAddon === null || typeof nativeAddon !== 'object') refuse();
    const descriptors = Object.getOwnPropertyDescriptors(nativeAddon);
    for (const name of capabilities) {
      if (!descriptors[name] || typeof descriptors[name].value !== 'function') {
        refuse();
      }
    }
    const contractDescriptor = descriptors.native_control_contract;
    const configDescriptor = descriptors.read_self_service_config;
    const epochDescriptor = descriptors.observe_self_process_epoch;
    if (!contractDescriptor || typeof contractDescriptor.value !== 'function' ||
        !configDescriptor || typeof configDescriptor.value !== 'function' ||
        !epochDescriptor || typeof epochDescriptor.value !== 'function') refuse();
    const contract = Reflect.apply(
      contractDescriptor.value, nativeAddon, [],
    );
    if (!validateNativeAddonContract(contract)) refuse();
    return Object.freeze({
      readSelfServiceConfig: (...args) => Reflect.apply(
        configDescriptor.value, nativeAddon, args,
      ),
      observeSelfProcessEpoch: (...args) => Reflect.apply(
        epochDescriptor.value, nativeAddon, args,
      ),
    });
  } catch {
    refuse();
  }
}

export function createServiceBootstrapNative() {
  if (arguments.length !== 0) refuse();
  return loadProductionAddon();
}
