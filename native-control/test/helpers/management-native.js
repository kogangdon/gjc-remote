import { createAdapter } from '../../src/adapter.js';

const normalizeTestIdentity = (identity) => {
  if (!identity || Object.getPrototypeOf(identity) !== Object.prototype) return null;
  const owner = typeof identity.owner === 'string' ? identity.owner : undefined;
  if (Number.isSafeInteger(identity.volumeSerial) && Number.isSafeInteger(identity.fileIndexHigh) &&
      Number.isSafeInteger(identity.fileIndexLow) && Number.isSafeInteger(identity.attributes)) {
    return { kind: 'win32', volumeSerial: identity.volumeSerial, fileIndexHigh: identity.fileIndexHigh,
      fileIndexLow: identity.fileIndexLow, attributes: identity.attributes, ...(owner === undefined ? {} : { owner }) };
  }
  if (typeof identity.device === 'string' && typeof identity.inode === 'string' && Number.isSafeInteger(identity.mode)) {
    return { kind: 'posix', device: identity.device, inode: identity.inode, mode: identity.mode,
      ...(owner === undefined ? {} : { owner }) };
  }
  if (typeof identity.path === 'string') {
    return { kind: 'test', path: identity.path, ...(Number.isSafeInteger(identity.generation) ? { generation: identity.generation } : {}),
      ...(owner === undefined ? {} : { owner }) };
  }
  return null;
};

export function createManagementNativeForTest({ lowLevel, configPath, arbitraryPrincipalProbe = true, roles, platform = 'win32' } = {}) {
  return createAdapter({ lowLevel, configPath, arbitraryPrincipalProbe, roles, platform, identityNormalizer: normalizeTestIdentity });
}
