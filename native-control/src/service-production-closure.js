import { createHash } from 'node:crypto';
import { getNodeValue, parseTree } from 'jsonc-parser';
import semver from 'semver';
import { DEPLOYMENT_ENVELOPE_LIMITS } from '@gjc-remote/shared/deployment-envelope';
import {
  assertStrictText,
  canonicalJsonHash,
  parseStrictJsonBytes,
  utf8Compare,
} from '@gjc-remote/shared/strict-json';

export const SERVICE_PRODUCTION_WORKSPACES = Object.freeze([
  'bot', 'daemon', 'native-control', 'shared',
]);

const PACKAGE_LIMIT = 1024 * 1024;
const LOCK_LIMIT = 16 * 1024 * 1024;
const MAX_LOCK_NODES = 1_000_000;
const MAX_LOCK_DEPTH = 64;
const WORKSPACE_PACKAGES = new Map([
  ['bot', '@gjc-remote/bot'],
  ['daemon', '@gjc-remote/daemon'],
  ['native-control', '@gjc-remote/native-control'],
  ['shared', '@gjc-remote/shared'],
]);
const PARSED_LOCKS = new WeakMap();

function fail(code) {
  const error = new TypeError(code);
  error.code = code;
  throw error;
}

function plain(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value) &&
    Object.getPrototypeOf(value) === Object.prototype;
}

function exact(value, keys) {
  return plain(value) && Object.keys(value).length === keys.length &&
    keys.every((key) => Object.hasOwn(value, key));
}

function deepFreeze(value) {
  if (value === null || typeof value !== 'object' || Object.isFrozen(value)) return value;
  for (const child of Object.values(value)) deepFreeze(child);
  return Object.freeze(value);
}

function comparePath(left, right) {
  return utf8Compare(left, right);
}

function hashBytes(bytes) {
  return createHash('sha256').update(bytes).digest('hex');
}

function treeValue(node, state, depth = 0) {
  if (!node || depth > MAX_LOCK_DEPTH) fail('SERVICE_PRODUCTION_LOCK_INVALID');
  state.nodes += 1;
  if (state.nodes > MAX_LOCK_NODES) fail('SERVICE_PRODUCTION_LOCK_INVALID');
  if (node.type === 'object') {
    const value = {};
    const names = new Set();
    for (const property of node.children ?? []) {
      if (property.type !== 'property' || property.children?.length !== 2 || property.children[0].type !== 'string') {
        fail('SERVICE_PRODUCTION_LOCK_INVALID');
      }
      const name = property.children[0].value;
      if (typeof name !== 'string' || names.has(name) || ['__proto__', 'constructor', 'prototype'].includes(name)) {
        fail('SERVICE_PRODUCTION_LOCK_INVALID');
      }
      names.add(name);
      Object.defineProperty(value, name, {
        value: treeValue(property.children[1], state, depth + 1),
        enumerable: true,
        configurable: false,
        writable: false,
      });
    }
    return value;
  }
  if (node.type === 'array') return (node.children ?? []).map((child) => treeValue(child, state, depth + 1));
  if (!['string', 'number', 'boolean', 'null'].includes(node.type)) fail('SERVICE_PRODUCTION_LOCK_INVALID');
  const value = getNodeValue(node);
  if (typeof value === 'string') {
    try { assertStrictText(value, 'Bun lock string', LOCK_LIMIT); } catch { fail('SERVICE_PRODUCTION_LOCK_INVALID'); }
  }
  if (typeof value === 'number' && !Number.isSafeInteger(value)) fail('SERVICE_PRODUCTION_LOCK_INVALID');
  return value;
}

function validSri(value) {
  if (typeof value !== 'string' || !value.startsWith('sha512-')) return false;
  let decoded;
  try { decoded = Buffer.from(value.slice(7), 'base64'); } catch { return false; }
  return decoded.length === 64 && `sha512-${decoded.toString('base64')}` === value;
}

/** Parse and validate the exact Bun v1 lock schema used by service release builds. */
export function parseBunProductionLock(bytes) {
  if (!Buffer.isBuffer(bytes) || bytes.length === 0 || bytes.length > LOCK_LIMIT) {
    fail('SERVICE_PRODUCTION_LOCK_INVALID');
  }
  let text;
  try { text = new TextDecoder('utf-8', { fatal: true }).decode(bytes); } catch {
    fail('SERVICE_PRODUCTION_LOCK_INVALID');
  }
  const errors = [];
  const root = parseTree(text, errors, { allowTrailingComma: true, disallowComments: false, allowEmptyContent: false });
  if (!root || errors.length !== 0) fail('SERVICE_PRODUCTION_LOCK_INVALID');
  const lock = treeValue(root, { nodes: 0 });
  if (!exact(lock, ['lockfileVersion', 'configVersion', 'workspaces', 'packages']) ||
      lock.lockfileVersion !== 1 || lock.configVersion !== 0 || !plain(lock.workspaces) || !plain(lock.packages) ||
      JSON.stringify(Object.keys(lock.workspaces).sort(comparePath)) !==
        JSON.stringify(['', ...SERVICE_PRODUCTION_WORKSPACES].sort(comparePath))) {
    fail('SERVICE_PRODUCTION_LOCK_INVALID');
  }

  const identities = new Map();
  const names = new Map();
  const workspaces = new Map();
  for (const [key, record] of Object.entries(lock.packages)) {
    if (!Array.isArray(record) || record.length === 0 || typeof record[0] !== 'string') {
      fail('SERVICE_PRODUCTION_LOCK_INVALID');
    }
    const identity = record[0];
    const workspaceMatch = /^(@[^/]+\/[^@]+|[^@/]+)@workspace:(bot|daemon|native-control|shared)$/.exec(identity);
    if (workspaceMatch) {
      if (record.length !== 1 || key !== workspaceMatch[1] || workspaces.has(workspaceMatch[1])) {
        fail('SERVICE_PRODUCTION_LOCK_INVALID');
      }
      workspaces.set(workspaceMatch[1], Object.freeze({ key, identity, workspace: workspaceMatch[2] }));
      continue;
    }
    if (record.length !== 4 || record[1] !== '' || !plain(record[2]) || !validSri(record[3])) {
      fail('SERVICE_PRODUCTION_LOCK_INVALID');
    }
    const separator = identity.lastIndexOf('@');
    if (separator <= 0 || separator === identity.length - 1) fail('SERVICE_PRODUCTION_LOCK_INVALID');
    const name = identity.slice(0, separator);
    const version = identity.slice(separator + 1);
    if ((name.startsWith('@') && !/^@[^/]+\/[^/]+$/.test(name)) ||
        (!name.startsWith('@') && !/^[A-Za-z0-9][A-Za-z0-9._-]*$/.test(name)) ||
        semver.valid(version) !== version) fail('SERVICE_PRODUCTION_LOCK_INVALID');
    const item = Object.freeze({ key, identity, name, version, metadata: record[2], integrity: record[3] });
    if (!identities.has(identity)) identities.set(identity, []);
    identities.get(identity).push(item);
    if (!names.has(name)) names.set(name, []);
    names.get(name).push(item);
  }
  if (workspaces.size !== SERVICE_PRODUCTION_WORKSPACES.length) fail('SERVICE_PRODUCTION_LOCK_INVALID');
  const frozenLock = deepFreeze(lock);
  const result = Object.freeze({ lock: frozenLock, identities, names, workspaces, sha256: hashBytes(bytes) });
  PARSED_LOCKS.set(result, {
    lock: frozenLock,
    identities: new Map([...identities].map(([key, values]) => [key, Object.freeze([...values])])),
    names: new Map([...names].map(([key, values]) => [key, Object.freeze([...values])])),
    workspaces: new Map(workspaces),
  });
  return result;
}

function sameStringMap(left, right) {
  const a = left === undefined ? {} : left;
  const b = right === undefined ? {} : right;
  return plain(a) && plain(b) && canonicalJsonHash(a) === canonicalJsonHash(b);
}

function sameStringMapEntries(value) {
  return Object.entries(value).every(([name, specifier]) =>
    name.length > 0 && typeof specifier === 'string' && specifier.length > 0);
}

function targetRules(value) {
  if (value === undefined) return [];
  const rules = typeof value === 'string' ? [value] : value;
  if (!Array.isArray(rules) || rules.some((rule) =>
    typeof rule !== 'string' || !/^!?[A-Za-z0-9_-]+$/.test(rule))) fail('SERVICE_PRODUCTION_LOCK_INVALID');
  return [...rules].sort(comparePath);
}

function packageTargetApplies(packageJson, platform, architecture) {
  const applies = (rules, value) => {
    if (rules === undefined) return true;
    const values = typeof rules === 'string' ? [rules] : rules;
    if (!Array.isArray(values) || values.some((rule) => typeof rule !== 'string' || rule.length === 0)) {
      fail('SERVICE_PRODUCTION_LOCK_INVALID');
    }
    const positive = values.filter((rule) => !rule.startsWith('!'));
    if (values.includes(`!${value}`)) return false;
    return positive.length === 0 || positive.includes(value);
  };
  return applies(packageJson.os, platform) && applies(packageJson.cpu, architecture);
}

function dependencyCategories(packageJson, lockMetadata) {
  for (const field of ['dependencies', 'optionalDependencies', 'peerDependencies']) {
    const packageEdges = packageJson[field];
    const lockEdges = lockMetadata[field];
    if (packageEdges !== undefined &&
        (!plain(packageEdges) || Object.entries(packageEdges).some(([name, specifier]) =>
          typeof specifier !== 'string' || specifier.length === 0 ||
          !plain(lockEdges) || lockEdges[name] !== specifier))) fail('SERVICE_PRODUCTION_LOCK_INVALID');
    if (lockEdges !== undefined && !sameStringMapEntries(lockEdges)) fail('SERVICE_PRODUCTION_LOCK_INVALID');
  }
  if (canonicalJsonHash(targetRules(packageJson.os)) !== canonicalJsonHash(targetRules(lockMetadata.os)) ||
      canonicalJsonHash(targetRules(packageJson.cpu)) !== canonicalJsonHash(targetRules(lockMetadata.cpu))) {
    fail('SERVICE_PRODUCTION_LOCK_INVALID');
  }
  const optionalPeers = new Set(Array.isArray(lockMetadata.optionalPeers) ? lockMetadata.optionalPeers : []);
  if ([...optionalPeers].some((name) => typeof name !== 'string')) fail('SERVICE_PRODUCTION_LOCK_INVALID');
  const lockPeers = plain(lockMetadata.peerDependencies) ? lockMetadata.peerDependencies : {};
  const peerMeta = plain(packageJson.peerDependenciesMeta) ? packageJson.peerDependenciesMeta : {};
  for (const [name, metadata] of Object.entries(peerMeta)) {
    if (!exact(metadata, ['optional']) || metadata.optional !== true || !optionalPeers.has(name) ||
        lockPeers[name] === undefined) fail('SERVICE_PRODUCTION_LOCK_INVALID');
  }
  if ([...optionalPeers].some((name) => peerMeta[name]?.optional !== true)) fail('SERVICE_PRODUCTION_LOCK_INVALID');
  const edges = [];
  const lockDependencies = plain(lockMetadata.dependencies) ? lockMetadata.dependencies : {};
  for (const [name, specifier] of Object.entries(lockDependencies)) {
    edges.push({ name, specifier, kind: 'dependency', optional: false, allowAbsent: false });
  }
  const lockOptional = plain(lockMetadata.optionalDependencies) ? lockMetadata.optionalDependencies : {};
  for (const [name, specifier] of Object.entries(lockOptional)) {
    edges.push({ name, specifier, kind: 'optional', optional: true, allowAbsent: false });
  }
  for (const [name, specifier] of Object.entries(lockPeers)) {
    const optional = optionalPeers.has(name);
    edges.push({
      name,
      specifier,
      kind: optional ? 'optional-peer' : 'peer',
      optional,
      allowAbsent: optional,
    });
  }
  return edges.sort((left, right) => comparePath(`${left.kind}:${left.name}`, `${right.kind}:${right.name}`));
}

function edgeAcceptsVersion(edge, version) {
  if (typeof edge.specifier !== 'string' || semver.valid(version) !== version) return false;
  const range = semver.validRange(edge.specifier);
  return range !== null && semver.satisfies(version, range);
}

function workspaceLockForEdge(lock, edge) {
  const workspace = lock.workspaces.get(edge.name);
  if (!workspace) return null;
  const record = lock.lock.workspaces[workspace.workspace];
  if (!plain(record) || record.name !== edge.name || !edgeAcceptsVersion(edge, record.version)) {
    fail('SERVICE_PRODUCTION_LOCK_INVALID');
  }
  return Object.freeze({ workspace, version: record.version });
}

function dependencySegments(name) {
  if (/^@[^/]+\/[^/]+$/.test(name)) return name.split('/');
  if (/^[A-Za-z0-9][A-Za-z0-9._-]*$/.test(name)) return [name];
  fail('SERVICE_PRODUCTION_CLOSURE_INVALID');
}

/** Return the existing production package root encoded by an inventory file path. */
export function bunPackageRootForPath(path) {
  if (typeof path !== 'string' || path.startsWith('/') || path.includes('\\') ||
      path.split('/').some((segment) => segment === '' || segment === '.' || segment === '..')) return null;
  for (const workspace of SERVICE_PRODUCTION_WORKSPACES) {
    if (path === `${workspace}/package.json`) return workspace;
  }
  if (!path.endsWith('/package.json')) return null;
  const segments = path.split('/');
  for (let index = segments.length - 2; index >= 0; index -= 1) {
    if (segments[index] !== 'node_modules') continue;
    const packageLength = segments[index + 1]?.startsWith('@') ? 2 : 1;
    if (index + packageLength + 1 !== segments.length - 1) continue;
    return segments.slice(0, index + packageLength + 1).join('/');
  }
  return null;
}

export function bunLockKeyForRelativePackagePath(relativePath) {
  if (typeof relativePath !== 'string' || relativePath.startsWith('../') || relativePath === '..' ||
      relativePath.startsWith('/') || relativePath.length === 0 || relativePath.includes('\\')) {
    fail('SERVICE_PRODUCTION_CLOSURE_INVALID');
  }
  const segments = relativePath.split('/');
  const chain = [];
  let index = segments.indexOf('node_modules');
  if (index < 0) fail('SERVICE_PRODUCTION_CLOSURE_INVALID');
  const workspacePrefix = segments.slice(0, index).join('/');
  if (workspacePrefix.length > 0) {
    const workspaceName = WORKSPACE_PACKAGES.get(workspacePrefix);
    if (!workspaceName) fail('SERVICE_PRODUCTION_CLOSURE_INVALID');
    chain.push(workspaceName);
  }
  while (index < segments.length) {
    if (segments[index] !== 'node_modules') fail('SERVICE_PRODUCTION_CLOSURE_INVALID');
    index += 1;
    if (index >= segments.length) fail('SERVICE_PRODUCTION_CLOSURE_INVALID');
    let name = segments[index];
    if (name.startsWith('@')) {
      if (index + 1 >= segments.length) fail('SERVICE_PRODUCTION_CLOSURE_INVALID');
      name = `${name}/${segments[index + 1]}`;
      index += 2;
    } else {
      index += 1;
    }
    dependencySegments(name);
    chain.push(name);
  }
  return chain.join('/');
}

function externalLockForEdge(lock, edge, packageJson, platform, architecture, selectedLockKey) {
  if (packageJson.name !== edge.name || !edgeAcceptsVersion(edge, packageJson.version)) {
    fail('SERVICE_PRODUCTION_CLOSURE_INVALID');
  }
  const candidates = (lock.names.get(edge.name) ?? []).filter((candidate) =>
    candidate.key === selectedLockKey && candidate.version === packageJson.version &&
    packageTargetApplies({ os: candidate.metadata.os, cpu: candidate.metadata.cpu }, platform, architecture));
  if (candidates.length !== 1) fail('SERVICE_PRODUCTION_LOCK_INVALID');
  return candidates[0];
}

function dependencyCandidates(consumerRoot, name) {
  const segments = dependencySegments(name);
  const candidates = [];
  let directory = consumerRoot;
  while (true) {
    candidates.push(directory === '' ? `node_modules/${segments.join('/')}`
      : `${directory}/node_modules/${segments.join('/')}`);
    if (directory === '') break;
    const parent = directory.includes('/') ? directory.slice(0, directory.lastIndexOf('/')) : '';
    const parentName = parent.includes('/') ? parent.slice(parent.lastIndexOf('/') + 1) : parent;
    directory = parentName === 'node_modules' ?
      (parent.includes('/') ? parent.slice(0, parent.lastIndexOf('/')) : '') : parent;
    if (directory === '.') directory = '';
  }
  return candidates;
}

function applicableLockCandidate(lock, edge, platform, architecture) {
  if (workspaceLockForEdge(lock, edge) !== null) return true;
  return (lock.names.get(edge.name) ?? []).some((candidate) =>
    edgeAcceptsVersion(edge, candidate.version) &&
    packageTargetApplies({ os: candidate.metadata.os, cpu: candidate.metadata.cpu }, platform, architecture));
}

function validatePackageRoot(path) {
  if (typeof path !== 'string' || path.length === 0 || path.startsWith('/') || path.includes('\\') ||
      path.split('/').some((segment) => segment === '' || segment === '.' || segment === '..')) {
    fail('SERVICE_PRODUCTION_CLOSURE_INVALID');
  }
  return path;
}

function ownDataRecord(value, keys, optionalKeys = []) {
  if (!plain(value)) fail('SERVICE_PRODUCTION_CLOSURE_INVALID');
  const ownKeys = Reflect.ownKeys(value);
  const accepted = new Set([...keys, ...optionalKeys]);
  if (ownKeys.some((key) => typeof key !== 'string' || !accepted.has(key)) ||
      keys.some((key) => !ownKeys.includes(key))) fail('SERVICE_PRODUCTION_CLOSURE_INVALID');
  const result = {};
  for (const key of ownKeys) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (!descriptor || !descriptor.enumerable || !Object.hasOwn(descriptor, 'value')) {
      fail('SERVICE_PRODUCTION_CLOSURE_INVALID');
    }
    result[key] = descriptor.value;
  }
  return result;
}

function packageFacts(value) {
  const facts = ownDataRecord(value, ['realRoot', 'packageBytes']);
  if (!boundedRootIdentity(facts.realRoot) || !(facts.packageBytes instanceof Uint8Array) ||
      facts.packageBytes.byteLength === 0 || facts.packageBytes.byteLength > PACKAGE_LIMIT) {
    fail('SERVICE_PRODUCTION_CLOSURE_INVALID');
  }
  let packageJson;
  try {
    packageJson = parseStrictJsonBytes(facts.packageBytes, {
      maxBytes: PACKAGE_LIMIT,
      maxDepth: 32,
      maxNodes: 100_000,
    });
  } catch {
    fail('SERVICE_PRODUCTION_CLOSURE_INVALID');
  }
  if (!plain(packageJson) || typeof packageJson.name !== 'string' || typeof packageJson.version !== 'string') {
    fail('SERVICE_PRODUCTION_CLOSURE_INVALID');
  }
  return { realRoot: facts.realRoot, packageBytes: facts.packageBytes, packageJson };
}

function boundedRootIdentity(value) {
  if (typeof value !== 'string' || value.length === 0) return false;
  try {
    assertStrictText(value, 'package root identity', DEPLOYMENT_ENVELOPE_LIMITS.pathBytes);
    return true;
  } catch {
    return false;
  }
}

/**
 * Resolve the production package graph using Bun lock metadata and Node's
 * hoisted node_modules search order. `readPackageRoot` is the boundary adapter:
 * return null only for a proved absent candidate, otherwise exact package.json
 * bytes plus the adapter's root identity.
 */
export async function resolveBunProductionClosure(input) {
  const options = ownDataRecord(input, ['lock', 'contract', 'platform', 'architecture', 'readPackageRoot'], [
    'packageRoots', 'requireWorkspaceRealRoot',
  ]);
  const lock = PARSED_LOCKS.get(options.lock);
  const contract = options.contract;
  const platform = options.platform;
  const architecture = options.architecture;
  const readPackageRoot = options.readPackageRoot;
  const requireWorkspaceRealRoot = options.requireWorkspaceRealRoot ?? false;
  let packageRoots = options.packageRoots ?? null;
  if (!lock || !contract || !['linux', 'win32'].includes(platform) ||
      !['x64', 'arm64'].includes(architecture) || typeof readPackageRoot !== 'function' ||
      typeof requireWorkspaceRealRoot !== 'boolean') fail('SERVICE_PRODUCTION_CLOSURE_INVALID');
  if (packageRoots !== null) {
    if (!(packageRoots instanceof Set) || Object.getPrototypeOf(packageRoots) !== Set.prototype ||
        Reflect.ownKeys(packageRoots).length !== 0 || packageRoots.size > DEPLOYMENT_ENVELOPE_LIMITS.payloadEntries) {
      fail('SERVICE_PRODUCTION_CLOSURE_INVALID');
    }
    packageRoots = new Set(Set.prototype.values.call(packageRoots));
    for (const root of packageRoots) validatePackageRoot(root);
  }
  const workspaceByName = new Map();
  const nodes = new Map();
  const queue = [];
  for (const workspace of contract.sourceWorkspaces) {
    const root = validatePackageRoot(workspace.path);
    const rawFacts = await readPackageRoot(root);
    const facts = rawFacts === null || rawFacts === undefined ? null : packageFacts(rawFacts);
    const packageJson = facts?.packageJson;
    const lockWorkspace = lock.lock.workspaces[workspace.path];
    if (!facts || !plain(packageJson) || packageJson.name !== workspace.packageName ||
        packageJson.version !== workspace.packageVersion || !plain(lockWorkspace) ||
        lockWorkspace.name !== workspace.packageName || lockWorkspace.version !== workspace.packageVersion ||
        !sameStringMap(packageJson.dependencies, lockWorkspace.dependencies) ||
        lock.workspaces.get(workspace.packageName)?.workspace !== workspace.path) {
      fail('SERVICE_PRODUCTION_LOCK_INVALID');
    }
    const node = {
      key: `workspace:${workspace.path}`,
      root,
      logicalRoot: root,
      realRoot: facts.realRoot,
      packageJson,
      packageBytes: facts.packageBytes,
      name: workspace.packageName,
      version: workspace.packageVersion,
      identity: `${workspace.packageName}@workspace:${workspace.path}`,
      integrity: null,
      lockMetadata: lockWorkspace,
      workspace: workspace.path,
      edges: [],
    };
    nodes.set(node.key, node);
    workspaceByName.set(node.name, node);
    queue.push(node);
  }

  const admittedRoots = new Set(SERVICE_PRODUCTION_WORKSPACES);
  while (queue.length > 0) {
    const node = queue.shift();
    for (const edge of dependencyCategories(node.packageJson, node.lockMetadata)) {
      const workspaceEdge = workspaceLockForEdge(lock, edge);
      let root = null;
      let facts = null;
      for (const candidate of dependencyCandidates(node.root, edge.name)) {
        if (packageRoots !== null && !packageRoots.has(candidate)) continue;
        const rawFacts = await readPackageRoot(candidate);
        if (rawFacts === null || rawFacts === undefined) {
          if (packageRoots?.has(candidate)) fail('SERVICE_PRODUCTION_CLOSURE_INVALID');
          continue;
        }
        root = candidate;
        facts = packageFacts(rawFacts);
        break;
      }
      if (root === null) {
        if (edge.allowAbsent || (edge.optional && !applicableLockCandidate(lock, edge, platform, architecture))) continue;
        fail('SERVICE_PRODUCTION_CLOSURE_INVALID');
      }
      const packageJson = facts.packageJson;
      if (!plain(packageJson) || packageJson.name !== edge.name || !edgeAcceptsVersion(edge, packageJson.version)) {
        fail('SERVICE_PRODUCTION_CLOSURE_INVALID');
      }
      if (!packageTargetApplies(packageJson, platform, architecture)) {
        if (edge.optional) continue;
        fail('SERVICE_PRODUCTION_CLOSURE_INVALID');
      }
      let target;
      if (workspaceEdge !== null) {
        const workspace = workspaceByName.get(edge.name);
        if (!workspace || packageJson.version !== workspaceEdge.version ||
            (requireWorkspaceRealRoot && facts.realRoot !== workspace.realRoot)) {
          fail('SERVICE_PRODUCTION_CLOSURE_INVALID');
        }
        if (!root.includes('/node_modules/') && !root.startsWith('node_modules/')) {
          fail('SERVICE_PRODUCTION_CLOSURE_INVALID');
        }
        const key = `location:${root}`;
        target = nodes.get(key);
        if (!target) {
          target = { ...workspace, key, root, logicalRoot: root, packageJson, edges: [] };
          nodes.set(key, target);
          queue.push(target);
        }
      } else {
        const locked = externalLockForEdge(
          lock, edge, packageJson, platform, architecture, bunLockKeyForRelativePackagePath(root),
        );
        const key = `location:${root}`;
        target = nodes.get(key);
        if (!target) {
          target = {
            key,
            root,
            logicalRoot: root,
            realRoot: facts.realRoot,
            packageJson,
            packageBytes: facts.packageBytes,
            name: packageJson.name,
            version: packageJson.version,
            identity: locked.identity,
            integrity: locked.integrity,
            lockMetadata: locked.metadata,
            workspace: null,
            edges: [],
          };
          nodes.set(key, target);
          queue.push(target);
        }
      }
      admittedRoots.add(root);
      node.edges.push(Object.freeze({ kind: edge.kind, name: edge.name, targetKey: target.key, targetIdentity: target.identity }));
    }
  }
  if (packageRoots !== null && [...packageRoots].some((root) => !admittedRoots.has(root))) {
    fail('SERVICE_PRODUCTION_CLOSURE_INVALID');
  }
  return Object.freeze({ nodes, admittedRoots });
}

/** Collect a node's reachable package records with the builder's canonical shape. */
export function collectBunPackageClosure({ nodes, rootKey, recordsByOwner, requireExternal = false }) {
  if (!(nodes instanceof Map) || !(recordsByOwner instanceof Map) || typeof rootKey !== 'string') {
    fail('SERVICE_PRODUCTION_CLOSURE_INVALID');
  }
  const reachable = new Set();
  const visit = (node) => {
    if (!node || reachable.has(node.key)) return;
    reachable.add(node.key);
    for (const edge of node.edges) visit(nodes.get(edge.targetKey));
  };
  visit(nodes.get(rootKey));
  const packages = [];
  const records = new Map();
  for (const key of reachable) {
    const node = nodes.get(key);
    if (!node || (requireExternal && node.workspace !== null)) fail('SERVICE_PRODUCTION_CLOSURE_INVALID');
    const ownedRecords = recordsByOwner.get(key) ?? [];
    const files = ownedRecords.map((record) => ({
      path: record.packageRelativePath,
      size: record.size,
      sha256: record.sha256,
      executablePolicy: record.executablePolicy,
    }));
    if (files.length === 0) fail('SERVICE_PRODUCTION_CLOSURE_INVALID');
    packages.push({
      identity: node.identity,
      integrity: node.integrity,
      files,
      edges: node.edges.map((edge) => ({ kind: edge.kind, name: edge.name, targetIdentity: edge.targetIdentity })),
    });
    records.set(key, ownedRecords);
  }
  return Object.freeze({ packages: Object.freeze(packages), recordsByOwner: records });
}
