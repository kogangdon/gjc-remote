import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { after, test } from 'node:test';
import { gzipSync } from 'node:zlib';
import { Header } from 'tar';
import {
  canonicalJson,
  canonicalJsonBytes,
  canonicalJsonHash,
} from '@gjc-remote/shared/strict-json';
import {
  buildApplicationDeploymentManifest,
  buildBundleInventory,
  buildDeploymentCompatibility,
  buildShawlDeploymentManifest,
  SHAWL_UPSTREAM,
} from '@gjc-remote/shared/deployment-envelope';
import {
  SERVICE_STORE_NAMESPACES,
  buildServiceArtifactBinding,
  buildServiceCandidateProof,
  buildServiceFinalProof,
  buildServiceManualCleanup,
  buildServiceManifest,
  buildServiceOldProof,
  buildServicePlatformState,
  buildServiceResourceProof,
  buildServiceCursorSet,
  buildServiceFamilyCursor,
  buildServiceFileCursor,
  buildServiceStartupProof,
  buildServiceReferenceRecord,
  buildServiceReferenceSlot,
  buildServiceTombstone,
  buildServiceTransaction,
  buildServiceTransitionProof,
  deriveServiceInstanceKey,
  serviceConfigurationFingerprint,
  serviceRolesFingerprint,
  buildServiceTrialBoundary,
} from '@gjc-remote/shared/service-lifecycle-envelope';
import { assertPinnedDeploymentManifest as assertProductionPinnedDeploymentManifest } from '../src/deployment-provenance.js';
import { createPinnedDeploymentInstallation } from '../test-fixtures/pinned-deployment-installation.mjs';

const pinnedInstallation = await createPinnedDeploymentInstallation({
  keyIds: ['deployment-test'],
  includeStore: true,
});
after(() => pinnedInstallation.dispose());
const { SERVICE_STORE_LAYOUT, createServiceStore } = pinnedInstallation.store;

// This suite is an in-memory metadata model. It is explicitly not filesystem,
// lock-kernel, ACL, durability, systemd, SCM, Shawl, or disposable-host evidence.
// Its signed manifests and brands belong only to an isolated fixture installation,
// not the production module instance or a real production trust store.

const hash = (character = 'a') => character.repeat(64);
const sha256 = (bytes) => createHash('sha256').update(bytes).digest('hex');
const linuxRoles = Object.freeze({
  management: Object.freeze({ kind: 'uid', value: 'uid:1000' }),
  bot: Object.freeze({ kind: 'uid', value: 'uid:1001' }),
  recovery: Object.freeze({ kind: 'uid', value: 'uid:1002' }),
  daemon: Object.freeze({ kind: 'uid', value: 'uid:1003' }),
  system: Object.freeze({ kind: 'uid', value: 'uid:0' }),
});
const windowsRoles = Object.freeze({
  management: Object.freeze({ kind: 'sid', value: 'S-1-5-21-1' }),
  bot: Object.freeze({ kind: 'sid', value: 'S-1-5-21-2' }),
  recovery: Object.freeze({ kind: 'sid', value: 'S-1-5-21-3' }),
  daemon: Object.freeze({ kind: 'sid', value: 'S-1-5-21-4' }),
  system: Object.freeze({ kind: 'sid', value: 'S-1-5-18' }),
});
const linuxBotConfiguration = Object.freeze({
  runtimePath: '/usr/bin/node',
  workingDirectory: '/srv/gjc-remote-bot',
  homeDirectory: '/var/lib/gjc-bot',
  logDirectory: '/var/log/gjc-remote-bot',
  channelsConfig: '/etc/gjc-remote/channels.json',
  expectedHostSetFingerprint: hash('8'),
  expectedHostCount: 2,
});

function clone(value) {
  return JSON.parse(JSON.stringify(value));
}

function same(left, right) {
  return canonicalJson(left) === canonicalJson(right);
}

function nativeError(code, operation, writes = 0, ambiguous = false) {
  const error = new Error(code);
  Object.assign(error, { code, operation, writes, ambiguous });
  return error;
}

class FakeServiceNative {
  constructor(platform = 'linux') {
    this.platform = platform;
    this.roots = new Map();
    this.locks = new Map();
    this.heldLocks = [];
    this.identityCounter = 0;
    this.factCounter = 0;
    this.calls = [];
    this.totalWrites = 0;
    this.publishOccurrences = new Map();
    this.publishFault = null;
    this.publishCollision = null;
    this.artifactWriteFault = null;
    this.rootCreateFaults = new Map();
    this.unregisteredRootParents = new Set();
    this.artifactRemoveFault = null;
    this.recordRemoveFault = null;
    this.closeFailure = null;
    this.artifactReaderReceiptFault = null;
    this.activeArtifactReaders = 0;
    this.directoryFault = null;
    this.facade = Object.freeze({
      open_service_root: this.open_service_root.bind(this),
      open_service_directory: this.open_service_directory.bind(this),
      acquire_service_lock: this.acquire_service_lock.bind(this),
      close_service_handle: this.close_service_handle.bind(this),
      read_service_file: this.read_service_file.bind(this),
      publish_service_file_atomic: this.publish_service_file_atomic.bind(this),
      remove_service_object_exact: this.remove_service_object_exact.bind(this),
      list_service_directory: this.list_service_directory.bind(this),
      publish_service_directory_no_replace: this.publish_service_directory_no_replace.bind(this),
      begin_service_artifact_write: this.begin_service_artifact_write.bind(this),
      write_service_artifact_chunk: this.write_service_artifact_chunk.bind(this),
      finish_service_artifact_write: this.finish_service_artifact_write.bind(this),
      open_service_artifact_reader: this.open_service_artifact_reader.bind(this),
      read_service_artifact_chunk: this.read_service_artifact_chunk.bind(this),
      remove_service_artifact_file_exact: this.remove_service_artifact_file_exact.bind(this),
      seal_service_directory: this.seal_service_directory.bind(this),
      open_service_artifact_source: this.open_service_artifact_source.bind(this),
      plan_service_artifact_location: this.plan_service_artifact_location.bind(this),
      resolve_service_artifact_location: this.resolve_service_artifact_location.bind(this),
      open_linux_service_scope: this.open_linux_service_scope.bind(this),
      read_linux_service_object: this.read_linux_service_object.bind(this),
    });
  }

  open_linux_service_scope(roles, serviceKey, access) {
    if (access !== 'read-existing' || serviceKey !== null) throw nativeError('SERVICE_INVALID', 'open_linux_service_scope');
    return { handle: this.handle('linux-scope', { bytes: Buffer.from('daemon-template') }), writes: 0 };
  }

  read_linux_service_object(scope, objectKind) {
    if (scope?.kind !== 'linux-scope' || objectKind !== 'daemon-template') throw nativeError('SERVICE_INVALID', 'read_linux_service_object');
    const bytes = Buffer.from(scope.node.bytes);
    return { snapshot: { state: 'file', bytes, facts: this.facts(this.identity('service-control-file'), bytes) }, writes: 0 };
  }

  identity(profile) {
    this.identityCounter += 1;
    if (this.platform === 'win32') {
      return {
        profile,
        kind: 'win32-service-object-v1',
        volumeSerial: this.identityCounter.toString(16).padStart(16, '0'),
        fileId: this.identityCounter.toString(16).padStart(32, '0'),
        attributes: profile.endsWith('directory') ? 16 : 128,
        owner: windowsRoles.management.value,
        securitySha256: sha256(Buffer.from(`security:${profile}:${this.identityCounter}`)),
      };
    }
    return {
      profile,
      kind: 'linux-service-object-v1',
      device: '1',
      inode: String(this.identityCounter),
      mode: profile.endsWith('directory') ? 16832 : 33152,
      owner: linuxRoles.management.value,
      securitySha256: sha256(Buffer.from(`security:${profile}:${this.identityCounter}`)),
    };
  }

  directory(profile, rootKind, name) {
    return { type: 'directory', profile, rootKind, name, identity: this.identity(profile), entries: new Map() };
  }

  file(bytes, profile = 'service-control-file') {
    const identity = this.identity(profile);
    const data = Buffer.from(bytes);
    return {
      type: 'file',
      profile,
      identity,
      bytes: data,
      facts: this.facts(identity, data),
    };
  }

  facts(identity, bytes) {
    this.factCounter += 1;
    if (this.platform === 'win32') {
      return {
        kind: 'win32-file-v1',
        volumeSerial: identity.volumeSerial,
        fileId: identity.fileId,
        size: bytes.length,
        sha256: sha256(bytes),
        attributes: identity.attributes,
        owner: identity.owner,
        securitySha256: identity.securitySha256,
      };
    }
    return {
      kind: 'linux-file-v1',
      device: identity.device,
      inode: identity.inode,
      size: bytes.length,
      sha256: sha256(bytes),
      mode: identity.mode,
      owner: identity.owner,
      securitySha256: identity.securitySha256,
    };
  }

  makeRoot(rootKind) {
    const profile = rootKind === 'staging' ? 'service-staging-directory' :
      rootKind === 'control' ? 'service-control-directory' : 'service-release-directory';
    const node = this.directory(profile, rootKind, rootKind);
    if (rootKind === 'control') {
      for (const name of SERVICE_STORE_NAMESPACES) {
        node.entries.set(name, this.directory('service-control-directory', rootKind, name));
      }
    }
    const binding = {
      schemaVersion: 1,
      rootKind,
      rootPath: this.platform === 'win32'
        ? rootKind === 'shawl'
          ? 'C:\\ProgramData\\gjc-remote\\supervisors\\shawl'
          : `C:\\ProgramData\\gjc-remote\\${rootKind === 'control' ? 'service-control' : rootKind}`
        : rootKind === 'control'
          ? '/var/lib/gjc-remote/service-control'
          : `/opt/gjc-remote/${rootKind === 'staging' ? '.staging' : 'releases'}`,
      rootNonce: sha256(Buffer.from(`nonce:${rootKind}`)).slice(0, 32),
      rolesFingerprint: hash('b'),
      identity: clone(node.identity),
      directoryIdentities: rootKind === 'control'
        ? Object.fromEntries([...node.entries].map(([name, child]) => [name, clone(child.identity)]))
        : {},
      bindingFingerprint: sha256(Buffer.from(`binding:${rootKind}:${node.identity.securitySha256}`)),
    };
    const root = { node, binding };
    this.roots.set(rootKind, root);
    return root;
  }

  handle(kind, node, parent = null, extra = {}) {
    const handle = { kind, node, parent, children: 0, closed: false, ...extra };
    if (parent) parent.children += 1;
    return handle;
  }

  recordWrite(count) {
    this.totalWrites += count;
    return count;
  }

  open_service_root(rootKind, access) {
    if (arguments.length !== 2) throw nativeError('SERVICE_INVALID', 'open_service_root');
    this.calls.push(`root:${rootKind}:${access}`);
    let root = this.roots.get(rootKind);
    if (access === 'create-new') {
      const fault = this.rootCreateFaults.get(rootKind);
      if (fault) {
        this.rootCreateFaults.delete(rootKind);
        this.recordWrite(fault.writes);
        throw nativeError(
          fault.code,
          'open_service_root',
          fault.writes,
          fault.ambiguous,
        );
      }
      if (root) throw nativeError('SERVICE_ALREADY_EXISTS', 'open_service_root');
      this.unregisteredRootParents.delete(rootKind);
      root = this.makeRoot(rootKind);
      const writes = this.recordWrite(rootKind === 'control' ? 9 : 2);
      return { handle: this.handle('root', root.node), rootBinding: clone(root.binding), writes };
    }
    if (!root && this.unregisteredRootParents.has(rootKind)) {
      throw nativeError(
        'SERVICE_MANUAL_CLEANUP',
        'open_service_root',
        0,
        true,
      );
    }
    if (!root) return null;
    return { handle: this.handle('root', root.node), rootBinding: clone(root.binding), writes: 0 };
  }

  open_service_directory(parent, name, access, expectedIdentity, lock) {
    if (arguments.length !== 5) throw nativeError('SERVICE_INVALID', 'open_service_directory');
    this.assertHandle(parent);
    this.calls.push(`directory:${name}:${access}`);
    let node = parent.node.entries.get(name);
    let writes = 0;
    if (access === 'create-new') {
      if (node) throw nativeError('SERVICE_ALREADY_EXISTS', 'open_service_directory');
      if (expectedIdentity !== null || !lock || !lock.exclusive) throw nativeError('SERVICE_INVALID', 'open_service_directory');
      if (this.directoryFault?.name === name && this.directoryFault.when === 'before') {
        this.directoryFault = null;
        throw nativeError('SERVICE_IO_FAILED', 'open_service_directory');
      }
      const profile = parent.node.rootKind === 'staging' ? 'service-staging-directory' :
        parent.node.rootKind === 'control' ? 'service-control-directory' : 'service-release-directory';
      node = this.directory(profile, parent.node.rootKind, name);
      parent.node.entries.set(name, node);
      writes = this.recordWrite(1);
      if (this.directoryFault?.name === name && this.directoryFault.when === 'after') {
        this.directoryFault = null;
        throw nativeError('SERVICE_MANUAL_CLEANUP', 'open_service_directory', writes, true);
      }
    } else {
      if (!node || node.type !== 'directory' || !same(node.identity, expectedIdentity)) {
        throw nativeError('SERVICE_STALE', 'open_service_directory');
      }
    }
    return { handle: this.handle('directory', node, parent), identity: clone(node.identity), writes };
  }

  lockKey(scope, serviceKey) {
    return `${scope}:${serviceKey ?? ''}`;
  }

  acquire_service_lock(root, scope, serviceKey, mode) {
    if (arguments.length !== 4) throw nativeError('SERVICE_INVALID', 'acquire_service_lock');
    this.assertHandle(root);
    const rank = scope === 'artifact' ? 1 : scope === 'shared-template' ? 2 : 3;
    const previous = this.heldLocks.at(-1);
    if (previous && (previous.rank > rank || (previous.rank === rank && !(rank === 3 && previous.serviceKey < serviceKey)))) {
      throw nativeError('SERVICE_INVALID', 'acquire_service_lock');
    }
    const key = this.lockKey(scope, serviceKey);
    let identity = this.locks.get(key);
    let writes = 0;
    if (!identity) {
      if (mode === 'shared-existing') throw nativeError('SERVICE_PENDING', 'acquire_service_lock');
      identity = this.identity('service-control-file');
      this.locks.set(key, identity);
      writes = this.recordWrite(2);
    }
    if (this.heldLocks.some((held) => held.key === key && (mode === 'exclusive' || held.exclusive))) {
      throw nativeError('SERVICE_PENDING', 'acquire_service_lock');
    }
    const handle = this.handle('lock', { name: key }, root, {
      key,
      rank,
      scope,
      serviceKey,
      exclusive: mode === 'exclusive',
      identity,
    });
    this.heldLocks.push(handle);
    this.calls.push(`lock:${scope}:${serviceKey ?? 'global'}:${mode}`);
    return { handle, identity: clone(identity), writes };
  }

  close_service_handle(handle) {
    if (arguments.length !== 1) throw nativeError('SERVICE_INVALID', 'close_service_handle');
    if (!handle || typeof handle !== 'object') throw nativeError('SERVICE_INVALID', 'close_service_handle');
    if (handle.closed) return undefined;
    if (handle.children !== 0 || (handle.kind === 'lock' && this.heldLocks.at(-1) !== handle)) {
      throw nativeError('SERVICE_PENDING', 'close_service_handle');
    }
    const closeName = handle.name ?? handle.node?.name;
    if (this.closeFailure?.name === closeName &&
        this.closeFailure.remaining > 0) {
      this.closeFailure.remaining -= 1;
      throw nativeError(
        'SERVICE_IO_FAILED',
        'close_service_handle',
        0,
        true,
      );
    }
    if (handle.kind === 'lock') this.heldLocks.pop();
    if (handle.kind === 'artifact-reader') {
      this.activeArtifactReaders -= 1;
    }
    if (handle.parent) handle.parent.children -= 1;
    handle.closed = true;
    this.calls.push(`close:${handle.kind}:${handle.scope ?? handle.node.name}`);
    return undefined;
  }

  read_service_file(parent, name, maxBytes) {
    if (arguments.length !== 3) throw nativeError('SERVICE_INVALID', 'read_service_file');
    this.assertHandle(parent);
    const node = parent.node.entries.get(name);
    this.calls.push(`read:${parent.node.name}/${name}`);
    if (!node) return null;
    if (node.type !== 'file' || node.bytes.length > maxBytes) throw nativeError('SERVICE_STALE', 'read_service_file', 0, true);
    return { bytes: Buffer.from(node.bytes), facts: clone(node.facts), writes: 0 };
  }

  publish_service_file_atomic(parent, name, bytes, expected, lock) {
    if (arguments.length !== 5) throw nativeError('SERVICE_INVALID', 'publish_service_file_atomic');
    this.assertHandle(parent);
    this.assertHandle(lock);
    const occurrence = (this.publishOccurrences.get(name) ?? 0) + 1;
    this.publishOccurrences.set(name, occurrence);
    if (this.publishFault?.name === name && this.publishFault.occurrence === occurrence && this.publishFault.when === 'before') {
      this.publishFault = null;
      throw nativeError('SERVICE_IO_FAILED', 'publish_service_file_atomic', 0, false);
    }
    if (this.publishCollision?.name === name) {
      const collision = this.publishCollision;
      this.publishCollision = null;
      parent.node.entries.set(
        name,
        this.file(collision.bytes === null ? bytes : collision.bytes),
      );
    }
    const prior = parent.node.entries.get(name);
    if (expected === null) {
      if (prior) throw nativeError('SERVICE_ALREADY_EXISTS', 'publish_service_file_atomic');
    } else if (!prior || prior.type !== 'file' || !same(prior.facts, expected.facts) || !prior.bytes.equals(expected.bytes)) {
      throw nativeError('SERVICE_STALE', 'publish_service_file_atomic');
    }
    const file = this.file(
      bytes,
      parent.node.rootKind === 'staging'
        ? 'service-staging-file'
        : 'service-control-file',
    );
    parent.node.entries.set(name, file);
    const writes = this.recordWrite(2);
    this.calls.push(`publish:${parent.node.name}/${name}`);
    if (this.publishFault?.name === name && this.publishFault.occurrence === occurrence && this.publishFault.when === 'after') {
      this.publishFault = null;
      throw nativeError('SERVICE_MANUAL_CLEANUP', 'publish_service_file_atomic', writes, true);
    }
    return { facts: clone(file.facts), writes };
  }

  remove_service_object_exact(parent, name, expected, lock) {
    if (arguments.length !== 4) throw nativeError('SERVICE_INVALID', 'remove_service_object_exact');
    this.assertHandle(parent);
    this.assertHandle(lock);
    const prior = parent.node.entries.get(name);
    const directoryRemoval = expected !== null &&
      typeof expected === 'object' &&
      Object.keys(expected).length === 1 &&
      Object.hasOwn(expected, 'identity');
    if (directoryRemoval) {
      if (!prior || prior.type !== 'directory' ||
          prior.entries.size !== 0 ||
          !same(prior.identity, expected.identity)) {
        throw nativeError('SERVICE_STALE', 'remove_service_object_exact');
      }
    } else if (!prior || prior.type !== 'file' ||
        !same(prior.facts, expected.facts) ||
        !prior.bytes.equals(expected.bytes)) {
      throw nativeError('SERVICE_STALE', 'remove_service_object_exact');
    }
    if (!directoryRemoval &&
        this.recordRemoveFault?.name === name &&
        this.recordRemoveFault.when === 'before') {
      this.recordRemoveFault = null;
      throw nativeError('SERVICE_IO_FAILED', 'remove_service_object_exact');
    }
    parent.node.entries.delete(name);
    const writes = this.recordWrite(2);
    this.calls.push(`remove:${parent.node.name}/${name}`);
    if (directoryRemoval &&
        this.artifactRemoveFault?.kind === 'directory' &&
        this.artifactRemoveFault.name === name) {
      this.artifactRemoveFault = null;
      throw nativeError(
        'SERVICE_MANUAL_CLEANUP',
        'remove_service_object_exact',
        writes,
        true,
      );
    }
    if (!directoryRemoval &&
        this.recordRemoveFault?.name === name &&
        this.recordRemoveFault.when === 'after') {
      this.recordRemoveFault = null;
      throw nativeError(
        'SERVICE_MANUAL_CLEANUP',
        'remove_service_object_exact',
        writes,
        true,
      );
    }
    return { removed: true, writes };
  }

  list_service_directory(directory, maxEntries, lock) {
    if (arguments.length !== 3) throw nativeError('SERVICE_INVALID', 'list_service_directory');
    this.assertHandle(directory);
    this.assertHandle(lock);
    const entries = [...directory.node.entries]
      .sort(([left], [right]) => Buffer.compare(Buffer.from(left), Buffer.from(right)))
      .map(([name, node]) => ({ name, identity: clone(node.identity) }));
    if (entries.length > maxEntries) throw nativeError('SERVICE_STALE', 'list_service_directory', 0, true);
    return { directoryIdentity: clone(directory.node.identity), entries, writes: 0 };
  }

  publish_service_directory_no_replace(source, destination, name, identity, artifactLock) {
    if (arguments.length !== 5) throw nativeError('SERVICE_INVALID', 'publish_service_directory_no_replace');
    this.assertHandle(source);
    this.assertHandle(destination);
    this.assertHandle(artifactLock);
    if (source.kind !== 'directory' || source.node.rootKind !== 'staging' ||
        !same(source.node.identity, identity) || destination.node.entries.has(name) ||
        artifactLock.scope !== 'artifact') {
      throw nativeError('SERVICE_INVALID', 'publish_service_directory_no_replace');
    }
    source.parent.node.entries.delete(source.node.name);
    source.parent.children -= 1;
    destination.node.entries.set(name, source.node);
    source.parent = destination;
    destination.children += 1;
    source.node.name = name;
    source.node.rootKind = destination.node.rootKind;
    const writes = this.recordWrite(1);
    return { handle: source, identity: clone(source.node.identity), writes };
  }

  begin_service_artifact_write(parent, name, expectedSize, expectedSha256, lock) {
    if (this.artifactWriteFault !== null) {
      const fault = this.artifactWriteFault;
      this.artifactWriteFault = null;
      this.recordWrite(fault.writes);
      throw nativeError(
        fault.code,
        'begin_service_artifact_write',
        fault.writes,
        fault.ambiguous,
      );
    }
    if (arguments.length !== 5) {
      throw nativeError('SERVICE_INVALID', 'begin_service_artifact_write');
    }
    this.assertHandle(parent);
    this.assertHandle(lock);
    if (parent.node.rootKind !== 'staging' ||
        !Number.isSafeInteger(expectedSize) || expectedSize < 0 ||
        !/^[0-9a-f]{64}$/.test(expectedSha256)) {
      throw nativeError('SERVICE_INVALID', 'begin_service_artifact_write');
    }
    if (parent.node.entries.has(name)) {
      throw nativeError('SERVICE_ALREADY_EXISTS', 'begin_service_artifact_write');
    }
    const node = this.file(Buffer.alloc(0), 'service-staging-file');
    node.name = name;
    parent.node.entries.set(name, node);
    const writes = this.recordWrite(1);
    const handle = this.handle('artifact-writer', node, parent, {
      name,
      expectedSize,
      expectedSha256,
      offset: 0,
      completed: false,
    });
    this.calls.push(`artifact-begin:${parent.node.name}/${name}`);
    return { handle, identity: clone(node.identity), writes };
  }

  write_service_artifact_chunk(writer, expectedOffset, bytes) {
    if (arguments.length !== 3) {
      throw nativeError('SERVICE_INVALID', 'write_service_artifact_chunk');
    }
    this.assertHandle(writer);
    if (writer.kind !== 'artifact-writer' || writer.completed ||
        writer.offset !== expectedOffset) {
      throw nativeError('SERVICE_STALE', 'write_service_artifact_chunk');
    }
    const chunk = Buffer.from(bytes);
    writer.node.bytes = Buffer.concat([writer.node.bytes, chunk]);
    writer.offset += chunk.length;
    writer.node.facts = this.facts(writer.node.identity, writer.node.bytes);
    const writes = this.recordWrite(1);
    return { nextOffset: writer.offset, writes };
  }

  finish_service_artifact_write(writer, profile) {
    if (arguments.length !== 2) {
      throw nativeError('SERVICE_INVALID', 'finish_service_artifact_write');
    }
    this.assertHandle(writer);
    if (writer.kind !== 'artifact-writer' || writer.completed) {
      throw nativeError('SERVICE_INVALID', 'finish_service_artifact_write');
    }
    const node = writer.node;
    const digest = sha256(node.bytes);
    if (node.bytes.length !== writer.expectedSize ||
        digest !== writer.expectedSha256) {
      if (writer.parent) writer.parent.children -= 1;
      writer.closed = true;
      throw nativeError('SERVICE_STALE', 'finish_service_artifact_write');
    }
    let writes = 0;
    if (node.profile !== profile) {
      node.profile = profile;
      node.identity = this.identity(profile, node.identity);
      writes = this.recordWrite(1);
    }
    node.facts = this.facts(node.identity, node.bytes);
    writer.completed = true;
    if (writer.parent) writer.parent.children -= 1;
    writer.closed = true;
    this.calls.push(`artifact-finish:${writer.name}`);
    return { facts: clone(node.facts), writes };
  }

  open_service_artifact_reader(parent, name, maximum, expected, lock) {
    if (arguments.length !== 5) {
      throw nativeError('SERVICE_INVALID', 'open_service_artifact_reader');
    }
    this.assertHandle(parent);
    this.assertHandle(lock);
    const node = parent.node.entries.get(name);
    if (!node) {
      if (expected !== null) {
        throw nativeError('SERVICE_STALE', 'open_service_artifact_reader');
      }
      return null;
    }
    if (node.type !== 'file' || node.facts.size > maximum ||
        (expected !== null && !same(node.facts, expected))) {
      throw nativeError('SERVICE_STALE', 'open_service_artifact_reader');
    }
    const handle = this.handle('artifact-reader', node, parent, {
        offset: 0,
        name,
      });
    this.activeArtifactReaders += 1;
    const facts = clone(node.facts);
    if (this.artifactReaderReceiptFault === name) {
      this.artifactReaderReceiptFault = null;
      facts.sha256 = 'invalid';
    }
    return {
      handle,
      facts,
      writes: 0,
    };
  }

  read_service_artifact_chunk(reader, expectedOffset, maximum) {
    if (arguments.length !== 3) {
      throw nativeError('SERVICE_INVALID', 'read_service_artifact_chunk');
    }
    this.assertHandle(reader);
    if (reader.kind !== 'artifact-reader' ||
        reader.offset !== expectedOffset) {
      throw nativeError('SERVICE_STALE', 'read_service_artifact_chunk');
    }
    const end = Math.min(reader.node.bytes.length, reader.offset + maximum);
    const bytes = reader.node.bytes.subarray(reader.offset, end);
    reader.offset = end;
    return {
      bytes: Buffer.from(bytes),
      nextOffset: reader.offset,
      eof: reader.offset === reader.node.bytes.length,
      writes: 0,
    };
  }

  remove_service_artifact_file_exact(parent, name, expected, lock) {
    if (arguments.length !== 4) {
      throw nativeError(
        'SERVICE_INVALID',
        'remove_service_artifact_file_exact',
      );
    }
    this.assertHandle(parent);
    this.assertHandle(lock);
    const node = parent.node.entries.get(name);
    if (!node || node.type !== 'file' || !same(node.facts, expected)) {
      throw nativeError(
        'SERVICE_STALE',
        'remove_service_artifact_file_exact',
      );
    }
    parent.node.entries.delete(name);
    const writes = this.recordWrite(2);
    this.calls.push(`artifact-remove:${parent.node.name}/${name}`);
    if (this.artifactRemoveFault?.kind === 'file' &&
        this.artifactRemoveFault.name === name) {
      this.artifactRemoveFault = null;
      throw nativeError(
        'SERVICE_MANUAL_CLEANUP',
        'remove_service_artifact_file_exact',
        writes,
        true,
      );
    }
    return { removed: true, writes };
  }

  seal_service_directory() {
    throw nativeError('SERVICE_INVALID', 'seal_service_directory');
  }

  open_service_artifact_source() {
    throw nativeError('SERVICE_INVALID', 'open_service_artifact_source');
  }

  plan_service_artifact_location(rootKind, artifactFingerprint, relativePath) {
    if (arguments.length !== 3) {
      throw nativeError('SERVICE_INVALID', 'plan_service_artifact_location');
    }
    if (this.platform !== 'win32') {
      throw nativeError('SERVICE_UNSUPPORTED', 'plan_service_artifact_location');
    }
    const components = relativePath.split('/');
    if (!['releases', 'shawl'].includes(rootKind) ||
        !/^[0-9a-f]{64}$/.test(artifactFingerprint) ||
        components.length === 0 || components.some((part) =>
          part.length === 0 || part === '.' || part === '..' || /[\\:\0]/.test(part))) {
      throw nativeError('SERVICE_INVALID', 'plan_service_artifact_location');
    }
    const root = this.roots.get(rootKind) ?? null;
    const absoluteRoot = root?.binding.rootPath ?? (rootKind === 'shawl'
      ? 'C:\\ProgramData\\gjc-remote\\supervisors\\shawl'
      : 'C:\\ProgramData\\gjc-remote\\releases');
    let existingDirectoryIdentity = root?.node.identity ?? null;
    let missingSegments = [artifactFingerprint, ...components];
    let current = root?.node ?? null;
    if (current !== null) {
      const pathComponents = [artifactFingerprint, ...components];
      for (let index = 0; index < pathComponents.length - 1; index += 1) {
        const child = current.entries.get(pathComponents[index]);
        if (!child) {
          missingSegments = pathComponents.slice(index);
          existingDirectoryIdentity = current.identity;
          break;
        }
        if (child.type !== 'directory') {
          throw nativeError('SERVICE_STALE', 'plan_service_artifact_location');
        }
        current = child;
        existingDirectoryIdentity = current.identity;
        missingSegments = [];
      }
      if (missingSegments.length === 0) {
        const target = current.entries.get(pathComponents.at(-1));
        if (target) {
          throw nativeError('SERVICE_PENDING', 'plan_service_artifact_location', 0, true);
        }
        missingSegments = [pathComponents.at(-1)];
      }
    }
    const anchorIdentityFingerprint = sha256(Buffer.from(
      JSON.stringify(existingDirectoryIdentity ?? { rootKind, absoluteRoot }),
    ));
    const absolutePath = `${absoluteRoot.replace(/[\\/]$/, '')}\\${artifactFingerprint}\\${components.join('\\')}`;
    const intent = {
      schemaVersion: 1,
      rootKind,
      artifactFingerprint,
      relativePath,
      absoluteRoot,
      absolutePath,
      anchorIdentityFingerprint,
      missingSegments,
      existingDirectoryIdentity: existingDirectoryIdentity === null
        ? null
        : clone(existingDirectoryIdentity),
      intentFingerprint: sha256(Buffer.from(JSON.stringify({
        rootKind,
        artifactFingerprint,
        relativePath,
        absolutePath,
        missingSegments,
      }))),
      writes: 0,
    };
    this.calls.push(`plan-location:${rootKind}:${artifactFingerprint}:${relativePath}`);
    return intent;
  }

  resolve_service_artifact_location(directory, relativePath, expectedFileSha256) {
    if (arguments.length !== 3) {
      throw nativeError('SERVICE_INVALID', 'resolve_service_artifact_location');
    }
    if (this.platform !== 'win32') {
      throw nativeError('SERVICE_UNSUPPORTED', 'resolve_service_artifact_location');
    }
    this.assertHandle(directory);
    const components = relativePath.split('/');
    if (directory.kind !== 'directory' ||
        directory.node.rootKind !== 'releases' && directory.node.rootKind !== 'shawl' ||
        directory.node.profile !== 'service-release-directory' ||
        components.length === 0 || components.some((part) =>
          part.length === 0 || part === '.' || part === '..' || /[\\:\0]/.test(part)) ||
        !/^[0-9a-f]{64}$/.test(expectedFileSha256)) {
      throw nativeError('SERVICE_INVALID', 'resolve_service_artifact_location');
    }
    let parent = directory.node;
    for (const component of components.slice(0, -1)) {
      const child = parent.entries.get(component);
      if (!child || child.type !== 'directory' ||
          child.profile !== 'service-release-directory' || child.reparse === true) {
        throw nativeError('SERVICE_STALE', 'resolve_service_artifact_location', 0, true);
      }
      parent = child;
    }
    const file = parent.entries.get(components.at(-1));
    if (!file || file.type !== 'file' ||
        file.reparse === true ||
        !['service-release-file', 'service-release-executable'].includes(file.profile) ||
        file.bytes.length !== file.facts.size ||
        file.facts.sha256 !== expectedFileSha256 ||
        sha256(file.bytes) !== expectedFileSha256) {
      throw nativeError('SERVICE_STALE', 'resolve_service_artifact_location', 0, true);
    }
    const rootPath = this.roots.get(directory.node.rootKind).binding.rootPath;
    return {
      schemaVersion: 1,
      publishedPath: relativePath,
      absolutePath: `${rootPath.replace(/[\\/]$/, '')}\\${directory.node.name}\\${components.join('\\')}`,
      directoryIdentity: clone(parent.identity),
      fileIdentity: clone(file.identity),
      fileSha256: file.facts.sha256,
      writes: 0,
    };
  }

  assertHandle(handle) {
    if (!handle || handle.closed) throw nativeError('SERVICE_INVALID', 'fake_handle');
  }

  failPublish(name, when = 'before', occurrence = (this.publishOccurrences.get(name) ?? 0) + 1) {
    this.publishFault = { name, when, occurrence };
  }

  collidePublish(name, bytes = null) {
    this.publishCollision = {
      name,
      bytes: bytes === null ? null : Buffer.from(bytes),
    };
  }

  failArtifactWrite(
    code = 'SERVICE_MANUAL_CLEANUP',
    writes = 1,
    ambiguous = true,
  ) {
    this.artifactWriteFault = { code, writes, ambiguous };
  }

  seedSafeExternalRootParent(rootKind) {
    this.unregisteredRootParents.add(rootKind);
  }

  failRootCreate(
    rootKind,
    code = 'SERVICE_MANUAL_CLEANUP',
    writes = 1,
    ambiguous = true,
  ) {
    this.rootCreateFaults.set(rootKind, { code, writes, ambiguous });
  }

  failDirectory(name, when = 'after') {
    this.directoryFault = { name, when };
  }

  namespace(name) {
    return this.roots.get('control')?.node.entries.get(name);
  }

  serviceDirectory(namespace, serviceKey, create = true) {
    const parent = this.namespace(namespace);
    let directory = parent?.entries.get(serviceKey);
    if (!directory && create) {
      directory = this.directory('service-control-directory', 'control', serviceKey);
      parent.entries.set(serviceKey, directory);
    }
    return directory;
  }

  putRaw(namespace, serviceKey, name, bytes) {
    const parent = serviceKey === null ? this.namespace(namespace) : this.serviceDirectory(namespace, serviceKey);
    parent.entries.set(name, this.file(Buffer.from(bytes)));
  }

  deleteRecord(namespace, serviceKey, name) {
    const parent = serviceKey === null ? this.namespace(namespace) : this.serviceDirectory(namespace, serviceKey, false);
    parent?.entries.delete(name);
  }

  recreateRecordSameBytes(namespace, serviceKey, name) {
    const parent = serviceKey === null
      ? this.namespace(namespace)
      : this.serviceDirectory(namespace, serviceKey, false);
    const prior = parent?.entries.get(name);
    if (!prior || prior.type !== 'file') throw new Error(`missing record ${namespace}/${name}`);
    parent.entries.set(name, this.file(prior.bytes));
  }

  recordBytes(namespace, serviceKey, name) {
    const parent = serviceKey === null
      ? this.namespace(namespace)
      : this.serviceDirectory(namespace, serviceKey, false);
    const record = parent?.entries.get(name);
    if (!record || record.type !== 'file') throw new Error(`missing record ${namespace}/${name}`);
    return Buffer.from(record.bytes);
  }

  seedPublication(rootKind, name) {
    const root = this.roots.get(rootKind) ?? this.makeRoot(rootKind);
    let node = root.node.entries.get(name);
    if (!node) {
      node = this.directory('service-release-directory', rootKind, name);
      root.node.entries.set(name, node);
    }
    return clone(node.identity);
  }

  seedApplicationPublication(manifest) {
    const identity = this.seedPublication(
      'releases',
      manifest.archive.sha256,
    );
    const target = this.roots.get('releases').node.entries.get(
      manifest.archive.sha256,
    );
    const { inventory, bytes } = applicationInventory(
      manifest.target.platform,
    );
    const put = (path, record, content) => {
      const segments = path.split('/');
      let parent = target;
      for (const segment of segments.slice(0, -1)) {
        let child = parent.entries.get(segment);
        if (!child) {
          child = this.directory(
            'service-release-directory',
            'releases',
            segment,
          );
          parent.entries.set(segment, child);
        }
        parent = child;
      }
      const profile = record.executablePolicy === 'required'
        ? 'service-release-executable'
        : 'service-release-file';
      const file = this.file(content, profile);
      file.facts = {
        ...file.facts,
        size: record.size,
        sha256: record.sha256,
      };
      parent.entries.set(segments.at(-1), file);
    };
    const inventoryFile = this.file(bytes, 'service-release-file');
    inventoryFile.facts = {
      ...inventoryFile.facts,
      size: bytes.length,
      sha256: sha256(bytes),
    };
    target.entries.set('bundle-files.json', inventoryFile);
    for (const record of inventory.payloadEntries) {
      put(record.path, record, applicationPayloadBytes(record.path));
    }
    return identity;
  }

  seedShawlPublication(manifest) {
    const identity = this.seedPublication(
      'shawl',
      manifest.executable.sha256,
    );
    const target = this.roots.get('shawl').node.entries.get(
      manifest.executable.sha256,
    );
    const executable = this.file(
      Buffer.from(SHAWL_FIXTURE_BYTES),
      'service-release-executable',
    );
    executable.facts = {
      ...executable.facts,
      size: manifest.executable.byteLength,
      sha256: manifest.executable.sha256,
    };
    target.entries.set('shawl.exe', executable);
    return identity;
  }

  recreateControlRootIdentity() {
    const root = this.roots.get('control');
    root.node.identity = this.identity('service-control-directory');
    root.binding.identity = clone(root.node.identity);
    root.binding.bindingFingerprint = sha256(Buffer.from(`recreated:${root.node.identity.securitySha256}`));
  }
}

function compatibility() {
  return buildDeploymentCompatibility({
    bot: { domains: [{ domain: 'bot-mapping-reader', readableFormats: ['mapping-v1'], writableFormats: ['mapping-v1'] }] },
    daemon: {
      domains: [
        { domain: 'daemon-app-session', readableFormats: ['session-v1'], writableFormats: ['session-v1'] },
        { domain: 'workspace-lifecycle', readableFormats: ['workspace-v1'], writableFormats: ['workspace-v1'] },
      ],
      sdkExternalStateContractFingerprint: hash('9'),
    },
  });
}

function applicationInventory(platform) {
  const payloadEntries = [
    'bot/src/bot.js',
    'daemon/src/daemon.js',
    'native-control/build/Release/native-control.manifest.json',
  ].map((path) => {
    const bytes = applicationPayloadBytes(path);
    return {
      path,
      size: bytes.length,
      sha256: sha256(bytes),
      executablePolicy: 'forbidden',
    };
  });
  const inventory = buildBundleInventory({
    payloadEntries,
  }, { platform });
  return Object.freeze({
    inventory,
    bytes: canonicalJsonBytes(inventory, {
      maxBytes: 32 * 1024 * 1024,
      maxDepth: 16,
      maxNodes: 600_032,
    }),
  });
}

function applicationManifest({
  sequence = 1,
  version = '1.0.0',
  archiveHash = hash('4'),
  platform = 'linux',
  architecture = 'x64',
} = {}) {
  const { inventory: files, bytes: inventoryBytes } =
    applicationInventory(platform);
  return pinnedInstallation.verifyManifest(buildApplicationDeploymentManifest({
    signingKeyId: 'deployment-test',
    releaseId: `v${version}`,
    releaseVersion: version,
    releaseSequence: sequence,
    source: { repository: 'kogangdon/gjc-remote', tag: `v${version}`, commit: '1'.repeat(40), tree: '2'.repeat(40), bunLockSha256: hash('3') },
    target: { platform, architecture },
    archive: { name: `gjc-remote-service-${version}-${platform}-${architecture}.tar.gz`, mediaType: 'application/gzip', byteLength: 100, sha256: archiveHash, entryCount: 4 },
    inventory: { path: 'bundle-files.json', byteLength: inventoryBytes.length, sha256: sha256(inventoryBytes), payloadEntryCount: files.payloadEntryCount, unpackedPayloadBytes: files.unpackedPayloadBytes, treeFingerprint: files.treeFingerprint },
    entrypoints: { bot: 'bot/src/bot.js', daemon: 'daemon/src/daemon.js' },
    runtimes: { node: { minimumVersion: '26.0.0' }, bun: { minimumVersion: '1.4.0' } },
    nativeControl: { manifestPath: 'native-control/build/Release/native-control.manifest.json', manifestFingerprint: hash('5'), contractVersion: 5, contractRevision: 1 },
    wireCapabilities: ['gate_presentation_v1'],
    compatibility: compatibility(),
  }));
}

function scratchTarHeader(path, size) {
  const value = new Header({
    path,
    mode: 0o644,
    uid: 0,
    gid: 0,
    size,
    mtime: new Date(0),
    type: 'File',
    linkpath: '',
    uname: '',
    gname: '',
    devmaj: 0,
    devmin: 0,
  });
  value.encode();
  return Buffer.from(value.block);
}

function scratchTarEntry(path, bytes) {
  const body = Buffer.from(bytes);
  const remainder = body.length % 512;
  const padding = remainder === 0 ? Buffer.alloc(0) : Buffer.alloc(512 - remainder);
  return Buffer.concat([scratchTarHeader(path, body.length), body, padding]);
}

function realArchiveApplication({
  sequence = 1,
  version = '1.0.0',
  payloadSeed = 'scratch-payload',
} = {}) {
  const files = new Map([
    ['bot/src/bot.js', Buffer.from(`${payloadSeed}:bot`)],
    ['daemon/src/daemon.js', Buffer.from(`${payloadSeed}:daemon`)],
    [
      'native-control/build/Release/native-control.manifest.json',
      Buffer.from(`${payloadSeed}:native`),
    ],
    ['lib/data', Buffer.from(`${payloadSeed}:lib`)],
  ]);
  const inventory = buildBundleInventory({
    payloadEntries: [...files].map(([path, bytes]) => ({
      path,
      size: bytes.length,
      sha256: sha256(bytes),
      executablePolicy: 'forbidden',
    })),
  }, { platform: 'linux' });
  const inventoryBytes = canonicalJsonBytes(inventory, {
    maxBytes: 32 * 1024 * 1024,
    maxDepth: 16,
    maxNodes: 600_032,
  });
  const archive = Buffer.from(gzipSync(Buffer.concat([
    scratchTarEntry('bundle-files.json', inventoryBytes),
    ...[...files].map(([path, bytes]) => scratchTarEntry(path, bytes)),
    Buffer.alloc(1024),
  ]), { level: 6 }));
  archive[9] = 255;
  const manifest = pinnedInstallation.verifyManifest(
    buildApplicationDeploymentManifest({
      signingKeyId: 'deployment-test',
      releaseId: `v${version}`,
      releaseVersion: version,
      releaseSequence: sequence,
      source: {
        repository: 'kogangdon/gjc-remote',
        tag: `v${version}`,
        commit: '1'.repeat(40),
        tree: '2'.repeat(40),
        bunLockSha256: hash('3'),
      },
      target: { platform: 'linux', architecture: 'x64' },
      archive: {
        name: `gjc-remote-service-${version}-linux-x64.tar.gz`,
        mediaType: 'application/gzip',
        byteLength: archive.length,
        sha256: sha256(archive),
        entryCount: inventory.payloadEntryCount + 1,
      },
      inventory: {
        path: 'bundle-files.json',
        byteLength: inventoryBytes.length,
        sha256: sha256(inventoryBytes),
        payloadEntryCount: inventory.payloadEntryCount,
        unpackedPayloadBytes: inventory.unpackedPayloadBytes,
        treeFingerprint: inventory.treeFingerprint,
      },
      entrypoints: { bot: 'bot/src/bot.js', daemon: 'daemon/src/daemon.js' },
      runtimes: {
        node: { minimumVersion: '26.0.0' },
        bun: { minimumVersion: '1.4.0' },
      },
      nativeControl: {
        manifestPath: 'native-control/build/Release/native-control.manifest.json',
        manifestFingerprint: hash('5'),
        contractVersion: 5,
        contractRevision: 1,
      },
      wireCapabilities: ['gate_presentation_v1'],
      compatibility: compatibility(),
    }),
  );
  return {
    archive,
    inventory,
    inventoryBytes,
    manifest,
    payloadBytes: files.get('lib/data'),
  };
}

function committedScratchResidue() {
  const fake = new FakeServiceNative();
  const store = bootstrap(fake);
  const deployment = realArchiveApplication();
  const session = store.openMutation();
  const identity = fake.seedApplicationPublication(deployment.manifest);
  const transactionId = 'tx-scratch-residue';
  const transactionNonce = '6'.repeat(32);
  const configuration = linuxBotConfiguration;
  const configurationFingerprint = serviceConfigurationFingerprint(
    configuration,
    { component: 'bot', platform: 'linux' },
  );
  const rolesFingerprint = serviceRolesFingerprint(linuxRoles, 'linux');
  const platformState = buildServicePlatformState('linux', 'final');
  const resource = buildServiceResourceProof({
    serviceKey: 'bot',
    component: 'bot',
    platform: 'linux',
    architecture: 'x64',
    operation: 'install',
    serviceGeneration: 1,
    applicationManifestFingerprint: deployment.manifest.manifestFingerprint,
    shawlManifestFingerprint: null,
    configurationFingerprint,
    rolesFingerprint,
    transactionId,
    transactionNonce,
    predecessorResourceProof: null,
    platformResourceFingerprint: hash('b'),
    platformState,
  });
  const manifestRecord = buildServiceManifest({
    serviceKey: 'bot',
    component: 'bot',
    platform: 'linux',
    architecture: 'x64',
    serviceGeneration: 1,
    applicationManifestFingerprint: deployment.manifest.manifestFingerprint,
    shawlManifestFingerprint: null,
    predecessorManifestFingerprint: null,
    configuration,
    configurationFingerprint,
    roles: linuxRoles,
    rolesFingerprint,
    resourceProof: resource.resourceProof,
    platformState,
  });
  const prepared = transactionFixture({
    transactionId,
    transactionNonce,
    candidateManifestFingerprint: deployment.manifest.manifestFingerprint,
    releaseSequence: deployment.manifest.releaseSequence,
    releaseTreeFingerprint: deployment.manifest.inventory.treeFingerprint,
    finalManifestFingerprint: manifestRecord.manifestFingerprint,
    finalResourceProof: resource.resourceProof,
  });
  session.appendJournal(prepared);
  session.retainDeploymentEnvelope({
    ...signedEnvelope('application', deployment.manifest),
    transaction: prepared,
  });
  session.reserveApplicationSequence({
    manifest: deployment.manifest,
    transaction: prepared,
    currentSequence: 0,
  });
  const reserved = nextJournal(prepared, 'sequence-reserved', 'observed');
  session.appendJournal(reserved);
  return {
    fake,
    store,
    session,
    deployment,
    identity,
    prepared,
    reserved,
    resource,
    manifestRecord,
  };
}

async function stagePartialScratchCandidate(model) {
  const access = model.session.openArtifactAccess({
    purpose: 'application',
    manifest: model.deployment.manifest,
    transaction: model.reserved,
  });
  await access.stageAsset([model.deployment.archive]);
  access.prepareCandidate(model.deployment.inventoryBytes);
  await access.writeCandidateFile('lib/data', [model.deployment.payloadBytes]);
  access.close();
}

function commitScratchResidueTransaction(model) {
  const { session, deployment, reserved, identity, resource } = model;
  const published = nextJournal(
    reserved,
    'release-published',
    'observed',
  );
  session.appendJournal(published);
  session.commitApplicationSequence({
    manifest: deployment.manifest,
    transaction: published,
    publication: session.observeApplicationPublication(
      deployment.manifest,
      identity,
    ),
  });
  session.publishResourceProof(
    'current',
    resource,
    session.readResourceProof('current'),
  );
  session.publishManifest(
    'current',
    model.manifestRecord,
    session.readManifest('current'),
  );
  const publication = session.observeApplicationPublication(
    deployment.manifest,
    identity,
  );
  const slot = buildServiceReferenceSlot({
    serviceGeneration: 1,
    transactionId: model.prepared.transactionId,
    transactionNonce: model.prepared.transactionNonce,
    artifacts: [publication.binding],
  }, { platform: 'linux', component: 'bot' });
  let references = session.readReferences();
  references = session.publishReferences(buildServiceReferenceRecord({
    serviceKey: 'bot',
    component: 'bot',
    platform: 'linux',
    architecture: 'x64',
    serviceGeneration: 0,
    current: null,
    previous: null,
    provisional: slot,
  }), references);
  session.publishReferences(buildServiceReferenceRecord({
    serviceKey: 'bot',
    component: 'bot',
    platform: 'linux',
    architecture: 'x64',
    serviceGeneration: 1,
    current: slot,
    previous: null,
    provisional: null,
  }), references);
  const committed = nextJournal(published, 'committed', 'observed');
  session.appendJournal(committed);
  return committed;
}

function scratchEntries(model) {
  return model.fake.roots.get('staging')?.node.entries ?? new Map();
}

const SHAWL_FIXTURE_BYTES = Buffer.alloc(100, 0x6);

function applicationPayloadBytes(path) {
  return Buffer.from(`service-store fixture payload: ${path}`);
}

function shawlManifest({ sequence = 1 } = {}) {
  return pinnedInstallation.verifyManifest(buildShawlDeploymentManifest({
    signingKeyId: 'deployment-test',
    releaseSequence: sequence,
    target: { platform: 'win32', architecture: 'x64' },
    upstream: {
      repository: SHAWL_UPSTREAM.repository,
      tag: SHAWL_UPSTREAM.tag,
      commit: SHAWL_UPSTREAM.commit,
      assetId: 42,
      assetName: 'shawl-v1.9.0-win64.zip',
      zipSha256: hash('5'),
    },
    executable: {
      name: 'shawl.exe',
      byteLength: 100,
      sha256: sha256(SHAWL_FIXTURE_BYTES),
      version: '1.9.0',
      versionOutput: 'shawl 1.9.0',
      authenticode: 'unsigned',
    },
    projectAsset: {
      repository: 'kogangdon/gjc-remote',
      tag: 'v1.0.0',
      name: 'gjc-remote-shawl-win32-x64.exe',
    },
  }));
}

function signedEnvelope(purpose, manifest) {
  return Object.freeze({
    purpose,
    ...pinnedInstallation.signManifest(manifest),
  });
}

function transactionFixture({
  transactionId = 'tx-1',
  transactionNonce = '1'.repeat(32),
  phase = 'prepared',
  substep = 'none',
  previousJournalFingerprint = undefined,
  operation = 'install',
  serviceGeneration = operation === 'install' ? 1 : 2,
  old = undefined,
  candidateManifestFingerprint = hash('a'),
  releaseSequence = serviceGeneration,
  releaseTreeFingerprint = hash('b'),
  compatibilityFingerprint = canonicalJsonHash(compatibility()),
  platform = 'linux',
  architecture = 'x64',
  shawlManifestFingerprint = platform === 'win32' ? hash('d') : null,
  component = 'bot',
  serviceKey = component === 'bot' ? 'bot' : deriveServiceInstanceKey('daemon sibling'),
  finalManifestFingerprint = hash('1'),
  finalResourceProof = hash('2'),
  platformResourceFingerprint = hash('f'),
} = {}) {
  const oldProof = old ?? (operation === 'install'
    ? buildServiceOldProof({ disposition: 'absent', manifestFingerprint: null, resourceProof: null, applicationManifestFingerprint: null, shawlManifestFingerprint: null, serviceGeneration: 0, activation: 'disabled-not-startable' }, platform)
    : buildServiceOldProof({ disposition: 'stable', manifestFingerprint: hash('6'), resourceProof: hash('7'), applicationManifestFingerprint: hash('8'), shawlManifestFingerprint, serviceGeneration: serviceGeneration - 1, activation: 'enabled' }, platform));
  const candidate = buildServiceCandidateProof({
    disposition: 'release',
    applicationManifestFingerprint: candidateManifestFingerprint,
    shawlManifestFingerprint,
    releaseSequence,
    releaseTreeFingerprint,
    compatibilityFingerprint,
  }, platform);
  const transition = buildServiceTransitionProof({
    oldFingerprint: oldProof.oldFingerprint,
    candidateFingerprint: candidate.candidateFingerprint,
    expectedBeforeResourceFingerprint: operation === 'install' ? null : hash('d'),
    expectedAfterResourceFingerprint: hash('e'),
    platformResourceFingerprint,
    platformState: buildServicePlatformState(platform, 'trial'),
  }, platform);
  const final = buildServiceFinalProof({
    disposition: 'stable',
    manifestFingerprint: finalManifestFingerprint,
    resourceProof: finalResourceProof,
    applicationManifestFingerprint: candidate.applicationManifestFingerprint,
    shawlManifestFingerprint,
    serviceGeneration,
    activation: 'enabled',
  }, platform);
  return buildServiceTransaction({
    transactionId,
    transactionNonce,
    operation,
    component,
    serviceKey,
    platform,
    architecture,
    serviceGeneration,
    old: oldProof,
    candidate,
    transition,
    final,
    phase,
    substep,
    previousJournalFingerprint: previousJournalFingerprint ??
      (operation === 'install' ? null : hash('0')),
  });
}

function nextJournal(previous, phase, substep) {
  return buildServiceTransaction({
    ...previous,
    phase,
    substep,
    previousJournalFingerprint: previous.transactionFingerprint,
  });
}

function uninstallTransactionFixture(installed, {
  transactionId = 'tx-uninstall',
  transactionNonce = '8'.repeat(32),
} = {}) {
  const old = buildServiceOldProof({
    disposition: 'stable',
    manifestFingerprint: installed.manifest.manifestFingerprint,
    resourceProof: installed.resource.resourceProof,
    applicationManifestFingerprint: installed.manifest.applicationManifestFingerprint,
    shawlManifestFingerprint: installed.manifest.shawlManifestFingerprint,
    serviceGeneration: installed.manifest.serviceGeneration,
    activation: 'enabled',
  }, installed.manifest.platform);
  const candidate = buildServiceCandidateProof({
    disposition: 'none',
    applicationManifestFingerprint: null,
    shawlManifestFingerprint: null,
    releaseSequence: 0,
    releaseTreeFingerprint: null,
    compatibilityFingerprint: null,
  }, installed.manifest.platform);
  const transition = buildServiceTransitionProof({
    oldFingerprint: old.oldFingerprint,
    candidateFingerprint: candidate.candidateFingerprint,
    expectedBeforeResourceFingerprint: installed.resource.platformResourceFingerprint,
    expectedAfterResourceFingerprint: null,
    platformResourceFingerprint: installed.resource.platformResourceFingerprint,
    platformState: buildServicePlatformState(installed.manifest.platform, 'trial'),
  }, installed.manifest.platform);
  const final = buildServiceFinalProof({
    disposition: 'absent',
    manifestFingerprint: null,
    resourceProof: null,
    applicationManifestFingerprint: null,
    shawlManifestFingerprint: null,
    serviceGeneration: 0,
    activation: 'disabled-not-startable',
  }, installed.manifest.platform);
  return buildServiceTransaction({
    transactionId,
    transactionNonce,
    operation: 'uninstall',
    component: installed.manifest.component,
    serviceKey: installed.manifest.serviceKey,
    platform: installed.manifest.platform,
    architecture: installed.manifest.architecture,
    serviceGeneration: installed.manifest.serviceGeneration + 1,
    old,
    candidate,
    transition,
    final,
    phase: 'prepared',
    substep: 'none',
    previousJournalFingerprint: installed.committed.transactionFingerprint,
  });
}

function emptyReferences(serviceKey = 'bot', component = 'bot', generation = 0) {
  return buildServiceReferenceRecord({
    serviceKey,
    component,
    platform: 'linux',
    architecture: 'x64',
    serviceGeneration: generation,
    current: null,
    previous: null,
    provisional: null,
  });
}

function startupProofFor(transaction, resource) {
  return buildServiceStartupProof({
    component: transaction.component,
    serviceKey: transaction.serviceKey,
    platform: transaction.platform,
    architecture: transaction.architecture,
    serviceGeneration: transaction.serviceGeneration,
    transactionId: transaction.transactionId,
    resourceProof: resource.resourceProof,
    applicationManifestFingerprint: resource.applicationManifestFingerprint,
    bootFingerprint: hash('1'),
    processEpochFingerprint: hash('2'),
    platformEvidenceFingerprint: hash('3'),
    applicationEvidenceFingerprint: hash('4'),
    platformState: buildServicePlatformState(transaction.platform, 'trial'),
    startBoundaryMs: 1_000,
    observedAtMs: 50_000,
    expiresAtMs: 61_000,
    startupEvidence: 'fresh-current-epoch',
    connectivityObservation: transaction.component === 'bot'
      ? 'last-observed-connected'
      : 'startup-only',
  });
}

function trialCursorSet({ bootFingerprint = hash('1'), configFingerprint, wrapperOffset = 4_096, childOffset = 4_096 } = {}) {
  const family = (name, offset, identity) => buildServiceFamilyCursor({
    family: name,
    baseName: `gjc-remote-bot-${name}`,
    directoryIdentityFingerprint: hash(name === 'wrapper' ? 'a' : 'b'),
    files: [buildServiceFileCursor({
      identityFingerprint: hash(identity),
      logicalStartOffset: offset,
      observedLength: 128,
      prefixSha256: hash(name === 'wrapper' ? 'c' : 'd'),
    })],
    nextLogicalOffset: offset + 128,
    partialLineBytes: 4,
    absenceFingerprint: null,
  });
  return buildServiceCursorSet({
    bootFingerprint,
    serviceKey: 'bot',
    configFingerprint,
    families: [family('wrapper', wrapperOffset, 'e'), family('child', childOffset, 'f')],
  });
}

function trialBoundaryFor(transaction, resource, fields = {}) {
  const values = {
    serviceKey: transaction.serviceKey,
    transactionId: transaction.transactionId,
    transactionNonce: transaction.transactionNonce,
    transitionFingerprint: transaction.transition.transitionFingerprint,
    attempt: 1,
    revision: 1,
    previousBoundaryFingerprint: null,
    phase: 'captured',
    bootFingerprint: hash('1'),
    startTickMs: 1_000,
    lastTickMs: 1_000,
    applicationManifestFingerprint: transaction.candidate.applicationManifestFingerprint,
    resourceFingerprint: transaction.transition.platformResourceFingerprint,
    effectiveConfigFingerprint: resource.configurationFingerprint,
    configSourceIdentityFingerprint: hash('5'),
    wrapperEpochFingerprint: null,
    childEpochFingerprint: null,
    initialCursor: trialCursorSet({ configFingerprint: resource.configurationFingerprint }),
    childCursor: null,
    ...fields,
  };
  for (const generated of ['schemaVersion', 'kind', 'deadlineTickMs', 'boundaryFingerprint']) delete values[generated];
  return buildServiceTrialBoundary(values);
}

function floorHistoryDirectoryName(scope, revision, action, transaction) {
  return `${scope.replaceAll(':', '-')}-r${String(revision).padStart(16, '0')}-${action}-${transaction.transactionFingerprint}-${transaction.serviceKey}`;
}

function serviceMetadata(configuration = linuxBotConfiguration) {
  const configurationFingerprint = serviceConfigurationFingerprint(configuration, { component: 'bot', platform: 'linux' });
  const rolesFingerprint = serviceRolesFingerprint(linuxRoles, 'linux');
  const platformState = buildServicePlatformState('linux', 'final');
  const resource = buildServiceResourceProof({
    serviceKey: 'bot',
    component: 'bot',
    platform: 'linux',
    architecture: 'x64',
    operation: 'install',
    serviceGeneration: 1,
    applicationManifestFingerprint: hash('a'),
    shawlManifestFingerprint: null,
    configurationFingerprint,
    rolesFingerprint,
    transactionId: 'tx-install',
    transactionNonce: '1'.repeat(32),
    predecessorResourceProof: null,
    platformResourceFingerprint: hash('b'),
    platformState,
  });
  const manifest = buildServiceManifest({
    serviceKey: 'bot',
    component: 'bot',
    platform: 'linux',
    architecture: 'x64',
    serviceGeneration: 1,
    applicationManifestFingerprint: hash('a'),
    shawlManifestFingerprint: null,
    predecessorManifestFingerprint: null,
    configuration,
    configurationFingerprint,
    roles: linuxRoles,
    rolesFingerprint,
    resourceProof: resource.resourceProof,
    platformState,
  });
  return { resource, manifest };
}

function publishCommittedInstallation(session, deploymentManifest, identity, {
  transactionId = 'tx-install',
  transactionNonce = '1'.repeat(32),
  component = 'bot',
  serviceKey = 'bot',
  retainedEnvelopes = [],
} = {}) {
  const configuration = component === 'bot' ? linuxBotConfiguration : {
    runtimePath: '/usr/bin/bun',
    workingDirectory: `/srv/${serviceKey}`,
    homeDirectory: `/var/lib/${serviceKey}`,
    logDirectory: `/var/log/${serviceKey}`,
  };
  const configurationFingerprint = serviceConfigurationFingerprint(
    configuration,
    { component, platform: 'linux' },
  );
  const rolesFingerprint = serviceRolesFingerprint(linuxRoles, 'linux');
  const platformState = buildServicePlatformState('linux', 'final');
  const resource = buildServiceResourceProof({
    serviceKey,
    component,
    platform: 'linux',
    architecture: 'x64',
    operation: 'install',
    serviceGeneration: 1,
    applicationManifestFingerprint: deploymentManifest.manifestFingerprint,
    shawlManifestFingerprint: null,
    configurationFingerprint,
    rolesFingerprint,
    transactionId,
    transactionNonce,
    predecessorResourceProof: null,
    platformResourceFingerprint: hash('b'),
    platformState,
  });
  const manifest = buildServiceManifest({
    serviceKey,
    component,
    platform: 'linux',
    architecture: 'x64',
    serviceGeneration: 1,
    applicationManifestFingerprint: deploymentManifest.manifestFingerprint,
    shawlManifestFingerprint: null,
    predecessorManifestFingerprint: null,
    configuration,
    configurationFingerprint,
    roles: linuxRoles,
    rolesFingerprint,
    resourceProof: resource.resourceProof,
    platformState,
  });
  const transaction = transactionFixture({
    transactionId,
    transactionNonce,
    candidateManifestFingerprint: deploymentManifest.manifestFingerprint,
    releaseSequence: deploymentManifest.releaseSequence,
    releaseTreeFingerprint: deploymentManifest.inventory.treeFingerprint,
    finalManifestFingerprint: manifest.manifestFingerprint,
    finalResourceProof: resource.resourceProof,
    component,
    serviceKey,
  });
  session.appendJournal(transaction);
  for (const envelope of retainedEnvelopes) {
    session.retainDeploymentEnvelope({ ...envelope, transaction });
  }
  session.publishResourceProof('current', resource, session.readResourceProof('current'));
  session.publishManifest('current', manifest, session.readManifest('current'));
  const publication = session.observeApplicationPublication(deploymentManifest, identity);
  const artifacts = [publication.binding];
  if (component === 'daemon') artifacts.push(session.createSharedTemplateBinding());
  const slot = buildServiceReferenceSlot({
    serviceGeneration: 1,
    transactionId,
    transactionNonce,
    artifacts,
  }, { platform: 'linux', component });
  let references = session.readReferences();
  references = session.publishReferences(buildServiceReferenceRecord({
    serviceKey,
    component,
    platform: 'linux',
    architecture: 'x64',
    serviceGeneration: 0,
    current: null,
    previous: null,
    provisional: slot,
  }), references);
  session.publishReferences(buildServiceReferenceRecord({
    serviceKey,
    component,
    platform: 'linux',
    architecture: 'x64',
    serviceGeneration: 1,
    current: slot,
    previous: null,
    provisional: null,
  }), references);
  const committed = nextJournal(transaction, 'committed', 'observed');
  session.appendJournal(committed);
  return { resource, manifest, transaction, committed, publication, slot };
}

function successorFixture(installed, deploymentManifest, {
  operation = 'update',
  transactionId = `tx-${operation}-${installed.manifest.serviceGeneration + 1}`,
  transactionNonce = operation === 'update' ? '2'.repeat(32) : '3'.repeat(32),
} = {}) {
  const serviceGeneration = installed.manifest.serviceGeneration + 1;
  const old = buildServiceOldProof({
    disposition: 'stable',
    manifestFingerprint: installed.manifest.manifestFingerprint,
    resourceProof: installed.resource.resourceProof,
    applicationManifestFingerprint: installed.manifest.applicationManifestFingerprint,
    shawlManifestFingerprint: null,
    serviceGeneration: installed.manifest.serviceGeneration,
    activation: 'enabled',
  }, 'linux');
  const candidate = buildServiceCandidateProof({
    disposition: 'release',
    applicationManifestFingerprint: deploymentManifest.manifestFingerprint,
    shawlManifestFingerprint: null,
    releaseSequence: deploymentManifest.releaseSequence,
    releaseTreeFingerprint: deploymentManifest.inventory.treeFingerprint,
    compatibilityFingerprint: canonicalJsonHash(deploymentManifest.compatibility),
  }, 'linux');
  const finalState = buildServicePlatformState('linux', 'final');
  const resource = buildServiceResourceProof({
    serviceKey: installed.manifest.serviceKey,
    component: installed.manifest.component,
    platform: 'linux',
    architecture: 'x64',
    operation,
    serviceGeneration,
    applicationManifestFingerprint: deploymentManifest.manifestFingerprint,
    shawlManifestFingerprint: null,
    configurationFingerprint: installed.manifest.configurationFingerprint,
    rolesFingerprint: installed.manifest.rolesFingerprint,
    transactionId,
    transactionNonce,
    predecessorResourceProof: installed.resource.resourceProof,
    platformResourceFingerprint: hash(operation === 'update' ? 'c' : 'd'),
    platformState: finalState,
  });
  const manifest = buildServiceManifest({
    serviceKey: installed.manifest.serviceKey,
    component: installed.manifest.component,
    platform: 'linux',
    architecture: 'x64',
    serviceGeneration,
    applicationManifestFingerprint: deploymentManifest.manifestFingerprint,
    shawlManifestFingerprint: null,
    predecessorManifestFingerprint: installed.manifest.manifestFingerprint,
    configuration: installed.manifest.configuration,
    configurationFingerprint: installed.manifest.configurationFingerprint,
    roles: installed.manifest.roles,
    rolesFingerprint: installed.manifest.rolesFingerprint,
    resourceProof: resource.resourceProof,
    platformState: finalState,
  });
  const transition = buildServiceTransitionProof({
    oldFingerprint: old.oldFingerprint,
    candidateFingerprint: candidate.candidateFingerprint,
    expectedBeforeResourceFingerprint: installed.resource.platformResourceFingerprint,
    expectedAfterResourceFingerprint: resource.platformResourceFingerprint,
    platformResourceFingerprint: hash(operation === 'update' ? 'e' : 'f'),
    platformState: buildServicePlatformState('linux', 'trial'),
  }, 'linux');
  const final = buildServiceFinalProof({
    disposition: 'stable',
    manifestFingerprint: manifest.manifestFingerprint,
    resourceProof: resource.resourceProof,
    applicationManifestFingerprint: deploymentManifest.manifestFingerprint,
    shawlManifestFingerprint: null,
    serviceGeneration,
    activation: 'enabled',
  }, 'linux');
  const transaction = buildServiceTransaction({
    transactionId,
    transactionNonce,
    operation,
    component: installed.manifest.component,
    serviceKey: installed.manifest.serviceKey,
    platform: 'linux',
    architecture: 'x64',
    serviceGeneration,
    old,
    candidate,
    transition,
    final,
    phase: 'prepared',
    substep: 'none',
    previousJournalFingerprint: installed.committed.transactionFingerprint,
  });
  return { old, candidate, resource, manifest, transaction };
}

function publishCommittedSuccessor(
  session,
  installed,
  deploymentManifest,
  identity,
  options = {},
) {
  const {
    retainedEnvelopes = [],
    ...successorOptions
  } = options;
  const successor = successorFixture(
    installed,
    deploymentManifest,
    successorOptions,
  );
  session.appendJournal(successor.transaction);
  for (const envelope of retainedEnvelopes) {
    session.retainDeploymentEnvelope({
      ...envelope,
      transaction: successor.transaction,
    });
  }
  const retainedManifest = session.readManifest('previous');
  if (retainedManifest.present) {
    session.removeManifest('previous', retainedManifest);
  }
  const retainedResource = session.readResourceProof('previous');
  if (retainedResource.present) {
    session.removeResourceProof('previous', retainedResource);
  }
  session.publishResourceProof(
    'previous',
    installed.resource,
    session.readResourceProof('previous'),
  );
  session.publishManifest(
    'previous',
    installed.manifest,
    session.readManifest('previous'),
  );
  session.removeManifest('current', session.readManifest('current'));
  session.removeResourceProof('current', session.readResourceProof('current'));
  session.publishResourceProof(
    'current',
    successor.resource,
    session.readResourceProof('current'),
  );
  session.publishManifest(
    'current',
    successor.manifest,
    session.readManifest('current'),
  );
  const publication = session.observeApplicationPublication(
    deploymentManifest,
    identity,
  );
  const slot = buildServiceReferenceSlot({
    serviceGeneration: successor.transaction.serviceGeneration,
    transactionId: successor.transaction.transactionId,
    transactionNonce: successor.transaction.transactionNonce,
    artifacts: [publication.binding],
  }, { platform: 'linux', component: installed.manifest.component });
  let references = session.readReferences();
  if (successor.transaction.operation !== 'rollback') {
    references = session.publishReferences(buildServiceReferenceRecord({
      ...references.value,
      provisional: slot,
    }), references);
  }
  session.publishReferences(buildServiceReferenceRecord({
    serviceKey: installed.manifest.serviceKey,
    component: installed.manifest.component,
    platform: 'linux',
    architecture: 'x64',
    serviceGeneration: successor.transaction.serviceGeneration,
    current: slot,
    previous: installed.slot,
    provisional: null,
  }), references);
  const committed = nextJournal(successor.transaction, 'committed', 'observed');
  session.appendJournal(committed);
  return { ...successor, committed, publication, slot };
}

function committedUpdateModel() {
  const fake = new FakeServiceNative();
  const store = bootstrap(fake);
  const originalDeployment = applicationManifest();
  const originalIdentity = fake.seedPublication(
    'releases',
    originalDeployment.archive.sha256,
  );
  let session = store.openMutation();
  const installed = publishCommittedInstallation(
    session,
    originalDeployment,
    originalIdentity,
  );
  session.close();
  const updateDeployment = applicationManifest({
    sequence: 2,
    version: '2.0.0',
    archiveHash: hash('5'),
  });
  const updateIdentity = fake.seedPublication(
    'releases',
    updateDeployment.archive.sha256,
  );
  session = store.openMutation();
  const updated = publishCommittedSuccessor(
    session,
    installed,
    updateDeployment,
    updateIdentity,
    {
      operation: 'update',
      transactionId: 'tx-committed-update',
      transactionNonce: '8'.repeat(32),
    },
  );
  session.close();
  return {
    fake,
    store,
    originalDeployment,
    originalIdentity,
    installed,
    updateDeployment,
    updateIdentity,
    updated,
  };
}

function unreferencedApplicationCollectionModel() {
  const fake = new FakeServiceNative();
  const store = bootstrap(fake);
  const retiredDeployment = applicationManifest({
    sequence: 1,
    version: '1.0.0',
    archiveHash: hash('4'),
  });
  const retiredIdentity = fake.seedApplicationPublication(
    retiredDeployment,
  );
  const session = store.openMutation();
  const installed = publishCommittedInstallation(
    session,
    retiredDeployment,
    retiredIdentity,
    {
      retainedEnvelopes: [
        signedEnvelope('application', retiredDeployment),
      ],
    },
  );
  const secondDeployment = applicationManifest({
    sequence: 2,
    version: '2.0.0',
    archiveHash: hash('5'),
  });
  const second = publishCommittedSuccessor(
    session,
    installed,
    secondDeployment,
    fake.seedApplicationPublication(secondDeployment),
    {
      transactionId: 'tx-update-2',
      transactionNonce: '2'.repeat(32),
    },
  );
  const thirdDeployment = applicationManifest({
    sequence: 3,
    version: '3.0.0',
    archiveHash: hash('6'),
  });
  const third = publishCommittedSuccessor(
    session,
    second,
    thirdDeployment,
    fake.seedApplicationPublication(thirdDeployment),
    {
      transactionId: 'tx-update-3',
      transactionNonce: '3'.repeat(32),
    },
  );
  const publication = session.observeApplicationPublication(
    retiredDeployment,
    retiredIdentity,
  );
  return {
    fake,
    store,
    session,
    retiredDeployment,
    retiredIdentity,
    publication,
    transaction: third.committed,
  };
}

function recoverCommittedSuccessor(
  store,
  installed,
  deploymentManifest,
  identity,
  options,
  { restartBetweenPreviousSteps = false } = {},
) {
  const successor = successorFixture(installed, deploymentManifest, options);
  let session = store.openMutation();
  session.appendJournal(successor.transaction);
  session.close();
  session = store.openRecovery();
  const restart = () => {
    session.close();
    session = store.openRecovery();
  };
  session.removeManifest('previous', session.readManifest('previous'));
  if (restartBetweenPreviousSteps) restart();
  session.removeResourceProof('previous', session.readResourceProof('previous'));
  if (restartBetweenPreviousSteps) restart();
  session.publishResourceProof(
    'previous',
    installed.resource,
    session.readResourceProof('previous'),
  );
  if (restartBetweenPreviousSteps) restart();
  session.publishManifest(
    'previous',
    installed.manifest,
    session.readManifest('previous'),
  );
  if (restartBetweenPreviousSteps) restart();
  session.removeManifest('current', session.readManifest('current'));
  session.removeResourceProof('current', session.readResourceProof('current'));
  session.publishResourceProof(
    'current',
    successor.resource,
    session.readResourceProof('current'),
  );
  session.publishManifest(
    'current',
    successor.manifest,
    session.readManifest('current'),
  );
  const publication = session.observeApplicationPublication(
    deploymentManifest,
    identity,
  );
  const slot = buildServiceReferenceSlot({
    serviceGeneration: successor.transaction.serviceGeneration,
    transactionId: successor.transaction.transactionId,
    transactionNonce: successor.transaction.transactionNonce,
    artifacts: [publication.binding],
  }, { platform: 'linux', component: installed.manifest.component });
  let references = session.readReferences();
  if (successor.transaction.operation !== 'rollback') {
    references = session.publishReferences(buildServiceReferenceRecord({
      ...references.value,
      provisional: slot,
    }), references);
  }
  session.publishReferences(buildServiceReferenceRecord({
    serviceKey: installed.manifest.serviceKey,
    component: installed.manifest.component,
    platform: 'linux',
    architecture: 'x64',
    serviceGeneration: successor.transaction.serviceGeneration,
    current: slot,
    previous: installed.slot,
    provisional: null,
  }), references);
  const committed = nextJournal(successor.transaction, 'committed', 'observed');
  session.appendJournal(committed);
  session.close();
  return { ...successor, committed, publication, slot };
}

function publishCommittedWindowsInstallation(
  session,
  deploymentManifest,
  applicationIdentity,
  shawl,
  shawlIdentity,
  {
    transactionId,
    transactionNonce,
    component = 'bot',
    serviceKey = 'bot',
    retainedEnvelopes = [],
  },
) {
  const configuration = component === 'bot' ? {
    runtimePath: 'C:\\Program Files\\nodejs\\node.exe',
    workingDirectory: 'C:\\ProgramData\\gjc-remote\\bot',
    homeDirectory: 'C:\\ProgramData\\gjc-remote\\bot-home',
    logDirectory: 'C:\\ProgramData\\gjc-remote\\logs\\bot',
    channelsConfig: 'C:\\ProgramData\\gjc-remote\\channels.json',
    expectedHostSetFingerprint: hash('8'),
    expectedHostCount: 2,
  } : {
    runtimePath: 'C:\\Program Files\\nodejs\\node.exe',
    workingDirectory: `C:\\ProgramData\\gjc-remote\\${serviceKey}`,
    homeDirectory: `C:\\ProgramData\\gjc-remote\\home\\${serviceKey}`,
    logDirectory: `C:\\ProgramData\\gjc-remote\\logs\\${serviceKey}`,
  };
  const configurationFingerprint = serviceConfigurationFingerprint(
    configuration,
    { component, platform: 'win32' },
  );
  const rolesFingerprint = serviceRolesFingerprint(windowsRoles, 'win32');
  const platformState = buildServicePlatformState('win32', 'final');
  const resource = buildServiceResourceProof({
    serviceKey,
    component,
    platform: 'win32',
    architecture: 'x64',
    operation: 'install',
    serviceGeneration: 1,
    applicationManifestFingerprint: deploymentManifest.manifestFingerprint,
    shawlManifestFingerprint: shawl.manifestFingerprint,
    configurationFingerprint,
    rolesFingerprint,
    transactionId,
    transactionNonce,
    predecessorResourceProof: null,
    platformResourceFingerprint: hash('b'),
    platformState,
  });
  const manifest = buildServiceManifest({
    serviceKey,
    component,
    platform: 'win32',
    architecture: 'x64',
    serviceGeneration: 1,
    applicationManifestFingerprint: deploymentManifest.manifestFingerprint,
    shawlManifestFingerprint: shawl.manifestFingerprint,
    predecessorManifestFingerprint: null,
    configuration,
    configurationFingerprint,
    roles: windowsRoles,
    rolesFingerprint,
    resourceProof: resource.resourceProof,
    platformState,
  });
  const transaction = transactionFixture({
    transactionId,
    transactionNonce,
    component,
    serviceKey,
    platform: 'win32',
    candidateManifestFingerprint: deploymentManifest.manifestFingerprint,
    shawlManifestFingerprint: shawl.manifestFingerprint,
    releaseSequence: deploymentManifest.releaseSequence,
    releaseTreeFingerprint: deploymentManifest.inventory.treeFingerprint,
    finalManifestFingerprint: manifest.manifestFingerprint,
    finalResourceProof: resource.resourceProof,
    platformResourceFingerprint: resource.platformResourceFingerprint,
  });
  session.appendJournal(transaction);
  for (const envelope of retainedEnvelopes) {
    session.retainDeploymentEnvelope({ ...envelope, transaction });
  }
  session.publishResourceProof('current', resource, session.readResourceProof('current'));
  session.publishManifest('current', manifest, session.readManifest('current'));
  const application = session.observeApplicationPublication(
    deploymentManifest,
    applicationIdentity,
  ).binding;
  const supervisor = session.observeShawlPublication(shawl, shawlIdentity).binding;
  const slot = buildServiceReferenceSlot({
    serviceGeneration: 1,
    transactionId,
    transactionNonce,
    artifacts: [application, supervisor],
  }, { platform: 'win32', component });
  let references = session.readReferences();
  references = session.publishReferences(buildServiceReferenceRecord({
    serviceKey,
    component,
    platform: 'win32',
    architecture: 'x64',
    serviceGeneration: 0,
    current: null,
    previous: null,
    provisional: slot,
  }), references);
  session.publishReferences(buildServiceReferenceRecord({
    serviceKey,
    component,
    platform: 'win32',
    architecture: 'x64',
    serviceGeneration: 1,
    current: slot,
    previous: null,
    provisional: null,
  }), references);
  const committed = nextJournal(transaction, 'committed', 'observed');
  session.appendJournal(committed);
  return { resource, manifest, transaction, committed, application, supervisor, slot };
}

function storeFor(fake, target = { component: 'bot' }) {
  const platform = fake.platform;
  return createServiceStore({
    native: fake.facade,
    roles: platform === 'win32' ? windowsRoles : linuxRoles,
    target,
    platform,
    architecture: 'x64',
  });
}

function bootstrap(fake, target = { component: 'bot' }) {
  const store = storeFor(fake, target);
  const session = store.bootstrap();
  session.close();
  return store;
}

function expectCode(fn, code) {
  assert.throws(fn, (error) => {
    assert.equal(error.code, code);
    assert.ok(Number.isSafeInteger(error.writes));
    return true;
  });
}

function expectPinnedStoreFailure(invoke, writes) {
  assert.throws(invoke, (error) => {
    assert.equal(error.name, 'ServiceStoreError');
    assert.equal(error.code, 'DEPLOYMENT_PINNED_PROVENANCE_REQUIRED');
    assert.equal(error.operation, 'verify_deployment_provenance');
    assert.equal(error.writes, writes);
    assert.equal(error.ambiguous, false);
    assert.equal(error.message, 'verify_deployment_provenance failed');
    assert.equal(error.cause, undefined);
    assert.doesNotMatch(
      error.message,
      /deployment-test|manifest|signature|[\\/]/i,
    );
    return true;
  });
}

test('model: fixture-pinned manifests are branded only by the copied module instance', () => {
  const manifest = applicationManifest();
  assert.equal(
    pinnedInstallation.provenance.assertPinnedDeploymentManifest(manifest, 'application'),
    manifest,
  );
  assert.throws(
    () => assertProductionPinnedDeploymentManifest(manifest, 'application'),
    (error) => {
      assert.equal(error.code, 'DEPLOYMENT_PINNED_PROVENANCE_REQUIRED');
      assert.equal(error.operation, 'verify_deployment_provenance');
      assert.equal(error.writes, 0);
      return true;
    },
  );
  assert.throws(
    () => pinnedInstallation.provenance.assertPinnedDeploymentManifest(clone(manifest), 'application'),
    (error) => {
      assert.equal(error.code, 'DEPLOYMENT_PINNED_PROVENANCE_REQUIRED');
      assert.equal(error.operation, 'verify_deployment_provenance');
      assert.equal(error.writes, 0);
      return true;
    },
  );
  assert.throws(
    () => pinnedInstallation.provenance.assertPinnedDeploymentManifest(manifest, 'shawl'),
    (error) => {
      assert.equal(error.code, 'DEPLOYMENT_PINNED_PROVENANCE_REQUIRED');
      assert.equal(error.operation, 'verify_deployment_provenance');
      assert.equal(error.writes, 0);
      return true;
    },
  );
});

test('model: every deployment-manifest authority boundary preserves cumulative writes on an unbranded clone', () => {
  const application = applicationManifest();
  const applicationClone = clone(application);
  const transaction = transactionFixture({
    candidateManifestFingerprint: application.manifestFingerprint,
    releaseSequence: application.releaseSequence,
    releaseTreeFingerprint: application.inventory.treeFingerprint,
  });
  const linuxFake = new FakeServiceNative();
  const linux = storeFor(linuxFake).bootstrap();
  linux.appendJournal(transaction);
  linux.retainDeploymentEnvelope({
    ...signedEnvelope('application', application),
    transaction,
  });
  const linuxWrites = linux.writes;
  assert.ok(linuxWrites > 0);
  for (const invoke of [
    () => linux.openArtifactAccess({
      purpose: 'application',
      manifest: applicationClone,
      transaction,
    }),
    () => linux.reserveApplicationSequence({
      manifest: applicationClone,
      transaction,
      currentSequence: 0,
    }),
    () => linux.commitApplicationSequence({
      manifest: applicationClone,
      transaction,
      publication: {},
    }),
    () => linux.observeApplicationPublication(applicationClone, {}),
    () => linux.assertApplicationRollback({
      manifest: applicationClone,
      publication: {},
    }),
  ]) {
    expectPinnedStoreFailure(invoke, linuxWrites);
    assert.equal(linux.writes, linuxWrites);
  }
  linux.close();

  const windowsApplication = applicationManifest({ platform: 'win32' });
  const windowsApplicationClone = clone(windowsApplication);
  const shawl = shawlManifest();
  const shawlClone = clone(shawl);
  const windowsTransaction = transactionFixture({
    candidateManifestFingerprint: windowsApplication.manifestFingerprint,
    releaseSequence: windowsApplication.releaseSequence,
    releaseTreeFingerprint: windowsApplication.inventory.treeFingerprint,
    platform: 'win32',
    shawlManifestFingerprint: shawl.manifestFingerprint,
  });
  const windowsFake = new FakeServiceNative('win32');
  const windows = storeFor(windowsFake).bootstrap();
  windows.appendJournal(windowsTransaction);
  windows.retainDeploymentEnvelope({
    ...signedEnvelope('application', windowsApplication),
    transaction: windowsTransaction,
  });
  windows.retainDeploymentEnvelope({
    ...signedEnvelope('shawl', shawl),
    transaction: windowsTransaction,
  });
  const windowsWrites = windows.writes;
  assert.ok(windowsWrites > 0);
  for (const invoke of [
    () => windows.openArtifactAccess({
      purpose: 'application',
      manifest: windowsApplicationClone,
      transaction: windowsTransaction,
    }),
    () => windows.openArtifactAccess({
      purpose: 'shawl',
      manifest: shawlClone,
      transaction: windowsTransaction,
    }),
    () => windows.reserveApplicationSequence({
      manifest: windowsApplicationClone,
      transaction: windowsTransaction,
      currentSequence: 0,
    }),
    () => windows.commitApplicationSequence({
      manifest: windowsApplicationClone,
      transaction: windowsTransaction,
      publication: {},
    }),
    () => windows.observeApplicationPublication(windowsApplicationClone, {}),
    () => windows.assertApplicationRollback({
      manifest: windowsApplicationClone,
      publication: {},
    }),
    () => windows.reserveShawlSequence({
      manifest: shawlClone,
      transaction: windowsTransaction,
      currentSequence: 0,
    }),
    () => windows.commitShawlSequence({
      manifest: shawlClone,
      transaction: windowsTransaction,
      publication: {},
    }),
    () => windows.observeShawlPublication(shawlClone, {}),
    () => windows.assertShawlRollback({
      manifest: shawlClone,
      publication: {},
    }),
  ]) {
    expectPinnedStoreFailure(invoke, windowsWrites);
    assert.equal(windows.writes, windowsWrites);
  }
  windows.close();
});

test('model: retained signed envelope pairs round-trip through a fresh pinned verification', () => {
  const fake = new FakeServiceNative();
  const store = bootstrap(fake);
  const manifest = applicationManifest();
  const envelope = signedEnvelope('application', manifest);
  const transaction = transactionFixture({
    transactionId: 'tx-retained-application',
    transactionNonce: '1'.repeat(32),
    candidateManifestFingerprint: manifest.manifestFingerprint,
    releaseSequence: manifest.releaseSequence,
    releaseTreeFingerprint: manifest.inventory.treeFingerprint,
  });
  const mutation = store.openMutation();
  mutation.appendJournal(transaction);
  const beforeRetain = mutation.writes;
  const retained = mutation.retainDeploymentEnvelope({
    ...envelope,
    transaction,
  });
  assert.equal(retained.manifestFingerprint, manifest.manifestFingerprint);
  assert.equal(
    pinnedInstallation.provenance.assertPinnedDeploymentManifest(
      retained.manifest,
      'application',
    ),
    retained.manifest,
  );
  assert.ok(mutation.writes > beforeRetain);
  const afterRetain = mutation.writes;
  mutation.retainDeploymentEnvelope({ ...envelope, transaction });
  assert.equal(mutation.writes, afterRetain);
  const name = `deployment-application-${manifest.manifestFingerprint}.json`;
  const recordBytes = fake.recordBytes('manifest', 'bot', name);
  const record = JSON.parse(recordBytes.toString('utf8'));
  assert.equal(recordBytes.equals(canonicalJsonBytes(record)), true);
  assert.equal(
    Buffer.from(record.manifestBase64, 'base64').equals(envelope.manifestBytes),
    true,
  );
  assert.equal(
    Buffer.from(record.signatureBase64, 'base64').equals(envelope.signatureBytes),
    true,
  );
  mutation.close();

  const readOnly = store.openReadOnly();
  assert.equal(readOnly.writes, 0);
  expectCode(
    () => readOnly.retainDeploymentEnvelope({ ...envelope, transaction }),
    'SERVICE_ACCESS_DENIED',
  );
  assert.equal(readOnly.writes, 0);
  const first = readOnly.readRetainedDeploymentEnvelope({
    purpose: 'application',
    manifestFingerprint: manifest.manifestFingerprint,
  });
  const second = readOnly.readRetainedDeploymentEnvelope({
    purpose: 'application',
    manifestFingerprint: manifest.manifestFingerprint,
  });
  assert.notEqual(first.manifest, retained.manifest);
  assert.notEqual(second.manifest, first.manifest);
  assert.deepEqual(first.manifest, manifest);
  assert.equal(Object.hasOwn(first, 'verified'), false);
  assert.equal(Object.hasOwn(first, 'recordSha256'), false);
  assert.equal(Object.hasOwn(first, 'value'), false);
  assert.equal(Object.isFrozen(first), true);
  assert.equal(Object.isFrozen(first.manifest), true);
  assert.equal(
    pinnedInstallation.provenance.assertPinnedDeploymentManifest(
      first.manifest,
      'application',
    ),
    first.manifest,
  );
  assert.equal(readOnly.writes, 0);
  readOnly.close();
  const recovery = store.openRecovery();
  const beforeRecoveryReplay = recovery.writes;
  recovery.retainDeploymentEnvelope({ ...envelope, transaction });
  assert.equal(recovery.writes, beforeRecoveryReplay);
  recovery.close();

  const windowsFake = new FakeServiceNative('win32');
  const windowsStore = bootstrap(windowsFake);
  const windowsApplication = applicationManifest({ platform: 'win32' });
  const shawl = shawlManifest();
  const shawlEnvelope = signedEnvelope('shawl', shawl);
  const windowsTransaction = transactionFixture({
    transactionId: 'tx-retained-shawl',
    transactionNonce: '2'.repeat(32),
    candidateManifestFingerprint: windowsApplication.manifestFingerprint,
    releaseSequence: windowsApplication.releaseSequence,
    releaseTreeFingerprint: windowsApplication.inventory.treeFingerprint,
    platform: 'win32',
    shawlManifestFingerprint: shawl.manifestFingerprint,
  });
  const windowsMutation = windowsStore.openMutation();
  windowsMutation.appendJournal(windowsTransaction);
  windowsMutation.retainDeploymentEnvelope({
    ...signedEnvelope('application', windowsApplication),
    transaction: windowsTransaction,
  });
  windowsMutation.retainDeploymentEnvelope({
    ...shawlEnvelope,
    transaction: windowsTransaction,
  });
  windowsMutation.close();
  const windowsReadOnly = windowsStore.openReadOnly();
  const rereadShawl = windowsReadOnly.readRetainedDeploymentEnvelope({
    purpose: 'shawl',
    manifestFingerprint: shawl.manifestFingerprint,
  });
  assert.deepEqual(rereadShawl.manifest, shawl);
  const rereadApplication = windowsReadOnly.readRetainedDeploymentEnvelope({
    purpose: 'application',
    manifestFingerprint: windowsApplication.manifestFingerprint,
  });
  assert.deepEqual(rereadApplication.manifest, windowsApplication);
  assert.equal(Object.hasOwn(rereadShawl, 'verified'), false);
  assert.equal(Object.hasOwn(rereadShawl, 'recordSha256'), false);
  assert.equal(
    pinnedInstallation.provenance.assertPinnedDeploymentManifest(
      rereadShawl.manifest,
      'shawl',
    ),
    rereadShawl.manifest,
  );
  assert.equal(windowsReadOnly.writes, 0);
  windowsReadOnly.close();
});

test('model: retained envelope writes require the active exact transaction and candidate', () => {
  const fake = new FakeServiceNative();
  const store = bootstrap(fake);
  const manifest = applicationManifest();
  const envelope = signedEnvelope('application', manifest);
  const transaction = transactionFixture({
    transactionId: 'tx-envelope-authority',
    transactionNonce: '3'.repeat(32),
    candidateManifestFingerprint: manifest.manifestFingerprint,
    releaseSequence: manifest.releaseSequence,
    releaseTreeFingerprint: manifest.inventory.treeFingerprint,
  });
  const session = store.openMutation();
  session.appendJournal(transaction);
  const initialWrites = session.writes;
  const otherManifest = applicationManifest({
    sequence: 2,
    version: '2.0.0',
    archiveHash: hash('5'),
  });
  expectCode(
    () => session.retainDeploymentEnvelope({
      ...signedEnvelope('application', otherManifest),
      transaction,
    }),
    'SERVICE_SCOPE_MISMATCH',
  );
  assert.equal(session.writes, initialWrites);
  const foreignTransaction = transactionFixture({
    transactionId: 'tx-envelope-foreign',
    transactionNonce: '4'.repeat(32),
    candidateManifestFingerprint: manifest.manifestFingerprint,
    releaseSequence: manifest.releaseSequence,
    releaseTreeFingerprint: manifest.inventory.treeFingerprint,
  });
  expectCode(
    () => session.retainDeploymentEnvelope({
      ...envelope,
      transaction: foreignTransaction,
    }),
    'SERVICE_PENDING',
  );
  assert.equal(session.writes, initialWrites);
  expectCode(
    () => session.retainDeploymentEnvelope({
      purpose: 'shawl',
      manifestBytes: envelope.manifestBytes,
      signatureBytes: envelope.signatureBytes,
      transaction,
    }),
    'DEPLOYMENT_TARGET_INVALID',
  );
  assert.equal(session.writes, initialWrites);
  const windowsManifest = applicationManifest({ platform: 'win32' });
  expectCode(
    () => session.retainDeploymentEnvelope({
      ...signedEnvelope('application', windowsManifest),
      transaction,
    }),
    'DEPLOYMENT_TARGET_INVALID',
  );
  assert.equal(session.writes, initialWrites);
  const changedManifest = clone(manifest);
  changedManifest.releaseId = 'v9.9.9';
  assert.throws(
    () => session.retainDeploymentEnvelope({
      purpose: 'application',
      manifestBytes: canonicalJsonBytes(changedManifest),
      signatureBytes: envelope.signatureBytes,
      transaction,
    }),
    (error) => {
      assert.equal(error.code, 'DEPLOYMENT_MANIFEST_INVALID');
      assert.equal(error.operation, 'retain_deployment_envelope');
      assert.equal(error.writes, initialWrites);
      assert.equal(error.message, 'retain_deployment_envelope failed');
      assert.equal(error.cause, undefined);
      assert.doesNotMatch(error.message, /deployment-test|manifestBytes|signatureBytes/);
      return true;
    },
  );
  assert.equal(session.writes, initialWrites);
  expectCode(
    () => session.retainDeploymentEnvelope({
      purpose: 'application',
      manifestBytes: envelope.manifestBytes,
      signatureBytes: Buffer.concat([
        envelope.signatureBytes,
        Buffer.from('\n'),
      ]),
      transaction,
    }),
    'DEPLOYMENT_MANIFEST_INVALID',
  );
  assert.equal(session.writes, initialWrites);
  expectCode(
    () => session.retainDeploymentEnvelope({
      purpose: 'application',
      manifestBytes: 'not-bytes',
      signatureBytes: envelope.signatureBytes,
      transaction,
    }),
    'SERVICE_INVALID',
  );
  assert.equal(session.writes, initialWrites);
  for (const input of [
    {
      purpose: 'application',
      manifestBytes: Buffer.alloc(1024 * 1024 + 1),
      signatureBytes: envelope.signatureBytes,
      transaction,
    },
    {
      purpose: 'application',
      manifestBytes: envelope.manifestBytes,
      signatureBytes: Buffer.alloc(16 * 1024 + 1),
      transaction,
    },
    {
      ...envelope,
      transaction,
      extra: true,
    },
  ]) {
    expectCode(
      () => session.retainDeploymentEnvelope(input),
      'SERVICE_INVALID',
    );
    assert.equal(session.writes, initialWrites);
  }
  expectCode(
    () => session.readRetainedDeploymentEnvelope({
      purpose: 'application',
      manifestFingerprint: hash('e'),
    }),
    'SERVICE_PENDING',
  );
  assert.equal(session.writes, initialWrites);
  session.close();

  const daemonStore = storeFor(
    fake,
    { component: 'daemon', hostId: 'retained envelope daemon' },
  );
  const daemon = daemonStore.openMutation();
  const daemonWrites = daemon.writes;
  expectCode(
    () => daemon.retainDeploymentEnvelope({ ...envelope, transaction }),
    'SERVICE_SCOPE_MISMATCH',
  );
  assert.equal(daemon.writes, daemonWrites);
  daemon.close();
});

test('model: retained envelope reads follow live reference or pending-floor authority only', () => {
  const fake = new FakeServiceNative();
  const store = bootstrap(fake);
  const firstManifest = applicationManifest();
  const firstEnvelope = signedEnvelope('application', firstManifest);
  const firstIdentity = fake.seedPublication(
    'releases',
    firstManifest.archive.sha256,
  );
  let session = store.openMutation();
  const installed = publishCommittedInstallation(
    session,
    firstManifest,
    firstIdentity,
    { retainedEnvelopes: [firstEnvelope] },
  );
  session.close();

  let readOnly = store.openReadOnly();
  assert.deepEqual(
    readOnly.readRetainedDeploymentEnvelope({
      purpose: 'application',
      manifestFingerprint: firstManifest.manifestFingerprint,
    }).manifest,
    firstManifest,
  );
  assert.equal(readOnly.writes, 0);
  readOnly.close();
  session = store.openMutation();
  const historicalWrites = session.writes;
  expectCode(
    () => session.retainDeploymentEnvelope({
      ...firstEnvelope,
      transaction: installed.transaction,
    }),
    'SERVICE_PENDING',
  );
  assert.equal(session.writes, historicalWrites);
  session.close();

  const secondManifest = applicationManifest({
    sequence: 2,
    version: '2.0.0',
    archiveHash: hash('5'),
  });
  const secondEnvelope = signedEnvelope('application', secondManifest);
  const secondIdentity = fake.seedPublication(
    'releases',
    secondManifest.archive.sha256,
  );
  session = store.openMutation();
  const updated = publishCommittedSuccessor(
    session,
    installed,
    secondManifest,
    secondIdentity,
    {
      transactionId: 'tx-retained-second-generation',
      transactionNonce: '5'.repeat(32),
      retainedEnvelopes: [secondEnvelope],
    },
  );
  session.close();
  readOnly = store.openReadOnly();
  assert.deepEqual(
    readOnly.readRetainedDeploymentEnvelope({
      purpose: 'application',
      manifestFingerprint: secondManifest.manifestFingerprint,
    }).manifest,
    secondManifest,
  );
  assert.deepEqual(
    readOnly.readRetainedDeploymentEnvelope({
      purpose: 'application',
      manifestFingerprint: firstManifest.manifestFingerprint,
    }).manifest,
    firstManifest,
  );
  readOnly.close();

  const thirdManifest = applicationManifest({
    sequence: 3,
    version: '3.0.0',
    archiveHash: hash('6'),
  });
  const thirdIdentity = fake.seedPublication(
    'releases',
    thirdManifest.archive.sha256,
  );
  session = store.openMutation();
  publishCommittedSuccessor(
    session,
    updated,
    thirdManifest,
    thirdIdentity,
    {
      transactionId: 'tx-retained-third-generation',
      transactionNonce: '6'.repeat(32),
    },
  );
  session.close();
  assert.ok(fake.recordBytes(
    'manifest',
    'bot',
    `deployment-application-${firstManifest.manifestFingerprint}.json`,
  ).length > 0);
  readOnly = store.openReadOnly();
  expectCode(
    () => readOnly.readRetainedDeploymentEnvelope({
      purpose: 'application',
      manifestFingerprint: firstManifest.manifestFingerprint,
    }),
    'SERVICE_PENDING',
  );
  assert.equal(readOnly.writes, 0);
  readOnly.close();

  const floorFake = new FakeServiceNative();
  const floorStore = bootstrap(floorFake);
  const floorManifest = applicationManifest({
    sequence: 4,
    version: '4.0.0',
    archiveHash: hash('7'),
  });
  const floorEnvelope = signedEnvelope('application', floorManifest);
  const floorTransaction = transactionFixture({
    transactionId: 'tx-retained-floor',
    transactionNonce: '7'.repeat(32),
    candidateManifestFingerprint: floorManifest.manifestFingerprint,
    releaseSequence: floorManifest.releaseSequence,
    releaseTreeFingerprint: floorManifest.inventory.treeFingerprint,
  });
  session = floorStore.openMutation();
  session.appendJournal(floorTransaction);
  session.retainDeploymentEnvelope({ ...floorEnvelope, transaction: floorTransaction });
  session.reserveApplicationSequence({
    manifest: floorManifest,
    transaction: floorTransaction,
    currentSequence: 0,
  });
  session.close();
  floorFake.deleteRecord('transaction', 'bot', 'head.json');
  floorFake.deleteRecord('transaction', 'bot', 'entry-0000000000000001.json');
  readOnly = floorStore.openReadOnly();
  assert.deepEqual(
    readOnly.readRetainedDeploymentEnvelope({
      purpose: 'application',
      manifestFingerprint: floorManifest.manifestFingerprint,
    }).manifest,
    floorManifest,
  );
  assert.equal(readOnly.writes, 0);
  readOnly.close();

  const provisionalFake = new FakeServiceNative();
  const provisionalStore = bootstrap(provisionalFake);
  const provisionalCurrentManifest = applicationManifest();
  const provisionalCurrentIdentity = provisionalFake.seedPublication(
    'releases',
    provisionalCurrentManifest.archive.sha256,
  );
  session = provisionalStore.openMutation();
  const provisionalInstalled = publishCommittedInstallation(
    session,
    provisionalCurrentManifest,
    provisionalCurrentIdentity,
  );
  session.close();
  const provisionalManifest = applicationManifest({
    sequence: 2,
    version: '2.0.0',
    archiveHash: hash('8'),
  });
  const provisionalEnvelope = signedEnvelope(
    'application',
    provisionalManifest,
  );
  const provisionalIdentity = provisionalFake.seedPublication(
    'releases',
    provisionalManifest.archive.sha256,
  );
  const provisionalTransaction = successorFixture(
    provisionalInstalled,
    provisionalManifest,
    {
      transactionId: 'tx-retained-provisional',
      transactionNonce: 'a'.repeat(32),
    },
  ).transaction;
  session = provisionalStore.openMutation();
  session.appendJournal(provisionalTransaction);
  session.retainDeploymentEnvelope({
    ...provisionalEnvelope,
    transaction: provisionalTransaction,
  });
  const provisionalPublication = session.observeApplicationPublication(
    provisionalManifest,
    provisionalIdentity,
  );
  const provisionalSlot = buildServiceReferenceSlot({
    serviceGeneration: provisionalTransaction.serviceGeneration,
    transactionId: provisionalTransaction.transactionId,
    transactionNonce: provisionalTransaction.transactionNonce,
    artifacts: [provisionalPublication.binding],
  }, { platform: 'linux', component: 'bot' });
  const provisionalReferences = session.readReferences();
  session.publishReferences(buildServiceReferenceRecord({
    ...provisionalReferences.value,
    provisional: provisionalSlot,
  }), provisionalReferences);
  session.close();
  readOnly = provisionalStore.openReadOnly();
  assert.equal(
    readOnly.readReferences().value.provisional.slotFingerprint,
    provisionalSlot.slotFingerprint,
  );
  assert.deepEqual(
    readOnly.readRetainedDeploymentEnvelope({
      purpose: 'application',
      manifestFingerprint: provisionalManifest.manifestFingerprint,
    }).manifest,
    provisionalManifest,
  );
  assert.equal(readOnly.writes, 0);
  readOnly.close();
});

test('model: retained envelope loss, corruption, namespace drift, and CAS races fail closed', () => {
  const lostFake = new FakeServiceNative();
  const lostStore = bootstrap(lostFake);
  const lostManifest = applicationManifest();
  const lostIdentity = lostFake.seedPublication(
    'releases',
    lostManifest.archive.sha256,
  );
  const lostEnvelope = signedEnvelope('application', lostManifest);
  let session = lostStore.openMutation();
  publishCommittedInstallation(
    session,
    lostManifest,
    lostIdentity,
    { retainedEnvelopes: [lostEnvelope] },
  );
  session.close();
  lostFake.deleteRecord(
    'manifest',
    'bot',
    `deployment-application-${lostManifest.manifestFingerprint}.json`,
  );
  let readOnly = lostStore.openReadOnly();
  expectCode(
    () => readOnly.readRetainedDeploymentEnvelope({
      purpose: 'application',
      manifestFingerprint: lostManifest.manifestFingerprint,
    }),
    'SERVICE_MANUAL_CLEANUP',
  );
  assert.equal(readOnly.writes, 0);
  readOnly.close();

  const corruptFake = new FakeServiceNative();
  const corruptStore = bootstrap(corruptFake);
  const corruptManifest = applicationManifest();
  const corruptEnvelope = signedEnvelope('application', corruptManifest);
  const corruptIdentity = corruptFake.seedPublication(
    'releases',
    corruptManifest.archive.sha256,
  );
  session = corruptStore.openMutation();
  publishCommittedInstallation(
    session,
    corruptManifest,
    corruptIdentity,
    { retainedEnvelopes: [corruptEnvelope] },
  );
  session.close();
  const corruptName =
    `deployment-application-${corruptManifest.manifestFingerprint}.json`;
  const corruptRecord = JSON.parse(
    corruptFake.recordBytes('manifest', 'bot', corruptName).toString('utf8'),
  );
  const corruptSignature = JSON.parse(
    Buffer.from(corruptRecord.signatureBase64, 'base64').toString('utf8'),
  );
  corruptSignature.signature =
    `${corruptSignature.signature[0] === 'A' ? 'B' : 'A'}${corruptSignature.signature.slice(1)}`;
  corruptRecord.signatureBase64 =
    canonicalJsonBytes(corruptSignature).toString('base64');
  corruptFake.putRaw(
    'manifest',
    'bot',
    corruptName,
    canonicalJsonBytes(corruptRecord),
  );
  readOnly = corruptStore.openReadOnly();
  expectCode(
    () => readOnly.readRetainedDeploymentEnvelope({
      purpose: 'application',
      manifestFingerprint: corruptManifest.manifestFingerprint,
    }),
    'SERVICE_MANUAL_CLEANUP',
  );
  assert.equal(readOnly.writes, 0);
  readOnly.close();

  const namespaceFake = new FakeServiceNative();
  const namespaceStore = bootstrap(namespaceFake);
  const namespaceManifest = applicationManifest();
  const namespaceEnvelope = signedEnvelope('application', namespaceManifest);
  const namespaceTransaction = transactionFixture({
    transactionId: 'tx-retained-namespace',
    transactionNonce: '8'.repeat(32),
    candidateManifestFingerprint: namespaceManifest.manifestFingerprint,
    releaseSequence: namespaceManifest.releaseSequence,
    releaseTreeFingerprint: namespaceManifest.inventory.treeFingerprint,
  });
  session = namespaceStore.openMutation();
  session.appendJournal(namespaceTransaction);
  session.retainDeploymentEnvelope({
    ...namespaceEnvelope,
    transaction: namespaceTransaction,
  });
  session.close();
  const namespaceName =
    `deployment-application-${namespaceManifest.manifestFingerprint}.json`;
  namespaceFake.putRaw(
    'manifest',
    'bot',
    `deployment-application-${hash('e')}.json`,
    namespaceFake.recordBytes('manifest', 'bot', namespaceName),
  );
  expectCode(
    () => namespaceStore.openReadOnly(),
    'SERVICE_MANUAL_CLEANUP',
  );

  const collisionFake = new FakeServiceNative('win32');
  const collisionStore = bootstrap(collisionFake);
  const collisionApplication = applicationManifest({ platform: 'win32' });
  const collisionShawl = shawlManifest();
  const applicationEnvelope = signedEnvelope(
    'application',
    collisionApplication,
  );
  const shawlEnvelope = signedEnvelope('shawl', collisionShawl);
  const collisionTransaction = transactionFixture({
    transactionId: 'tx-retained-collision',
    transactionNonce: '9'.repeat(32),
    candidateManifestFingerprint: collisionApplication.manifestFingerprint,
    releaseSequence: collisionApplication.releaseSequence,
    releaseTreeFingerprint: collisionApplication.inventory.treeFingerprint,
    platform: 'win32',
    shawlManifestFingerprint: collisionShawl.manifestFingerprint,
  });
  session = collisionStore.openMutation();
  session.appendJournal(collisionTransaction);
  session.retainDeploymentEnvelope({
    ...applicationEnvelope,
    transaction: collisionTransaction,
  });
  const beforeCollision = session.writes;
  const shawlName =
    `deployment-shawl-${collisionShawl.manifestFingerprint}.json`;
  collisionFake.collidePublish(shawlName);
  assert.throws(
    () => session.retainDeploymentEnvelope({
      ...shawlEnvelope,
      transaction: collisionTransaction,
    }),
    (error) => {
      assert.equal(error.code, 'SERVICE_ALREADY_EXISTS');
      assert.equal(error.operation, 'retain_deployment_envelope');
      assert.equal(error.writes, beforeCollision);
      assert.equal(error.message, 'retain_deployment_envelope failed');
      assert.equal(error.cause, undefined);
      assert.doesNotMatch(error.message, /deployment-shawl|deployment-test/);
      return true;
    },
  );
  assert.equal(session.writes, beforeCollision);
  const conflictingRecord = JSON.parse(
    collisionFake.recordBytes('manifest', 'bot', shawlName).toString('utf8'),
  );
  const conflictingSignature = JSON.parse(
    Buffer.from(conflictingRecord.signatureBase64, 'base64').toString('utf8'),
  );
  conflictingSignature.signature =
    `${conflictingSignature.signature[0] === 'A' ? 'B' : 'A'}${conflictingSignature.signature.slice(1)}`;
  conflictingRecord.signatureBase64 =
    canonicalJsonBytes(conflictingSignature).toString('base64');
  collisionFake.putRaw(
    'manifest',
    'bot',
    shawlName,
    canonicalJsonBytes(conflictingRecord),
  );
  const beforeConflict = session.writes;
  expectCode(
    () => session.retainDeploymentEnvelope({
      ...shawlEnvelope,
      transaction: collisionTransaction,
    }),
    'SERVICE_MANUAL_CLEANUP',
  );
  assert.equal(session.writes, beforeConflict);
  session.close();
});

test('model: artifact access is retained-envelope, exact-phase, brand, fence, and session bound', async () => {
  const fake = new FakeServiceNative();
  const store = bootstrap(fake);
  const manifest = applicationManifest();
  const envelope = signedEnvelope('application', manifest);
  const transaction = transactionFixture({
    transactionId: 'tx-artifact-access',
    transactionNonce: 'a'.repeat(32),
    candidateManifestFingerprint: manifest.manifestFingerprint,
    releaseSequence: manifest.releaseSequence,
    releaseTreeFingerprint: manifest.inventory.treeFingerprint,
  });
  let session = store.openMutation();
  session.appendJournal(transaction);
  let before = session.writes;
  expectCode(
    () => session.openArtifactAccess({
      purpose: 'application',
      manifest,
      transaction,
    }),
    'SERVICE_MANUAL_CLEANUP',
  );
  assert.equal(session.writes, before);
  assert.equal(fake.roots.has('staging'), false);
  session.retainDeploymentEnvelope({ ...envelope, transaction });
  const retainedRead = session.readRetainedDeploymentEnvelope({
    purpose: 'application',
    manifestFingerprint: manifest.manifestFingerprint,
  });
  assert.deepEqual(retainedRead.manifest, manifest);
  assert.equal(Object.hasOwn(retainedRead, 'recordSha256'), false);
  before = session.writes;
  expectCode(
    () => session.openArtifactAccess({
      purpose: 'application',
      manifest: clone(manifest),
      transaction,
    }),
    'DEPLOYMENT_PINNED_PROVENANCE_REQUIRED',
  );
  assert.equal(session.writes, before);
  const foreignTupleManifest = applicationManifest({ platform: 'win32' });
  expectCode(
    () => session.openArtifactAccess({
      purpose: 'application',
      manifest: foreignTupleManifest,
      transaction,
    }),
    'SERVICE_SCOPE_MISMATCH',
  );
  assert.equal(session.writes, before);
  const foreignServiceTransaction = transactionFixture({
    transactionId: 'tx-artifact-access-foreign',
    transactionNonce: 'b'.repeat(32),
    candidateManifestFingerprint: manifest.manifestFingerprint,
    releaseSequence: manifest.releaseSequence,
    releaseTreeFingerprint: manifest.inventory.treeFingerprint,
    component: 'daemon',
    serviceKey: deriveServiceInstanceKey('artifact foreign service'),
  });
  expectCode(
    () => session.openArtifactAccess({
      purpose: 'application',
      manifest,
      transaction: foreignServiceTransaction,
    }),
    'SERVICE_SCOPE_MISMATCH',
  );
  assert.equal(session.writes, before);
  const unretainedPhase = nextJournal(
    transaction,
    'sequence-reserved',
    'observed',
  );
  expectCode(
    () => session.openArtifactAccess({
      purpose: 'application',
      manifest,
      transaction: unretainedPhase,
    }),
    'SERVICE_PENDING',
  );
  assert.equal(session.writes, before);
  expectCode(
    () => session.openArtifactAccess({
      purpose: 'application',
      manifest,
      transaction,
    }),
    'SERVICE_PENDING',
  );
  assert.equal(session.writes, before);
  assert.equal(fake.roots.has('staging'), false);
  session.reserveApplicationSequence({
    manifest,
    transaction,
    currentSequence: 0,
  });
  const afterReservation = session.writes;
  assert.ok(afterReservation > before);
  session.appendJournal(unretainedPhase);
  fake.seedSafeExternalRootParent('staging');
  const rootCallsBefore = fake.calls.length;
  const locksBefore = fake.calls.filter((call) =>
    call.startsWith('lock:artifact:')).length;
  const access = session.openArtifactAccess({
    purpose: 'application',
    manifest,
    transaction: unretainedPhase,
  });
  assert.deepEqual(Object.keys(access), [
    'stageAsset',
    'openStagedAsset',
    'prepareCandidate',
    'writeCandidateFile',
    'publishCandidate',
    'close',
  ]);
  assert.equal(access.handle, undefined);
  assert.equal(
    fake.calls.filter((call) => call.startsWith('lock:artifact:')).length,
    locksBefore,
  );
  assert.deepEqual(
    fake.calls.slice(rootCallsBefore).filter((call) =>
      call.startsWith('root:staging:')),
    ['root:staging:create-new'],
  );
  const scratchName =
    `bot-${transaction.transactionNonce}-application`;
  const scratch = fake.roots.get('staging').node.entries.get(scratchName);
  assert.ok(scratch);
  assert.deepEqual([...scratch.entries.keys()], ['transaction.json']);
  const marker = JSON.parse(
    scratch.entries.get('transaction.json').bytes.toString('utf8'),
  );
  assert.equal(marker.transactionIdentity, canonicalJsonHash({
    transactionId: transaction.transactionId,
    transactionNonce: transaction.transactionNonce,
    operation: transaction.operation,
    component: transaction.component,
    serviceKey: transaction.serviceKey,
    platform: transaction.platform,
    architecture: transaction.architecture,
    serviceGeneration: transaction.serviceGeneration,
    old: transaction.old,
    candidate: transaction.candidate,
    transition: transaction.transition,
    final: transaction.final,
  }));
  assert.equal(marker.scratchIdentity.profile, 'service-staging-directory');
  assert.equal(marker.stagingRootIdentity.profile, 'service-staging-directory');
  assert.deepEqual(marker.roles, linuxRoles);
  const writesAfterOpen = session.writes;
  expectCode(
    () => session.openArtifactAccess({
      purpose: 'application',
      manifest,
      transaction: unretainedPhase,
    }),
    'SERVICE_PENDING',
  );
  assert.equal(session.writes, writesAfterOpen);
  const publishedPhase = nextJournal(
    unretainedPhase,
    'release-published',
    'observed',
  );
  expectCode(
    () => session.appendJournal(publishedPhase),
    'SERVICE_PENDING',
  );
  assert.equal(session.writes, writesAfterOpen);
  expectCode(() => session.close(), 'SERVICE_PENDING');
  assert.equal(session.writes, writesAfterOpen);
  access.close();
  await assert.rejects(
    access.stageAsset([Buffer.alloc(manifest.archive.byteLength)]),
    (error) => error.code === 'SERVICE_STALE' &&
      error.operation === 'stage_service_asset' &&
      error.writes === writesAfterOpen,
  );
  const beforeSameSessionReplay = session.writes;
  const replayRootCallsBefore = fake.calls.length;
  const replay = session.openArtifactAccess({
    purpose: 'application',
    manifest,
    transaction: unretainedPhase,
  });
  assert.equal(session.writes, beforeSameSessionReplay);
  assert.deepEqual(
    fake.calls.slice(replayRootCallsBefore).filter((call) =>
      call.startsWith('root:staging:')),
    [
      'root:staging:create-new',
      'root:staging:write-existing',
    ],
  );
  replay.close();
  session.close();

  session = store.openRecovery();
  const writesBeforeRecoveryOpen = session.writes;
  const recoveryRootCallsBefore = fake.calls.length;
  const recoveryLocksBefore = fake.calls.filter((call) =>
    call.startsWith('lock:artifact:')).length;
  const recovered = session.openArtifactAccess({
    purpose: 'application',
    manifest,
    transaction: unretainedPhase,
  });
  assert.equal(
    fake.calls.filter((call) => call.startsWith('lock:artifact:')).length,
    recoveryLocksBefore,
  );
  assert.equal(session.writes, writesBeforeRecoveryOpen);
  assert.deepEqual(
    fake.calls.slice(recoveryRootCallsBefore).filter((call) =>
      call.startsWith('root:staging:')),
    [
      'root:staging:create-new',
      'root:staging:write-existing',
    ],
  );
  const beforeArtifactFailure = session.writes;
  fake.failArtifactWrite();
  await assert.rejects(
    recovered.stageAsset([Buffer.alloc(manifest.archive.byteLength)]),
    (error) => error.code === 'SERVICE_MANUAL_CLEANUP' &&
      error.operation === 'stage_service_asset' &&
      error.writes === beforeArtifactFailure + 1 &&
      error.writes === session.writes,
  );
  expectCode(() => session.close(), 'SERVICE_PENDING');
  recovered.close();
  session.close();
});

test('model: artifact access floor admission rejects competing transactions and the wrong sequence scope', () => {
  const competingFake = new FakeServiceNative();
  const competingStore = bootstrap(competingFake);
  const manifest = applicationManifest({ sequence: 2, version: '2.0.0' });
  const reservedTransaction = transactionFixture({
    transactionId: 'tx-artifact-floor-reserved',
    transactionNonce: '3'.repeat(32),
    candidateManifestFingerprint: manifest.manifestFingerprint,
    releaseSequence: manifest.releaseSequence,
    releaseTreeFingerprint: manifest.inventory.treeFingerprint,
  });
  const candidateTransaction = transactionFixture({
    transactionId: 'tx-artifact-floor-competing',
    transactionNonce: '4'.repeat(32),
    candidateManifestFingerprint: manifest.manifestFingerprint,
    releaseSequence: manifest.releaseSequence,
    releaseTreeFingerprint: manifest.inventory.treeFingerprint,
  });
  let session = competingStore.openMutation();
  session.reserveApplicationSequence({
    manifest,
    transaction: reservedTransaction,
    currentSequence: 0,
  });
  session.appendJournal(candidateTransaction);
  session.retainDeploymentEnvelope({
    ...signedEnvelope('application', manifest),
    transaction: candidateTransaction,
  });
  let before = session.writes;
  expectCode(
    () => session.openArtifactAccess({
      purpose: 'application',
      manifest,
      transaction: candidateTransaction,
    }),
    'SERVICE_PENDING',
  );
  assert.equal(session.writes, before);
  assert.equal(competingFake.roots.has('staging'), false);
  session.close();

  const scopeFake = new FakeServiceNative('win32');
  const scopeStore = bootstrap(scopeFake);
  const application = applicationManifest({
    sequence: 3,
    version: '3.0.0',
    platform: 'win32',
  });
  const shawl = shawlManifest({ sequence: 5 });
  const transaction = transactionFixture({
    transactionId: 'tx-artifact-floor-scope',
    transactionNonce: '5'.repeat(32),
    candidateManifestFingerprint: application.manifestFingerprint,
    releaseSequence: application.releaseSequence,
    releaseTreeFingerprint: application.inventory.treeFingerprint,
    platform: 'win32',
    shawlManifestFingerprint: shawl.manifestFingerprint,
  });
  session = scopeStore.openMutation();
  session.appendJournal(transaction);
  session.retainDeploymentEnvelope({
    ...signedEnvelope('shawl', shawl),
    transaction,
  });
  session.reserveApplicationSequence({
    manifest: application,
    transaction,
    currentSequence: 0,
  });
  before = session.writes;
  expectCode(
    () => session.openArtifactAccess({
      purpose: 'shawl',
      manifest: shawl,
      transaction,
    }),
    'SERVICE_PENDING',
  );
  assert.equal(session.writes, before);
  assert.equal(scopeFake.roots.has('staging'), false);
  session.reserveShawlSequence({
    manifest: shawl,
    transaction,
    currentSequence: 0,
  });
  const retainedShawl = session.readRetainedDeploymentEnvelope({
    purpose: 'shawl',
    manifestFingerprint: shawl.manifestFingerprint,
  });
  assert.deepEqual(retainedShawl.manifest, shawl);
  assert.equal(Object.hasOwn(retainedShawl, 'recordSha256'), false);
  const access = session.openArtifactAccess({
    purpose: 'shawl',
    manifest: shawl,
    transaction,
  });
  access.close();
  session.close();
});

test('model: artifact access accepts an exact committed logical-transaction replay without a conflicting reservation', () => {
  const fake = new FakeServiceNative();
  const store = bootstrap(fake);
  const manifest = applicationManifest({ sequence: 4, version: '4.0.0' });
  const identity = fake.seedPublication('releases', manifest.archive.sha256);
  const prepared = transactionFixture({
    transactionId: 'tx-artifact-committed-replay',
    transactionNonce: '6'.repeat(32),
    candidateManifestFingerprint: manifest.manifestFingerprint,
    releaseSequence: manifest.releaseSequence,
    releaseTreeFingerprint: manifest.inventory.treeFingerprint,
  });
  const session = store.openMutation();
  session.appendJournal(prepared);
  session.retainDeploymentEnvelope({
    ...signedEnvelope('application', manifest),
    transaction: prepared,
  });
  session.reserveApplicationSequence({
    manifest,
    transaction: prepared,
    currentSequence: 0,
  });
  const reserved = nextJournal(prepared, 'sequence-reserved', 'observed');
  session.appendJournal(reserved);
  const published = nextJournal(reserved, 'release-published', 'observed');
  session.appendJournal(published);
  session.commitApplicationSequence({
    manifest,
    transaction: published,
    publication: session.observeApplicationPublication(manifest, identity),
  });
  assert.equal(session.readApplicationFloor().floor.activeReservation, null);
  const access = session.openArtifactAccess({
    purpose: 'application',
    manifest,
    transaction: published,
  });
  access.close();
  const conflicting = transactionFixture({
    transactionId: 'tx-artifact-committed-conflict',
    transactionNonce: '7'.repeat(32),
    candidateManifestFingerprint: manifest.manifestFingerprint,
    releaseSequence: manifest.releaseSequence,
    releaseTreeFingerprint: manifest.inventory.treeFingerprint,
  });
  session.reserveApplicationSequence({
    manifest,
    transaction: conflicting,
    currentSequence: 0,
  });
  const beforeConflict = session.writes;
  expectCode(
    () => session.openArtifactAccess({
      purpose: 'application',
      manifest,
      transaction: published,
    }),
    'SERVICE_PENDING',
  );
  assert.equal(session.writes, beforeConflict);
  session.abandonApplicationSequence({ transaction: conflicting });
  const beforeFault = session.writes;
  const callsBeforeFault = fake.calls.length;
  fake.failRootCreate('staging');
  assert.throws(
    () => session.openArtifactAccess({
      purpose: 'application',
      manifest,
      transaction: published,
    }),
    (error) => {
      assert.equal(error.code, 'SERVICE_MANUAL_CLEANUP');
      assert.equal(error.operation, 'open_service_artifact_access');
      assert.equal(error.writes, beforeFault + 1);
      assert.equal(error.ambiguous, true);
      return true;
    },
  );
  assert.equal(session.writes, beforeFault + 1);
  assert.deepEqual(
    fake.calls.slice(callsBeforeFault).filter((call) =>
      call.startsWith('root:staging:')),
    ['root:staging:create-new'],
  );
  session.close();
});

test('model: published artifact collection requires a live same-session publication and deletes an exact unreferenced target', async () => {
  const model = unreferencedApplicationCollectionModel();
  const {
    fake,
    store,
    retiredDeployment,
    retiredIdentity,
    publication,
    transaction,
  } = model;
  await assert.rejects(
    model.session.collectPublishedArtifact({
      purpose: 'application',
      manifest: retiredDeployment,
      transaction,
      publication: Object.freeze({
        binding: clone(publication.binding),
      }),
    }),
    (error) => error.code === 'SERVICE_STALE' &&
      error.operation === 'collect_published_artifact',
  );
  model.session.close();

  const readOnly = store.openReadOnly();
  await assert.rejects(
    readOnly.collectPublishedArtifact({
      purpose: 'application',
      manifest: retiredDeployment,
      transaction,
      publication,
    }),
    (error) => error.code === 'SERVICE_ACCESS_DENIED' &&
      error.writes === 0,
  );
  readOnly.close();

  const session = store.openMutation();
  const before = session.writes;
  await assert.rejects(
    session.collectPublishedArtifact({
      purpose: 'application',
      manifest: retiredDeployment,
      transaction,
      publication,
    }),
    (error) => error.code === 'SERVICE_STALE' &&
      error.writes === before,
  );
  const livePublication = session.observeApplicationPublication(
    retiredDeployment,
    retiredIdentity,
  );
  const collecting = session.collectPublishedArtifact({
    purpose: 'application',
    manifest: retiredDeployment,
    transaction,
    publication: livePublication,
  });
  expectCode(() => session.close(), 'SERVICE_PENDING');
  const overlapWrites = session.writes;
  await assert.rejects(
    session.collectPublishedArtifact({
      purpose: 'application',
      manifest: retiredDeployment,
      transaction,
      publication: livePublication,
    }),
    (error) => error.code === 'SERVICE_PENDING' &&
      error.operation === 'collect_published_artifact' &&
      error.writes === overlapWrites,
  );
  await assert.rejects(
    session.collectPublishedArtifact(),
    (error) => error.code === 'SERVICE_PENDING' &&
      error.operation === 'collect_published_artifact' &&
      error.writes === overlapWrites,
  );
  await assert.rejects(
    session.recoverPublishedArtifactCollection(),
    (error) => error.code === 'SERVICE_PENDING' &&
      error.operation === 'recover_published_artifact_collection' &&
      error.writes === overlapWrites,
  );
  await assert.rejects(
    session.recoverPublishedArtifactCollection('invalid'),
    (error) => error.code === 'SERVICE_INVALID' &&
      error.operation === 'recover_published_artifact_collection' &&
      error.writes === overlapWrites,
  );
  expectCode(
    () => session.appendJournal(transaction),
    'SERVICE_PENDING',
  );
  expectCode(() => session.close(), 'SERVICE_PENDING');
  assert.equal(session.writes, overlapWrites);
  const result = await collecting;
  assert.equal(result.collected, true);
  assert.equal(
    fake.roots.get('releases').node.entries.has(
      retiredDeployment.archive.sha256,
    ),
    false,
  );
  assert.equal(
    fake.serviceDirectory('manual', 'bot', false)
      ?.entries.has(SERVICE_STORE_LAYOUT.artifactCleanup),
    false,
  );
  assert.ok(session.writes > before);
  session.close();
});

test('model: durable published cleanup intent protects authority and converges after a destructive failure', async () => {
  const model = unreferencedApplicationCollectionModel();
  const {
    fake,
    store,
    retiredDeployment,
    retiredIdentity,
    publication,
    transaction,
  } = model;
  fake.artifactRemoveFault = { kind: 'file', name: 'bot.js' };
  const before = model.session.writes;
  await assert.rejects(
    model.session.collectPublishedArtifact({
      purpose: 'application',
      manifest: retiredDeployment,
      transaction,
      publication,
    }),
    (error) => error.code === 'SERVICE_MANUAL_CLEANUP' &&
      error.operation === 'collect_published_service_artifact' &&
      error.ambiguous === true &&
      error.writes === model.session.writes &&
      error.writes > before &&
      error.cause === undefined &&
      error.message === 'collect_published_service_artifact failed',
  );
  const intent = JSON.parse(fake.recordBytes(
    'manual',
    'bot',
    SERVICE_STORE_LAYOUT.artifactCleanup,
  ));
  assert.equal(intent.kind, 'service-artifact-cleanup');
  assert.equal(intent.phase, 'payload-removing');
  assert.equal(intent.revision, 0);
  assert.equal(
    intent.artifactBinding.bindingFingerprint,
    publication.binding.bindingFingerprint,
  );
  assert.equal(Object.hasOwn(intent, 'files'), false);
  assert.equal(Object.hasOwn(intent, 'fileFacts'), false);
  model.session.close();

  const competingKey = deriveServiceInstanceKey('cleanup competitor');
  const competingStore = storeFor(fake, {
    component: 'daemon',
    hostId: 'cleanup competitor',
  });
  const competing = competingStore.openMutation();
  expectCode(
    () => competing.observeApplicationPublication(
      retiredDeployment,
      retiredIdentity,
    ),
    'SERVICE_PENDING',
  );
  const competingSlot = buildServiceReferenceSlot({
    serviceGeneration: 1,
    transactionId: 'tx-cleanup-competitor',
    transactionNonce: '9'.repeat(32),
    artifacts: [
      publication.binding,
      competing.createSharedTemplateBinding(),
    ],
  }, { platform: 'linux', component: 'daemon' });
  expectCode(
    () => competing.publishReferences(buildServiceReferenceRecord({
      serviceKey: competingKey,
      component: 'daemon',
      platform: 'linux',
      architecture: 'x64',
      serviceGeneration: 0,
      current: null,
      previous: null,
      provisional: competingSlot,
    }), competing.readReferences()),
    'SERVICE_PENDING',
  );
  competing.close();

  const recovery = store.openMutation();
  expectCode(
    () => recovery.observeApplicationPublication(
      retiredDeployment,
      retiredIdentity,
    ),
    'SERVICE_PENDING',
  );
  const references = recovery.readReferences();
  const protectedCurrent = buildServiceReferenceSlot({
    ...references.value.current,
    artifacts: [publication.binding],
  }, { platform: 'linux', component: 'bot' });
  expectCode(
    () => recovery.publishReferences(buildServiceReferenceRecord({
      ...references.value,
      current: protectedCurrent,
    }), references),
    'SERVICE_PENDING',
  );
  const recoveryWrites = recovery.writes;
  const result = await recovery.recoverPublishedArtifactCollection();
  assert.equal(result.collected, true);
  assert.ok(recovery.writes > recoveryWrites);
  assert.equal(
    fake.roots.get('releases').node.entries.has(
      retiredDeployment.archive.sha256,
    ),
    false,
  );
  assert.equal(
    fake.serviceDirectory('manual', 'bot', false)
      ?.entries.has(SERVICE_STORE_LAYOUT.artifactCleanup),
    false,
  );
  recovery.close();

  const after = store.openReadOnly();
  await assert.rejects(
    after.recoverPublishedArtifactCollection(),
    (error) => error.code === 'SERVICE_ACCESS_DENIED' &&
      error.writes === 0,
  );
  after.close();
});

test('model: cleanup intent phase-write failures restart from durable progress', async () => {
  for (const [occurrence, expectedPhase] of [
    [1, 'payload-removing'],
    [2, 'inventory-removing'],
    [3, 'root-removing'],
  ]) {
    const model = unreferencedApplicationCollectionModel();
    model.fake.failPublish(
      SERVICE_STORE_LAYOUT.artifactCleanup,
      'after',
      occurrence,
    );
    const before = model.session.writes;
    await assert.rejects(
      model.session.collectPublishedArtifact({
        purpose: 'application',
        manifest: model.retiredDeployment,
        transaction: model.transaction,
        publication: model.publication,
      }),
      (error) => error.code === 'SERVICE_MANUAL_CLEANUP' &&
        error.ambiguous === true &&
        error.writes === model.session.writes &&
        error.writes > before,
    );
    const intent = JSON.parse(model.fake.recordBytes(
      'manual',
      'bot',
      SERVICE_STORE_LAYOUT.artifactCleanup,
    ));
    assert.equal(intent.phase, expectedPhase);
    model.session.close();
    const recovery = model.store.openMutation();
    const recovered = await recovery
      .recoverPublishedArtifactCollection();
    assert.equal(recovered.collected, true);
    assert.equal(
      model.fake.roots.get('releases').node.entries.has(
        model.retiredDeployment.archive.sha256,
      ),
      false,
    );
    assert.equal(
      model.fake.serviceDirectory('manual', 'bot', false)
        ?.entries.has(SERVICE_STORE_LAYOUT.artifactCleanup),
      false,
    );
    recovery.close();
  }
});

test('model: final cleanup-intent CAS failure retains recovery authority until exact retry', async () => {
  const model = unreferencedApplicationCollectionModel();
  model.fake.recordRemoveFault = {
    name: SERVICE_STORE_LAYOUT.artifactCleanup,
    when: 'before',
  };
  await assert.rejects(
    model.session.collectPublishedArtifact({
      purpose: 'application',
      manifest: model.retiredDeployment,
      transaction: model.transaction,
      publication: model.publication,
    }),
    (error) => error.code === 'SERVICE_IO_FAILED' &&
      error.writes === model.session.writes,
  );
  assert.equal(
    model.fake.roots.get('releases').node.entries.has(
      model.retiredDeployment.archive.sha256,
    ),
    false,
  );
  const intent = JSON.parse(model.fake.recordBytes(
    'manual',
    'bot',
    SERVICE_STORE_LAYOUT.artifactCleanup,
  ));
  assert.equal(intent.phase, 'root-removing');
  model.session.close();
  const recovery = model.store.openMutation();
  await recovery.recoverPublishedArtifactCollection();
  assert.equal(
    model.fake.serviceDirectory('manual', 'bot', false)
      ?.entries.has(SERVICE_STORE_LAYOUT.artifactCleanup),
    false,
  );
  recovery.close();
});

test('model: failed reader, directory, and root closes retain the session borrow until explicit retry', async () => {
  for (const name of [
    'bundle-files.json',
    'bot',
    'releases',
  ]) {
    const model = unreferencedApplicationCollectionModel();
    model.fake.closeFailure = { name, remaining: 10 };
    const before = model.session.writes;
    await assert.rejects(
      model.session.collectPublishedArtifact({
        purpose: 'application',
        manifest: model.retiredDeployment,
        transaction: model.transaction,
        publication: model.publication,
      }),
      (error) => {
        assert.deepEqual({
          code: error.code,
          operation: error.operation,
          writes: error.writes,
          ambiguous: error.ambiguous,
          cause: error.cause,
        }, {
          code: 'SERVICE_IO_FAILED',
          operation: name === 'bot'
            ? 'collect_published_artifact'
            : 'inspect_published_service_artifact',
          writes: before,
          ambiguous: true,
          cause: undefined,
        }, `close target ${name}`);
        return true;
      },
    );
    assert.equal(
      model.fake.serviceDirectory('manual', 'bot', false)
        ?.entries.has(SERVICE_STORE_LAYOUT.artifactCleanup) ?? false,
      false,
    );
    const blockedWrites = model.session.writes;
    expectCode(
      () => model.session.appendJournal(model.transaction),
      'SERVICE_PENDING',
    );
    expectCode(
      () => model.session.appendJournal(model.transaction),
      'SERVICE_PENDING',
    );
    assert.equal(model.session.writes, blockedWrites);
    assert.throws(
      () => model.session.close(),
      (error) => error.code === 'SERVICE_IO_FAILED' &&
        error.operation === 'close_service_store' &&
        error.writes === before &&
        error.ambiguous === true,
    );
    expectCode(
      () => model.session.publishReferences(
        model.session.readReferences().value,
        model.session.readReferences(),
      ),
      'SERVICE_PENDING',
    );
    await assert.rejects(
      model.session.recoverPublishedArtifactCollection(),
      (error) => error.code === 'SERVICE_IO_FAILED' &&
        error.operation === 'recover_published_artifact_collection' &&
        error.writes === before &&
        error.ambiguous === true,
    );
    model.fake.closeFailure.remaining = 0;
    assert.deepEqual(
      await model.session.recoverPublishedArtifactCollection(),
      { collected: false, cleanupReleased: true },
    );
    model.session.close();
  }
});

test('model: invalid reader receipts retain raw children ahead of collector parents until retry', async () => {
  const model = unreferencedApplicationCollectionModel();
  model.fake.artifactReaderReceiptFault = 'bundle-files.json';
  model.fake.closeFailure = {
    name: 'bundle-files.json',
    remaining: 10,
  };
  const before = model.session.writes;
  await assert.rejects(
    model.session.collectPublishedArtifact({
      purpose: 'application',
      manifest: model.retiredDeployment,
      transaction: model.transaction,
      publication: model.publication,
    }),
    (error) => error.code === 'SERVICE_MANUAL_CLEANUP' &&
      error.operation === 'inspect_published_service_artifact' &&
      error.writes === before &&
      error.ambiguous === true &&
      error.cause === undefined,
  );
  assert.equal(model.fake.activeArtifactReaders, 1);
  expectCode(
    () => model.session.appendJournal(model.transaction),
    'SERVICE_PENDING',
  );
  assert.throws(
    () => model.session.close(),
    (error) => error.code === 'SERVICE_IO_FAILED' &&
      error.operation === 'close_service_store' &&
      error.writes === before &&
      error.ambiguous === true,
  );
  assert.equal(model.fake.activeArtifactReaders, 1);
  await assert.rejects(
    model.session.recoverPublishedArtifactCollection(),
    (error) => error.code === 'SERVICE_IO_FAILED' &&
      error.operation === 'recover_published_artifact_collection' &&
      error.writes === before &&
      error.ambiguous === true,
  );
  assert.equal(model.fake.activeArtifactReaders, 1);
  model.fake.closeFailure.remaining = 0;
  assert.deepEqual(
    await model.session.recoverPublishedArtifactCollection(),
    { collected: false, cleanupReleased: true },
  );
  assert.equal(model.fake.activeArtifactReaders, 0);
  model.session.close();
});

test('model: a sibling cleanup intent blocks digest-alias acquisition before staging while unrelated targets remain admissible', async () => {
  const prepareBlockedTarget = async (archiveHash, hostId) => {
    const model = unreferencedApplicationCollectionModel();
    model.fake.artifactRemoveFault = {
      kind: 'directory',
      name: model.retiredDeployment.archive.sha256,
    };
    await assert.rejects(
      model.session.collectPublishedArtifact({
        purpose: 'application',
        manifest: model.retiredDeployment,
        transaction: model.transaction,
        publication: model.publication,
      }),
      (error) => error.code === 'SERVICE_MANUAL_CLEANUP' &&
        error.ambiguous === true,
    );
    assert.equal(
      model.fake.roots.get('releases').node.entries.has(
        model.retiredDeployment.archive.sha256,
      ),
      false,
    );
    model.session.close();
    const serviceKey = deriveServiceInstanceKey(hostId);
    const manifest = applicationManifest({
      sequence: 4,
      version: '4.0.0',
      archiveHash,
    });
    const transaction = transactionFixture({
      transactionId: `tx-${hostId.replaceAll(' ', '-')}`,
      transactionNonce: archiveHash ===
          model.retiredDeployment.archive.sha256
        ? '7'.repeat(32)
        : '8'.repeat(32),
      candidateManifestFingerprint: manifest.manifestFingerprint,
      releaseSequence: manifest.releaseSequence,
      releaseTreeFingerprint: manifest.inventory.treeFingerprint,
      component: 'daemon',
      serviceKey,
    });
    const siblingStore = storeFor(model.fake, {
      component: 'daemon',
      hostId,
    });
    const sibling = siblingStore.openMutation();
    sibling.appendJournal(transaction);
    sibling.retainDeploymentEnvelope({
      ...signedEnvelope('application', manifest),
      transaction,
    });
    sibling.reserveApplicationSequence({
      manifest,
      transaction,
      currentSequence: 0,
    });
    const reserved = nextJournal(
      transaction,
      'sequence-reserved',
      'observed',
    );
    sibling.appendJournal(reserved);
    return {
      ...model,
      sibling,
      serviceKey,
      manifest,
      transaction: reserved,
    };
  };

  const blocked = await prepareBlockedTarget(
    hash('4'),
    'cleanup blocked sibling',
  );
  const blockedWrites = blocked.sibling.writes;
  const stagingWrites = blocked.fake.totalWrites;
  expectCode(
    () => blocked.sibling.openArtifactAccess({
      purpose: 'application',
      manifest: blocked.manifest,
      transaction: blocked.transaction,
    }),
    'SERVICE_PENDING',
  );
  assert.equal(blocked.sibling.writes, blockedWrites);
  assert.equal(blocked.fake.totalWrites, stagingWrites);
  assert.equal(blocked.fake.roots.has('staging'), false);
  assert.equal(
    blocked.fake.roots.get('releases').node.entries.has(hash('4')),
    false,
  );
  blocked.sibling.abandonApplicationSequence({
    transaction: blocked.transaction,
  });
  blocked.sibling.close();
  blocked.fake.namespace('transaction').entries.delete(
    blocked.serviceKey,
  );
  blocked.fake.namespace('manifest').entries.delete(
    blocked.serviceKey,
  );
  const originalRecovery = blocked.store.openMutation();
  assert.equal(
    (await originalRecovery.recoverPublishedArtifactCollection())
      .collected,
    true,
  );
  originalRecovery.close();

  const unrelated = await prepareBlockedTarget(
    hash('8'),
    'cleanup unrelated sibling',
  );
  const unrelatedWrites = unrelated.sibling.writes;
  const access = unrelated.sibling.openArtifactAccess({
    purpose: 'application',
    manifest: unrelated.manifest,
    transaction: unrelated.transaction,
  });
  assert.ok(unrelated.sibling.writes > unrelatedWrites);
  assert.equal(unrelated.fake.roots.has('staging'), true);
  access.close();
  unrelated.sibling.close();
});

test('model: committed-residue scratch collection re-inspects the archive, removes in phase order, and recovers after crashes', async () => {
  for (const failure of [
    null,
    { kind: 'file', name: 'data' },
    { kind: 'phase', occurrence: 2 },
  ]) {
    const model = committedScratchResidue();
    await stagePartialScratchCandidate(model);
    const committed = commitScratchResidueTransaction(model);
    const scratchName = [...scratchEntries(model).keys()][0];
    assert.ok(scratchName.endsWith('-application'));

    if (failure?.kind === 'file') {
      model.fake.artifactRemoveFault = { kind: 'file', name: 'data' };
    } else if (failure?.kind === 'phase') {
      model.fake.failPublish(
        SERVICE_STORE_LAYOUT.artifactCleanup,
        'after',
        failure.occurrence,
      );
    }
    const before = model.session.writes;
    const collect = model.session.collectScratchArtifacts({
      purpose: 'application',
      manifest: model.deployment.manifest,
      transaction: committed,
    });
    if (failure === null) {
      const result = await collect;
      assert.equal(result.collected, true);
      assert.equal(scratchEntries(model).size, 0);
      assert.equal(
        model.fake.serviceDirectory('manual', 'bot', false)
          ?.entries.has(SERVICE_STORE_LAYOUT.artifactCleanup),
        false,
      );
      assert.ok(model.session.writes > before);
      const removals = model.fake.calls.filter((call) =>
        call.includes('remove'));
      const inventoryIndex = removals.findIndex((call) =>
        call.endsWith('/bundle-files.json'));
      assert.ok(inventoryIndex > removals.findIndex((call) =>
        call.endsWith('/data')));
      assert.ok(
        removals.findIndex((call) => call.endsWith('/archive')) >
          removals.findIndex((call) => call.endsWith('/candidate')));
      assert.ok(
        removals.findIndex((call) => call.endsWith('/transaction.json')) >
          removals.findIndex((call) => call.endsWith('/archive')));
      assert.ok(
        removals.at(-1).endsWith(`/${SERVICE_STORE_LAYOUT.artifactCleanup}`));
      const scratchRootIndex = removals.findIndex((call) =>
        call.endsWith(`/${scratchName}`));
      assert.ok(
        scratchRootIndex >
          removals.findIndex((call) => call.endsWith('/transaction.json')));
      model.session.close();
      continue;
    }
    await assert.rejects(
      collect,
      (error) => error.code === 'SERVICE_MANUAL_CLEANUP' &&
        error.ambiguous === true &&
        error.writes === model.session.writes &&
        error.writes > before,
    );
    const intent = JSON.parse(model.fake.recordBytes(
      'manual',
      'bot',
      SERVICE_STORE_LAYOUT.artifactCleanup,
    ));
    assert.equal(intent.kind, 'service-artifact-cleanup');
    assert.equal(intent.scope, 'scratch');
    assert.equal(intent.scratchName, scratchName);
    assert.equal(intent.assetName, 'archive');
    assert.equal(intent.assetSize, model.deployment.archive.length);
    assert.equal(intent.assetSha256, sha256(model.deployment.archive));
    assert.equal(typeof intent.markerFingerprint, 'string');
    assert.ok(intent.markerFacts);
    assert.ok(intent.candidateIdentity);
    assert.equal(Object.hasOwn(intent, 'files'), false);
    assert.equal(Object.hasOwn(intent, 'payloadEntries'), false);
    assert.equal(Object.hasOwn(intent, 'artifactBinding'), false);
    assert.equal(
      intent.phase,
      failure.kind === 'phase' ? 'candidate-inventory-removing'
        : 'candidate-payload-removing',
    );
    expectCode(
      () => model.session.appendJournal(committed),
      'SERVICE_PENDING',
    );
    model.session.close();
    const recovery = model.store.openMutation();
    const result = await recovery.recoverScratchArtifactCollection();
    assert.equal(result.collected, true);
    assert.equal(scratchEntries(model).size, 0);
    assert.equal(
      model.fake.serviceDirectory('manual', 'bot', false)
        ?.entries.has(SERVICE_STORE_LAYOUT.artifactCleanup),
      false,
    );
    recovery.close();
  }
});

test('model: scratch collection requires committed or explicitly abandoned lineage and exact scope', async () => {
  const fake = new FakeServiceNative();
  const store = bootstrap(fake);
  const session = store.openMutation();
  const deployment = realArchiveApplication();
  const transaction = transactionFixture({
    transactionId: 'tx-scratch-pending',
    transactionNonce: '5'.repeat(32),
    candidateManifestFingerprint: deployment.manifest.manifestFingerprint,
    releaseSequence: deployment.manifest.releaseSequence,
    releaseTreeFingerprint: deployment.manifest.inventory.treeFingerprint,
  });
  session.appendJournal(transaction);
  session.retainDeploymentEnvelope({
    ...signedEnvelope('application', deployment.manifest),
    transaction,
  });
  session.reserveApplicationSequence({
    manifest: deployment.manifest,
    transaction,
    currentSequence: 0,
  });
  const reserved = nextJournal(transaction, 'sequence-reserved', 'observed');
  session.appendJournal(reserved);
  const access = session.openArtifactAccess({
    purpose: 'application',
    manifest: deployment.manifest,
    transaction: reserved,
  });
  await assert.rejects(
    access.stageAsset([deployment.archive.subarray(0, 16)]),
    (error) => error.code === 'SERVICE_MANUAL_CLEANUP',
  );
  access.close();
  assert.ok(scratchEntries({ fake }).size === 1);

  const beforePending = session.writes;
  await assert.rejects(
    session.collectScratchArtifacts({
      purpose: 'application',
      manifest: deployment.manifest,
      transaction: reserved,
    }),
    (error) => error.code === 'SERVICE_PENDING' &&
      error.operation === 'collect_scratch_artifacts' &&
      error.writes === beforePending,
  );
  await assert.rejects(
    session.collectScratchArtifacts({
      purpose: 'application',
      manifest: deployment.manifest,
      transaction: transactionFixture({
        transactionId: 'tx-scratch-foreign',
        transactionNonce: '7'.repeat(32),
        candidateManifestFingerprint:
          deployment.manifest.manifestFingerprint,
        releaseSequence: deployment.manifest.releaseSequence,
        releaseTreeFingerprint:
          deployment.manifest.inventory.treeFingerprint,
      }),
    }),
    (error) => error.code === 'SERVICE_PENDING' &&
      error.writes === beforePending,
  );
  session.abandonApplicationSequence({ transaction: reserved });
  const result = await session.collectScratchArtifacts({
    purpose: 'application',
    manifest: deployment.manifest,
    transaction: reserved,
  });
  assert.equal(result.collected, true);
  assert.equal(scratchEntries({ fake }).size, 0);
  session.close();

  const readOnly = store.openReadOnly();
  await assert.rejects(
    readOnly.collectScratchArtifacts({
      purpose: 'application',
      manifest: deployment.manifest,
      transaction: reserved,
    }),
    (error) => error.code === 'SERVICE_ACCESS_DENIED' &&
      error.writes === 0,
  );
  await assert.rejects(
    readOnly.recoverScratchArtifactCollection(),
    (error) => error.code === 'SERVICE_ACCESS_DENIED' &&
      error.writes === 0,
  );
  readOnly.close();
});

test('model: scratch collection refuses unmarked or foreign-content scratch without cleanup writes', async () => {
  {
    const model = committedScratchResidue();
    await stagePartialScratchCandidate(model);
    const committed = commitScratchResidueTransaction(model);
    const scratchName = [...scratchEntries(model).keys()][0];
    scratchEntries(model).get(scratchName).entries.delete('transaction.json');
    const before = model.session.writes;
    await assert.rejects(
      model.session.collectScratchArtifacts({
        purpose: 'application',
        manifest: model.deployment.manifest,
        transaction: committed,
      }),
      (error) => error.code === 'SERVICE_MANUAL_CLEANUP' &&
        error.writes === before,
    );
    assert.equal(
      model.fake.calls.some((call) => call.includes('remove')),
      false,
    );
    model.session.close();
  }
  {
    const model = committedScratchResidue();
    await stagePartialScratchCandidate(model);
    const committed = commitScratchResidueTransaction(model);
    const scratchName = [...scratchEntries(model).keys()][0];
    scratchEntries(model).get(scratchName).entries.set(
      'foreign.txt',
      model.fake.file(Buffer.from('foreign'), 'service-staging-file'),
    );
    const before = model.session.writes;
    await assert.rejects(
      model.session.collectScratchArtifacts({
        purpose: 'application',
        manifest: model.deployment.manifest,
        transaction: committed,
      }),
      (error) => error.code === 'SERVICE_MANUAL_CLEANUP' &&
        error.writes === before,
    );
    model.session.close();
  }
  {
    const model = committedScratchResidue();
    await stagePartialScratchCandidate(model);
    const committed = commitScratchResidueTransaction(model);
    const before = model.session.writes;
    await assert.rejects(
      model.session.collectScratchArtifacts({
        purpose: 'shawl',
        manifest: model.deployment.manifest,
        transaction: committed,
      }),
      (error) => error.code === 'DEPLOYMENT_PINNED_PROVENANCE_REQUIRED' &&
        error.operation === 'verify_deployment_provenance' &&
        error.writes === before,
    );
    model.session.close();
  }
});

test('model: a pending scratch cleanup intent never blocks sibling published acquisition and still recovers', async () => {
  const model = committedScratchResidue();
  await stagePartialScratchCandidate(model);
  const committed = commitScratchResidueTransaction(model);
  model.fake.artifactRemoveFault = { kind: 'file', name: 'data' };
  await assert.rejects(
    model.session.collectScratchArtifacts({
      purpose: 'application',
      manifest: model.deployment.manifest,
      transaction: committed,
    }),
    (error) => error.code === 'SERVICE_MANUAL_CLEANUP' &&
      error.ambiguous === true,
  );
  const scratchName = [...scratchEntries(model).keys()][0];
  model.session.close();
  const siblingKey = deriveServiceInstanceKey('scratch sibling');
  const siblingDeployment = realArchiveApplication({
    sequence: 4,
    version: '4.0.0',
  });
  assert.equal(
    siblingDeployment.manifest.archive.sha256,
    model.deployment.manifest.archive.sha256,
  );
  assert.notEqual(
    siblingDeployment.manifest.manifestFingerprint,
    model.deployment.manifest.manifestFingerprint,
  );
  const siblingStore = storeFor(model.fake, {
    component: 'daemon',
    hostId: 'scratch sibling',
  });
  const sibling = siblingStore.openMutation();
  const transaction = transactionFixture({
    transactionId: 'tx-scratch-sibling',
    transactionNonce: '8'.repeat(32),
    candidateManifestFingerprint:
      siblingDeployment.manifest.manifestFingerprint,
    releaseSequence: siblingDeployment.manifest.releaseSequence,
    releaseTreeFingerprint:
      siblingDeployment.manifest.inventory.treeFingerprint,
    component: 'daemon',
    serviceKey: siblingKey,
  });
  sibling.appendJournal(transaction);
  sibling.retainDeploymentEnvelope({
    ...signedEnvelope('application', siblingDeployment.manifest),
    transaction,
  });
  sibling.reserveApplicationSequence({
    manifest: siblingDeployment.manifest,
    transaction,
    currentSequence: 0,
  });
  const reserved = nextJournal(transaction, 'sequence-reserved', 'observed');
  sibling.appendJournal(reserved);
  const siblingWrites = sibling.writes;
  const access = sibling.openArtifactAccess({
    purpose: 'application',
    manifest: siblingDeployment.manifest,
    transaction: reserved,
  });
  assert.ok(sibling.writes > siblingWrites);
  access.close();
  sibling.abandonApplicationSequence({ transaction: reserved });
  sibling.close();

  const recovery = model.store.openMutation();
  const result = await recovery.recoverScratchArtifactCollection();
  assert.equal(result.collected, true);
  assert.equal(scratchEntries(model).has(scratchName), false);
  assert.equal(scratchEntries(model).size, 1);
  recovery.close();
});

test('model: read-only absence and missing service lock perform zero writes', () => {
  const fake = new FakeServiceNative();
  const bot = storeFor(fake);
  assert.equal(bot.openReadOnly(), null);
  assert.equal(fake.totalWrites, 0);
  bootstrap(fake);
  const session = bot.openReadOnly();
  assert.equal(session.writes, 0);
  assert.equal(session.readManifest('current').present, false);
  assert.equal(session.writes, 0);
  session.close();
  const daemon = storeFor(fake, { component: 'daemon', hostId: 'new daemon' });
  assert.throws(() => daemon.openReadOnly(), (error) => {
    assert.equal(error.code, 'SERVICE_PENDING');
    assert.equal(error.writes, 0);
    return true;
  });
  assert.equal(fake.calls.some((value) => value.includes('new daemon')), false);
});

test('model: bootstrap records fixed namespaces, floors, registration, and native lock order', () => {
  const fake = new FakeServiceNative();
  const store = storeFor(fake);
  const session = store.bootstrap();
  assert.deepEqual([...fake.namespace('floor').entries.keys()].sort(), [
    'application-linux-x64.json',
    'application-linux-x64.witness.json',
    SERVICE_STORE_LAYOUT.historyDirectory,
    SERVICE_STORE_LAYOUT.registration,
  ].sort());
  assert.equal(
    fake.namespace('floor').entries
      .get(SERVICE_STORE_LAYOUT.historyDirectory)
      .entries.has(SERVICE_STORE_LAYOUT.registrationIncarnation),
    true,
  );
  assert.equal(session.readApplicationFloor().floor.highestReservedSequence, 0);
  assert.equal(Object.hasOwn(session, 'rootPath'), false);
  assert.equal(Object.hasOwn(session, 'rootBinding'), false);
  session.close();
  const acquisitions = fake.calls.filter((value) => value.startsWith('lock:')).slice(0, 3);
  assert.deepEqual(acquisitions, [
    'lock:artifact:global:exclusive',
    'lock:shared-template:global:exclusive',
    'lock:service-key:bot:exclusive',
  ]);
  const closes = fake.calls.filter((value) => value.startsWith('close:lock')).slice(-3);
  assert.deepEqual(closes, [
    'close:lock:service-key',
    'close:lock:shared-template',
    'close:lock:artifact',
  ]);
  assert.equal(fake.calls.at(-1), 'close:root:control');
});

test('model: partial bootstrap, lost floor, and recreated root never reinitialize sequence zero', () => {
  const partial = new FakeServiceNative();
  partial.failPublish(SERVICE_STORE_LAYOUT.registration);
  const store = storeFor(partial);
  assert.throws(() => store.bootstrap(), (error) => {
    assert.ok(error.writes > 0);
    return true;
  });
  const writes = partial.totalWrites;
  assert.throws(() => store.openReadOnly(), (error) => {
    assert.equal(error.code, 'SERVICE_MANUAL_CLEANUP');
    assert.equal(error.writes, 0);
    return true;
  });
  assert.equal(partial.totalWrites, writes);

  const lost = new FakeServiceNative();
  const lostStore = bootstrap(lost);
  lost.deleteRecord('floor', null, 'application-linux-x64.json');
  assert.throws(() => lostStore.openReadOnly(), (error) => {
    assert.equal(error.code, 'SERVICE_MANUAL_CLEANUP');
    assert.equal(error.writes, 0);
    return true;
  });

  const recreated = new FakeServiceNative();
  const recreatedStore = bootstrap(recreated);
  recreated.recreateControlRootIdentity();
  expectCode(() => recreatedStore.openReadOnly(), 'SERVICE_MANUAL_CLEANUP');

  const registrationRecreated = new FakeServiceNative();
  const registrationStore = bootstrap(registrationRecreated);
  registrationRecreated.recreateRecordSameBytes(
    'floor',
    null,
    SERVICE_STORE_LAYOUT.registration,
  );
  expectCode(() => registrationStore.openReadOnly(), 'SERVICE_MANUAL_CLEANUP');

  const witnessRecreated = new FakeServiceNative();
  const witnessStore = bootstrap(witnessRecreated);
  witnessRecreated.recreateRecordSameBytes(
    'floor',
    null,
    'application-linux-x64.witness.json',
  );
  expectCode(() => witnessStore.openReadOnly(), 'SERVICE_MANUAL_CLEANUP');

  const restored = new FakeServiceNative();
  const restoredStore = bootstrap(restored);
  const oldFloor = restored.recordBytes('floor', null, 'application-linux-x64.json');
  const oldWitness = restored.recordBytes(
    'floor',
    null,
    'application-linux-x64.witness.json',
  );
  const restoredManifest = applicationManifest({ sequence: 2, version: '2.0.0' });
  const restoredTransaction = transactionFixture({
    transactionId: 'tx-restored-pair',
    transactionNonce: '4'.repeat(32),
    candidateManifestFingerprint: restoredManifest.manifestFingerprint,
    releaseSequence: restoredManifest.releaseSequence,
  });
  const restoredSession = restoredStore.openMutation();
  restoredSession.reserveApplicationSequence({
    manifest: restoredManifest,
    transaction: restoredTransaction,
    currentSequence: 0,
  });
  restoredSession.close();
  restored.putRaw('floor', null, 'application-linux-x64.json', oldFloor);
  restored.putRaw('floor', null, 'application-linux-x64.witness.json', oldWitness);
  expectCode(() => restoredStore.openReadOnly(), 'SERVICE_MANUAL_CLEANUP');
});

test('model: constructor has no root override and requires metadata plus artifact primitives', () => {
  const fake = new FakeServiceNative();
  expectCode(() => createServiceStore({
    native: fake.facade,
    roles: linuxRoles,
    target: { component: 'bot' },
    platform: 'linux',
    architecture: 'x64',
    root: '/tmp/attacker',
  }), 'SERVICE_INVALID');
  const missing = { ...fake.facade };
  delete missing.read_service_file;
  expectCode(() => createServiceStore({
    native: missing,
    roles: linuxRoles,
    target: { component: 'bot' },
    platform: 'linux',
    architecture: 'x64',
  }), 'SERVICE_INVALID');
  const missingArtifact = { ...fake.facade };
  delete missingArtifact.read_service_artifact_chunk;
  expectCode(() => createServiceStore({
    native: missingArtifact,
    roles: linuxRoles,
    target: { component: 'bot' },
    platform: 'linux',
    architecture: 'x64',
  }), 'SERVICE_INVALID');
  let getterCalls = 0;
  const accessorOptions = {
    native: fake.facade,
    roles: linuxRoles,
    get target() {
      getterCalls += 1;
      return { component: 'bot' };
    },
    platform: 'linux',
    architecture: 'x64',
  };
  expectCode(() => createServiceStore(accessorOptions), 'SERVICE_INVALID');
  assert.equal(getterCalls, 0);
  const store = bootstrap(fake);
  const changedRoles = {
    ...linuxRoles,
    management: { kind: 'uid', value: 'uid:2000' },
  };
  const changed = createServiceStore({
    native: fake.facade,
    roles: changedRoles,
    target: { component: 'bot' },
    platform: 'linux',
    architecture: 'x64',
  });
  assert.throws(() => changed.openReadOnly(), (error) => {
    assert.equal(error.code, 'SERVICE_INVALID');
    assert.equal(error.writes, 0);
    return true;
  });
  assert.equal(store.serviceKey, 'bot');
});

test('model: canonical corruption, create collision, stale CAS, and cross-session receipts fail closed', () => {
  const fake = new FakeServiceNative();
  const store = bootstrap(fake);
  fake.putRaw('reference', null, 'bot.json', Buffer.from('{"kind":"bad","schemaVersion":1}'));
  assert.throws(() => store.openReadOnly(), (error) => {
    assert.equal(error.code, 'SERVICE_MANUAL_CLEANUP');
    assert.equal(error.writes, 0);
    return true;
  });
  fake.deleteRecord('reference', null, 'bot.json');

  const first = store.openMutation();
  const absent = first.readReferences();
  first.close();
  const second = store.openMutation();
  expectCode(() => second.publishReferences(emptyReferences(), absent), 'SERVICE_STALE');
  const secondAbsent = second.readReferences();
  fake.putRaw('reference', null, 'bot.json', canonicalJsonBytes(emptyReferences()));
  expectCode(() => second.publishReferences(emptyReferences(), secondAbsent), 'SERVICE_ALREADY_EXISTS');
  second.close();
});

test('model: manifest and resource records enforce service, tuple, role, hash, and immutable configuration scope', () => {
  const fake = new FakeServiceNative();
  const store = bootstrap(fake);
  const session = store.openMutation();
  const { resource, manifest } = serviceMetadata();
  session.publishResourceProof('current', resource, session.readResourceProof('current'));
  session.publishManifest('current', manifest, session.readManifest('current'));
  assert.equal(session.readManifest('current').value.configurationFingerprint, manifest.configurationFingerprint);
  const foreignResource = buildServiceResourceProof({
    ...resource,
    rolesFingerprint: hash('f'),
  });
  expectCode(
    () => session.publishResourceProof('previous', foreignResource, session.readResourceProof('previous')),
    'SERVICE_SCOPE_MISMATCH',
  );
  const changedConfiguration = {
    ...linuxBotConfiguration,
    workingDirectory: '/srv/other-bot',
  };
  const changed = serviceMetadata(changedConfiguration).manifest;
  expectCode(
    () => session.publishManifest('previous', changed, session.readManifest('previous')),
    'SERVICE_SCOPE_MISMATCH',
  );
  const wrongTuple = buildServiceManifest({
    ...manifest,
    architecture: 'arm64',
  });
  expectCode(
    () => session.publishManifest('previous', wrongTuple, session.readManifest('previous')),
    'SERVICE_SCOPE_MISMATCH',
  );
  const manifestReceipt = session.readManifest('current');
  session.removeManifest('current', manifestReceipt);
  expectCode(() => session.removeManifest('current', manifestReceipt), 'SERVICE_STALE');
  session.removeResourceProof('current', session.readResourceProof('current'));
  assert.equal(session.readManifest('current').present, false);
  assert.equal(session.readApplicationFloor().floor.highestReservedSequence, 0);
  session.close();
});

test('model: journal append retains history and exact intent/action/observed hash chaining', () => {
  const fake = new FakeServiceNative();
  const store = bootstrap(fake);
  const session = store.openMutation();
  const prepared = transactionFixture();
  session.appendJournal(prepared);
  assert.equal(session.appendJournal(prepared).value.sequence, 1);
  const intent = nextJournal(prepared, 'trial-start-intent', 'intent');
  session.appendJournal(intent);
  const action = nextJournal(intent, 'trial-start-intent', 'action');
  session.appendJournal(action);
  const observed = nextJournal(action, 'trial-start-observed', 'observed');
  session.appendJournal(observed);
  const journal = session.readJournal();
  assert.equal(journal.entries.length, 4);
  assert.equal(journal.head.value.sequence, 4);
  assert.equal(journal.entries[3].previousJournalFingerprint, journal.entries[2].transactionFingerprint);
  session.close();
});

test('model: journal fault after immutable entry write exposes one exact replay and aggregates writes', () => {
  const fake = new FakeServiceNative();
  const store = bootstrap(fake);
  const session = store.openMutation();
  fake.failPublish('entry-0000000000000001.json', 'after');
  const prepared = transactionFixture();
  assert.throws(() => session.appendJournal(prepared), (error) => {
    assert.equal(error.code, 'SERVICE_MANUAL_CLEANUP');
    assert.equal(error.ambiguous, true);
    assert.ok(error.writes > 0);
    return true;
  });
  session.close();

  expectCode(() => store.openMutation(), 'SERVICE_PENDING');
  const replay = store.openRecovery();
  assert.equal(replay.readJournal().pending.transactionFingerprint, prepared.transactionFingerprint);
  const other = transactionFixture({ transactionId: 'tx-other', transactionNonce: '2'.repeat(32) });
  expectCode(() => replay.appendJournal(other), 'SERVICE_PENDING');
  replay.appendJournal(prepared);
  assert.equal(replay.readJournal().head.value.sequence, 1);
  replay.close();
});

test('model: journal rejects nonce changes, immutable tuple forks, cross-transaction jumps, and torn history', () => {
  const fake = new FakeServiceNative();
  const store = bootstrap(fake);
  const session = store.openMutation();
  const prepared = transactionFixture();
  session.appendJournal(prepared);
  const nonceFork = buildServiceTransaction({
    ...prepared,
    transactionNonce: '3'.repeat(32),
    previousJournalFingerprint: prepared.transactionFingerprint,
    phase: 'starting',
    substep: 'intent',
  });
  expectCode(() => session.appendJournal(nonceFork), 'SERVICE_SCOPE_MISMATCH');
  const forkCandidate = buildServiceCandidateProof({
    ...prepared.candidate,
    releaseTreeFingerprint: hash('0'),
  }, 'linux');
  const tupleFork = buildServiceTransaction({
    ...prepared,
    candidate: forkCandidate,
    transition: buildServiceTransitionProof({
      ...prepared.transition,
      candidateFingerprint: forkCandidate.candidateFingerprint,
    }, 'linux'),
    previousJournalFingerprint: prepared.transactionFingerprint,
    phase: 'starting',
    substep: 'intent',
  });
  expectCode(() => session.appendJournal(tupleFork), 'SERVICE_SCOPE_MISMATCH');
  const cross = transactionFixture({
    transactionId: 'tx-2',
    transactionNonce: '4'.repeat(32),
    operation: 'update',
    previousJournalFingerprint: prepared.transactionFingerprint,
  });
  expectCode(() => session.appendJournal(cross), 'SERVICE_SCOPE_MISMATCH');
  session.close();
  fake.deleteRecord('transaction', 'bot', 'entry-0000000000000001.json');
  expectCode(() => store.openReadOnly(), 'SERVICE_MANUAL_CLEANUP');
});

test('model: floor lower/equal conflict, active reservation, update-greater, abandon, and rollback rules are closed', () => {
  const fake = new FakeServiceNative();
  const store = bootstrap(fake);
  const session = store.openMutation();
  const manifest1 = applicationManifest({ sequence: 2, version: '2.0.0', archiveHash: hash('4') });
  const tx1 = transactionFixture({
    candidateManifestFingerprint: manifest1.manifestFingerprint,
    releaseSequence: manifest1.releaseSequence,
  });
  session.reserveApplicationSequence({ manifest: manifest1, transaction: tx1, currentSequence: 0 });
  assert.equal(session.readApplicationFloor().floor.highestReservedSequence, 2);
  const transactionFork = buildServiceTransaction({
    ...tx1,
    transition: buildServiceTransitionProof({
      ...tx1.transition,
      platformResourceFingerprint: hash('0'),
    }, 'linux'),
  });
  expectCode(
    () => session.reserveApplicationSequence({ manifest: manifest1, transaction: transactionFork, currentSequence: 0 }),
    'RELEASE_SEQUENCE_RESERVED',
  );
  const other = transactionFixture({
    transactionId: 'tx-other',
    transactionNonce: '2'.repeat(32),
    candidateManifestFingerprint: manifest1.manifestFingerprint,
    releaseSequence: manifest1.releaseSequence,
  });
  expectCode(() => session.reserveApplicationSequence({ manifest: manifest1, transaction: other, currentSequence: 0 }), 'RELEASE_SEQUENCE_RESERVED');
  session.abandonApplicationSequence({ transaction: tx1 });
  assert.equal(session.readApplicationFloor().floor.highestReservedSequence, 2);
  assert.equal(session.readApplicationFloor().floor.activeReservation, null);
  const conflict = applicationManifest({ sequence: 2, version: '2.0.1', archiveHash: hash('5') });
  const conflictTx = transactionFixture({
    transactionId: 'tx-conflict',
    transactionNonce: '8'.repeat(32),
    candidateManifestFingerprint: conflict.manifestFingerprint,
    releaseSequence: conflict.releaseSequence,
  });
  expectCode(() => session.reserveApplicationSequence({ manifest: conflict, transaction: conflictTx, currentSequence: 0 }), 'RELEASE_SEQUENCE_CONFLICT');
  const lower = applicationManifest({ sequence: 1, version: '1.0.0', archiveHash: hash('6') });
  const lowerTx = transactionFixture({
    transactionId: 'tx-lower',
    transactionNonce: '7'.repeat(32),
    candidateManifestFingerprint: lower.manifestFingerprint,
    releaseSequence: lower.releaseSequence,
  });
  expectCode(() => session.reserveApplicationSequence({ manifest: lower, transaction: lowerTx, currentSequence: 0 }), 'RELEASE_SEQUENCE_DOWNGRADE');
  const update = transactionFixture({
    operation: 'update',
    transactionId: 'tx-update',
    transactionNonce: '3'.repeat(32),
    candidateManifestFingerprint: manifest1.manifestFingerprint,
    releaseSequence: manifest1.releaseSequence,
  });
  expectCode(() => session.reserveApplicationSequence({ manifest: manifest1, transaction: update, currentSequence: 2 }), 'RELEASE_SEQUENCE_NOT_ADVANCING');
  session.close();
  fake.recreateRecordSameBytes('floor', null, 'application-linux-x64.json');
  expectCode(() => store.openReadOnly(), 'SERVICE_MANUAL_CLEANUP');
});

test('model: sibling committed application is reusable above this service and identical Shawl is reusable', () => {
  const linuxFake = new FakeServiceNative();
  const botStore = bootstrap(linuxFake);
  const daemonKey = deriveServiceInstanceKey('daemon sibling');
  const daemonStore = storeFor(linuxFake, { component: 'daemon', hostId: 'daemon sibling' });
  const manifest = applicationManifest({ sequence: 3, version: '3.0.0' });
  const daemonTransaction = transactionFixture({
    component: 'daemon',
    serviceKey: daemonKey,
    transactionId: 'tx-daemon-floor',
    transactionNonce: 'a'.repeat(32),
    candidateManifestFingerprint: manifest.manifestFingerprint,
    releaseSequence: manifest.releaseSequence,
  });
  const identity = linuxFake.seedPublication('releases', manifest.archive.sha256);
  const daemon = daemonStore.openMutation();
  daemon.reserveApplicationSequence({
    manifest,
    transaction: daemonTransaction,
    currentSequence: 0,
  });
  const publication = daemon.observeApplicationPublication(manifest, identity);
  daemon.commitApplicationSequence({ manifest, transaction: daemonTransaction, publication });
  daemon.close();
  const bot = botStore.openMutation();
  const botOld = buildServiceOldProof({
    disposition: 'stable',
    manifestFingerprint: hash('4'),
    resourceProof: hash('5'),
    applicationManifestFingerprint: hash('6'),
    shawlManifestFingerprint: null,
    serviceGeneration: 1,
    activation: 'enabled',
  }, 'linux');
  const botTransaction = transactionFixture({
    operation: 'update',
    serviceGeneration: 2,
    transactionId: 'tx-bot-floor',
    transactionNonce: 'b'.repeat(32),
    old: botOld,
    candidateManifestFingerprint: manifest.manifestFingerprint,
    releaseSequence: manifest.releaseSequence,
  });
  bot.reserveApplicationSequence({
    manifest,
    transaction: botTransaction,
    currentSequence: 1,
  });
  assert.equal(bot.readApplicationFloor().floor.highestReservedSequence, 3);
  bot.abandonApplicationSequence({ transaction: botTransaction });
  bot.close();

  const windowsFake = new FakeServiceNative('win32');
  const windowsBotStore = bootstrap(windowsFake);
  const windowsDaemonKey = deriveServiceInstanceKey('windows daemon sibling');
  const windowsDaemonStore = storeFor(
    windowsFake,
    { component: 'daemon', hostId: 'windows daemon sibling' },
  );
  const windowsApplication = applicationManifest({
    sequence: 3,
    version: '3.0.0',
    platform: 'win32',
  });
  const shawl = shawlManifest({ sequence: 7 });
  const windowsDaemonTransaction = transactionFixture({
    component: 'daemon',
    serviceKey: windowsDaemonKey,
    transactionId: 'tx-windows-daemon',
    transactionNonce: 'c'.repeat(32),
    candidateManifestFingerprint: windowsApplication.manifestFingerprint,
    releaseSequence: windowsApplication.releaseSequence,
    platform: 'win32',
    shawlManifestFingerprint: shawl.manifestFingerprint,
  });
  const appIdentity = windowsFake.seedApplicationPublication(windowsApplication);
  const shawlIdentity = windowsFake.seedShawlPublication(shawl);
  const windowsDaemon = windowsDaemonStore.openMutation();
  windowsDaemon.reserveApplicationSequence({
    manifest: windowsApplication,
    transaction: windowsDaemonTransaction,
    currentSequence: 0,
  });
  windowsDaemon.reserveShawlSequence({
    manifest: shawl,
    transaction: windowsDaemonTransaction,
    currentSequence: 0,
  });
  windowsDaemon.commitApplicationSequence({
    manifest: windowsApplication,
    transaction: windowsDaemonTransaction,
    publication: windowsDaemon.observeApplicationPublication(windowsApplication, appIdentity),
  });
  windowsDaemon.commitShawlSequence({
    manifest: shawl,
    transaction: windowsDaemonTransaction,
    publication: windowsDaemon.observeShawlPublication(shawl, shawlIdentity),
  });
  windowsDaemon.close();
  const windowsBot = windowsBotStore.openMutation();
  const windowsOld = buildServiceOldProof({
    disposition: 'stable',
    manifestFingerprint: hash('7'),
    resourceProof: hash('8'),
    applicationManifestFingerprint: hash('9'),
    shawlManifestFingerprint: shawl.manifestFingerprint,
    serviceGeneration: 1,
    activation: 'enabled',
  }, 'win32');
  const windowsBotTransaction = transactionFixture({
    operation: 'update',
    serviceGeneration: 2,
    transactionId: 'tx-windows-bot',
    transactionNonce: 'd'.repeat(32),
    old: windowsOld,
    candidateManifestFingerprint: windowsApplication.manifestFingerprint,
    releaseSequence: windowsApplication.releaseSequence,
    platform: 'win32',
    shawlManifestFingerprint: shawl.manifestFingerprint,
  });
  windowsBot.reserveShawlSequence({
    manifest: shawl,
    transaction: windowsBotTransaction,
    currentSequence: 7,
  });
  windowsBot.abandonShawlSequence({ transaction: windowsBotTransaction });
  windowsBot.close();
});

test('model: recovery resolves floor authority across exact retained journal phases', () => {
  const fake = new FakeServiceNative();
  const store = bootstrap(fake);
  const manifest = applicationManifest({ sequence: 4, version: '4.0.0' });
  const identity = fake.seedPublication('releases', manifest.archive.sha256);
  const prepared = transactionFixture({
    transactionId: 'tx-integrated-floor',
    transactionNonce: '4'.repeat(32),
    candidateManifestFingerprint: manifest.manifestFingerprint,
    releaseSequence: manifest.releaseSequence,
    releaseTreeFingerprint: manifest.inventory.treeFingerprint,
  });
  const session = store.openMutation();
  session.appendJournal(prepared);
  session.reserveApplicationSequence({
    manifest,
    transaction: prepared,
    currentSequence: 0,
  });
  const reserved = nextJournal(prepared, 'sequence-reserved', 'observed');
  session.appendJournal(reserved);
  session.close();

  const recovery = store.openRecovery();
  const published = nextJournal(reserved, 'release-published', 'observed');
  recovery.appendJournal(published);
  const publication = recovery.observeApplicationPublication(manifest, identity);
  recovery.commitApplicationSequence({
    manifest,
    transaction: published,
    publication,
  });
  const floor = recovery.readApplicationFloor().floor;
  assert.equal(floor.activeReservation, null);
  assert.equal(floor.committedTransactionFingerprint, published.transactionFingerprint);
  assert.equal(recovery.readJournal().head.value.transactionFingerprint, published.transactionFingerprint);
  recovery.close();
});

test('model: journal-only recovery advances one logical transaction without freezing its phase hash', () => {
  const fake = new FakeServiceNative();
  const store = bootstrap(fake);
  const prepared = transactionFixture({
    transactionId: 'tx-journal-only',
    transactionNonce: '5'.repeat(32),
  });
  const session = store.openMutation();
  session.appendJournal(prepared);
  session.close();

  const recovery = store.openRecovery();
  const forkCandidate = buildServiceCandidateProof({
    ...prepared.candidate,
    releaseTreeFingerprint: hash('0'),
  }, 'linux');
  const identityFork = buildServiceTransaction({
    ...prepared,
    candidate: forkCandidate,
    transition: buildServiceTransitionProof({
      ...prepared.transition,
      candidateFingerprint: forkCandidate.candidateFingerprint,
    }, 'linux'),
    phase: 'sequence-reserved',
    substep: 'observed',
    previousJournalFingerprint: prepared.transactionFingerprint,
  });
  expectCode(() => recovery.appendJournal(identityFork), 'SERVICE_PENDING');
  const advanced = nextJournal(prepared, 'sequence-reserved', 'observed');
  recovery.appendJournal(advanced);
  assert.equal(
    recovery.readJournal().head.value.transactionFingerprint,
    advanced.transactionFingerprint,
  );
  recovery.close();
});

test('model: floor-only recovery remains exact replay authority and cannot mint journal authority', () => {
  const fake = new FakeServiceNative();
  const store = bootstrap(fake);
  const manifest = applicationManifest({ sequence: 2, version: '2.0.0' });
  const transaction = transactionFixture({
    transactionId: 'tx-floor-only',
    transactionNonce: '6'.repeat(32),
    candidateManifestFingerprint: manifest.manifestFingerprint,
    releaseSequence: manifest.releaseSequence,
    releaseTreeFingerprint: manifest.inventory.treeFingerprint,
  });
  const envelope = signedEnvelope('application', manifest);
  const session = store.openMutation();
  session.reserveApplicationSequence({
    manifest,
    transaction,
    currentSequence: 0,
  });
  session.close();

  let recovery = store.openRecovery();
  let beforeWrites = recovery.writes;
  expectCode(() => recovery.appendJournal(transaction), 'SERVICE_PENDING');
  expectCode(
    () => recovery.retainDeploymentEnvelope({ ...envelope, transaction }),
    'SERVICE_PENDING',
  );
  assert.equal(recovery.writes, beforeWrites);
  recovery.reserveApplicationSequence({
    manifest,
    transaction,
    currentSequence: 0,
  });
  recovery.close();

  recovery = store.openRecovery();
  beforeWrites = recovery.writes;
  expectCode(() => recovery.appendJournal(transaction), 'SERVICE_PENDING');
  expectCode(
    () => recovery.retainDeploymentEnvelope({ ...envelope, transaction }),
    'SERVICE_PENDING',
  );
  assert.equal(recovery.writes, beforeWrites);
  recovery.close();
});

test('model: recovery floor transition requires that exact phase record before a new scope', () => {
  const fake = new FakeServiceNative('win32');
  const store = bootstrap(fake);
  const application = applicationManifest({
    sequence: 2,
    version: '2.0.0',
    platform: 'win32',
  });
  const shawl = shawlManifest({ sequence: 3 });
  const prepared = transactionFixture({
    transactionId: 'tx-retained-before-floor',
    transactionNonce: '7'.repeat(32),
    candidateManifestFingerprint: application.manifestFingerprint,
    releaseSequence: application.releaseSequence,
    releaseTreeFingerprint: application.inventory.treeFingerprint,
    platform: 'win32',
    shawlManifestFingerprint: shawl.manifestFingerprint,
  });
  const session = store.openMutation();
  session.appendJournal(prepared);
  session.close();

  const recovery = store.openRecovery();
  const next = nextJournal(prepared, 'sequence-reserved', 'observed');
  const beforeWrites = recovery.writes;
  expectCode(
    () => recovery.reserveShawlSequence({
      manifest: shawl,
      transaction: next,
      currentSequence: 0,
    }),
    'SERVICE_PENDING',
  );
  assert.equal(recovery.writes, beforeWrites);
  recovery.appendJournal(next);
  recovery.reserveShawlSequence({
    manifest: shawl,
    transaction: next,
    currentSequence: 0,
  });
  assert.equal(
    recovery.readShawlFloor().floor.activeReservation.transactionFingerprint,
    next.transactionFingerprint,
  );
  recovery.close();
});

test('model: floor intent/file/stable crash boundary admits only the exact transaction replay', () => {
  const fake = new FakeServiceNative();
  const store = bootstrap(fake);
  const session = store.openMutation();
  const manifest = applicationManifest({ sequence: 2, version: '2.0.0' });
  const tx = transactionFixture({
    transactionId: 'tx-floor',
    transactionNonce: '5'.repeat(32),
    candidateManifestFingerprint: manifest.manifestFingerprint,
    releaseSequence: manifest.releaseSequence,
  });
  fake.failPublish('application-linux-x64.json');
  assert.throws(() => session.reserveApplicationSequence({ manifest, transaction: tx, currentSequence: 0 }), (error) => {
    assert.equal(error.code, 'SERVICE_IO_FAILED');
    assert.ok(error.writes > 0);
    return true;
  });
  session.close();
  assert.throws(() => store.openMutation(), (error) => {
    assert.equal(error.code, 'SERVICE_PENDING');
    assert.equal(error.writes, 0);
    return true;
  });
  const pending = store.openRecovery();
  assert.equal(pending.readApplicationFloor().pending, true);
  expectCode(() => pending.appendJournal(tx), 'SERVICE_PENDING');
  const other = transactionFixture({
    transactionId: 'tx-other',
    transactionNonce: '6'.repeat(32),
    candidateManifestFingerprint: manifest.manifestFingerprint,
    releaseSequence: manifest.releaseSequence,
  });
  expectCode(() => pending.reserveApplicationSequence({ manifest, transaction: other, currentSequence: 0 }), 'SERVICE_PENDING');
  pending.reserveApplicationSequence({ manifest, transaction: tx, currentSequence: 0 });
  assert.equal(pending.readApplicationFloor().pending, false);
  expectCode(() => pending.appendJournal(tx), 'SERVICE_PENDING');
  pending.close();

  const directoryFake = new FakeServiceNative();
  const directoryStore = bootstrap(directoryFake);
  const directoryManifest = applicationManifest({ sequence: 5, version: '5.0.0' });
  const directoryTransaction = transactionFixture({
    transactionId: 'tx-directory-intent',
    transactionNonce: '9'.repeat(32),
    candidateManifestFingerprint: directoryManifest.manifestFingerprint,
    releaseSequence: directoryManifest.releaseSequence,
  });
  const directorySession = directoryStore.openMutation();
  directoryFake.failDirectory(floorHistoryDirectoryName(
    'application:linux:x64',
    1,
    'reserve',
    directoryTransaction,
  ));
  assert.throws(
    () => directorySession.reserveApplicationSequence({
      manifest: directoryManifest,
      transaction: directoryTransaction,
      currentSequence: 0,
    }),
    (error) => error.code === 'SERVICE_MANUAL_CLEANUP' && error.writes > 0,
  );
  directorySession.close();
  expectCode(() => directoryStore.openMutation(), 'SERVICE_PENDING');
  const directoryRecovery = directoryStore.openRecovery();
  expectCode(
    () => directoryRecovery.reserveApplicationSequence({
      manifest: directoryManifest,
      transaction: transactionFixture({
        transactionId: 'tx-wrong-directory',
        transactionNonce: '8'.repeat(32),
        candidateManifestFingerprint: directoryManifest.manifestFingerprint,
        releaseSequence: directoryManifest.releaseSequence,
      }),
      currentSequence: 0,
    }),
    'SERVICE_PENDING',
  );
  directoryRecovery.reserveApplicationSequence({
    manifest: directoryManifest,
    transaction: directoryTransaction,
    currentSequence: 0,
  });
  directoryRecovery.close();

  const stateFake = new FakeServiceNative();
  const stateStore = bootstrap(stateFake);
  const stateManifest = applicationManifest({ sequence: 6, version: '6.0.0' });
  const stateTransaction = transactionFixture({
    transactionId: 'tx-state-intent',
    transactionNonce: 'a'.repeat(32),
    candidateManifestFingerprint: stateManifest.manifestFingerprint,
    releaseSequence: stateManifest.releaseSequence,
  });
  const stateSession = stateStore.openMutation();
  stateFake.failPublish(SERVICE_STORE_LAYOUT.floorHistoryState);
  assert.throws(
    () => stateSession.reserveApplicationSequence({
      manifest: stateManifest,
      transaction: stateTransaction,
      currentSequence: 0,
    }),
    (error) => error.code === 'SERVICE_IO_FAILED' && error.writes > 0,
  );
  stateSession.close();
  expectCode(() => stateStore.openMutation(), 'SERVICE_PENDING');
  const stateRecovery = stateStore.openRecovery();
  stateRecovery.reserveApplicationSequence({
    manifest: stateManifest,
    transaction: stateTransaction,
    currentSequence: 0,
  });
  assert.equal(stateRecovery.readApplicationFloor().pending, false);
  stateRecovery.close();
});

test('model: floor replay also closes an observed primary update with a missing stable witness receipt', () => {
  const fake = new FakeServiceNative();
  const store = bootstrap(fake);
  const manifest = applicationManifest({ sequence: 4, version: '4.0.0' });
  const transaction = transactionFixture({
    transactionId: 'tx-floor-observed',
    transactionNonce: 'a'.repeat(32),
    candidateManifestFingerprint: manifest.manifestFingerprint,
    releaseSequence: manifest.releaseSequence,
  });
  const session = store.openMutation();
  fake.failPublish('application-linux-x64.witness.json', 'before', 3);
  assert.throws(
    () => session.reserveApplicationSequence({ manifest, transaction, currentSequence: 0 }),
    (error) => error.code === 'SERVICE_IO_FAILED' && error.writes > 0,
  );
  session.close();
  expectCode(() => store.openMutation(), 'SERVICE_PENDING');
  const recovery = store.openRecovery();
  assert.equal(recovery.readApplicationFloor().floor.highestReservedSequence, 4);
  assert.equal(recovery.readApplicationFloor().pending, true);
  recovery.reserveApplicationSequence({ manifest, transaction, currentSequence: 0 });
  assert.equal(recovery.readApplicationFloor().pending, false);
  recovery.close();
});

test('model: sequence commit requires same-session re-opened immutable publication and rollback does not rewind', () => {
  const fake = new FakeServiceNative();
  const store = bootstrap(fake);
  const manifest = applicationManifest({ sequence: 3, version: '3.0.0' });
  const retained = applicationManifest({ sequence: 1, version: '1.0.0', archiveHash: hash('8') });
  const identity = fake.seedPublication('releases', manifest.archive.sha256);
  let session = store.openMutation();
  const tx = transactionFixture({
    transactionId: 'tx-commit',
    transactionNonce: '7'.repeat(32),
    candidateManifestFingerprint: manifest.manifestFingerprint,
    releaseSequence: manifest.releaseSequence,
  });
  session.appendJournal(tx);
  session.reserveApplicationSequence({ manifest, transaction: tx, currentSequence: 0 });
  const crossSessionPublication = session.observeApplicationPublication(manifest, identity);
  session.close();
  expectCode(() => store.openMutation(), 'SERVICE_PENDING');
  session = store.openRecovery();
  const recoveryPublication = session.observeApplicationPublication(manifest, identity);
  expectCode(
    () => session.commitApplicationSequence({ manifest, transaction: tx, publication: crossSessionPublication }),
    'SERVICE_STALE',
  );
  expectCode(() => session.commitApplicationSequence({ manifest, transaction: tx, publication: { binding: recoveryPublication.binding } }), 'SERVICE_STALE');
  session.commitApplicationSequence({ manifest, transaction: tx, publication: recoveryPublication });
  session.commitApplicationSequence({ manifest, transaction: tx, publication: recoveryPublication });
  const committed = session.readApplicationFloor().floor;
  assert.equal(committed.committedSequence, 3);
  assert.equal(committed.activeReservation, null);
  session.close();

  const rollbackFake = new FakeServiceNative();
  const rollbackStore = bootstrap(rollbackFake);
  const rollbackIdentity = rollbackFake.seedPublication('releases', manifest.archive.sha256);
  const rollbackRetainedIdentity = rollbackFake.seedPublication('releases', retained.archive.sha256);
  session = rollbackStore.openMutation();
  session.reserveApplicationSequence({ manifest, transaction: tx, currentSequence: 0 });
  const publication = session.observeApplicationPublication(manifest, rollbackIdentity);
  const retainedPublication = session.observeApplicationPublication(retained, rollbackRetainedIdentity);
  session.commitApplicationSequence({ manifest, transaction: tx, publication });
  const rollbackFloor = session.readApplicationFloor().floor;
  const currentSlot = buildServiceReferenceSlot({
    serviceGeneration: 2,
    transactionId: 'tx-current-release',
    transactionNonce: 'b'.repeat(32),
    artifacts: [publication.binding],
  }, { platform: 'linux', component: 'bot' });
  const previousSlot = buildServiceReferenceSlot({
    serviceGeneration: 1,
    transactionId: 'tx-retained-release',
    transactionNonce: 'c'.repeat(32),
    artifacts: [retainedPublication.binding],
  }, { platform: 'linux', component: 'bot' });
  const provisionalSlot = currentSlot;
  let referenceReceipt = session.readReferences();
  referenceReceipt = session.publishReferences(buildServiceReferenceRecord({
    serviceKey: 'bot',
    component: 'bot',
    platform: 'linux',
    architecture: 'x64',
    serviceGeneration: 0,
    current: null,
    previous: null,
    provisional: previousSlot,
  }), referenceReceipt);
  referenceReceipt = session.publishReferences(buildServiceReferenceRecord({
    serviceKey: 'bot',
    component: 'bot',
    platform: 'linux',
    architecture: 'x64',
    serviceGeneration: 1,
    current: previousSlot,
    previous: null,
    provisional: null,
  }), referenceReceipt);
  referenceReceipt = session.publishReferences(buildServiceReferenceRecord({
    serviceKey: 'bot',
    component: 'bot',
    platform: 'linux',
    architecture: 'x64',
    serviceGeneration: 1,
    current: previousSlot,
    previous: null,
    provisional: provisionalSlot,
  }), referenceReceipt);
  session.publishReferences(buildServiceReferenceRecord({
    serviceKey: 'bot',
    component: 'bot',
    platform: 'linux',
    architecture: 'x64',
    serviceGeneration: 2,
    current: currentSlot,
    previous: previousSlot,
    provisional: null,
  }), referenceReceipt);
  const before = rollbackFloor.floorFingerprint;
  assert.equal(session.assertApplicationRollback({
    manifest: retained,
    publication: retainedPublication,
  }).retainedSequence, 1);
  assert.equal(session.readApplicationFloor().floor.floorFingerprint, before);
  session.close();
});

test('model: Windows location planning is closed, pinned, pre-publication, and matches the observed native path', () => {
  const fake = new FakeServiceNative('win32');
  const store = bootstrap(fake);
  const manifest = applicationManifest({ platform: 'win32' });
  const session = store.openMutation();
  const beforeWrites = session.writes;
  const beforeNativeWrites = fake.totalWrites;
  const intent = session.planArtifactLocation({
    purpose: 'application',
    manifest,
    relativePath: 'bot/src/bot.js',
  });
  assert.equal(Object.isFrozen(intent), true);
  assert.equal(intent.rootKind, 'releases');
  assert.equal(intent.relativePath, 'bot/src/bot.js');
  assert.equal(session.writes, beforeWrites);
  assert.equal(fake.totalWrites, beforeNativeWrites);

  const planCalls = fake.calls.filter((call) => call.startsWith('plan-location:')).length;
  expectCode(() => session.planArtifactLocation({
    purpose: 'application',
    manifest: clone(manifest),
    relativePath: 'bot/src/bot.js',
  }), 'DEPLOYMENT_PINNED_PROVENANCE_REQUIRED');
  expectCode(() => session.planArtifactLocation({
    purpose: 'application',
    manifest,
    relativePath: 'Bot/src/bot.js',
  }), 'SERVICE_SCOPE_MISMATCH');
  expectCode(() => session.planArtifactLocation({
    purpose: 'application',
    manifest,
    relativePath: 'bot/src/bot.js',
  }, 'caller-root-is-not-accepted'), 'SERVICE_INVALID');
  expectCode(() => session.planArtifactLocation({
    purpose: 'application',
    manifest,
    relativePath: 'bot/src/bot.js',
    absoluteRoot: 'C:\\caller-selected-root',
  }), 'SERVICE_INVALID');
  assert.equal(
    fake.calls.filter((call) => call.startsWith('plan-location:')).length,
    planCalls,
  );
  assert.equal(session.writes, beforeWrites);
  assert.equal(fake.totalWrites, beforeNativeWrites);

  const identity = fake.seedApplicationPublication(manifest);
  const publication = session.observeApplicationPublication(manifest, identity);
  const entrypoint = publication.locations.find((location) =>
    location.publishedPath === 'bot/src/bot.js');
  assert.ok(entrypoint);
  assert.equal(entrypoint.absolutePath, intent.absolutePath);
  assert.equal(entrypoint.fileSha256, applicationInventory('win32').inventory.payloadEntries
    .find((record) => record.path === 'bot/src/bot.js').sha256);
  assert.equal(Object.isFrozen(entrypoint), true);
  assert.deepEqual(entrypoint.binding, publication.binding);
  session.close();

  const incompleteNative = { ...fake.facade };
  delete incompleteNative.plan_service_artifact_location;
  assert.throws(
    () => createServiceStore({
      native: incompleteNative,
      roles: windowsRoles,
      target: { component: 'bot' },
      platform: 'win32',
      architecture: 'x64',
    }),
    (error) => error.code === 'SERVICE_INVALID',
  );
});

test('model: retained Windows publication receipts resolve signed application and Shawl locations', () => {
  const fake = new FakeServiceNative('win32');
  const store = bootstrap(fake);
  const application = applicationManifest({ platform: 'win32' });
  const shawl = shawlManifest();
  const applicationIdentity = fake.seedApplicationPublication(application);
  const shawlIdentity = fake.seedShawlPublication(shawl);
  const session = store.openMutation();
  const installed = publishCommittedWindowsInstallation(
    session,
    application,
    applicationIdentity,
    shawl,
    shawlIdentity,
    {
      transactionId: 'tx-retained-locations',
      transactionNonce: 'b'.repeat(32),
      retainedEnvelopes: [
        signedEnvelope('application', application),
        signedEnvelope('shawl', shawl),
      ],
    },
  );

  const appReceipt = session.readPublicationReceipt({
    slot: 'current',
    artifactKind: 'application',
  });
  const shawlReceipt = session.readPublicationReceipt({
    slot: 'current',
    artifactKind: 'shawl',
  });
  assert.deepEqual(
    appReceipt.locations.map((location) => location.publishedPath),
    ['bot/src/bot.js', 'native-control/build/Release/native-control.manifest.json'],
  );
  assert.equal(shawlReceipt.locations.length, 1);
  assert.equal(shawlReceipt.locations[0].publishedPath, 'shawl.exe');
  assert.equal(shawlReceipt.locations[0].fileSha256, shawl.executable.sha256);
  assert.equal(Object.isFrozen(appReceipt.locations), true);
  assert.equal(Object.isFrozen(shawlReceipt.locations[0]), true);
  expectCode(() => session.commitApplicationSequence({
    manifest: application,
    transaction: installed.transaction,
    publication: clone(appReceipt),
  }), 'SERVICE_STALE');

  const alternate = applicationManifest({
    sequence: 2,
    version: '2.0.0',
    platform: 'win32',
    archiveHash: hash('4'),
  });
  const alternateIdentity = fake.seedApplicationPublication(alternate);
  const alternateBinding = session.observeApplicationPublication(
    alternate,
    alternateIdentity,
  ).binding;
  const references = session.readReferences();
  const provisional = buildServiceReferenceSlot({
    serviceGeneration: 2,
    transactionId: 'tx-reference-cas',
    transactionNonce: 'c'.repeat(32),
    artifacts: [alternateBinding, installed.supervisor],
  }, { platform: 'win32', component: 'bot' });
  const rewrittenReferences = buildServiceReferenceRecord({
    ...references.value,
    provisional,
  });
  const storedReferences = fake.namespace('reference').entries.get('bot.json');
  storedReferences.bytes = canonicalJsonBytes(rewrittenReferences);
  storedReferences.facts = fake.facts(storedReferences.identity, storedReferences.bytes);
  expectCode(() => session.commitApplicationSequence({
    manifest: application,
    transaction: installed.transaction,
    publication: appReceipt,
  }), 'SERVICE_STALE');
  session.close();
});

test('model: Windows native path resolution rejects changed roots, hashes, and reparse components', () => {
  const observe = (mutate) => {
    const fake = new FakeServiceNative('win32');
    const store = bootstrap(fake);
    const manifest = applicationManifest({ platform: 'win32' });
    const identity = fake.seedApplicationPublication(manifest);
    const target = fake.roots.get('releases').node.entries.get(
      manifest.archive.sha256,
    );
    mutate(fake, target);
    const session = store.openMutation();
    const beforeWrites = fake.totalWrites;
    expectCode(
      () => session.observeApplicationPublication(manifest, identity),
      'SERVICE_STALE',
    );
    assert.equal(fake.totalWrites, beforeWrites);
    session.close();
  };

  observe((fake, target) => {
    target.identity = fake.identity('service-release-directory', target.identity);
  });
  observe((_fake, target) => {
    target.entries.get('bot').entries.get('src').entries.get('bot.js')
      .facts.sha256 = hash('e');
  });
  observe((_fake, target) => {
    target.entries.get('bot').entries.get('src').reparse = true;
  });
});

test('model: Windows application and Shawl floors reserve and commit independently', () => {
  const fake = new FakeServiceNative('win32');
  const store = bootstrap(fake);
  const application = applicationManifest({
    sequence: 2,
    version: '2.0.0',
    archiveHash: hash('4'),
    platform: 'win32',
  });
  const shawl = shawlManifest({ sequence: 7 });
  const transaction = transactionFixture({
    transactionId: 'tx-windows',
    transactionNonce: '8'.repeat(32),
    candidateManifestFingerprint: application.manifestFingerprint,
    releaseSequence: application.releaseSequence,
    platform: 'win32',
    shawlManifestFingerprint: shawl.manifestFingerprint,
  });
  const applicationIdentity = fake.seedApplicationPublication(application);
  const shawlIdentity = fake.seedShawlPublication(shawl);
  const session = store.openMutation();
  session.reserveApplicationSequence({ manifest: application, transaction, currentSequence: 0 });
  session.reserveShawlSequence({ manifest: shawl, transaction, currentSequence: 0 });
  const applicationPublication = session.observeApplicationPublication(application, applicationIdentity);
  const shawlPublication = session.observeShawlPublication(shawl, shawlIdentity);
  session.commitApplicationSequence({ manifest: application, transaction, publication: applicationPublication });
  session.commitShawlSequence({ manifest: shawl, transaction, publication: shawlPublication });
  assert.equal(session.readApplicationFloor().floor.committedSequence, 2);
  assert.equal(session.readShawlFloor().floor.committedSequence, 7);
  assert.notEqual(
    session.readApplicationFloor().floor.committedPublicationFingerprint,
    session.readShawlFloor().floor.committedPublicationFingerprint,
  );
  session.close();
});

test('model: recovery binds every global scope to one service and exact full transaction', () => {
  const fake = new FakeServiceNative('win32');
  const botStore = bootstrap(fake);
  const daemonStore = storeFor(fake, { component: 'daemon', hostId: 'recovery sibling' });
  const daemonSeed = daemonStore.openMutation();
  daemonSeed.close();
  const application = applicationManifest({
    sequence: 2,
    version: '2.0.0',
    platform: 'win32',
  });
  const shawl = shawlManifest({ sequence: 4 });
  const transaction = transactionFixture({
    transactionId: 'tx-cross-scope',
    transactionNonce: 'e'.repeat(32),
    candidateManifestFingerprint: application.manifestFingerprint,
    releaseSequence: application.releaseSequence,
    platform: 'win32',
    shawlManifestFingerprint: shawl.manifestFingerprint,
  });
  const session = botStore.openMutation();
  session.appendJournal(transaction);
  session.reserveApplicationSequence({ manifest: application, transaction, currentSequence: 0 });
  session.close();
  expectCode(() => daemonStore.openRecovery(), 'SERVICE_PENDING');
  const recovery = botStore.openRecovery();
  const other = transactionFixture({
    transactionId: 'tx-other-scope',
    transactionNonce: 'f'.repeat(32),
    candidateManifestFingerprint: application.manifestFingerprint,
    releaseSequence: application.releaseSequence,
    platform: 'win32',
    shawlManifestFingerprint: shawl.manifestFingerprint,
  });
  expectCode(
    () => recovery.reserveShawlSequence({ manifest: shawl, transaction: other, currentSequence: 0 }),
    'SERVICE_PENDING',
  );
  recovery.reserveShawlSequence({ manifest: shawl, transaction, currentSequence: 0 });
  recovery.abandonShawlSequence({ transaction });
  recovery.abandonApplicationSequence({ transaction });
  recovery.close();
});

test('model: current/previous/provisional references require observed artifacts and protect sibling services', () => {
  const fake = new FakeServiceNative();
  const botStore = bootstrap(fake);
  const previousManifest = applicationManifest({ sequence: 1, version: '1.0.0', archiveHash: hash('4') });
  const manifest = applicationManifest({ sequence: 2, version: '2.0.0', archiveHash: hash('5') });
  const candidateManifest = applicationManifest({ sequence: 3, version: '3.0.0', archiveHash: hash('6') });
  const previousIdentity = fake.seedPublication('releases', previousManifest.archive.sha256);
  const identity = fake.seedPublication('releases', manifest.archive.sha256);
  const candidateIdentity = fake.seedPublication('releases', candidateManifest.archive.sha256);
  const bot = botStore.openMutation();
  const previousApplication = bot.observeApplicationPublication(previousManifest, previousIdentity).binding;
  const application = bot.observeApplicationPublication(manifest, identity).binding;
  const candidateApplication = bot.observeApplicationPublication(candidateManifest, candidateIdentity).binding;
  const current = buildServiceReferenceSlot({
    serviceGeneration: 2,
    transactionId: 'tx-current',
    transactionNonce: '1'.repeat(32),
    artifacts: [application],
  }, { platform: 'linux', component: 'bot' });
  const previous = buildServiceReferenceSlot({
    serviceGeneration: 1,
    transactionId: 'tx-previous',
    transactionNonce: '9'.repeat(32),
    artifacts: [previousApplication],
  }, { platform: 'linux', component: 'bot' });
  const provisional = buildServiceReferenceSlot({
    serviceGeneration: 3,
    transactionId: 'tx-next',
    transactionNonce: '2'.repeat(32),
    artifacts: [candidateApplication],
  }, { platform: 'linux', component: 'bot' });
  let referenceReceipt = bot.readReferences();
  referenceReceipt = bot.publishReferences(buildServiceReferenceRecord({
    serviceKey: 'bot', component: 'bot', platform: 'linux', architecture: 'x64', serviceGeneration: 0,
    current: null, previous: null, provisional: previous,
  }), referenceReceipt);
  referenceReceipt = bot.publishReferences(buildServiceReferenceRecord({
    serviceKey: 'bot', component: 'bot', platform: 'linux', architecture: 'x64', serviceGeneration: 1,
    current: previous, previous: null, provisional: null,
  }), referenceReceipt);
  referenceReceipt = bot.publishReferences(buildServiceReferenceRecord({
    serviceKey: 'bot', component: 'bot', platform: 'linux', architecture: 'x64', serviceGeneration: 1,
    current: previous, previous: null, provisional: current,
  }), referenceReceipt);
  referenceReceipt = bot.publishReferences(buildServiceReferenceRecord({
    serviceKey: 'bot', component: 'bot', platform: 'linux', architecture: 'x64', serviceGeneration: 2,
    current, previous, provisional: null,
  }), referenceReceipt);
  const record = buildServiceReferenceRecord({
    serviceKey: 'bot', component: 'bot', platform: 'linux', architecture: 'x64', serviceGeneration: 2,
    current, previous, provisional,
  });
  referenceReceipt = bot.publishReferences(record, referenceReceipt);
  const driftedCurrent = buildServiceReferenceSlot({
    ...current,
    transactionId: 'tx-current-drift',
  }, { platform: 'linux', component: 'bot' });
  expectCode(
    () => bot.publishReferences(buildServiceReferenceRecord({
      ...record,
      current: driftedCurrent,
    }), referenceReceipt),
    'SERVICE_SCOPE_MISMATCH',
  );
  const driftedPrevious = buildServiceReferenceSlot({
    ...current,
    transactionNonce: '8'.repeat(32),
  }, { platform: 'linux', component: 'bot' });
  expectCode(
    () => bot.publishReferences(buildServiceReferenceRecord({
      serviceKey: 'bot',
      component: 'bot',
      platform: 'linux',
      architecture: 'x64',
      serviceGeneration: 3,
      current: provisional,
      previous: driftedPrevious,
      provisional: null,
    }), referenceReceipt),
    'SERVICE_SCOPE_MISMATCH',
  );
  bot.close();

  const inventoryFake = new FakeServiceNative();
  const inventoryBotStore = bootstrap(inventoryFake);
  const sharedArchiveHash = hash('7');
  const botDeployment = applicationManifest({
    sequence: 4,
    version: '4.0.0',
    archiveHash: sharedArchiveHash,
  });
  const daemonDeployment = applicationManifest({
    sequence: 5,
    version: '5.0.0',
    archiveHash: sharedArchiveHash,
  });
  const unreferencedProvenance = applicationManifest({
    sequence: 6,
    version: '6.0.0',
    archiveHash: sharedArchiveHash,
  });
  const sharedIdentity = inventoryFake.seedPublication('releases', sharedArchiveHash);
  const inventoryBot = inventoryBotStore.openMutation();
  publishCommittedInstallation(inventoryBot, botDeployment, sharedIdentity, {
    transactionId: 'tx-inventory-bot',
    transactionNonce: '4'.repeat(32),
  });
  const physicalCandidate = inventoryBot.observeApplicationPublication(
    unreferencedProvenance,
    sharedIdentity,
  ).binding;
  inventoryBot.close();
  const inventoryDaemonKey = deriveServiceInstanceKey('inventory daemon');
  const inventoryDaemonStore = storeFor(
    inventoryFake,
    { component: 'daemon', hostId: 'inventory daemon' },
  );
  const inventoryDaemon = inventoryDaemonStore.openMutation();
  publishCommittedInstallation(inventoryDaemon, daemonDeployment, sharedIdentity, {
    transactionId: 'tx-inventory-daemon',
    transactionNonce: '5'.repeat(32),
    component: 'daemon',
    serviceKey: inventoryDaemonKey,
  });
  inventoryDaemon.close();
  const scanner = inventoryBotStore.openMutation();
  expectCode(() => scanner.observeZeroReferences(physicalCandidate), 'SERVICE_REFERENCED');
  const unrelatedDeployment = applicationManifest({
    sequence: 7,
    version: '7.0.0',
    archiveHash: hash('8'),
  });
  const unrelatedIdentity = inventoryFake.seedPublication(
    'releases',
    unrelatedDeployment.archive.sha256,
  );
  const unrelated = scanner.observeApplicationPublication(
    unrelatedDeployment,
    unrelatedIdentity,
  ).binding;
  const observation = scanner.observeZeroReferences(unrelated);
  assert.equal(observation.artifactRootKind, 'releases');
  assert.equal(observation.artifactFingerprint, unrelatedDeployment.archive.sha256);
  assert.equal(
    observation.artifactDirectoryIdentityFingerprint,
    unrelated.directoryIdentityFingerprint,
  );
  assert.equal(Object.hasOwn(observation, 'allowed'), false);
  assert.equal(Object.hasOwn(observation, 'permission'), false);
  const conflictingIdentity = inventoryFake.identity('service-release-directory');
  const conflicting = buildServiceArtifactBinding({
    ...physicalCandidate,
    directoryIdentity: conflictingIdentity,
    directoryIdentityFingerprint: canonicalJsonHash(conflictingIdentity),
  }, 'linux');
  expectCode(() => scanner.observeZeroReferences(conflicting), 'SERVICE_MANUAL_CLEANUP');
  scanner.close();
  inventoryFake.deleteRecord('reference', null, `${inventoryDaemonKey}.json`);
  const incompleteScanner = inventoryBotStore.openMutation();
  expectCode(
    () => incompleteScanner.observeZeroReferences(physicalCandidate),
    'SERVICE_MANUAL_CLEANUP',
  );
  incompleteScanner.close();
});

test('model: surviving committed journal refuses lost current metadata and lost reference inventory', () => {
  const lostCurrentFake = new FakeServiceNative();
  const lostCurrentStore = bootstrap(lostCurrentFake);
  const deployment = applicationManifest();
  const identity = lostCurrentFake.seedPublication('releases', deployment.archive.sha256);
  const installed = lostCurrentStore.openMutation();
  publishCommittedInstallation(installed, deployment, identity);
  installed.close();
  lostCurrentFake.deleteRecord('manifest', 'bot', 'current.json');
  lostCurrentFake.deleteRecord('manifest', 'bot', 'current-resource.json');
  expectCode(() => lostCurrentStore.openReadOnly(), 'SERVICE_MANUAL_CLEANUP');

  const lostReferenceFake = new FakeServiceNative();
  const lostReferenceStore = bootstrap(lostReferenceFake);
  const referenceDeployment = applicationManifest({
    sequence: 2,
    version: '2.0.0',
  });
  const referenceIdentity = lostReferenceFake.seedPublication(
    'releases',
    referenceDeployment.archive.sha256,
  );
  const referenceInstalled = lostReferenceStore.openMutation();
  publishCommittedInstallation(
    referenceInstalled,
    referenceDeployment,
    referenceIdentity,
  );
  referenceInstalled.close();
  lostReferenceFake.deleteRecord('reference', null, 'bot.json');
  expectCode(() => lostReferenceStore.openReadOnly(), 'SERVICE_MANUAL_CLEANUP');
});

test('model: committed update and rollback require complete generation predecessor records', () => {
  const model = committedUpdateModel();
  let readOnly = model.store.openReadOnly();
  assert.equal(readOnly.readManifest('current').value.serviceGeneration, 2);
  assert.equal(readOnly.readManifest('previous').value.serviceGeneration, 1);
  readOnly.close();

  let session = model.store.openMutation();
  const rolledBack = publishCommittedSuccessor(
    session,
    model.updated,
    model.originalDeployment,
    model.originalIdentity,
    {
      operation: 'rollback',
      transactionId: 'tx-committed-rollback',
      transactionNonce: '9'.repeat(32),
    },
  );
  session.close();
  readOnly = model.store.openReadOnly();
  assert.equal(readOnly.readManifest('current').value.serviceGeneration, 3);
  assert.equal(
    readOnly.readManifest('current').value.applicationManifestFingerprint,
    model.originalDeployment.manifestFingerprint,
  );
  assert.equal(
    readOnly.readManifest('previous').value.manifestFingerprint,
    model.updated.manifest.manifestFingerprint,
  );
  assert.equal(rolledBack.transaction.operation, 'rollback');
  readOnly.close();

  for (const mutate of [
    (fixture) => fixture.fake.deleteRecord('manifest', 'bot', 'previous.json'),
    (fixture) => fixture.fake.deleteRecord('manifest', 'bot', 'previous-resource.json'),
    (fixture) => {
      const reference = JSON.parse(
        fixture.fake.recordBytes('reference', null, 'bot.json').toString('utf8'),
      );
      fixture.fake.putRaw(
        'reference',
        null,
        'bot.json',
        canonicalJsonBytes(buildServiceReferenceRecord({
          ...reference,
          previous: null,
        })),
      );
    },
  ]) {
    const fixture = committedUpdateModel();
    mutate(fixture);
    expectCode(() => fixture.store.openReadOnly(), 'SERVICE_MANUAL_CLEANUP');
  }

  const rollbackLoss = committedUpdateModel();
  session = rollbackLoss.store.openMutation();
  publishCommittedSuccessor(
    session,
    rollbackLoss.updated,
    rollbackLoss.originalDeployment,
    rollbackLoss.originalIdentity,
    {
      operation: 'rollback',
      transactionId: 'tx-rollback-loss',
      transactionNonce: 'a'.repeat(32),
    },
  );
  session.close();
  rollbackLoss.fake.deleteRecord('manifest', 'bot', 'previous-resource.json');
  expectCode(() => rollbackLoss.store.openReadOnly(), 'SERVICE_MANUAL_CLEANUP');
});

test('model: generation-three update and rollback recovery rotate older previous evidence', () => {
  const updateModel = committedUpdateModel();
  const thirdDeployment = applicationManifest({
    sequence: 3,
    version: '3.0.0',
    archiveHash: hash('6'),
  });
  const thirdIdentity = updateModel.fake.seedPublication(
    'releases',
    thirdDeployment.archive.sha256,
  );
  const recoveredUpdate = recoverCommittedSuccessor(
    updateModel.store,
    updateModel.updated,
    thirdDeployment,
    thirdIdentity,
    {
      operation: 'update',
      transactionId: 'tx-recovered-generation-three-update',
      transactionNonce: 'b'.repeat(32),
    },
    { restartBetweenPreviousSteps: true },
  );
  let readOnly = updateModel.store.openReadOnly();
  assert.equal(readOnly.readManifest('current').value.serviceGeneration, 3);
  assert.equal(
    readOnly.readManifest('current').value.manifestFingerprint,
    recoveredUpdate.manifest.manifestFingerprint,
  );
  assert.equal(
    readOnly.readManifest('previous').value.manifestFingerprint,
    updateModel.updated.manifest.manifestFingerprint,
  );
  readOnly.close();

  const rollbackModel = committedUpdateModel();
  const recoveredRollback = recoverCommittedSuccessor(
    rollbackModel.store,
    rollbackModel.updated,
    rollbackModel.originalDeployment,
    rollbackModel.originalIdentity,
    {
      operation: 'rollback',
      transactionId: 'tx-recovered-generation-three-rollback',
      transactionNonce: 'c'.repeat(32),
    },
    { restartBetweenPreviousSteps: true },
  );
  readOnly = rollbackModel.store.openReadOnly();
  assert.equal(readOnly.readManifest('current').value.serviceGeneration, 3);
  assert.equal(
    readOnly.readManifest('current').value.manifestFingerprint,
    recoveredRollback.manifest.manifestFingerprint,
  );
  assert.equal(
    readOnly.readManifest('previous').value.manifestFingerprint,
    rollbackModel.updated.manifest.manifestFingerprint,
  );
  readOnly.close();

  const foreignModel = committedUpdateModel();
  const foreignDeployment = applicationManifest({
    sequence: 3,
    version: '3.0.0',
    archiveHash: hash('7'),
  });
  const foreignSuccessor = successorFixture(
    foreignModel.updated,
    foreignDeployment,
    {
      operation: 'update',
      transactionId: 'tx-generation-three-foreign-previous',
      transactionNonce: 'e'.repeat(32),
    },
  );
  let session = foreignModel.store.openMutation();
  session.appendJournal(foreignSuccessor.transaction);
  session.close();
  const foreignResource = buildServiceResourceProof({
    ...foreignModel.installed.resource,
    platformResourceFingerprint: hash('f'),
  });
  const foreignManifest = buildServiceManifest({
    ...foreignModel.installed.manifest,
    resourceProof: foreignResource.resourceProof,
  });
  foreignModel.fake.putRaw(
    'manifest',
    'bot',
    'previous-resource.json',
    canonicalJsonBytes(foreignResource),
  );
  foreignModel.fake.putRaw(
    'manifest',
    'bot',
    'previous.json',
    canonicalJsonBytes(foreignManifest),
  );
  session = foreignModel.store.openRecovery();
  expectCode(
    () => session.removeManifest('previous', session.readManifest('previous')),
    'SERVICE_PENDING',
  );
  expectCode(
    () => session.removeResourceProof(
      'previous',
      session.readResourceProof('previous'),
    ),
    'SERVICE_PENDING',
  );
  session.close();

  const foreignReferenceModel = committedUpdateModel();
  const referenceSuccessor = successorFixture(
    foreignReferenceModel.updated,
    foreignDeployment,
    {
      operation: 'update',
      transactionId: 'tx-generation-three-foreign-reference',
      transactionNonce: 'f'.repeat(32),
    },
  );
  session = foreignReferenceModel.store.openMutation();
  session.appendJournal(referenceSuccessor.transaction);
  session.close();
  const references = JSON.parse(
    foreignReferenceModel.fake.recordBytes(
      'reference',
      null,
      'bot.json',
    ).toString('utf8'),
  );
  const previousApplication = references.previous.artifacts.find(
    ({ artifactKind }) => artifactKind === 'application',
  );
  const foreignApplication = buildServiceArtifactBinding({
    ...previousApplication,
    treeFingerprint: hash('0'),
  }, 'linux');
  const foreignPrevious = buildServiceReferenceSlot({
    ...references.previous,
    artifacts: [foreignApplication],
  }, { platform: 'linux', component: 'bot' });
  foreignReferenceModel.fake.putRaw(
    'reference',
    null,
    'bot.json',
    canonicalJsonBytes(buildServiceReferenceRecord({
      ...references,
      previous: foreignPrevious,
    })),
  );
  session = foreignReferenceModel.store.openRecovery();
  expectCode(
    () => session.removeManifest('previous', session.readManifest('previous')),
    'SERVICE_PENDING',
  );
  expectCode(
    () => session.removeResourceProof(
      'previous',
      session.readResourceProof('previous'),
    ),
    'SERVICE_PENDING',
  );
  session.close();
});

test('model: generation-three tombstoned uninstall recovers through committed absence', () => {
  const model = committedUpdateModel();
  const transaction = uninstallTransactionFixture(model.updated, {
    transactionId: 'tx-generation-three-uninstall',
    transactionNonce: 'd'.repeat(32),
  });
  let session = model.store.openMutation();
  session.appendJournal(transaction);
  session.close();

  session = model.store.openRecovery();
  const writesBeforeTombstone = session.writes;
  expectCode(
    () => session.removeManifest('previous', session.readManifest('previous')),
    'SERVICE_PENDING',
  );
  expectCode(
    () => session.removeResourceProof('previous', session.readResourceProof('previous')),
    'SERVICE_PENDING',
  );
  assert.equal(session.writes, writesBeforeTombstone);
  assert.equal(session.readManifest('previous').present, true);
  assert.equal(session.readResourceProof('previous').present, true);
  const tombstoned = nextJournal(transaction, 'tombstoned', 'observed');
  session.appendJournal(tombstoned);
  const tombstone = buildServiceTombstone({
    component: 'bot',
    serviceKey: 'bot',
    platform: 'linux',
    architecture: 'x64',
    serviceGeneration: transaction.serviceGeneration,
    transactionId: transaction.transactionId,
    transactionFingerprint: tombstoned.transactionFingerprint,
    resourceProof: transaction.old.resourceProof,
    currentManifestFingerprint: transaction.old.manifestFingerprint,
    applicationSequenceFloor: 2,
    shawlSequenceFloor: null,
  });
  session.publishTombstone(tombstone, session.readTombstone());
  session.close();

  session = model.store.openRecovery();
  session.removeManifest('current', session.readManifest('current'));
  session.close();
  session = model.store.openRecovery();
  session.removeResourceProof('current', session.readResourceProof('current'));
  session.removeManifest('previous', session.readManifest('previous'));
  session.close();
  session = model.store.openRecovery();
  session.removeResourceProof('previous', session.readResourceProof('previous'));
  const resourceRemoved = nextJournal(tombstoned, 'resource-removed', 'observed');
  session.appendJournal(resourceRemoved);
  session.publishReferences(buildServiceReferenceRecord({
    serviceKey: 'bot',
    component: 'bot',
    platform: 'linux',
    architecture: 'x64',
    serviceGeneration: transaction.serviceGeneration,
    current: null,
    previous: null,
    provisional: null,
  }), session.readReferences());
  const referencesReleased = nextJournal(
    resourceRemoved,
    'references-released',
    'observed',
  );
  session.appendJournal(referencesReleased);
  const committed = nextJournal(referencesReleased, 'committed', 'observed');
  session.appendJournal(committed);
  session.close();

  const readOnly = model.store.openReadOnly();
  assert.equal(readOnly.readManifest('current').present, false);
  assert.equal(readOnly.readManifest('previous').present, false);
  assert.equal(readOnly.readResourceProof('current').present, false);
  assert.equal(readOnly.readResourceProof('previous').present, false);
  assert.equal(readOnly.readReferences().value.serviceGeneration, 3);
  assert.equal(readOnly.readReferences().value.current, null);
  assert.equal(readOnly.readTombstone().value.tombstoneFingerprint, tombstone.tombstoneFingerprint);
  assert.equal(readOnly.readJournal().entries.at(-1).phase, 'committed');
  readOnly.close();
});

test('model: different Shawl provenance for one physical executable remains referenced', () => {
  const fake = new FakeServiceNative('win32');
  const botStore = bootstrap(fake);
  const botApplication = applicationManifest({
    sequence: 2,
    version: '2.0.0',
    platform: 'win32',
    archiveHash: hash('4'),
  });
  const daemonApplication = applicationManifest({
    sequence: 3,
    version: '3.0.0',
    platform: 'win32',
    archiveHash: hash('5'),
  });
  const botShawl = shawlManifest({ sequence: 4 });
  const daemonShawl = shawlManifest({ sequence: 5 });
  const candidateShawl = shawlManifest({ sequence: 6 });
  const botApplicationIdentity = fake.seedApplicationPublication(botApplication);
  const daemonApplicationIdentity = fake.seedApplicationPublication(daemonApplication);
  const sharedShawlIdentity = fake.seedShawlPublication(botShawl);
  const bot = botStore.openMutation();
  publishCommittedWindowsInstallation(
    bot,
    botApplication,
    botApplicationIdentity,
    botShawl,
    sharedShawlIdentity,
    {
      transactionId: 'tx-shawl-bot',
      transactionNonce: '6'.repeat(32),
    },
  );
  const physicalCandidate = bot.observeShawlPublication(
    candidateShawl,
    sharedShawlIdentity,
  ).binding;
  bot.close();
  const daemonKey = deriveServiceInstanceKey('shawl daemon');
  const daemonStore = storeFor(fake, { component: 'daemon', hostId: 'shawl daemon' });
  const daemon = daemonStore.openMutation();
  publishCommittedWindowsInstallation(
    daemon,
    daemonApplication,
    daemonApplicationIdentity,
    daemonShawl,
    sharedShawlIdentity,
    {
      transactionId: 'tx-shawl-daemon',
      transactionNonce: '7'.repeat(32),
      component: 'daemon',
      serviceKey: daemonKey,
    },
  );
  daemon.close();
  const scanner = botStore.openMutation();
  expectCode(() => scanner.observeZeroReferences(physicalCandidate), 'SERVICE_REFERENCED');
  scanner.close();
});

test('model: recovery rejects update-as-uninstall and unrelated observed provisional artifacts', () => {
  const fake = new FakeServiceNative();
  const store = bootstrap(fake);
  const originalDeployment = applicationManifest();
  const originalIdentity = fake.seedPublication(
    'releases',
    originalDeployment.archive.sha256,
  );
  let session = store.openMutation();
  const installed = publishCommittedInstallation(
    session,
    originalDeployment,
    originalIdentity,
  );
  session.close();

  const candidateDeployment = applicationManifest({
    sequence: 2,
    version: '2.0.0',
    archiveHash: hash('5'),
  });
  const unrelatedDeployment = applicationManifest({
    sequence: 3,
    version: '3.0.0',
    archiveHash: hash('6'),
  });
  const candidateIdentity = fake.seedPublication(
    'releases',
    candidateDeployment.archive.sha256,
  );
  const unrelatedIdentity = fake.seedPublication(
    'releases',
    unrelatedDeployment.archive.sha256,
  );
  const successor = successorFixture(installed, candidateDeployment, {
    transactionId: 'tx-reference-recovery',
    transactionNonce: '7'.repeat(32),
  });
  session = store.openMutation();
  session.appendJournal(successor.transaction);
  session.close();

  const recovery = store.openRecovery();
  expectCode(
    () => recovery.publishReferences(buildServiceReferenceRecord({
      serviceKey: 'bot',
      component: 'bot',
      platform: 'linux',
      architecture: 'x64',
      serviceGeneration: 2,
      current: null,
      previous: null,
      provisional: null,
    }), recovery.readReferences()),
    'SERVICE_PENDING',
  );
  const unrelated = recovery.observeApplicationPublication(
    unrelatedDeployment,
    unrelatedIdentity,
  );
  const wrongProvisional = buildServiceReferenceSlot({
    serviceGeneration: 2,
    transactionId: successor.transaction.transactionId,
    transactionNonce: successor.transaction.transactionNonce,
    artifacts: [unrelated.binding],
  }, { platform: 'linux', component: 'bot' });
  const wrongReceipt = recovery.readReferences();
  expectCode(
    () => recovery.publishReferences(buildServiceReferenceRecord({
      ...wrongReceipt.value,
      provisional: wrongProvisional,
    }), wrongReceipt),
    'SERVICE_PENDING',
  );
  const candidate = recovery.observeApplicationPublication(
    candidateDeployment,
    candidateIdentity,
  );
  const exactProvisional = buildServiceReferenceSlot({
    serviceGeneration: 2,
    transactionId: successor.transaction.transactionId,
    transactionNonce: successor.transaction.transactionNonce,
    artifacts: [candidate.binding],
  }, { platform: 'linux', component: 'bot' });
  const referenceReceipt = recovery.readReferences();
  recovery.publishReferences(buildServiceReferenceRecord({
    ...referenceReceipt.value,
    provisional: exactProvisional,
  }), referenceReceipt);
  recovery.close();
});

test('model: recovery copies and restores exact O records with predecessor provenance', () => {
  const fake = new FakeServiceNative();
  const store = bootstrap(fake);
  const originalDeployment = applicationManifest();
  const originalIdentity = fake.seedPublication(
    'releases',
    originalDeployment.archive.sha256,
  );
  let session = store.openMutation();
  const installed = publishCommittedInstallation(
    session,
    originalDeployment,
    originalIdentity,
  );
  session.close();

  const candidateDeployment = applicationManifest({
    sequence: 2,
    version: '2.0.0',
    archiveHash: hash('5'),
  });
  const successor = successorFixture(installed, candidateDeployment, {
    transactionId: 'tx-recovery-copy',
    transactionNonce: '6'.repeat(32),
  });
  session = store.openMutation();
  session.appendJournal(successor.transaction);
  session.close();

  const recovery = store.openRecovery();
  expectCode(
    () => recovery.removeManifest('current', recovery.readManifest('current')),
    'SERVICE_PENDING',
  );
  recovery.publishResourceProof(
    'previous',
    installed.resource,
    recovery.readResourceProof('previous'),
  );
  recovery.publishManifest(
    'previous',
    installed.manifest,
    recovery.readManifest('previous'),
  );
  assert.equal(
    recovery.readResourceProof('previous').value.transactionId,
    installed.transaction.transactionId,
  );
  recovery.removeManifest('current', recovery.readManifest('current'));
  recovery.removeResourceProof('current', recovery.readResourceProof('current'));
  recovery.publishResourceProof(
    'current',
    successor.resource,
    recovery.readResourceProof('current'),
  );
  recovery.publishManifest(
    'current',
    successor.manifest,
    recovery.readManifest('current'),
  );
  recovery.removeManifest('current', recovery.readManifest('current'));
  recovery.removeResourceProof('current', recovery.readResourceProof('current'));
  recovery.publishResourceProof(
    'current',
    installed.resource,
    recovery.readResourceProof('current'),
  );
  recovery.publishManifest(
    'current',
    installed.manifest,
    recovery.readManifest('current'),
  );
  assert.equal(
    recovery.readResourceProof('current').value.transactionId,
    installed.transaction.transactionId,
  );
  recovery.close();
});

test('model: install recovery removes only exact records owned by that installation', () => {
  const fake = new FakeServiceNative();
  const store = bootstrap(fake);
  const owned = serviceMetadata();
  const transaction = transactionFixture({
    transactionId: owned.resource.transactionId,
    transactionNonce: owned.resource.transactionNonce,
    candidateManifestFingerprint: owned.manifest.applicationManifestFingerprint,
    finalManifestFingerprint: owned.manifest.manifestFingerprint,
    finalResourceProof: owned.resource.resourceProof,
  });
  const session = store.openMutation();
  session.appendJournal(transaction);
  session.publishResourceProof(
    'current',
    owned.resource,
    session.readResourceProof('current'),
  );
  session.publishManifest(
    'current',
    owned.manifest,
    session.readManifest('current'),
  );
  session.publishStartupProof(
    startupProofFor(transaction, owned.resource),
    session.readStartupProof(),
  );
  session.close();

  const recovery = store.openRecovery();
  recovery.removeStartupProof(recovery.readStartupProof());
  recovery.removeManifest('current', recovery.readManifest('current'));
  recovery.removeResourceProof('current', recovery.readResourceProof('current'));
  assert.equal(recovery.readManifest('current').present, false);
  assert.equal(recovery.readResourceProof('current').present, false);
  assert.equal(recovery.readStartupProof().present, false);
  recovery.close();

  const foreignFake = new FakeServiceNative();
  const foreignStore = bootstrap(foreignFake);
  const declared = serviceMetadata();
  const foreign = serviceMetadata({
    ...linuxBotConfiguration,
    workingDirectory: '/srv/foreign-bot',
  });
  const declaredTransaction = transactionFixture({
    transactionId: declared.resource.transactionId,
    transactionNonce: declared.resource.transactionNonce,
    candidateManifestFingerprint: declared.manifest.applicationManifestFingerprint,
    finalManifestFingerprint: declared.manifest.manifestFingerprint,
    finalResourceProof: declared.resource.resourceProof,
  });
  const foreignSession = foreignStore.openMutation();
  foreignSession.appendJournal(declaredTransaction);
  foreignSession.publishResourceProof(
    'current',
    foreign.resource,
    foreignSession.readResourceProof('current'),
  );
  foreignSession.publishManifest(
    'current',
    foreign.manifest,
    foreignSession.readManifest('current'),
  );
  foreignSession.close();
  const foreignRecovery = foreignStore.openRecovery();
  expectCode(
    () => foreignRecovery.removeManifest(
      'current',
      foreignRecovery.readManifest('current'),
    ),
    'SERVICE_PENDING',
  );
  expectCode(
    () => foreignRecovery.removeResourceProof(
      'current',
      foreignRecovery.readResourceProof('current'),
    ),
    'SERVICE_PENDING',
  );
  foreignRecovery.close();
});

test('model: tombstone and manual-cleanup block normal mutation; only recovery exact-CAS clears manual state', () => {
  const fake = new FakeServiceNative();
  const store = bootstrap(fake);
  const deployment = applicationManifest();
  const identity = fake.seedPublication('releases', deployment.archive.sha256);
  let session = store.openMutation();
  const installedService = publishCommittedInstallation(session, deployment, identity);
  session.close();
  session = store.openMutation();
  const transaction = uninstallTransactionFixture(installedService);
  session.appendJournal(transaction);
  session.close();
  session = store.openRecovery();
  expectCode(
    () => session.publishReferences(buildServiceReferenceRecord({
      serviceKey: 'bot',
      component: 'bot',
      platform: 'linux',
      architecture: 'x64',
      serviceGeneration: 2,
      current: null,
      previous: null,
      provisional: null,
    }), session.readReferences()),
    'SERVICE_PENDING',
  );
  const tombstonedTransaction = nextJournal(transaction, 'tombstoned', 'observed');
  session.appendJournal(tombstonedTransaction);
  const tombstone = buildServiceTombstone({
    component: 'bot', serviceKey: 'bot', platform: 'linux', architecture: 'x64', serviceGeneration: 2,
    transactionId: tombstonedTransaction.transactionId,
    transactionFingerprint: tombstonedTransaction.transactionFingerprint,
    resourceProof: transaction.old.resourceProof,
    currentManifestFingerprint: transaction.old.manifestFingerprint,
    applicationSequenceFloor: 3,
    shawlSequenceFloor: null,
  });
  session.publishTombstone(tombstone, session.readTombstone());
  const stoppingTransaction = nextJournal(
    tombstonedTransaction,
    'stopping',
    'observed',
  );
  session.appendJournal(stoppingTransaction);
  session.close();
  expectCode(() => store.openMutation(), 'SERVICE_TOMBSTONED');
  const recovery = store.openRecovery();
  assert.equal(recovery.readTombstone().value.tombstoneFingerprint, tombstone.tombstoneFingerprint);
  const quiescentTransaction = nextJournal(
    stoppingTransaction,
    'quiescent',
    'observed',
  );
  recovery.appendJournal(quiescentTransaction);
  assert.equal(
    recovery.readJournal().head.value.transactionFingerprint,
    quiescentTransaction.transactionFingerprint,
  );
  const unrelatedResource = serviceMetadata().resource;
  expectCode(
    () => recovery.publishResourceProof(
      'current',
      unrelatedResource,
      recovery.readResourceProof('current'),
    ),
    'SERVICE_TOMBSTONED',
  );
  recovery.close();

  const manualFake = new FakeServiceNative();
  const manualStore = bootstrap(manualFake);
  const initialDeployment = applicationManifest();
  const initialIdentity = manualFake.seedPublication('releases', initialDeployment.archive.sha256);
  let normal = manualStore.openMutation();
  const installed = publishCommittedInstallation(normal, initialDeployment, initialIdentity);
  normal.close();
  normal = manualStore.openMutation();
  const old = buildServiceOldProof({
    disposition: 'stable',
    manifestFingerprint: installed.manifest.manifestFingerprint,
    resourceProof: installed.resource.resourceProof,
    applicationManifestFingerprint: initialDeployment.manifestFingerprint,
    shawlManifestFingerprint: null,
    serviceGeneration: 1,
    activation: 'enabled',
  }, 'linux');
  const update = transactionFixture({
    operation: 'update',
    serviceGeneration: 2,
    transactionId: 'tx-cleanup',
    transactionNonce: '3'.repeat(32),
    old,
    candidateManifestFingerprint: applicationManifest({
      sequence: 2,
      version: '2.0.0',
    }).manifestFingerprint,
    releaseSequence: 2,
    previousJournalFingerprint: installed.committed.transactionFingerprint,
  });
  normal.appendJournal(update);
  const manualTransaction = nextJournal(update, 'manual-cleanup', 'observed');
  normal.appendJournal(manualTransaction);
  const cleanup = buildServiceManualCleanup({
    component: 'bot', serviceKey: 'bot', platform: 'linux', architecture: 'x64', serviceGeneration: 2,
    transactionId: manualTransaction.transactionId,
    journalFingerprint: manualTransaction.transactionFingerprint,
    phase: 'manual-cleanup',
    reason: 'recreated-resource', operatorAction: 'remove-unmarked-resource',
    expectedDisposition: 'stable-old', expectedOldProofFingerprint: old.oldFingerprint,
    observedDisposition: 'foreign', observedFingerprint: hash('4'), blockedUntilOperatorAction: true,
  });
  normal.publishManualCleanup(cleanup, normal.readManualCleanup());
  normal.close();
  expectCode(() => manualStore.openMutation(), 'SERVICE_MANUAL_CLEANUP');
  const exactRecovery = manualStore.openRecovery();
  const manualReceipt = exactRecovery.readManualCleanup();
  expectCode(
    () => exactRecovery.publishManualCleanup(cleanup, manualReceipt),
    'SERVICE_MANUAL_CLEANUP',
  );
  const wrong = buildServiceOldProof({
    ...old,
    resourceProof: hash('6'),
  }, 'linux');
  expectCode(() => exactRecovery.clearManualCleanup(manualReceipt, wrong), 'SERVICE_SCOPE_MISMATCH');
  exactRecovery.clearManualCleanup(manualReceipt, old);
  assert.equal(exactRecovery.readManualCleanup().present, false);
  exactRecovery.close();
  expectCode(() => manualStore.openMutation(), 'SERVICE_PENDING');
});

test('model: failures after earlier namespace or record writes never report zero writes', () => {
  const fake = new FakeServiceNative();
  const store = bootstrap(fake);
  const daemonStore = storeFor(fake, { component: 'daemon', hostId: 'new service' });
  const session = daemonStore.openMutation();
  const daemonKey = deriveServiceInstanceKey('new service');
  assert.ok(session.writes > 0, 'new service lock registration is a counted write');
  const beforeFailure = session.writes;
  fake.failPublish(`${daemonKey}.json`, 'after');
  let failedWrites;
  assert.throws(
    () => session.publishReferences(
      emptyReferences(daemonKey, 'daemon', 0),
      session.readReferences(),
    ),
    (error) => {
      assert.equal(error.code, 'SERVICE_MANUAL_CLEANUP');
      assert.ok(error.writes > beforeFailure);
      failedWrites = error.writes;
      return true;
    },
  );
  assert.equal(session.writes, failedWrites);
  // A later caller failure preserves, but does not recount, the failed native mutation.
  assert.throws(() => session.publishReferences({ kind: 'bad' }, session.readReferences()), (error) => {
    assert.equal(error.code, 'SERVICE_INVALID');
    assert.equal(error.writes, failedWrites);
    return true;
  });
  session.close();
});

test('model: shared-template binding rejects caller-supplied digest authority', () => {
  const fake = new FakeServiceNative();
  const store = bootstrap(fake);
  const daemonStore = storeFor(fake, { component: 'daemon', hostId: 'binding authority' });
  const session = daemonStore.openMutation();
  expectCode(() => session.createSharedTemplateBinding(hash('9')), 'SERVICE_INVALID');
  const binding = session.createSharedTemplateBinding();
  assert.equal(binding.artifactKind, 'shared-template');
  assert.equal(binding.artifactFingerprint, sha256(Buffer.from('daemon-template')));
  session.close();
});

test('model: Windows trial boundary is durable, CAS-branded, and never resets a same-attempt budget', () => {
  const fake = new FakeServiceNative('win32');
  const store = bootstrap(fake);
  const application = applicationManifest({ platform: 'win32' });
  const shawl = shawlManifest();
  const applicationIdentity = fake.seedApplicationPublication(application);
  const shawlIdentity = fake.seedShawlPublication(shawl);
  let session = store.openMutation();
  const installed = publishCommittedWindowsInstallation(
    session,
    application,
    applicationIdentity,
    shawl,
    shawlIdentity,
    { transactionId: 'tx-trial-boundary', transactionNonce: 'a'.repeat(32) },
  );
  const resourcePublished = nextJournal(installed.committed, 'resource-published', 'observed');
  session.appendJournal(resourcePublished);

  const captured = trialBoundaryFor(resourcePublished, installed.resource);
  const absent = session.readTrialBoundary();
  assert.equal(absent.present, false);
  const capturedReceipt = session.publishTrialBoundary(captured, absent);
  assert.equal(capturedReceipt.value.boundaryFingerprint, captured.boundaryFingerprint);
  expectCode(() => session.publishTrialBoundary(captured, absent), 'SERVICE_STALE');

  const startIntent = nextJournal(resourcePublished, 'trial-start-intent', 'intent');
  session.appendJournal(startIntent);
  const startObserved = nextJournal(startIntent, 'trial-start-observed', 'observed');
  session.appendJournal(startObserved);
  const observed = trialBoundaryFor(resourcePublished, installed.resource, {
    ...captured,
    phase: 'observed',
    revision: 2,
    previousBoundaryFingerprint: captured.boundaryFingerprint,
    lastTickMs: 1_500,
    wrapperEpochFingerprint: hash('6'),
    childEpochFingerprint: hash('7'),
    childCursor: trialCursorSet({
      bootFingerprint: captured.bootFingerprint,
      configFingerprint: captured.effectiveConfigFingerprint,
      wrapperOffset: 4_200,
      childOffset: 4_200,
    }),
  });
  session.publishTrialBoundary(observed, session.readTrialBoundary());
  const starting = nextJournal(startObserved, 'starting', 'intent');
  session.appendJournal(starting);
  const replacedChild = trialBoundaryFor(resourcePublished, installed.resource, {
    ...observed,
    revision: 3,
    previousBoundaryFingerprint: observed.boundaryFingerprint,
    lastTickMs: 5_000,
    childEpochFingerprint: hash('8'),
    childCursor: trialCursorSet({
      bootFingerprint: observed.bootFingerprint,
      configFingerprint: observed.effectiveConfigFingerprint,
      wrapperOffset: 4_300,
      childOffset: 4_300,
    }),
  });
  session.publishTrialBoundary(replacedChild, session.readTrialBoundary());
  assert.equal(replacedChild.startTickMs, captured.startTickMs);
  assert.equal(replacedChild.deadlineTickMs, captured.deadlineTickMs);
  assert.equal(replacedChild.initialCursor.cursorFingerprint, captured.initialCursor.cursorFingerprint);
  assert.equal(replacedChild.childEpochFingerprint, hash('8'));

  const retry = trialBoundaryFor(resourcePublished, installed.resource, {
    ...replacedChild,
    attempt: 2,
    revision: 4,
    previousBoundaryFingerprint: replacedChild.boundaryFingerprint,
    phase: 'captured',
    startTickMs: 6_000,
    lastTickMs: 6_000,
    wrapperEpochFingerprint: null,
    childEpochFingerprint: null,
    initialCursor: trialCursorSet({
      bootFingerprint: replacedChild.bootFingerprint,
      configFingerprint: replacedChild.effectiveConfigFingerprint,
      wrapperOffset: 4_500,
      childOffset: 4_500,
    }),
    childCursor: null,
  });
  const writesBeforePrematureRetry = session.writes;
  expectCode(
    () => session.publishTrialBoundary(retry, session.readTrialBoundary()),
    'SERVICE_PENDING',
  );
  assert.equal(session.writes, writesBeforePrematureRetry);

  const quiescent = nextJournal(starting, 'quiescent', 'observed');
  session.appendJournal(quiescent);
  session.publishTrialBoundary(retry, session.readTrialBoundary());
  const committed = nextJournal(quiescent, 'committed', 'observed');
  session.appendJournal(committed);
  session.close();

  const readOnly = store.openReadOnly();
  const persisted = readOnly.readTrialBoundary();
  assert.equal(persisted.present, true);
  assert.equal(persisted.value.attempt, 2);
  assert.equal(persisted.value.startTickMs, 6_000);
  const writesBeforeReadOnlyAttempt = readOnly.writes;
  expectCode(() => readOnly.publishTrialBoundary(retry, persisted), 'SERVICE_ACCESS_DENIED');
  assert.equal(readOnly.writes, writesBeforeReadOnlyAttempt);
  readOnly.close();

  session = store.openMutation();
  expectCode(() => session.removeTrialBoundary(persisted), 'SERVICE_STALE');
  const expected = session.readTrialBoundary();
  fake.recreateRecordSameBytes('manifest', 'bot', SERVICE_STORE_LAYOUT.trialBoundary);
  expectCode(() => session.removeTrialBoundary(expected), 'SERVICE_STALE');
  session.removeTrialBoundary(session.readTrialBoundary());
  assert.equal(session.readTrialBoundary().present, false);
  session.close();

  const reopened = store.openReadOnly();
  assert.equal(reopened.readTrialBoundary().present, false);
  assert.equal(reopened.writes, 0);
  reopened.close();
});

test('model: torn Windows trial boundary is classified as protected-store corruption', () => {
  const fake = new FakeServiceNative('win32');
  const store = bootstrap(fake);
  fake.putRaw(
    'manifest',
    'bot',
    SERVICE_STORE_LAYOUT.trialBoundary,
    Buffer.from('{"schemaVersion":1,"kind":"windows-service-trial-boundary"'),
  );
  expectCode(() => store.openReadOnly(), 'SERVICE_MANUAL_CLEANUP');
});

test('model: Linux store remains write-free with no Windows trial boundary', () => {
  const fake = new FakeServiceNative();
  const store = bootstrap(fake);
  const readOnly = store.openReadOnly();
  assert.deepEqual(readOnly.readTrialBoundary(), { present: false, value: null });
  assert.equal(readOnly.writes, 0);
  readOnly.close();
  const mutation = store.openMutation();
  const captured = trialBoundaryFor(transactionFixture({ platform: 'win32' }), {
    configurationFingerprint: hash('9'),
  });
  expectCode(
    () => mutation.publishTrialBoundary(captured, mutation.readTrialBoundary()),
    'SERVICE_UNSUPPORTED',
  );
  mutation.close();
});
