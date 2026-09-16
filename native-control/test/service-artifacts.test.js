import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { test } from 'node:test';
import { gzipSync } from 'node:zlib';
import { Header } from 'tar';
import {
  canonicalJsonBytes,
  canonicalJsonHash,
} from '@gjc-remote/shared/strict-json';
import {
  APPLICATION_BUNDLE_INVENTORY_PATH,
  SHAWL_UPSTREAM,
  buildApplicationDeploymentManifest,
  buildBundleInventory,
  buildDeploymentCompatibility,
  buildShawlDeploymentManifest,
} from '@gjc-remote/shared/deployment-envelope';
import { buildServiceArtifactBinding } from '@gjc-remote/shared/service-lifecycle-envelope';
import { inspectApplicationArchive } from '../src/service-archive.js';
import {
  createScratchArtifactCollectorInternal,
  createServiceArtifactAccessInternal,
  createServicePublishedArtifactCollectorInternal,
} from '../src/service-artifacts.js';

// This is a fake-native contract model only. It does not establish filesystem,
// ACL, lock-kernel, durability, archive-parser, signing, or real-host evidence.
const hash = (character) => character.repeat(64);
const sha256 = (bytes) => createHash('sha256').update(bytes).digest('hex');
const roles = Object.freeze({
  management: Object.freeze({ kind: 'uid', value: 'uid:1000' }),
  bot: Object.freeze({ kind: 'uid', value: 'uid:1001' }),
  recovery: Object.freeze({ kind: 'uid', value: 'uid:1002' }),
  daemon: Object.freeze({ kind: 'uid', value: 'uid:1003' }),
  system: Object.freeze({ kind: 'uid', value: 'uid:0' }),
});
const rolesFingerprint = canonicalJsonHash(roles);

function clone(value) {
  return JSON.parse(JSON.stringify(value));
}

function same(left, right) {
  return canonicalJsonBytes(left).equals(canonicalJsonBytes(right));
}

function compatibility() {
  return buildDeploymentCompatibility({
    bot: {
      domains: [{
        domain: 'bot-mapping-reader',
        readableFormats: ['mapping-v1'],
        writableFormats: ['mapping-v1'],
      }],
    },
    daemon: {
      domains: [
        {
          domain: 'daemon-app-session',
          readableFormats: ['session-v1'],
          writableFormats: ['session-v1'],
        },
        {
          domain: 'workspace-lifecycle',
          readableFormats: ['workspace-v1'],
          writableFormats: ['workspace-v1'],
        },
      ],
      sdkExternalStateContractFingerprint: hash('9'),
    },
  });
}

function applicationFixture() {
  const asset = Buffer.from('strict-streamed-application-archive');
  const files = Object.freeze({
    'bin/run': Buffer.from('run'),
    'bot/src/bot.js': Buffer.from('bot'),
    'daemon/src/daemon.js': Buffer.from('daemon'),
    'empty.txt': Buffer.alloc(0),
    'lib/data': Buffer.from('payload'),
    'native-control/build/Release/native-control.manifest.json': Buffer.from('native'),
  });
  const inventory = buildBundleInventory({
    payloadEntries: [
      {
        path: 'bin/run',
        size: files['bin/run'].length,
        sha256: sha256(files['bin/run']),
        executablePolicy: 'required',
      },
      {
        path: 'bot/src/bot.js',
        size: files['bot/src/bot.js'].length,
        sha256: sha256(files['bot/src/bot.js']),
        executablePolicy: 'forbidden',
      },
      {
        path: 'daemon/src/daemon.js',
        size: files['daemon/src/daemon.js'].length,
        sha256: sha256(files['daemon/src/daemon.js']),
        executablePolicy: 'forbidden',
      },
      {
        path: 'empty.txt',
        size: 0,
        sha256: sha256(files['empty.txt']),
        executablePolicy: 'forbidden',
      },
      {
        path: 'lib/data',
        size: files['lib/data'].length,
        sha256: sha256(files['lib/data']),
        executablePolicy: 'forbidden',
      },
      {
        path: 'native-control/build/Release/native-control.manifest.json',
        size: files['native-control/build/Release/native-control.manifest.json'].length,
        sha256: sha256(files['native-control/build/Release/native-control.manifest.json']),
        executablePolicy: 'forbidden',
      },
    ],
  }, { platform: 'linux' });
  const inventoryBytes = canonicalJsonBytes(inventory, {
    maxBytes: 32 * 1024 * 1024,
    maxDepth: 16,
    maxNodes: 600_032,
  });
  const manifest = buildApplicationDeploymentManifest({
    signingKeyId: 'fixture',
    releaseId: 'v1.0.0',
    releaseVersion: '1.0.0',
    releaseSequence: 1,
    source: {
      repository: 'kogangdon/gjc-remote',
      tag: 'v1.0.0',
      commit: '1'.repeat(40),
      tree: '2'.repeat(40),
      bunLockSha256: hash('3'),
    },
    target: { platform: 'linux', architecture: 'x64' },
    archive: {
      name: 'gjc-remote-service-1.0.0-linux-x64.tar.gz',
      mediaType: 'application/gzip',
      byteLength: asset.length,
      sha256: sha256(asset),
      entryCount: inventory.payloadEntryCount + 1,
    },
    inventory: {
      path: APPLICATION_BUNDLE_INVENTORY_PATH,
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
      manifestFingerprint: hash('4'),
      contractVersion: 4,
      contractRevision: 4,
    },
    wireCapabilities: ['gate_presentation_v1'],
    compatibility: compatibility(),
  });
  return { asset, files, inventory, inventoryBytes, manifest };
}

function shawlFixture() {
  const asset = Buffer.from('shawl-binary');
  const manifest = buildShawlDeploymentManifest({
    signingKeyId: 'fixture',
    releaseSequence: 7,
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
      byteLength: asset.length,
      sha256: sha256(asset),
      version: SHAWL_UPSTREAM.version,
      versionOutput: `shawl ${SHAWL_UPSTREAM.version}`,
      authenticode: 'unsigned',
    },
    projectAsset: {
      repository: 'kogangdon/gjc-remote',
      tag: 'v1.0.0',
      name: 'gjc-remote-shawl-win32-x64.exe',
    },
  });
  return { asset, manifest };
}

function transactionFor(purpose, manifest, platform = manifest.target.platform) {
  const candidate = {
    disposition: 'release',
    applicationManifestFingerprint: purpose === 'application'
      ? manifest.manifestFingerprint
      : hash('a'),
    shawlManifestFingerprint: purpose === 'shawl'
      ? manifest.manifestFingerprint
      : null,
    releaseSequence: purpose === 'application' ? manifest.releaseSequence : 1,
    releaseTreeFingerprint: purpose === 'application'
      ? manifest.inventory.treeFingerprint
      : hash('b'),
    compatibilityFingerprint: purpose === 'application'
      ? canonicalJsonHash(manifest.compatibility)
      : hash('c'),
    candidateFingerprint: hash('d'),
  };
  return {
    transactionId: `tx-${purpose}`,
    transactionNonce: purpose === 'application' ? '1'.repeat(32) : '2'.repeat(32),
    operation: 'install',
    component: 'bot',
    serviceKey: 'bot',
    platform,
    architecture: 'x64',
    serviceGeneration: 1,
    old: { disposition: 'absent', oldFingerprint: hash('e') },
    candidate,
    transition: { transitionFingerprint: hash('f') },
    final: { disposition: 'stable', finalFingerprint: hash('0') },
  };
}

function transactionIdentity(transaction) {
  return canonicalJsonHash(transaction);
}

function error(code, operation, writes, ambiguous = false) {
  const value = new Error(`${operation} failed`);
  Object.assign(value, { code, operation, writes, ambiguous });
  return value;
}

class ArtifactNativeModel {
  constructor(platform = 'linux') {
    this.platform = platform;
    this.roots = new Map();
    this.nextIdentity = 1;
    this.writes = 0;
    this.log = [];
    this.failNextChunk = false;
    this.failNextRead = null;
    this.failNextPublish = false;
    this.directoryOpenFailure = null;
    this.removeFailure = null;
    this.closeFailure = null;
    this.readerChunkBytes = null;
    this.activeReaders = 0;
    this.publications = 0;
  }

  profileMode(profile) {
    return {
      'service-staging-directory': 16832,
      'service-release-directory': 16749,
      'service-staging-file': 33152,
      'service-release-file': 33060,
      'service-release-executable': 33069,
    }[profile];
  }

  identity(profile, prior = null) {
    if (this.platform === 'win32') {
      const fileId = prior?.fileId ??
        BigInt(this.nextIdentity++).toString(16).padStart(32, '0');
      return {
        profile,
        kind: 'win32-service-object-v1',
        volumeSerial: '0000000000000001',
        fileId,
        attributes: profile.endsWith('-directory') ? 0x10 : 0x80,
        owner: 'S-1-5-21-1-2-3-1000',
        securitySha256: sha256(Buffer.from(`${profile}:${fileId}`)),
      };
    }
    const id = prior?.inode ?? String(this.nextIdentity++);
    return {
      profile,
      kind: 'linux-service-object-v1',
      device: '1',
      inode: id,
      mode: this.profileMode(profile),
      owner: roles.management.value,
      securitySha256: sha256(Buffer.from(`${profile}:${id}`)),
    };
  }

  directory(name, rootKind, profile, parent = null) {
    return {
      kind: 'directory',
      name,
      rootKind,
      profile,
      identity: this.identity(profile),
      parent,
      entries: new Map(),
    };
  }

  file(name, parent, profile, bytes) {
    const node = {
      kind: 'file',
      name,
      parent,
      profile,
      identity: this.identity(profile),
      bytes: Buffer.from(bytes),
    };
    return node;
  }

  facts(node) {
    if (this.platform === 'win32') {
      return {
        kind: 'win32-file-v1',
        volumeSerial: node.identity.volumeSerial,
        fileId: node.identity.fileId,
        size: node.bytes.length,
        sha256: sha256(node.bytes),
        attributes: node.identity.attributes,
        owner: node.identity.owner,
        securitySha256: node.identity.securitySha256,
      };
    }
    return {
      kind: 'linux-file-v1',
      device: node.identity.device,
      inode: node.identity.inode,
      size: node.bytes.length,
      sha256: sha256(node.bytes),
      mode: node.identity.mode,
      owner: node.identity.owner,
      securitySha256: node.identity.securitySha256,
    };
  }

  handle(node, access, parentHandle = null) {
    const handle = {
      node,
      access,
      parentHandle,
      children: 0,
      closed: false,
    };
    if (parentHandle) parentHandle.children += 1;
    return handle;
  }

  assertHandle(handle) {
    if (!handle || handle.closed) throw error('SERVICE_STALE', 'model_handle', this.writes);
  }

  root(rootKind, create) {
    let node = this.roots.get(rootKind);
    if (!node && create) {
      const profile = rootKind === 'staging'
        ? 'service-staging-directory'
        : 'service-release-directory';
      node = this.directory(rootKind, rootKind, profile);
      this.roots.set(rootKind, node);
      this.writes += 2;
    }
    return node;
  }

  rootBinding(node) {
    return {
      schemaVersion: 1,
      rootKind: node.rootKind,
      rootPath: this.platform === 'win32'
        ? `C:\\native\\${node.rootKind}`
        : `/native/${node.rootKind}`,
      rootNonce: 'a'.repeat(32),
      rolesFingerprint: hash('b'),
      identity: clone(node.identity),
      directoryIdentities: {},
      bindingFingerprint: sha256(Buffer.from(
        `root:${node.rootKind}:${node.identity.inode ?? node.identity.fileId}`,
      )),
    };
  }

  bridge() {
    const model = this;
    return Object.freeze({
      bootstrapRoot(rootKind, operation) {
        model.log.push(`bootstrap-root:${rootKind}:create-new`);
        let node = model.roots.get(rootKind);
        if (node) {
          model.log.push(`bootstrap-root:${rootKind}:already-exists`);
          model.log.push(`open-root:${rootKind}:write-existing`);
        } else {
          node = model.root(rootKind, true);
        }
        return Object.freeze({
          handle: model.handle(node, 'write'),
          rootBinding: clone(model.rootBinding(node)),
        });
      },
      openRoot(rootKind, access, operation) {
        model.log.push(`open-root:${rootKind}:${access}`);
        let node = model.roots.get(rootKind);
        if (access !== 'write-existing') {
          throw error('SERVICE_INVALID', operation, model.writes);
        }
        if (!node) {
          return null;
        }
        return Object.freeze({
          handle: model.handle(node, 'write'),
          rootBinding: clone(model.rootBinding(node)),
        });
      },
      adoptHandle() {},
      disownHandle(handle) {
        model.assertHandle(handle);
      },
      openDirectory(parent, name, access, expected, operation) {
        model.assertHandle(parent);
        if (model.directoryOpenFailure?.name === name &&
            model.directoryOpenFailure.access === access) {
          const failure = model.directoryOpenFailure;
          model.directoryOpenFailure = null;
          throw error(
            failure.code,
            operation,
            model.writes,
            failure.ambiguous,
          );
        }
        let node = parent.node.entries.get(name);
        if (access === 'create-new') {
          if (node) throw error('SERVICE_ALREADY_EXISTS', operation, model.writes);
          node = model.directory(
            name,
            parent.node.rootKind,
            parent.node.rootKind === 'staging'
              ? 'service-staging-directory'
              : 'service-release-directory',
            parent.node,
          );
          parent.node.entries.set(name, node);
          model.writes += 1;
        } else if (!node || node.kind !== 'directory' || !same(node.identity, expected)) {
          throw error('SERVICE_STALE', operation, model.writes);
        }
        model.log.push(`open-directory:${name}:${access}`);
        return Object.freeze({
          handle: model.handle(node, access === 'read-existing' ? 'read' : 'write', parent),
          identity: clone(node.identity),
        });
      },
      readFile(parent, name) {
        model.assertHandle(parent);
        const node = parent.node.entries.get(name);
        if (!node) return null;
        if (node.kind !== 'file') throw error('SERVICE_STALE', 'read_file', model.writes, true);
        return Object.freeze({ bytes: Buffer.from(node.bytes), facts: clone(model.facts(node)) });
      },
      publishFile(parent, name, bytes, expected, operation) {
        model.assertHandle(parent);
        if (expected !== null || parent.node.entries.has(name)) {
          throw error('SERVICE_ALREADY_EXISTS', operation, model.writes);
        }
        const node = model.file(name, parent.node, 'service-staging-file', bytes);
        parent.node.entries.set(name, node);
        model.writes += 2;
        model.log.push(`publish-file:${name}`);
        return Object.freeze({ facts: clone(model.facts(node)) });
      },
      listDirectory(directory) {
        model.assertHandle(directory);
        const entries = [...directory.node.entries.values()]
          .sort((left, right) => Buffer.compare(Buffer.from(left.name), Buffer.from(right.name)))
          .map((node) => Object.freeze({ name: node.name, identity: clone(node.identity) }));
        return Object.freeze({
          directoryIdentity: clone(directory.node.identity),
          entries: Object.freeze(entries),
        });
      },
      beginWrite(parent, name, expectedSize, expectedSha256, operation) {
        model.assertHandle(parent);
        if (parent.node.entries.has(name)) throw error('SERVICE_ALREADY_EXISTS', operation, model.writes);
        const node = model.file(name, parent.node, 'service-staging-file', Buffer.alloc(0));
        parent.node.entries.set(name, node);
        model.writes += 1;
        const handle = model.handle(node, 'write', parent);
        handle.expectedSize = expectedSize;
        handle.expectedSha256 = expectedSha256;
        handle.offset = 0;
        model.log.push(`begin:${name}`);
        return Object.freeze({ handle, identity: clone(node.identity) });
      },
      writeChunk(writer, expectedOffset, bytes, operation) {
        model.assertHandle(writer);
        if (writer.offset !== expectedOffset) throw error('SERVICE_STALE', operation, model.writes);
        writer.node.bytes = Buffer.concat([writer.node.bytes, Buffer.from(bytes)]);
        writer.offset += bytes.length;
        model.writes += 1;
        model.log.push(`write:${writer.node.name}:${bytes.length}`);
        if (model.failNextChunk) {
          model.failNextChunk = false;
          throw error('SERVICE_MANUAL_CLEANUP', operation, model.writes, true);
        }
        return Object.freeze({ nextOffset: writer.offset });
      },
      finishWrite(writer, profile, operation) {
        model.assertHandle(writer);
        const digest = sha256(writer.node.bytes);
        if (writer.node.bytes.length !== writer.expectedSize || digest !== writer.expectedSha256) {
          writer.closed = true;
          writer.parentHandle.children -= 1;
          throw error('SERVICE_STALE', operation, model.writes);
        }
        if (writer.node.profile !== profile) {
          writer.node.profile = profile;
          writer.node.identity = model.identity(profile, writer.node.identity);
          model.writes += 1;
        }
        writer.closed = true;
        writer.parentHandle.children -= 1;
        model.log.push(`finish:${writer.node.name}:${profile}`);
        return Object.freeze({ facts: clone(model.facts(writer.node)) });
      },
      openReader(parent, name, maximum, expectedFacts, operation) {
        model.assertHandle(parent);
        const node = parent.node.entries.get(name);
        if (!node) return null;
        if (node.kind !== 'file' || node.bytes.length > maximum ||
            (expectedFacts !== null && !same(model.facts(node), expectedFacts))) {
          throw error('SERVICE_STALE', operation, model.writes);
        }
        const handle = model.handle(node, 'read', parent);
        handle.offset = 0;
        model.activeReaders += 1;
        model.log.push(`open-reader:${name}`);
        return Object.freeze({ handle, facts: clone(model.facts(node)) });
      },
      readChunk(reader, expectedOffset, maximum, operation) {
        model.assertHandle(reader);
        if (model.failNextRead !== null) {
          const failure = model.failNextRead;
          model.failNextRead = null;
          if (failure === 'raw') throw new Error('sensitive reader failure');
          throw error(failure, operation, model.writes);
        }
        if (reader.offset !== expectedOffset) throw error('SERVICE_STALE', operation, model.writes);
        const end = Math.min(
          reader.node.bytes.length,
          reader.offset + Math.min(maximum, model.readerChunkBytes ?? maximum),
        );
        const bytes = reader.node.bytes.subarray(reader.offset, end);
        reader.offset = end;
        model.log.push(`read:${reader.node.name}:${bytes.length}`);
        return Object.freeze({
          bytes: Buffer.from(bytes),
          nextOffset: reader.offset,
          eof: reader.offset === reader.node.bytes.length,
        });
      },
      removeFile(parent, name, expectedFacts, operation) {
        model.assertHandle(parent);
        const node = parent.node.entries.get(name);
        if (!node || node.kind !== 'file' ||
            !same(model.facts(node), expectedFacts)) {
          throw error('SERVICE_STALE', operation, model.writes);
        }
        parent.node.entries.delete(name);
        model.writes += 2;
        model.log.push(`remove-file:${name}`);
        if (model.removeFailure?.kind === 'file' &&
            model.removeFailure.name === name) {
          model.removeFailure = null;
          throw error(
            'SERVICE_MANUAL_CLEANUP',
            operation,
            model.writes,
            true,
          );
        }
        return Object.freeze({ removed: true });
      },
      removeObject(parent, name, expectedIdentity, operation) {
        model.assertHandle(parent);
        const node = parent.node.entries.get(name);
        if (!node || node.kind !== 'directory' ||
            node.entries.size !== 0 ||
            !same(node.identity, expectedIdentity)) {
          throw error('SERVICE_STALE', operation, model.writes);
        }
        parent.node.entries.delete(name);
        model.writes += 2;
        model.log.push(`remove-directory:${name}`);
        if (model.removeFailure?.kind === 'directory' &&
            model.removeFailure.name === name) {
          model.removeFailure = null;
          throw error(
            'SERVICE_MANUAL_CLEANUP',
            operation,
            model.writes,
            true,
          );
        }
        return Object.freeze({ removed: true });
      },
      sealDirectory(directory, expected, operation) {
        model.assertHandle(directory);
        if (directory.children !== 0 || !same(directory.node.identity, expected) ||
            [...directory.node.entries.values()].some((node) =>
              node.kind === 'directory'
                ? node.profile !== 'service-release-directory'
                : !['service-release-file', 'service-release-executable'].includes(node.profile))) {
          throw error('SERVICE_STALE', operation, model.writes, true);
        }
        directory.node.profile = 'service-release-directory';
        directory.node.identity = model.identity(
          'service-release-directory',
          directory.node.identity,
        );
        model.writes += 1;
        model.log.push(`seal:${directory.node.name}`);
        return Object.freeze({ handle: directory, identity: clone(directory.node.identity) });
      },
      publishDirectory(source, destination, name, expected, operation) {
        model.assertHandle(source);
        model.assertHandle(destination);
        if (model.failNextPublish) {
          model.failNextPublish = false;
          throw error('SERVICE_IO_FAILED', operation, model.writes);
        }
        if (!same(source.node.identity, expected) || destination.node.entries.has(name)) {
          throw error('SERVICE_ALREADY_EXISTS', operation, model.writes);
        }
        source.node.parent.entries.delete(source.node.name);
        source.parentHandle.children -= 1;
        destination.node.entries.set(name, source.node);
        source.node.name = name;
        source.node.parent = destination.node;
        const updateRoot = (directory) => {
          directory.rootKind = destination.node.rootKind;
          for (const child of directory.entries.values()) {
            if (child.kind === 'directory') updateRoot(child);
          }
        };
        updateRoot(source.node);
        source.parentHandle = destination;
        destination.children += 1;
        model.writes += 1;
        model.publications += 1;
        model.log.push(`publish-directory:${name}`);
        return Object.freeze({ handle: source, identity: clone(source.node.identity) });
      },
      closeHandle(handle, operation) {
        model.assertHandle(handle);
        if (handle.children !== 0) throw error('SERVICE_PENDING', operation, model.writes);
        if (model.closeFailure?.name === handle.node.name &&
            model.closeFailure.remaining > 0) {
          model.closeFailure.remaining -= 1;
          throw error(
            'SERVICE_IO_FAILED',
            operation,
            model.writes,
            true,
          );
        }
        handle.closed = true;
        if (handle.parentHandle) handle.parentHandle.children -= 1;
        if (handle.access === 'read' && handle.node.kind === 'file') {
          model.activeReaders -= 1;
        }
        model.log.push(`close:${handle.node.name}`);
      },
      observePublication(purpose, manifest, identity) {
        const rootKind = purpose === 'application' ? 'releases' : 'shawl';
        const name = purpose === 'application' ? manifest.archive.sha256 : manifest.executable.sha256;
        const node = model.roots.get(rootKind)?.entries.get(name);
        if (!node || !same(node.identity, identity)) {
          throw error('SERVICE_STALE', 'observe_service_publication', model.writes);
        }
        return Object.freeze({
          purpose,
          manifestFingerprint: manifest.manifestFingerprint,
          directoryIdentity: clone(identity),
        });
      },
      fail(code, operation, ambiguous = false) {
        throw error(code, operation, model.writes, ambiguous);
      },
    });
  }

  scratchName(transaction, purpose) {
    return `${transaction.serviceKey}-${transaction.transactionNonce}-${purpose}`;
  }

  seedUnmarkedScratch(transaction, purpose) {
    const root = this.root('staging', true);
    const name = this.scratchName(transaction, purpose);
    root.entries.set(name, this.directory(name, 'staging', 'service-staging-directory', root));
  }

  target(rootKind, name) {
    return this.roots.get(rootKind)?.entries.get(name) ?? null;
  }

  scratch(transaction, purpose) {
    return this.roots.get('staging')?.entries.get(this.scratchName(transaction, purpose)) ?? null;
  }

  injectCandidateFile(transaction, purpose, path, bytes, profile = 'service-release-file') {
    const candidate = this.scratch(transaction, purpose)?.entries.get('candidate');
    if (!candidate) throw new Error('candidate absent');
    const segments = path.split('/');
    let parent = candidate;
    for (const segment of segments.slice(0, -1)) {
      let child = parent.entries.get(segment);
      if (!child) {
        child = this.directory(segment, 'staging', 'service-staging-directory', parent);
        parent.entries.set(segment, child);
      }
      parent = child;
    }
    const name = segments.at(-1);
    parent.entries.set(name, this.file(name, parent, profile, bytes));
  }

  injectCandidateDirectory(transaction, purpose, name) {
    const candidate = this.scratch(transaction, purpose)?.entries.get('candidate');
    if (!candidate) throw new Error('candidate absent');
    candidate.entries.set(
      name,
      this.directory(name, 'staging', 'service-staging-directory', candidate),
    );
  }
}

function accessFor(model, purpose, manifest, transaction = transactionFor(purpose, manifest)) {
  return createServiceArtifactAccessInternal({
    bridge: model.bridge(),
    purpose,
    manifest,
    transaction,
    transactionIdentity: transactionIdentity(transaction),
    roles,
    rolesFingerprint,
    platform: manifest.target.platform,
    architecture: manifest.target.architecture,
    component: transaction.component,
    serviceKey: transaction.serviceKey,
    onClose() { model.log.push('access-closed'); },
  });
}

async function collect(chunks) {
  const values = [];
  for await (const bytes of chunks) values.push(Buffer.from(bytes));
  return Buffer.concat(values);
}

async function prepareApplication(access, fixture) {
  access.prepareCandidate(fixture.inventoryBytes);
  await access.writeCandidateFile(
    APPLICATION_BUNDLE_INVENTORY_PATH,
    [fixture.inventoryBytes],
  );
  await access.writeCandidateFile('bin/run', [Buffer.from('r'), Buffer.from('un')]);
  await access.writeCandidateFile('bot/src/bot.js', [fixture.files['bot/src/bot.js']]);
  await access.writeCandidateFile('daemon/src/daemon.js', [fixture.files['daemon/src/daemon.js']]);
  await access.writeCandidateFile('empty.txt', [Buffer.alloc(0)]);
  await access.writeCandidateFile('lib/data', (async function* () {
    yield Buffer.from('pay');
    yield Buffer.from('load');
  })());
  await access.writeCandidateFile(
    'native-control/build/Release/native-control.manifest.json',
    [fixture.files['native-control/build/Release/native-control.manifest.json']],
  );
}

function publishedArtifact(model, purpose, manifest) {
  const rootKind = purpose === 'application' ? 'releases' : 'shawl';
  const artifactFingerprint = purpose === 'application'
    ? manifest.archive.sha256
    : manifest.executable.sha256;
  const directory = model.target(rootKind, artifactFingerprint);
  return buildServiceArtifactBinding({
    artifactKind: purpose,
    rootKind,
    artifactFingerprint,
    manifestFingerprint: manifest.manifestFingerprint,
    treeFingerprint: purpose === 'application'
      ? manifest.inventory.treeFingerprint
      : null,
    directoryIdentity: clone(directory.identity),
    directoryIdentityFingerprint: canonicalJsonHash(directory.identity),
  }, manifest.target.platform);
}

async function inspectPublished(model, purpose, manifest, artifact) {
  const owner = createServicePublishedArtifactCollectorInternal({
    bridge: model.bridge(),
    purpose,
    manifest,
    artifact,
    platform: manifest.target.platform,
    expectedRootBindingFingerprint: null,
    expectedRootIdentity: null,
    phase: null,
    advancePhase() {
      throw new Error('inspect cannot advance');
    },
  });
  return owner.inspect();
}

async function collectPublished(
  model,
  purpose,
  manifest,
  artifact,
  inspected,
  phaseState,
) {
  const owner = createServicePublishedArtifactCollectorInternal({
    bridge: model.bridge(),
    purpose,
    manifest,
    artifact,
    platform: manifest.target.platform,
    expectedRootBindingFingerprint:
      inspected.artifactRootBindingFingerprint,
    expectedRootIdentity: inspected.artifactRootIdentity,
    phase: phaseState.value,
    advancePhase(next) {
      phaseState.value = next;
    },
  });
  return owner.collect();
}

test('artifact access streams, rereads twice, writes empty files, seals bottom-up, and publishes by archive digest', async () => {
  const fixture = applicationFixture();
  const transaction = transactionFor('application', fixture.manifest);
  const model = new ArtifactNativeModel();
  const access = accessFor(model, 'application', fixture.manifest, transaction);
  assert.deepEqual(Object.keys(access), [
    'stageAsset',
    'openStagedAsset',
    'prepareCandidate',
    'writeCandidateFile',
    'publishCandidate',
    'close',
  ]);
  assert.equal(Object.isFrozen(access), true);
  await access.stageAsset((async function* () {
    yield fixture.asset.subarray(0, 7);
    yield fixture.asset.subarray(7);
  })());

  const first = access.openStagedAsset();
  assert.deepEqual(Object.keys(first), ['facts', 'chunks', 'close']);
  assert.equal(first.handle, undefined);
  assert.equal(first.facts.size, fixture.asset.length);
  assert.deepEqual(await collect(first.chunks), fixture.asset);
  assert.throws(
    () => first.chunks[Symbol.asyncIterator](),
    (caught) => caught.code === 'SERVICE_STALE' &&
      caught.operation === 'read_staged_service_asset',
  );
  first.close();
  const second = access.openStagedAsset();
  assert.deepEqual(await collect(second.chunks), fixture.asset);
  second.close();

  await prepareApplication(access, fixture);
  const publication = access.publishCandidate();
  assert.equal(publication.manifestFingerprint, fixture.manifest.manifestFingerprint);
  const writesAfterPublication = model.writes;
  access.publishCandidate();
  assert.equal(model.writes, writesAfterPublication);
  const target = model.target('releases', fixture.manifest.archive.sha256);
  assert.ok(target);
  assert.equal(model.target('releases', fixture.manifest.manifestFingerprint), null);
  assert.equal(target.profile, 'service-release-directory');
  assert.equal(target.entries.get('bin').profile, 'service-release-directory');
  assert.equal(target.entries.get('bin').entries.get('run').profile, 'service-release-executable');
  assert.equal(target.entries.get('empty.txt').bytes.length, 0);
  assert.equal(target.entries.get('lib').entries.get('data').profile, 'service-release-file');
  assert.equal(target.entries.get(APPLICATION_BUNDLE_INVENTORY_PATH).profile, 'service-release-file');
  assert.ok(model.log.includes('bootstrap-root:releases:create-new'));
  assert.ok(model.log.indexOf('seal:bin') < model.log.indexOf('seal:candidate'));
  assert.ok(model.log.indexOf('seal:lib') < model.log.indexOf('seal:candidate'));
  access.close();
  assert.equal(model.log.at(-1), 'access-closed');
});

test('artifact access publishes raw Shawl by executable digest without inventory', async () => {
  const fixture = shawlFixture();
  const transaction = transactionFor('shawl', fixture.manifest, 'win32');
  const model = new ArtifactNativeModel('win32');
  const access = accessFor(model, 'shawl', fixture.manifest, transaction);
  await access.stageAsset([fixture.asset]);
  assert.throws(
    () => access.prepareCandidate(Buffer.from('{}')),
    (caught) => caught.code === 'SERVICE_INVALID' &&
      caught.operation === 'prepare_service_candidate',
  );
  access.prepareCandidate(null);
  await access.writeCandidateFile('shawl.exe', [fixture.asset]);
  const publication = access.publishCandidate();
  assert.equal(publication.purpose, 'shawl');
  const target = model.target('shawl', fixture.manifest.executable.sha256);
  assert.ok(target);
  assert.equal(target.entries.get('shawl.exe').profile, 'service-release-executable');
  access.close();
});

test('artifact access refuses unmarked scratch, incomplete and extra trees, and changed files', async () => {
  const fixture = applicationFixture();
  const transaction = transactionFor('application', fixture.manifest);
  const unmarked = new ArtifactNativeModel();
  unmarked.seedUnmarkedScratch(transaction, 'application');
  assert.throws(
    () => accessFor(unmarked, 'application', fixture.manifest, transaction),
    (caught) => caught.code === 'SERVICE_MANUAL_CLEANUP' && caught.ambiguous === true,
  );
  const conflicting = new ArtifactNativeModel();
  const conflictingAccess = accessFor(
    conflicting,
    'application',
    fixture.manifest,
    transaction,
  );
  conflictingAccess.close();
  conflicting.scratch(transaction, 'application')
    .entries.get('transaction.json').bytes = Buffer.from('{}');
  assert.throws(
    () => accessFor(conflicting, 'application', fixture.manifest, transaction),
    (caught) => caught.code === 'SERVICE_MANUAL_CLEANUP' && caught.ambiguous === true,
  );
  const foreignScratch = new ArtifactNativeModel();
  const foreignScratchAccess = accessFor(
    foreignScratch,
    'application',
    fixture.manifest,
    transaction,
  );
  foreignScratchAccess.close();
  const scratchNode = foreignScratch.scratch(transaction, 'application');
  scratchNode.entries.set(
    'foreign',
    foreignScratch.file(
      'foreign',
      scratchNode,
      'service-staging-file',
      Buffer.from('x'),
    ),
  );
  assert.throws(
    () => accessFor(foreignScratch, 'application', fixture.manifest, transaction),
    (caught) => caught.code === 'SERVICE_MANUAL_CLEANUP' && caught.ambiguous === true,
  );

  const incomplete = new ArtifactNativeModel();
  const incompleteAccess = accessFor(incomplete, 'application', fixture.manifest, transaction);
  await incompleteAccess.stageAsset([fixture.asset]);
  incompleteAccess.prepareCandidate(fixture.inventoryBytes);
  await assert.rejects(
    incompleteAccess.writeCandidateFile('../escape', [Buffer.from('x')]),
    (caught) => caught.code === 'SERVICE_INVALID' &&
      caught.operation === 'write_service_candidate_file',
  );
  assert.throws(
    () => incompleteAccess.publishCandidate(),
    (caught) => caught.code === 'SERVICE_PENDING' &&
      caught.operation === 'publish_service_candidate',
  );
  assert.equal(incomplete.roots.has('releases'), false);
  incompleteAccess.close();
  const partialReplay = accessFor(
    incomplete,
    'application',
    fixture.manifest,
    transaction,
  );
  assert.throws(
    () => partialReplay.prepareCandidate(fixture.inventoryBytes),
    (caught) => caught.code === 'SERVICE_MANUAL_CLEANUP' &&
      caught.operation === 'prepare_service_candidate',
  );
  partialReplay.close();

  const extra = new ArtifactNativeModel();
  const extraAccess = accessFor(extra, 'application', fixture.manifest, transaction);
  await extraAccess.stageAsset([fixture.asset]);
  await prepareApplication(extraAccess, fixture);
  extra.injectCandidateFile(transaction, 'application', 'extra', Buffer.from('x'));
  extra.injectCandidateDirectory(transaction, 'application', 'empty-directory');
  assert.throws(
    () => extraAccess.publishCandidate(),
    (caught) => caught.code === 'SERVICE_MANUAL_CLEANUP' && caught.ambiguous === true,
  );
  extraAccess.close();

  const changed = new ArtifactNativeModel();
  const changedAccess = accessFor(changed, 'application', fixture.manifest, transaction);
  await changedAccess.stageAsset([fixture.asset]);
  await prepareApplication(changedAccess, fixture);
  changed.injectCandidateFile(transaction, 'application', 'lib/data', Buffer.from('changed'));
  assert.throws(
    () => changedAccess.publishCandidate(),
    (caught) => caught.code === 'SERVICE_MANUAL_CLEANUP' && caught.ambiguous === true,
  );
  changedAccess.close();
});

test('artifact access reuses only an exact immutable target and refuses drift', async () => {
  const fixture = applicationFixture();
  const transaction = transactionFor('application', fixture.manifest);
  const model = new ArtifactNativeModel();
  let access = accessFor(model, 'application', fixture.manifest, transaction);
  await access.stageAsset([fixture.asset]);
  await prepareApplication(access, fixture);
  access.publishCandidate();
  access.close();
  assert.equal(model.publications, 1);

  access = accessFor(model, 'application', fixture.manifest, transaction);
  await access.stageAsset([fixture.asset]);
  await prepareApplication(access, fixture);
  access.publishCandidate();
  assert.equal(model.publications, 1);
  access.close();

  const drift = new ArtifactNativeModel();
  access = accessFor(drift, 'application', fixture.manifest, transaction);
  await access.stageAsset([fixture.asset]);
  await prepareApplication(access, fixture);
  access.publishCandidate();
  access.close();
  drift.target('releases', fixture.manifest.archive.sha256)
    .entries.get('empty.txt').bytes = Buffer.from('foreign');
  access = accessFor(drift, 'application', fixture.manifest, transaction);
  await access.stageAsset([fixture.asset]);
  await prepareApplication(access, fixture);
  assert.throws(
    () => access.publishCandidate(),
    (caught) => caught.code === 'SERVICE_MANUAL_CLEANUP' && caught.ambiguous === true,
  );
  access.close();
});

test('artifact access reopens a sealed candidate still retained under scratch', async () => {
  const fixture = applicationFixture();
  const transaction = transactionFor('application', fixture.manifest);
  const model = new ArtifactNativeModel();
  let access = accessFor(model, 'application', fixture.manifest, transaction);
  await access.stageAsset([fixture.asset]);
  await prepareApplication(access, fixture);
  model.failNextPublish = true;
  assert.throws(
    () => access.publishCandidate(),
    (caught) => caught.code === 'SERVICE_IO_FAILED' &&
      caught.operation === 'publish_service_candidate',
  );
  const candidate = model.scratch(transaction, 'application')
    .entries.get('candidate');
  assert.equal(candidate.profile, 'service-release-directory');
  access.close();

  access = accessFor(model, 'application', fixture.manifest, transaction);
  access.prepareCandidate(fixture.inventoryBytes);
  const publication = access.publishCandidate();
  assert.equal(
    publication.manifestFingerprint,
    fixture.manifest.manifestFingerprint,
  );
  assert.equal(
    model.scratch(transaction, 'application').entries.has('candidate'),
    false,
  );
  access.close();
});

test('artifact access unwinds opened candidate ancestors when a nested open fails', async () => {
  const fixture = applicationFixture();
  const transaction = transactionFor('application', fixture.manifest);
  const model = new ArtifactNativeModel();
  const access = accessFor(model, 'application', fixture.manifest, transaction);
  await access.stageAsset([fixture.asset]);
  access.prepareCandidate(fixture.inventoryBytes);
  model.directoryOpenFailure = {
    name: 'build',
    access: 'create-new',
    code: 'SERVICE_IO_FAILED',
    ambiguous: false,
  };
  const before = model.writes;
  const logStart = model.log.length;
  await assert.rejects(
    access.writeCandidateFile(
      'native-control/build/Release/native-control.manifest.json',
      [fixture.files['native-control/build/Release/native-control.manifest.json']],
    ),
    (caught) => caught.code === 'SERVICE_MANUAL_CLEANUP' &&
      caught.operation === 'write_service_candidate_file' &&
      caught.writes === model.writes &&
      caught.writes > before &&
      caught.ambiguous === true,
  );
  const failureLog = model.log.slice(logStart);
  assert.ok(failureLog.includes('open-directory:native-control:create-new'));
  assert.ok(failureLog.includes('close:native-control'));
  access.close();
  assert.equal(model.log.at(-1), 'access-closed');
});

test('published artifact collection verifies exact trees and removes application inventory last', async () => {
  const fixture = applicationFixture();
  const transaction = transactionFor('application', fixture.manifest);
  const model = new ArtifactNativeModel();
  const access = accessFor(model, 'application', fixture.manifest, transaction);
  await access.stageAsset([fixture.asset]);
  await prepareApplication(access, fixture);
  access.publishCandidate();
  access.close();
  const artifact = publishedArtifact(
    model,
    'application',
    fixture.manifest,
  );
  const inspected = await inspectPublished(
    model,
    'application',
    fixture.manifest,
    artifact,
  );
  const driftedManifest = clone(fixture.manifest);
  driftedManifest.releaseSequence += 1;
  const beforeDrift = model.writes;
  await assert.rejects(
    collectPublished(
      model,
      'application',
      driftedManifest,
      artifact,
      inspected,
      { value: 'payload-removing' },
    ),
    (caught) => caught.code === 'SERVICE_MANUAL_CLEANUP',
  );
  assert.equal(model.writes, beforeDrift);
  const phase = { value: 'payload-removing' };
  const logStart = model.log.length;
  const result = await collectPublished(
    model,
    'application',
    fixture.manifest,
    artifact,
    inspected,
    phase,
  );
  assert.equal(result.targetAbsent, true);
  assert.equal(phase.value, 'root-removing');
  assert.equal(
    model.target('releases', fixture.manifest.archive.sha256),
    null,
  );
  const cleanupLog = model.log.slice(logStart);
  const inventoryRemoval = cleanupLog.indexOf(
    `remove-file:${APPLICATION_BUNDLE_INVENTORY_PATH}`,
  );
  assert.ok(inventoryRemoval > cleanupLog.indexOf('remove-file:run'));
  assert.ok(inventoryRemoval > cleanupLog.indexOf('remove-file:data'));
  assert.ok(
    cleanupLog.indexOf(
      `remove-directory:${fixture.manifest.archive.sha256}`,
    ) > inventoryRemoval,
  );
  assert.equal(model.activeReaders, 0);
});

test('published artifact collection deletes exact Shawl and never creates a missing root', async () => {
  const fixture = shawlFixture();
  const transaction = transactionFor('shawl', fixture.manifest, 'win32');
  const model = new ArtifactNativeModel('win32');
  const access = accessFor(model, 'shawl', fixture.manifest, transaction);
  await access.stageAsset([fixture.asset]);
  access.prepareCandidate(null);
  await access.writeCandidateFile('shawl.exe', [fixture.asset]);
  access.publishCandidate();
  access.close();
  const artifact = publishedArtifact(model, 'shawl', fixture.manifest);
  const inspected = await inspectPublished(
    model,
    'shawl',
    fixture.manifest,
    artifact,
  );
  const phase = { value: 'payload-removing' };
  await collectPublished(
    model,
    'shawl',
    fixture.manifest,
    artifact,
    inspected,
    phase,
  );
  assert.equal(
    model.target('shawl', fixture.manifest.executable.sha256),
    null,
  );
  assert.equal(phase.value, 'root-removing');

  model.roots.delete('shawl');
  const writes = model.writes;
  const logStart = model.log.length;
  await assert.rejects(
    collectPublished(
      model,
      'shawl',
      fixture.manifest,
      artifact,
      inspected,
      { value: 'root-removing' },
    ),
    (caught) => caught.code === 'SERVICE_STALE' &&
      caught.operation === 'collect_published_service_artifact',
  );
  assert.equal(model.writes, writes);
  assert.deepEqual(
    model.log.slice(logStart).filter((entry) =>
      entry.includes('bootstrap-root')),
    [],
  );
});

test('published artifact collection refuses extra, missing, recreated, and drifted targets before deletion', async () => {
  const cases = [
    {
      mutate(model, fixture) {
        const target = model.target(
          'releases',
          fixture.manifest.archive.sha256,
        );
        target.entries.set(
          'extra',
          model.file(
            'extra',
            target,
            'service-release-file',
            Buffer.from('foreign'),
          ),
        );
      },
    },
    {
      mutate(model, fixture) {
        model.target('releases', fixture.manifest.archive.sha256)
          .entries.delete('empty.txt');
      },
    },
    {
      mutate(model, fixture) {
        const root = model.roots.get('releases');
        const prior = root.entries.get(fixture.manifest.archive.sha256);
        const replacement = model.directory(
          prior.name,
          'releases',
          'service-release-directory',
          root,
        );
        replacement.entries = prior.entries;
        root.entries.set(prior.name, replacement);
      },
    },
    {
      mutate(model, fixture) {
        model.target('releases', fixture.manifest.archive.sha256)
          .entries.get('lib').entries.get('data').bytes =
            Buffer.from('drift');
      },
    },
  ];
  for (const { mutate } of cases) {
    const fixture = applicationFixture();
    const transaction = transactionFor('application', fixture.manifest);
    const model = new ArtifactNativeModel();
    const access = accessFor(
      model,
      'application',
      fixture.manifest,
      transaction,
    );
    await access.stageAsset([fixture.asset]);
    await prepareApplication(access, fixture);
    access.publishCandidate();
    access.close();
    const artifact = publishedArtifact(
      model,
      'application',
      fixture.manifest,
    );
    mutate(model, fixture);
    const writes = model.writes;
    await assert.rejects(
      inspectPublished(
        model,
        'application',
        fixture.manifest,
        artifact,
      ),
      (caught) => ['SERVICE_MANUAL_CLEANUP', 'SERVICE_STALE']
        .includes(caught.code),
    );
    assert.equal(model.writes, writes);
    assert.equal(
      model.log.slice().some((entry) => entry.startsWith('remove-')),
      false,
    );
  }
});

test('published artifact recovery refuses a recreated fixed root before destructive writes', async () => {
  const fixture = applicationFixture();
  const transaction = transactionFor('application', fixture.manifest);
  const model = new ArtifactNativeModel();
  const access = accessFor(model, 'application', fixture.manifest, transaction);
  await access.stageAsset([fixture.asset]);
  await prepareApplication(access, fixture);
  access.publishCandidate();
  access.close();
  const artifact = publishedArtifact(
    model,
    'application',
    fixture.manifest,
  );
  const inspected = await inspectPublished(
    model,
    'application',
    fixture.manifest,
    artifact,
  );
  const root = model.roots.get('releases');
  root.identity = model.identity('service-release-directory');
  const writes = model.writes;
  const removeCount = model.log.filter((entry) =>
    entry.startsWith('remove-')).length;
  await assert.rejects(
    collectPublished(
      model,
      'application',
      fixture.manifest,
      artifact,
      inspected,
      { value: 'payload-removing' },
    ),
    (caught) => caught.code === 'SERVICE_MANUAL_CLEANUP' &&
      caught.ambiguous === true,
  );
  assert.equal(model.writes, writes);
  assert.equal(
    model.log.filter((entry) => entry.startsWith('remove-')).length,
    removeCount,
  );
});

test('published artifact collection converges after each destructive crash boundary', async () => {
  for (const failure of [
    { kind: 'file', name: 'run' },
    { kind: 'directory', name: 'bin' },
    { kind: 'file', name: APPLICATION_BUNDLE_INVENTORY_PATH },
    { kind: 'directory', name: null },
  ]) {
    const fixture = applicationFixture();
    const transaction = transactionFor('application', fixture.manifest);
    const model = new ArtifactNativeModel();
    const access = accessFor(
      model,
      'application',
      fixture.manifest,
      transaction,
    );
    await access.stageAsset([fixture.asset]);
    await prepareApplication(access, fixture);
    access.publishCandidate();
    access.close();
    const artifact = publishedArtifact(
      model,
      'application',
      fixture.manifest,
    );
    const inspected = await inspectPublished(
      model,
      'application',
      fixture.manifest,
      artifact,
    );
    const phase = { value: 'payload-removing' };
    model.removeFailure = {
      ...failure,
      name: failure.name ?? fixture.manifest.archive.sha256,
    };
    const before = model.writes;
    await assert.rejects(
      collectPublished(
        model,
        'application',
        fixture.manifest,
        artifact,
        inspected,
        phase,
      ),
      (caught) => caught.code === 'SERVICE_MANUAL_CLEANUP' &&
        caught.ambiguous === true &&
        caught.writes === model.writes &&
        caught.writes > before,
    );
    assert.equal(model.activeReaders, 0);
    await collectPublished(
      model,
      'application',
      fixture.manifest,
      artifact,
      inspected,
      phase,
    );
    assert.equal(
      model.target('releases', fixture.manifest.archive.sha256),
      null,
    );
    assert.equal(phase.value, 'root-removing');
  }
});

test('published collector owners retain failed reader, directory, and root closes for child-first retry', async () => {
  for (const closeCase of [
    { name: APPLICATION_BUNDLE_INVENTORY_PATH, remaining: 3 },
    { name: 'bin', remaining: 3 },
    { name: 'releases', remaining: 1 },
  ]) {
    const fixture = applicationFixture();
    const transaction = transactionFor('application', fixture.manifest);
    const model = new ArtifactNativeModel();
    const access = accessFor(
      model,
      'application',
      fixture.manifest,
      transaction,
    );
    await access.stageAsset([fixture.asset]);
    await prepareApplication(access, fixture);
    access.publishCandidate();
    access.close();
    const artifact = publishedArtifact(
      model,
      'application',
      fixture.manifest,
    );
    const owner = createServicePublishedArtifactCollectorInternal({
      bridge: model.bridge(),
      purpose: 'application',
      manifest: fixture.manifest,
      artifact,
      platform: 'linux',
      expectedRootBindingFingerprint: null,
      expectedRootIdentity: null,
      phase: null,
      advancePhase() {
        throw new Error('inspect cannot advance');
      },
    });
    assert.deepEqual(
      Object.keys(owner),
      ['inspect', 'collect', 'retryClose'],
    );
    assert.equal(owner.handle, undefined);
    const writes = model.writes;
    model.closeFailure = { ...closeCase };
    await assert.rejects(
      owner.inspect(),
      (caught) => caught.code === 'SERVICE_IO_FAILED' &&
        caught.operation === 'inspect_published_service_artifact' &&
        caught.writes === writes &&
        caught.ambiguous === true,
    );
    assert.equal(model.writes, writes);
    if (closeCase.remaining > 1) {
      assert.throws(
        () => owner.retryClose(),
        (caught) => caught.code === 'SERVICE_IO_FAILED' &&
          caught.writes === writes &&
          caught.ambiguous === true,
      );
    }
    model.closeFailure.remaining = 0;
    assert.deepEqual(owner.retryClose(), { released: true });
    assert.equal(model.activeReaders, 0);
    const closes = model.log.filter((entry) =>
      entry.startsWith('close:'));
    assert.ok(closes.indexOf(`close:${fixture.manifest.archive.sha256}`) <
      closes.lastIndexOf('close:releases'));
  }
});

test('staged readers close eagerly on EOF, return, throw, and read failure without false completion', async () => {
  const fixture = applicationFixture();
  const transaction = transactionFor('application', fixture.manifest);
  const model = new ArtifactNativeModel();
  const access = accessFor(model, 'application', fixture.manifest, transaction);
  await access.stageAsset([fixture.asset]);

  let reader = access.openStagedAsset();
  let iterator = reader.chunks[Symbol.asyncIterator]();
  assert.equal(model.activeReaders, 1);
  await assert.rejects(
    iterator.return(),
    (caught) => caught.code === 'SERVICE_PENDING' &&
      caught.operation === 'read_staged_service_asset',
  );
  assert.equal(model.activeReaders, 0);
  await assert.rejects(
    iterator.next(),
    (caught) => caught.code === 'SERVICE_STALE',
  );
  reader.close();
  reader.close();

  model.readerChunkBytes = 4;
  reader = access.openStagedAsset();
  iterator = reader.chunks[Symbol.asyncIterator]();
  const partial = await iterator.next();
  assert.equal(partial.done, false);
  assert.equal(partial.value.length, 4);
  assert.equal(model.activeReaders, 1);
  await assert.rejects(
    iterator.return(),
    (caught) => caught.code === 'SERVICE_PENDING',
  );
  assert.equal(model.activeReaders, 0);
  reader.close();

  model.readerChunkBytes = null;
  reader = access.openStagedAsset();
  assert.deepEqual(await collect(reader.chunks), fixture.asset);
  assert.equal(model.activeReaders, 0);
  reader.close();
  reader.close();

  reader = access.openStagedAsset();
  iterator = reader.chunks[Symbol.asyncIterator]();
  await assert.rejects(
    iterator.throw(new Error('sensitive cancellation detail')),
    (caught) => caught.code === 'SERVICE_PENDING' &&
      !caught.message.includes('sensitive cancellation detail'),
  );
  assert.equal(model.activeReaders, 0);
  reader.close();

  reader = access.openStagedAsset();
  iterator = reader.chunks[Symbol.asyncIterator]();
  model.failNextRead = 'raw';
  await assert.rejects(
    iterator.next(),
    (caught) => caught.code === 'SERVICE_IO_FAILED' &&
      caught.operation === 'read_staged_service_asset' &&
      !caught.message.includes('sensitive reader failure'),
  );
  assert.equal(model.activeReaders, 0);
  reader.close();
  access.close();
});

test('artifact chunk sources cannot forge codes, writes, operations, messages, or getters', async () => {
  const fixture = applicationFixture();
  const transaction = transactionFor('application', fixture.manifest);
  const model = new ArtifactNativeModel();
  const access = accessFor(model, 'application', fixture.manifest, transaction);
  const markerWrites = model.writes;
  assert.ok(markerWrites > 0);

  let getterCalls = 0;
  const getterFailure = new Error('raw first-chunk getter failure');
  for (const name of ['code', 'writes', 'operation', 'ambiguous', 'cause']) {
    Object.defineProperty(getterFailure, name, {
      configurable: true,
      get() {
        getterCalls += 1;
        throw new Error(`read ${name}`);
      },
    });
  }
  await assert.rejects(
    access.stageAsset((async function* () {
      throw getterFailure;
    })()),
    (caught) => {
      assert.equal(caught.code, 'SERVICE_IO_FAILED');
      assert.equal(caught.operation, 'stage_service_asset');
      assert.equal(caught.writes, markerWrites);
      assert.equal(caught.ambiguous, false);
      assert.equal(caught.message, 'stage_service_asset failed');
      assert.equal(caught.cause, undefined);
      return true;
    },
  );
  assert.equal(getterCalls, 0);
  assert.equal(model.writes, markerWrites);

  await access.stageAsset([fixture.asset]);
  const retainedWrites = model.writes;
  assert.ok(retainedWrites > markerWrites);
  for (const sourceFailure of [
    Object.assign(new Error('raw deployment source failure'), {
      code: 'DEPLOYMENT_SIGNATURE_INVALID',
      writes: 999,
      operation: 'attacker-operation',
      ambiguous: true,
      cause: new Error('raw cause'),
    }),
    Object.assign(new Error('raw unknown service failure'), {
      code: 'SERVICE_ATTACKER_CONTROLLED',
      writes: 999,
      operation: 'attacker-operation',
      ambiguous: true,
    }),
  ]) {
    await assert.rejects(
      access.stageAsset((async function* () {
        throw sourceFailure;
      })()),
      (caught) => {
        assert.equal(caught.code, 'SERVICE_IO_FAILED');
        assert.equal(caught.operation, 'stage_service_asset');
        assert.equal(caught.writes, retainedWrites);
        assert.equal(caught.ambiguous, false);
        assert.equal(caught.message, 'stage_service_asset failed');
        assert.equal(caught.cause, undefined);
        assert.doesNotMatch(caught.message, /raw|attacker|deployment/i);
        return true;
      },
    );
    assert.equal(model.writes, retainedWrites);
  }

  const boundedInternal = Object.assign(new Error('raw internal failure'), {
    code: 'SERVICE_PENDING',
    writes: 999,
    operation: 'attacker-operation',
    ambiguous: true,
    cause: new Error('raw cause'),
  });
  await assert.rejects(
    access.stageAsset((async function* () {
      throw boundedInternal;
    })()),
    (caught) => {
      assert.equal(caught.code, 'SERVICE_PENDING');
      assert.equal(caught.operation, 'stage_service_asset');
      assert.equal(caught.writes, retainedWrites);
      assert.equal(caught.ambiguous, true);
      assert.equal(caught.message, 'stage_service_asset failed');
      assert.equal(caught.cause, undefined);
      return true;
    },
  );
  assert.equal(model.writes, retainedWrites);

  access.prepareCandidate(fixture.inventoryBytes);
  const preparedWrites = model.writes;
  const candidateSourceFailure = Object.assign(
    new Error('raw candidate source failure'),
    {
      code: 'DEPLOYMENT_INPUT_INVALID',
      writes: 999,
      operation: 'attacker-operation',
      ambiguous: true,
    },
  );
  await assert.rejects(
    access.writeCandidateFile('bin/run', (async function* () {
      throw candidateSourceFailure;
    })()),
    (caught) => {
      assert.equal(caught.code, 'SERVICE_IO_FAILED');
      assert.equal(caught.operation, 'write_service_candidate_file');
      assert.equal(caught.writes, preparedWrites);
      assert.equal(caught.ambiguous, false);
      assert.equal(caught.message, 'write_service_candidate_file failed');
      assert.equal(caught.cause, undefined);
      return true;
    },
  );
  assert.equal(model.writes, preparedWrites);
  access.close();
});

test('artifact readers and writers remain child-bound and failed writes count exactly once', async () => {
  const fixture = applicationFixture();
  const transaction = transactionFor('application', fixture.manifest);
  const mismatch = new ArtifactNativeModel();
  const mismatchAccess = accessFor(
    mismatch,
    'application',
    fixture.manifest,
    transaction,
  );
  await assert.rejects(
    mismatchAccess.stageAsset([Buffer.alloc(fixture.asset.length)]),
    (caught) => caught.code === 'SERVICE_MANUAL_CLEANUP' &&
      caught.operation === 'stage_service_asset' &&
      caught.writes === mismatch.writes &&
      caught.writes > 0,
  );
  mismatchAccess.close();

  const oversized = new ArtifactNativeModel();
  const oversizedAccess = accessFor(
    oversized,
    'application',
    fixture.manifest,
    transaction,
  );
  const beforeOversizedChunk = oversized.writes;
  await assert.rejects(
    oversizedAccess.stageAsset([Buffer.alloc(1024 * 1024 + 1)]),
    (caught) => caught.code === 'SERVICE_INVALID' &&
      caught.operation === 'stage_service_asset' &&
      caught.writes === beforeOversizedChunk &&
      oversized.writes === beforeOversizedChunk,
  );
  oversizedAccess.close();

  const model = new ArtifactNativeModel();
  const access = accessFor(model, 'application', fixture.manifest, transaction);
  await access.stageAsset([fixture.asset]);
  const reader = access.openStagedAsset();
  const closeStart = model.log.length;
  access.close();
  const closeLog = model.log.slice(closeStart);
  assert.ok(closeLog.indexOf('close:archive') <
    closeLog.indexOf('close:bot-11111111111111111111111111111111-application'));
  reader.close();
  assert.throws(
    () => reader.chunks[Symbol.asyncIterator](),
    (caught) => caught.code === 'SERVICE_STALE' &&
      caught.operation === 'read_staged_service_asset',
  );

  const failed = new ArtifactNativeModel();
  const failedAccess = accessFor(failed, 'application', fixture.manifest, transaction);
  failed.failNextChunk = true;
  await assert.rejects(
    failedAccess.stageAsset([fixture.asset]),
    (caught) => caught.code === 'SERVICE_MANUAL_CLEANUP' &&
      caught.operation === 'stage_service_asset' &&
      caught.writes === failed.writes &&
      caught.writes > 0,
  );
  const writes = failed.writes;
  assert.throws(
    () => failedAccess.openStagedAsset(),
    (caught) => caught.code === 'SERVICE_MANUAL_CLEANUP' && caught.writes === writes,
  );
  failedAccess.close();
  assert.equal(failed.writes, writes);
});

function tarHeader(path, size) {
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

function rawTarEntry(path, bytes) {
  const body = Buffer.from(bytes);
  const remainder = body.length % 512;
  const padding = remainder === 0 ? Buffer.alloc(0) : Buffer.alloc(512 - remainder);
  return Buffer.concat([tarHeader(path, body.length), body, padding]);
}

function realApplicationFixture() {
  const files = {
    'bin/run': Buffer.from('run'),
    'bot/src/bot.js': Buffer.from('bot'),
    'daemon/src/daemon.js': Buffer.from('daemon'),
    'lib/data': Buffer.from('payload'),
    'native-control/build/Release/native-control.manifest.json': Buffer.from('native'),
  };
  const payloadEntries = Object.entries(files).map(([path, bytes]) => ({
    path,
    size: bytes.length,
    sha256: sha256(bytes),
    executablePolicy: path === 'bin/run' ? 'required' : 'forbidden',
  }));
  const inventory = buildBundleInventory({ payloadEntries }, { platform: 'linux' });
  const inventoryBytes = canonicalJsonBytes(inventory, {
    maxBytes: 32 * 1024 * 1024,
    maxDepth: 16,
    maxNodes: 600_032,
  });
  const archiveBytes = Buffer.from(gzipSync(Buffer.concat([
    rawTarEntry(APPLICATION_BUNDLE_INVENTORY_PATH, inventoryBytes),
    ...payloadEntries.map((entry) => rawTarEntry(entry.path, files[entry.path])),
    Buffer.alloc(1024),
  ]), { level: 6 }));
  archiveBytes[9] = 255;
  const manifest = buildApplicationDeploymentManifest({
    signingKeyId: 'fixture',
    releaseId: 'v1.0.0',
    releaseVersion: '1.0.0',
    releaseSequence: 1,
    source: {
      repository: 'kogangdon/gjc-remote',
      tag: 'v1.0.0',
      commit: '1'.repeat(40),
      tree: '2'.repeat(40),
      bunLockSha256: hash('3'),
    },
    target: { platform: 'linux', architecture: 'x64' },
    archive: {
      name: 'gjc-remote-service-1.0.0-linux-x64.tar.gz',
      mediaType: 'application/gzip',
      byteLength: archiveBytes.length,
      sha256: sha256(archiveBytes),
      entryCount: inventory.payloadEntryCount + 1,
    },
    inventory: {
      path: APPLICATION_BUNDLE_INVENTORY_PATH,
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
      manifestFingerprint: hash('4'),
      contractVersion: 4,
      contractRevision: 4,
    },
    wireCapabilities: ['gate_presentation_v1'],
    compatibility: compatibility(),
  });
  return { asset: archiveBytes, files, inventory, inventoryBytes, manifest };
}

async function captureScratch(model, purpose, manifest, transaction) {
  const owner = createScratchArtifactCollectorInternal({
    bridge: model.bridge(),
    purpose,
    manifest,
    transaction,
    transactionIdentity: transactionIdentity(transaction),
    roles,
    rolesFingerprint,
    platform: manifest.target.platform,
    architecture: 'x64',
    component: 'bot',
    serviceKey: transaction.serviceKey,
    authority: null,
    inspectArchive: null,
    phase: null,
    advancePhase() {
      throw new Error('capture cannot advance');
    },
  });
  return owner.capture();
}

async function collectScratch(model, purpose, manifest, authority, phaseState) {
  const owner = createScratchArtifactCollectorInternal({
    bridge: model.bridge(),
    purpose,
    manifest,
    transaction: null,
    transactionIdentity: null,
    roles: null,
    rolesFingerprint: null,
    platform: manifest.target.platform,
    architecture: null,
    component: null,
    serviceKey: null,
    authority,
    inspectArchive: purpose === 'application'
      ? (chunks) => inspectApplicationArchive({ manifest, chunks })
      : null,
    phase: phaseState.value,
    advancePhase(next) {
      phaseState.value = next;
    },
  });
  return owner.collect();
}

function removalLog(model, start = 0) {
  return model.log.slice(start).filter((entry) => entry.startsWith('remove-'));
}

test('scratch collection re-inspects the authentic archive and removes a partial candidate in phase order', async () => {
  const fixture = realApplicationFixture();
  const transaction = transactionFor('application', fixture.manifest);
  const model = new ArtifactNativeModel();
  const access = accessFor(model, 'application', fixture.manifest, transaction);
  await access.stageAsset([fixture.asset]);
  access.prepareCandidate(fixture.inventoryBytes);
  await access.writeCandidateFile('bin/run', [fixture.files['bin/run']]);
  model.failNextChunk = true;
  await assert.rejects(
    access.writeCandidateFile('lib/data', [fixture.files['lib/data']]),
    (caught) => caught.code === 'SERVICE_MANUAL_CLEANUP',
  );
  access.close();
  assert.equal(model.activeReaders, 0);
  const scratch = model.scratch(transaction, 'application');
  assert.ok(scratch !== null);

  const authority = await captureScratch(
    model,
    'application',
    fixture.manifest,
    transaction,
  );
  assert.equal(
    authority.scratchName,
    `bot-${'1'.repeat(32)}-application`,
  );
  assert.equal(authority.assetName, 'archive');
  assert.equal(authority.assetSize, fixture.asset.length);
  assert.equal(authority.assetSha256, sha256(fixture.asset));
  assert.equal(authority.assetFacts.sha256, sha256(fixture.asset));
  assert.ok(authority.candidateIdentity !== null);
  assert.equal(authority.candidateIdentity.profile, 'service-staging-directory');
  assert.equal(typeof authority.markerFingerprint, 'string');

  const phase = { value: 'candidate-payload-removing' };
  const logStart = model.log.length;
  const result = await collectScratch(
    model,
    'application',
    fixture.manifest,
    authority,
    phase,
  );
  assert.equal(result.targetAbsent, true);
  assert.equal(phase.value, 'scratch-root-removing');
  assert.equal(model.scratch(transaction, 'application'), null);
  assert.equal(model.activeReaders, 0);
  const removals = removalLog(model, logStart);
  const inventoryIndex = removals.indexOf(
    `remove-file:${APPLICATION_BUNDLE_INVENTORY_PATH}`,
  );
  assert.ok(inventoryIndex > removals.indexOf('remove-file:bin/run'));
  assert.ok(inventoryIndex > removals.indexOf('remove-file:lib/data'));
  assert.ok(removals.indexOf('remove-directory:candidate') > inventoryIndex);
  assert.ok(
    removals.indexOf('remove-file:archive') >
      removals.indexOf('remove-directory:candidate'),
  );
  assert.ok(
    removals.indexOf('remove-file:transaction.json') >
      removals.indexOf('remove-file:archive'),
  );
  assert.equal(
    removals.at(-1),
    `remove-directory:bot-${'1'.repeat(32)}-application`,
  );
});

test('scratch collection converges after crashes at every phase boundary', async () => {
  const crashPhases = [
    'candidate-inventory-removing',
    'candidate-root-removing',
    'asset-removing',
    'marker-removing',
    'scratch-root-removing',
  ];
  for (const crashAt of crashPhases) {
    const fixture = realApplicationFixture();
    const transaction = transactionFor('application', fixture.manifest);
    const model = new ArtifactNativeModel();
    const access = accessFor(model, 'application', fixture.manifest, transaction);
    await access.stageAsset([fixture.asset]);
    access.prepareCandidate(fixture.inventoryBytes);
    await access.writeCandidateFile('bin/run', [fixture.files['bin/run']]);
    access.close();
    const authority = await captureScratch(
      model,
      'application',
      fixture.manifest,
      transaction,
    );
    const phase = { value: 'candidate-payload-removing' };
    const writes = model.writes;
    await assert.rejects(
      (async () => {
        const owner = createScratchArtifactCollectorInternal({
          bridge: model.bridge(),
          purpose: 'application',
          manifest: fixture.manifest,
          transaction: null,
          transactionIdentity: null,
          roles: null,
          rolesFingerprint: null,
          platform: 'linux',
          architecture: null,
          component: null,
          serviceKey: null,
          authority,
          inspectArchive: (chunks) => inspectApplicationArchive({
            manifest: fixture.manifest,
            chunks,
          }),
          phase: phase.value,
          advancePhase(next) {
            phase.value = next;
            if (next === crashAt) {
              throw error(
                'SERVICE_MANUAL_CLEANUP',
                'collect_scratch_artifact_space',
                model.writes,
                true,
              );
            }
          },
        });
        return owner.collect();
      })(),
      (caught) => caught.code === 'SERVICE_MANUAL_CLEANUP' &&
        caught.ambiguous === true &&
        caught.writes > writes,
    );
    assert.equal(model.activeReaders, 0);
    const resumed = await collectScratch(
      model,
      'application',
      fixture.manifest,
      authority,
      phase,
    );
    assert.equal(resumed.targetAbsent, true);
    assert.equal(model.scratch(transaction, 'application'), null);
    assert.equal(model.activeReaders, 0);
  }

  const fixture = realApplicationFixture();
  const transaction = transactionFor('application', fixture.manifest);
  const model = new ArtifactNativeModel();
  const access = accessFor(model, 'application', fixture.manifest, transaction);
  await access.stageAsset([fixture.asset]);
  access.prepareCandidate(fixture.inventoryBytes);
  await access.writeCandidateFile('bin/run', [fixture.files['bin/run']]);
  access.close();
  const authority = await captureScratch(
    model,
    'application',
    fixture.manifest,
    transaction,
  );
  model.removeFailure = { kind: 'file', name: 'run' };
  const phase = { value: 'candidate-payload-removing' };
  const writes = model.writes;
  await assert.rejects(
    collectScratch(model, 'application', fixture.manifest, authority, phase),
    (caught) => caught.code === 'SERVICE_MANUAL_CLEANUP' &&
      caught.ambiguous === true &&
      caught.writes > writes,
  );
  assert.equal(phase.value, 'candidate-payload-removing');
  assert.equal(model.activeReaders, 0);
  const resumed = await collectScratch(
    model,
    'application',
    fixture.manifest,
    authority,
    phase,
  );
  assert.equal(resumed.targetAbsent, true);
  assert.equal(model.scratch(transaction, 'application'), null);
});

test('scratch collection removes partial assets and marker-only scratch without candidate authority', async () => {
  const fixture = realApplicationFixture();
  const transaction = transactionFor('application', fixture.manifest);
  const model = new ArtifactNativeModel();
  const access = accessFor(model, 'application', fixture.manifest, transaction);
  model.failNextChunk = true;
  await assert.rejects(
    access.stageAsset([fixture.asset.subarray(0, 8)]),
    (caught) => caught.code === 'SERVICE_MANUAL_CLEANUP',
  );
  access.close();
  const authority = await captureScratch(
    model,
    'application',
    fixture.manifest,
    transaction,
  );
  assert.equal(authority.candidateIdentity, null);
  assert.ok(authority.assetFacts.size < authority.assetSize);
  const phase = { value: 'asset-removing' };
  const result = await collectScratch(
    model,
    'application',
    fixture.manifest,
    authority,
    phase,
  );
  assert.equal(result.targetAbsent, true);
  assert.equal(model.scratch(transaction, 'application'), null);
  assert.ok(removalLog(model).includes('remove-file:archive'));

  const emptyModel = new ArtifactNativeModel();
  const emptyAccess = accessFor(
    emptyModel,
    'application',
    fixture.manifest,
    transaction,
  );
  emptyAccess.close();
  const emptyAuthority = await captureScratch(
    emptyModel,
    'application',
    fixture.manifest,
    transaction,
  );
  assert.equal(emptyAuthority.assetFacts, null);
  assert.equal(emptyAuthority.candidateIdentity, null);
  const emptyPhase = { value: 'asset-removing' };
  await collectScratch(
    emptyModel,
    'application',
    fixture.manifest,
    emptyAuthority,
    emptyPhase,
  );
  assert.equal(emptyModel.scratch(transaction, 'application'), null);
  assert.deepEqual(removalLog(emptyModel), [
    'remove-file:transaction.json',
    `remove-directory:bot-${'1'.repeat(32)}-application`,
  ]);
  const absent = await captureScratch(
    emptyModel,
    'application',
    fixture.manifest,
    transaction,
  );
  assert.equal(absent, null);
});

test('scratch collection removes Shawl candidates without an inventory phase', async () => {
  const fixture = shawlFixture();
  const transaction = transactionFor('shawl', fixture.manifest, 'win32');
  const model = new ArtifactNativeModel('win32');
  const access = accessFor(model, 'shawl', fixture.manifest, transaction);
  await access.stageAsset([fixture.asset]);
  access.prepareCandidate(null);
  await access.writeCandidateFile('shawl.exe', [fixture.asset]);
  access.close();
  const authority = await captureScratch(
    model,
    'shawl',
    fixture.manifest,
    transaction,
  );
  assert.equal(authority.assetName, 'raw-shawl');
  assert.ok(authority.candidateIdentity !== null);
  const transitions = [];
  const phase = { value: 'candidate-payload-removing' };
  const owner = createScratchArtifactCollectorInternal({
    bridge: model.bridge(),
    purpose: 'shawl',
    manifest: fixture.manifest,
    transaction: null,
    transactionIdentity: null,
    roles: null,
    rolesFingerprint: null,
    platform: 'win32',
    architecture: null,
    component: null,
    serviceKey: null,
    authority,
    inspectArchive: null,
    phase: phase.value,
    advancePhase(next) {
      transitions.push(next);
      phase.value = next;
    },
  });
  const result = await owner.collect();
  assert.equal(result.targetAbsent, true);
  assert.deepEqual(transitions, [
    'candidate-root-removing',
    'asset-removing',
    'marker-removing',
    'scratch-root-removing',
  ]);
  assert.equal(model.scratch(transaction, 'shawl'), null);

  const emptyModel = new ArtifactNativeModel('win32');
  const emptyAccess = accessFor(
    emptyModel,
    'shawl',
    fixture.manifest,
    transaction,
  );
  await emptyAccess.stageAsset([fixture.asset]);
  emptyAccess.prepareCandidate(null);
  emptyAccess.close();
  const emptyAuthority = await captureScratch(
    emptyModel,
    'shawl',
    fixture.manifest,
    transaction,
  );
  assert.ok(emptyAuthority.candidateIdentity !== null);
  const emptyPhase = { value: 'candidate-payload-removing' };
  const emptyResult = await collectScratch(
    emptyModel,
    'shawl',
    fixture.manifest,
    emptyAuthority,
    emptyPhase,
  );
  assert.equal(emptyResult.targetAbsent, true);
  assert.equal(emptyModel.scratch(transaction, 'shawl'), null);
});

test('scratch collection refuses foreign entries, identity drift, and unusable archives without cleanup writes', async () => {
  const fixture = realApplicationFixture();
  const transaction = transactionFor('application', fixture.manifest);

  async function partialCandidateModel(mutate) {
    const model = new ArtifactNativeModel();
    const access = accessFor(model, 'application', fixture.manifest, transaction);
    await access.stageAsset([fixture.asset]);
    access.prepareCandidate(fixture.inventoryBytes);
    await access.writeCandidateFile('bin/run', [fixture.files['bin/run']]);
    access.close();
    const authority = await captureScratch(
      model,
      'application',
      fixture.manifest,
      transaction,
    );
    mutate(model, authority);
    return { model, authority };
  }

  async function assertRefused({ model, authority }, phaseValue) {
    const phase = { value: phaseValue };
    const writes = model.writes;
    const logStart = model.log.length;
    await assert.rejects(
      collectScratch(model, 'application', fixture.manifest, authority, phase),
      (caught) => caught.code === 'SERVICE_MANUAL_CLEANUP',
    );
    assert.equal(model.writes, writes);
    assert.equal(removalLog(model, logStart).length, 0);
    assert.equal(model.activeReaders, 0);
  }

  // Case C: the archive is missing while the candidate is nonempty.
  await assertRefused(
    await partialCandidateModel((model) => {
      model.scratch(transaction, 'application').entries.delete('archive');
    }),
    'candidate-payload-removing',
  );

  // Case C: the archive no longer matches the signed facts.
  await assertRefused(
    await partialCandidateModel((model) => {
      model.scratch(transaction, 'application').entries.get('archive').bytes =
        Buffer.from('corrupted archive bytes');
    }),
    'candidate-payload-removing',
  );

  // An unknown candidate descendant is never enumerated into deletion.
  await assertRefused(
    await partialCandidateModel((model) => {
      model.injectCandidateFile(
        transaction,
        'application',
        'foreign.txt',
        Buffer.from('foreign'),
      );
    }),
    'candidate-payload-removing',
  );

  // Scratch directory recreation loses the recorded identity.
  await assertRefused(
    await partialCandidateModel((model) => {
      const name = model.scratchName(transaction, 'application');
      const root = model.roots.get('staging');
      const prior = root.entries.get(name);
      const replacement = model.directory(
        name,
        'staging',
        'service-staging-directory',
        root,
      );
      replacement.entries = prior.entries;
      root.entries.set(name, replacement);
    }),
    'candidate-payload-removing',
  );

  // Marker bytes are bound to the captured fingerprint and facts.
  await assertRefused(
    await partialCandidateModel((model) => {
      model.scratch(transaction, 'application')
        .entries.get('transaction.json').bytes = Buffer.from('{}');
    }),
    'candidate-payload-removing',
  );

  // A marker from a different logical transaction never authorizes capture.
  {
    const model = new ArtifactNativeModel();
    const access = accessFor(model, 'application', fixture.manifest, transaction);
    await access.stageAsset([fixture.asset]);
    access.close();
    const foreign = {
      ...transaction,
      transactionId: 'tx-foreign-application',
    };
    await assert.rejects(
      captureScratch(model, 'application', fixture.manifest, foreign),
      (caught) => caught.code === 'SERVICE_MANUAL_CLEANUP',
    );
    assert.equal(removalLog(model).length, 0);
  }
});
