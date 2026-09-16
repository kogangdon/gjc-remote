import { createHash } from 'node:crypto';
import {
  DEPLOYMENT_ENVELOPE_LIMITS,
  validateDeploymentSource,
} from '@gjc-remote/shared/deployment-envelope';
import { canonicalJsonBytes, parseCanonicalJsonBytes } from '@gjc-remote/shared/strict-json';
import { validateServiceArtifactFileFacts } from '@gjc-remote/shared/service-lifecycle-envelope';
import { assertPinnedDeploymentManifest } from './deployment-provenance.js';

const CHUNK_BYTES = 1024 * 1024;
const JSON_LIMITS = Object.freeze({ maxBytes: 64 * 1024, maxDepth: 8, maxNodes: 256 });

class OfflineSourceError extends Error {
  constructor(code, writes = 0) {
    super(code);
    this.name = 'OfflineSourceError';
    this.code = code;
    this.operation = 'read_offline_deployment_source';
    this.writes = writes;
  }
}

function fail(code, writes = 0) {
  throw new OfflineSourceError(code, writes);
}

function data(object, name) {
  const descriptor = Object.getOwnPropertyDescriptor(object, name);
  if (!descriptor || !Object.hasOwn(descriptor, 'value')) fail('DEPLOYMENT_SOURCE_INVALID');
  return descriptor.value;
}

function snapshot(value) {
  return parseCanonicalJsonBytes(canonicalJsonBytes(value, JSON_LIMITS), JSON_LIMITS);
}

function freeze(value) {
  if (value && typeof value === 'object' && !Object.isFrozen(value)) {
    for (const child of Object.values(value)) freeze(child);
    Object.freeze(value);
  }
  return value;
}

// Only the private acquisition orchestrator supplies this already role-bound
// native facade. No JavaScript filesystem or injected verifier fallback exists.
export function createOfflineDeploymentSource(options) {
  let source;
  let platform;
  let architecture;
  let native;
  try {
    if (Object.getPrototypeOf(options) !== Object.prototype ||
        Reflect.ownKeys(options).length !== 4) fail('DEPLOYMENT_SOURCE_INVALID');
    platform = data(options, 'platform');
    architecture = data(options, 'architecture');
    source = snapshot(data(options, 'source'));
    validateDeploymentSource(source, { platform, architecture });
    if (source.kind !== 'offline') fail('DEPLOYMENT_SOURCE_INVALID');
    const facade = data(options, 'native');
    native = Object.fromEntries([
      'open_service_artifact_source',
      'read_service_artifact_chunk',
      'close_service_handle',
    ].map((name) => {
      const method = data(facade, name);
      if (typeof method !== 'function') fail('DEPLOYMENT_SOURCE_INVALID');
      return [name, method.bind(facade)];
    }));
  } catch {
    fail('DEPLOYMENT_SOURCE_INVALID');
  }
  let closed = false;
  const readers = new Set();

  const ensureOpen = () => {
    if (closed) fail('DEPLOYMENT_SOURCE_CLOSED');
  };
  const invoke = (name, ...args) => {
    try {
      const result = native[name](...args);
      if (result !== null && result !== undefined &&
          (!Number.isSafeInteger(result.writes) || result.writes !== 0)) {
        fail('DEPLOYMENT_SOURCE_NATIVE_WRITES',
          Number.isSafeInteger(result.writes) && result.writes > 0 ? result.writes : 0);
      }
      return result;
    } catch (error) {
      if (error instanceof OfflineSourceError) throw error;
      const writes = Number.isSafeInteger(error?.writes) && error.writes > 0 ? error.writes : 0;
      throw new OfflineSourceError('DEPLOYMENT_SOURCE_NATIVE_FAILED', writes);
    }
  };

  function openFile(path, maximum, expected = null) {
    ensureOpen();
    const opened = invoke('open_service_artifact_source', path, maximum, null);
    if (opened === null) fail('DEPLOYMENT_SOURCE_MISSING');
    if (!opened || !Object.hasOwn(opened, 'handle')) fail('DEPLOYMENT_SOURCE_NATIVE_INVALID');
    let readerClosed = false;
    const close = () => {
      if (readerClosed) return;
      invoke('close_service_handle', opened.handle);
      readerClosed = true;
      readers.delete(close);
    };
    readers.add(close);
    let facts;
    try {
      facts = snapshot(opened.facts);
      validateServiceArtifactFileFacts(facts, platform);
      if (facts.size > maximum ||
          (expected !== null &&
            (facts.size !== expected.size || facts.sha256 !== expected.sha256))) {
        fail('DEPLOYMENT_SOURCE_IDENTITY_MISMATCH');
      }
      freeze(facts);
    } catch (error) {
      close();
      if (error instanceof OfflineSourceError) throw error;
      fail('DEPLOYMENT_SOURCE_NATIVE_INVALID');
    }
    let started = false;
    async function* consume() {
      let complete = false;
      let failed = false;
      try {
        ensureOpen();
        if (readerClosed) fail('DEPLOYMENT_SOURCE_CLOSED');
        let offset = 0;
        const hash = createHash('sha256');
        while (!complete) {
          ensureOpen();
          if (readerClosed) fail('DEPLOYMENT_SOURCE_CLOSED');
          const chunk = invoke('read_service_artifact_chunk', opened.handle, offset, CHUNK_BYTES);
          if (!chunk || !Buffer.isBuffer(chunk.bytes) ||
              chunk.bytes.length > CHUNK_BYTES ||
              chunk.nextOffset !== offset + chunk.bytes.length ||
              chunk.nextOffset > facts.size ||
              typeof chunk.eof !== 'boolean' ||
              chunk.eof !== (chunk.nextOffset === facts.size) ||
              (!chunk.eof && chunk.bytes.length === 0)) {
            fail('DEPLOYMENT_SOURCE_NATIVE_INVALID');
          }
          hash.update(chunk.bytes);
          offset = chunk.nextOffset;
          if (chunk.eof) {
            if (hash.digest('hex') !== facts.sha256) fail('DEPLOYMENT_SOURCE_HASH_INVALID');
            complete = true;
          }
          if (chunk.bytes.length > 0) yield chunk.bytes;
        }
      } catch (error) {
        failed = true;
        if (error instanceof OfflineSourceError) throw error;
        fail('DEPLOYMENT_SOURCE_NATIVE_FAILED');
      } finally {
        close();
        if (!complete && !failed) fail('DEPLOYMENT_SOURCE_INCOMPLETE');
      }
    }
    const chunks = Object.freeze({
      [Symbol.asyncIterator]() {
        if (started) fail('DEPLOYMENT_SOURCE_ALREADY_CONSUMED');
        started = true;
        const iterator = consume();
        let begun = false;
        return Object.freeze({
          next(value) {
            begun = true;
            return iterator.next(value);
          },
          async return(value) {
            if (!begun) {
              close();
              await iterator.return(value);
              fail('DEPLOYMENT_SOURCE_INCOMPLETE');
            }
            return iterator.return(value);
          },
          async throw() {
            close();
            try {
              await iterator.return();
            } catch (error) {
              if (!(error instanceof OfflineSourceError) ||
                  error.code !== 'DEPLOYMENT_SOURCE_INCOMPLETE') throw error;
            }
            fail('DEPLOYMENT_SOURCE_INCOMPLETE');
          },
          [Symbol.asyncIterator]() { return this; },
        });
      },
    });
    return Object.freeze({ facts, chunks, close });
  }

  async function readBytes(path, maximum) {
    const opened = openFile(path, maximum);
    const parts = [];
    for await (const bytes of opened.chunks) parts.push(bytes);
    return Buffer.concat(parts, opened.facts.size);
  }

  function assertManifest(manifest, purpose) {
    ensureOpen();
    try {
      assertPinnedDeploymentManifest(manifest, purpose);
      if (manifest.target.platform !== platform || manifest.target.architecture !== architecture) {
        fail('DEPLOYMENT_SOURCE_TARGET_MISMATCH');
      }
    } catch (error) {
      if (error instanceof OfflineSourceError) throw error;
      fail('DEPLOYMENT_SOURCE_PINNED_PROVENANCE_REQUIRED');
    }
  }

  return Object.freeze({
    async readBootstrap(purpose) {
      ensureOpen();
      if (purpose !== 'application' && !(purpose === 'shawl' && platform === 'win32')) {
        fail('DEPLOYMENT_SOURCE_INVALID');
      }
      const prefix = purpose === 'application' ? 'application' : 'shawl';
      const manifestBytes = await readBytes(source[`${prefix}ManifestPath`], DEPLOYMENT_ENVELOPE_LIMITS.manifestBytes);
      const signatureBytes = await readBytes(source[`${prefix}SignaturePath`], DEPLOYMENT_ENVELOPE_LIMITS.signatureBytes);
      return Object.freeze({ manifestBytes, signatureBytes });
    },
    openApplication(manifest) {
      assertManifest(manifest, 'application');
      return openFile(source.applicationArchivePath, manifest.archive.byteLength, {
        size: manifest.archive.byteLength,
        sha256: manifest.archive.sha256,
      });
    },
    openShawl(manifest) {
      assertManifest(manifest, 'shawl');
      return openFile(source.shawlExecutablePath, manifest.executable.byteLength, {
        size: manifest.executable.byteLength,
        sha256: manifest.executable.sha256,
      });
    },
    close() {
      if (closed && readers.size === 0) return;
      closed = true;
      let failure;
      for (const close of [...readers]) {
        try { close(); } catch (error) { failure ??= error; }
      }
      if (failure) throw failure;
    },
  });
}
