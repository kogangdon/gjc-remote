import { createHash } from 'node:crypto';
import https from 'node:https';
import { isIP } from 'node:net';
import { checkServerIdentity, rootCertificates } from 'node:tls';
import {
  APPLICATION_DEPLOYMENT_REPOSITORY,
  DEPLOYMENT_ENVELOPE_LIMITS,
  deploymentBootstrapAssetNames,
  validateDeploymentSource,
} from '@gjc-remote/shared/deployment-envelope';
import { assertPinnedDeploymentManifest } from './deployment-provenance.js';

const RESPONSE_HEADER_BYTES = 16 * 1024;
const RESPONSE_HEADER_COUNT = 64;
const LOCATION_BYTES = DEPLOYMENT_ENVELOPE_LIMITS.pathBytes;
const USER_AGENT = 'gjc-remote-native-control/1';
const REDIRECT_STATUSES = new Set([301, 302, 303, 307, 308]);
const RELEASE_ASSET_HOSTS = new Set([
  'release-assets.githubusercontent.com',
  'objects.githubusercontent.com',
]);
const SHA256 = /^[0-9a-f]{64}$/;
const HEADER_NAME = /^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/;
const NOOP = () => {};

const CODES = Object.freeze({
  invalid: 'SERVICE_TRANSPORT_INVALID',
  closed: 'SERVICE_TRANSPORT_CLOSED',
  deadline: 'SERVICE_TRANSPORT_DEADLINE_EXCEEDED',
  connectTimeout: 'SERVICE_TRANSPORT_CONNECT_TIMEOUT',
  idleTimeout: 'SERVICE_TRANSPORT_IDLE_TIMEOUT',
  network: 'SERVICE_TRANSPORT_NETWORK_FAILED',
  response: 'SERVICE_TRANSPORT_RESPONSE_INVALID',
  redirect: 'SERVICE_TRANSPORT_REDIRECT_INVALID',
  redirects: 'SERVICE_TRANSPORT_REDIRECT_LIMIT',
  size: 'SERVICE_TRANSPORT_SIZE_INVALID',
  hash: 'SERVICE_TRANSPORT_HASH_INVALID',
  incomplete: 'SERVICE_TRANSPORT_INCOMPLETE',
  consumed: 'SERVICE_TRANSPORT_ALREADY_CONSUMED',
  manifest: 'SERVICE_TRANSPORT_MANIFEST_MISMATCH',
  pinned: 'DEPLOYMENT_PINNED_PROVENANCE_REQUIRED',
});

class ServiceTransportError extends Error {
  constructor(code, operation) {
    super(code);
    Object.defineProperties(this, {
      name: { value: 'ServiceTransportError' },
      code: { value: code, enumerable: true },
      operation: { value: operation, enumerable: true },
      writes: { value: 0, enumerable: true },
    });
  }
}

function failure(code, operation) {
  return new ServiceTransportError(code, operation);
}

function fail(code, operation) {
  throw failure(code, operation);
}

function normalizeFailure(error, fallback, operation) {
  return error instanceof ServiceTransportError && error.operation === operation
    ? error
    : failure(fallback, operation);
}

function exactDataValues(value, keys) {
  if (value === null || typeof value !== 'object') return null;
  let ownKeys;
  let descriptors;
  try {
    if (Object.getPrototypeOf(value) !== Object.prototype) return null;
    ownKeys = Reflect.ownKeys(value);
    descriptors = Object.getOwnPropertyDescriptors(value);
  } catch {
    return null;
  }
  if (ownKeys.length !== keys.length || keys.some((key) => !ownKeys.includes(key))) return null;
  const result = Object.create(null);
  for (const key of keys) {
    const descriptor = descriptors[key];
    if (!descriptor || descriptor.enumerable !== true || descriptor.get !== undefined || descriptor.set !== undefined ||
        !Object.hasOwn(descriptor, 'value')) return null;
    result[key] = descriptor.value;
  }
  return result;
}

function destroyPair(request, response) {
  try { response?.setTimeout?.(0); } catch {}
  try { response?.destroy?.(); } catch {}
  try { request?.destroy?.(); } catch {}
}

function readResponseHeaders(response, operation) {
  const raw = response?.rawHeaders;
  if (!Array.isArray(raw) || raw.length % 2 !== 0 || raw.length / 2 > RESPONSE_HEADER_COUNT) {
    fail(CODES.response, operation);
  }
  const headers = new Map();
  let bytes = 0;
  for (let index = 0; index < raw.length; index += 2) {
    const name = raw[index];
    const value = raw[index + 1];
    if (typeof name !== 'string' || typeof value !== 'string' || !HEADER_NAME.test(name) ||
        /[\0\r\n]/.test(value)) fail(CODES.response, operation);
    bytes += Buffer.byteLength(name, 'utf8') + Buffer.byteLength(value, 'utf8') + 4;
    if (bytes > RESPONSE_HEADER_BYTES) fail(CODES.response, operation);
    const lower = name.toLowerCase();
    const values = headers.get(lower);
    if (values) values.push(value);
    else headers.set(lower, [value]);
  }
  return headers;
}

function validateResponseHeaders(response, maximumBytes, expectedLength, operation) {
  const headers = readResponseHeaders(response, operation);
  const encodings = headers.get('content-encoding') ?? [];
  if (encodings.length > 1 || (encodings.length === 1 && encodings[0].toLowerCase() !== 'identity')) {
    fail(CODES.response, operation);
  }
  const lengths = headers.get('content-length') ?? [];
  if (lengths.length > 1) fail(CODES.size, operation);
  let contentLength = null;
  if (lengths.length === 1) {
    const encoded = lengths[0];
    if (!/^[0-9]+$/.test(encoded)) fail(CODES.size, operation);
    let parsed;
    try { parsed = BigInt(encoded); } catch { fail(CODES.size, operation); }
    if (parsed > BigInt(maximumBytes) ||
        (expectedLength !== null && parsed !== BigInt(expectedLength))) fail(CODES.size, operation);
    contentLength = Number(parsed);
  }
  if (contentLength !== null && (headers.get('transfer-encoding')?.length ?? 0) !== 0) {
    fail(CODES.response, operation);
  }
  return Object.freeze({ headers, contentLength });
}

function initialAssetUrl(tag, assetName) {
  return new URL(
    `https://github.com/${APPLICATION_DEPLOYMENT_REPOSITORY}/releases/download/${encodeURIComponent(tag)}/${encodeURIComponent(assetName)}`,
  );
}

function redirectTarget(location, current, initial, operation) {
  if (typeof location !== 'string' || location.length === 0 ||
      Buffer.byteLength(location, 'utf8') > LOCATION_BYTES || /[\p{Cc}\p{Cs}\u2028\u2029]/u.test(location) ||
      location.trim() !== location || location.includes('\\') || location.includes('#')) fail(CODES.redirect, operation);
  let target;
  try { target = new URL(location, current); } catch { fail(CODES.redirect, operation); }
  if (target.protocol !== 'https:' || target.port !== '' || target.username !== '' || target.password !== '' ||
      target.hash !== '' || isIP(target.hostname) !== 0 ||
      Buffer.byteLength(target.href, 'utf8') > LOCATION_BYTES) fail(CODES.redirect, operation);
  const allowed = (target.hostname === 'github.com' && target.href === initial.href) ||
    RELEASE_ASSET_HOSTS.has(target.hostname);
  if (!allowed) fail(CODES.redirect, operation);
  return target;
}

function validateStatus(response, operation) {
  if (!Number.isSafeInteger(response?.statusCode) || response.statusCode < 100 || response.statusCode > 599) {
    fail(CODES.response, operation);
  }
  return response.statusCode;
}

function bufferChunk(value, operation) {
  if (!Buffer.isBuffer(value) && !(value instanceof Uint8Array)) fail(CODES.response, operation);
  return Buffer.isBuffer(value)
    ? value
    : Buffer.from(value.buffer, value.byteOffset, value.byteLength);
}

export function createGithubReleaseTransport(options) {
  if (arguments.length !== 1) fail(CODES.invalid, 'create_github_release_transport');
  const values = exactDataValues(options, ['tag', 'platform', 'architecture']);
  if (!values) fail(CODES.invalid, 'create_github_release_transport');
  const { tag, platform, architecture } = values;
  let bootstrapNames;
  try {
    validateDeploymentSource({ kind: 'github-release', tag }, { platform, architecture });
    bootstrapNames = deploymentBootstrapAssetNames(platform, architecture);
  } catch {
    fail(CODES.invalid, 'create_github_release_transport');
  }

  let agent;
  try {
    agent = new https.Agent({
      ca: rootCertificates,
      checkServerIdentity,
      keepAlive: false,
      maxFreeSockets: 0,
      maxSockets: 1,
      maxTotalSockets: 1,
      rejectUnauthorized: true,
      scheduling: 'fifo',
    });
  } catch {
    fail(CODES.network, 'create_github_release_transport');
  }

  const createdAt = Date.now();
  const pendingRequests = new Set();
  const responseStates = new Set();
  let terminalCode = null;
  let deadlineTimer = null;

  function shutdown(code) {
    if (terminalCode !== null) return;
    terminalCode = code;
    if (deadlineTimer !== null) clearTimeout(deadlineTimer);
    deadlineTimer = null;
    for (const pending of [...pendingRequests]) pending.abort(code);
    for (const state of [...responseStates]) state.abort(code);
    try { agent.destroy(); } catch {}
  }

  deadlineTimer = setTimeout(
    () => shutdown(CODES.deadline),
    DEPLOYMENT_ENVELOPE_LIMITS.acquisitionTimeoutMs,
  );
  deadlineTimer.unref?.();

  function ensureOpen(operation) {
    if (terminalCode !== null) fail(terminalCode, operation);
    const elapsed = Date.now() - createdAt;
    if (!Number.isFinite(elapsed) || elapsed < 0 || elapsed >= DEPLOYMENT_ENVELOPE_LIMITS.acquisitionTimeoutMs) {
      shutdown(CODES.deadline);
      fail(CODES.deadline, operation);
    }
  }

  function issueRequest(url, operation) {
    ensureOpen(operation);
    return new Promise((resolve, reject) => {
      let request;
      let timer = null;
      let settled = false;
      const pending = {
        abort(code) {
          if (settled) return;
          settled = true;
          if (timer !== null) clearTimeout(timer);
          timer = null;
          pendingRequests.delete(pending);
          detach();
          try { request?.destroy?.(); } catch {}
          reject(failure(code, operation));
        },
      };
      const onResponse = (response) => {
        if (settled) {
          response?.on?.('error', NOOP);
          destroyPair(request, response);
          return;
        }
        settled = true;
        if (timer !== null) clearTimeout(timer);
        timer = null;
        pendingRequests.delete(pending);
        detach();
        response?.on?.('error', NOOP);
        resolve(Object.freeze({ request, response }));
      };
      const onError = () => pending.abort(terminalCode ?? CODES.network);
      const onAbort = () => pending.abort(terminalCode ?? CODES.incomplete);
      const detach = () => {
        try { request?.off?.('response', onResponse); } catch {}
        try { request?.off?.('error', onError); } catch {}
        try { request?.off?.('abort', onAbort); } catch {}
      };
      try {
        request = https.request({
          agent,
          ca: rootCertificates,
          checkServerIdentity,
          headers: {
            accept: 'application/octet-stream',
            'accept-encoding': 'identity',
            connection: 'close',
            'user-agent': USER_AGENT,
          },
          hostname: url.hostname,
          joinDuplicateHeaders: false,
          maxHeaderSize: RESPONSE_HEADER_BYTES,
          method: 'GET',
          path: `${url.pathname}${url.search}`,
          port: 443,
          protocol: 'https:',
          rejectUnauthorized: true,
          servername: url.hostname,
          setHost: true,
        });
        if (request === null || typeof request !== 'object' || typeof request.end !== 'function' ||
            typeof request.destroy !== 'function' || typeof request.on !== 'function') {
          fail(CODES.network, operation);
        }
        request.on('error', NOOP);
        request.once('response', onResponse);
        request.once('error', onError);
        request.once('abort', onAbort);
        // Keep every header visible to the strict duplicate/count checks below.
        // The byte cap bounds parser memory; silently truncating at the count cap
        // could otherwise hide a conflicting security-sensitive field.
        request.maxHeadersCount = 0;
        pendingRequests.add(pending);
        timer = setTimeout(
          () => pending.abort(terminalCode ?? CODES.connectTimeout),
          DEPLOYMENT_ENVELOPE_LIMITS.connectTimeoutMs,
        );
        timer.unref?.();
        request.end();
      } catch (error) {
        if (error instanceof ServiceTransportError) pending.abort(error.code);
        else pending.abort(terminalCode ?? CODES.network);
      }
    });
  }

  function trackResponse(request, response, contentLength, operation) {
    if (response === null || typeof response !== 'object' || typeof response.destroy !== 'function' ||
        typeof response.on !== 'function' || typeof response.setTimeout !== 'function' ||
        typeof response[Symbol.asyncIterator] !== 'function') {
      destroyPair(request, response);
      fail(CODES.response, operation);
    }
    let finished = false;
    let failureCode = null;
    const state = {
      request,
      response,
      contentLength,
      operation,
      get failureCode() { return failureCode; },
      abort(code) {
        if (finished) return;
        if (failureCode === null) failureCode = code;
        responseStates.delete(state);
        cleanupListeners();
        destroyPair(request, response);
      },
      finish() {
        if (finished) return;
        finished = true;
        responseStates.delete(state);
        cleanupListeners();
        destroyPair(request, response);
      },
    };
    const onAborted = () => state.abort(terminalCode ?? CODES.incomplete);
    const onError = () => state.abort(terminalCode ?? CODES.network);
    const onRequestAbort = () => state.abort(terminalCode ?? CODES.incomplete);
    const onRequestError = () => state.abort(terminalCode ?? CODES.network);
    const onClose = () => {
      if (!finished && response.complete !== true) state.abort(terminalCode ?? CODES.incomplete);
    };
    const cleanupListeners = () => {
      try { request.off('abort', onRequestAbort); } catch {}
      try { request.off('error', onRequestError); } catch {}
      try { response.off('aborted', onAborted); } catch {}
      try { response.off('error', onError); } catch {}
      try { response.off('close', onClose); } catch {}
    };
    request.on('abort', onRequestAbort);
    request.on('error', onRequestError);
    response.on('aborted', onAborted);
    response.on('error', onError);
    response.on('close', onClose);
    responseStates.add(state);
    try {
      response.setTimeout(
        DEPLOYMENT_ENVELOPE_LIMITS.idleTimeoutMs,
        () => state.abort(terminalCode ?? CODES.idleTimeout),
      );
    } catch {
      state.abort(CODES.response);
      fail(CODES.response, operation);
    }
    if (response.destroyed === true && response.complete !== true) state.abort(CODES.incomplete);
    return state;
  }

  async function fetchResponse(initial, maximumBytes, expectedLength, operation) {
    let current = initial;
    for (let redirects = 0; ; redirects += 1) {
      ensureOpen(operation);
      let pair;
      try {
        pair = await issueRequest(current, operation);
      } catch (error) {
        throw normalizeFailure(error, terminalCode ?? CODES.network, operation);
      }
      const { request, response } = pair;
      let status;
      let headerState;
      try {
        status = validateStatus(response, operation);
        headerState = validateResponseHeaders(response, maximumBytes, status === 200 ? expectedLength : null, operation);
      } catch (error) {
        destroyPair(request, response);
        throw normalizeFailure(error, CODES.response, operation);
      }
      if (REDIRECT_STATUSES.has(status)) {
        const locations = headerState.headers.get('location') ?? [];
        let target;
        try {
          if (locations.length !== 1) fail(CODES.redirect, operation);
          if (redirects >= DEPLOYMENT_ENVELOPE_LIMITS.redirects) fail(CODES.redirects, operation);
          target = redirectTarget(locations[0], current, initial, operation);
        } catch (error) {
          destroyPair(request, response);
          throw normalizeFailure(error, CODES.redirect, operation);
        }
        destroyPair(request, response);
        current = target;
        continue;
      }
      if (status !== 200) {
        destroyPair(request, response);
        fail(CODES.response, operation);
      }
      return trackResponse(request, response, headerState.contentLength, operation);
    }
  }

  async function collectBounded(state, maximumBytes, operation) {
    let bytes;
    let byteLength = 0;
    try {
      bytes = Buffer.allocUnsafe(state.contentLength ?? maximumBytes);
      if (state.failureCode !== null) fail(state.failureCode, operation);
      for await (const value of state.response) {
        ensureOpen(operation);
        if (state.failureCode !== null) fail(state.failureCode, operation);
        const chunk = bufferChunk(value, operation);
        const nextLength = byteLength + chunk.byteLength;
        if (!Number.isSafeInteger(nextLength) || nextLength > maximumBytes || nextLength > bytes.length) {
          fail(CODES.size, operation);
        }
        chunk.copy(bytes, byteLength);
        byteLength = nextLength;
      }
      if (state.failureCode !== null) fail(state.failureCode, operation);
      if (state.response.complete !== true) fail(CODES.incomplete, operation);
      if (state.contentLength !== null && state.contentLength !== byteLength) fail(CODES.size, operation);
      state.finish();
      return Buffer.from(bytes.subarray(0, byteLength));
    } catch (error) {
      const normalized = normalizeFailure(error, state.failureCode ?? CODES.network, operation);
      state.abort(normalized.code);
      throw normalized;
    }
  }

  async function readBootstrap(purpose) {
    const operation = 'read_bootstrap';
    if (arguments.length !== 1 || !['application', 'shawl'].includes(purpose) ||
        (purpose === 'shawl' && platform !== 'win32')) fail(CODES.invalid, operation);
    ensureOpen(operation);
    const manifestName = purpose === 'application' ? bootstrapNames.applicationManifest : bootstrapNames.shawlManifest;
    const signatureName = purpose === 'application' ? bootstrapNames.applicationSignature : bootstrapNames.shawlSignature;
    const manifestState = await fetchResponse(
      initialAssetUrl(tag, manifestName),
      DEPLOYMENT_ENVELOPE_LIMITS.manifestBytes,
      null,
      operation,
    );
    const manifestBytes = await collectBounded(manifestState, DEPLOYMENT_ENVELOPE_LIMITS.manifestBytes, operation);
    ensureOpen(operation);
    const signatureState = await fetchResponse(
      initialAssetUrl(tag, signatureName),
      DEPLOYMENT_ENVELOPE_LIMITS.signatureBytes,
      null,
      operation,
    );
    const signatureBytes = await collectBounded(signatureState, DEPLOYMENT_ENVELOPE_LIMITS.signatureBytes, operation);
    ensureOpen(operation);
    return Object.freeze({ manifestBytes, signatureBytes });
  }

  function assertManifest(manifest, purpose, operation) {
    try { assertPinnedDeploymentManifest(manifest, purpose); } catch { fail(CODES.pinned, operation); }
    if (manifest.target.platform !== platform || manifest.target.architecture !== architecture) {
      fail(CODES.manifest, operation);
    }
    const signedTag = purpose === 'application' ? manifest.source.tag : manifest.projectAsset.tag;
    if (signedTag !== tag) fail(CODES.manifest, operation);
  }

  function createAsset(state, expectedLength, expectedSha256, operation) {
    let claimed = false;
    let completed = false;

    async function* verifiedStream() {
      const hash = createHash('sha256');
      let byteLength = 0;
      try {
        if (state.failureCode !== null) fail(state.failureCode, operation);
        for await (const value of state.response) {
          ensureOpen(operation);
          if (state.failureCode !== null) fail(state.failureCode, operation);
          const chunk = bufferChunk(value, operation);
          byteLength += chunk.byteLength;
          if (!Number.isSafeInteger(byteLength) || byteLength > expectedLength) fail(CODES.size, operation);
          hash.update(chunk);
          yield chunk;
        }
        if (state.failureCode !== null) fail(state.failureCode, operation);
        if (state.response.complete !== true) fail(CODES.incomplete, operation);
        if (state.contentLength !== null && state.contentLength !== byteLength) fail(CODES.size, operation);
        if (byteLength !== expectedLength) fail(CODES.size, operation);
        if (hash.digest('hex') !== expectedSha256) fail(CODES.hash, operation);
        ensureOpen(operation);
        completed = true;
        state.finish();
      } catch (error) {
        const normalized = normalizeFailure(error, state.failureCode ?? CODES.network, operation);
        state.abort(normalized.code);
        throw normalized;
      } finally {
        if (!completed && state.failureCode === null) state.abort(CODES.incomplete);
      }
    }

    const chunks = Object.freeze({
      [Symbol.asyncIterator]() {
        if (claimed) fail(CODES.consumed, operation);
        claimed = true;
        const source = verifiedStream();
        let ended = false;
        const iterator = {
          async next() {
            if (ended) return { value: undefined, done: true };
            try {
              const result = await source.next();
              if (result.done) ended = true;
              return result;
            } catch (error) {
              ended = true;
              throw normalizeFailure(error, state.failureCode ?? CODES.network, operation);
            }
          },
          async return() {
            if (ended && completed) return { value: undefined, done: true };
            ended = true;
            state.abort(CODES.incomplete);
            try { await source.return(); } catch {}
            throw failure(CODES.incomplete, operation);
          },
          async throw() {
            ended = true;
            state.abort(CODES.incomplete);
            try { await source.return(); } catch {}
            throw failure(CODES.incomplete, operation);
          },
          [Symbol.asyncIterator]() { return this; },
        };
        return Object.freeze(iterator);
      },
    });

    function closeAsset() {
      if (arguments.length !== 0) fail(CODES.invalid, operation);
      if (!completed) state.abort(CODES.incomplete);
    }

    return Object.freeze({ chunks, close: closeAsset });
  }

  async function openApplication(manifest) {
    const operation = 'open_application';
    if (arguments.length !== 1) fail(CODES.invalid, operation);
    assertManifest(manifest, 'application', operation);
    const { name, byteLength, sha256 } = manifest.archive;
    if (!Number.isSafeInteger(byteLength) || byteLength < 1 ||
        byteLength > DEPLOYMENT_ENVELOPE_LIMITS.archiveBytes || !SHA256.test(sha256)) fail(CODES.manifest, operation);
    ensureOpen(operation);
    const state = await fetchResponse(initialAssetUrl(tag, name), byteLength, byteLength, operation);
    return createAsset(state, byteLength, sha256, operation);
  }

  async function openShawl(manifest) {
    const operation = 'open_shawl';
    if (arguments.length !== 1) fail(CODES.invalid, operation);
    assertManifest(manifest, 'shawl', operation);
    const { name } = manifest.projectAsset;
    const { byteLength, sha256 } = manifest.executable;
    if (!Number.isSafeInteger(byteLength) || byteLength < 1 ||
        byteLength > DEPLOYMENT_ENVELOPE_LIMITS.archiveBytes || !SHA256.test(sha256)) fail(CODES.manifest, operation);
    ensureOpen(operation);
    const state = await fetchResponse(initialAssetUrl(tag, name), byteLength, byteLength, operation);
    return createAsset(state, byteLength, sha256, operation);
  }

  function close() {
    if (arguments.length !== 0) fail(CODES.invalid, 'close_github_release_transport');
    shutdown(CODES.closed);
  }

  return Object.freeze({ readBootstrap, openApplication, openShawl, close });
}
