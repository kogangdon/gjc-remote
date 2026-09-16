import {
  SERVICE_LIFECYCLE_LIMITS,
  SERVICE_MUTATION_OPERATIONS,
  SERVICE_OPERATIONS,
  validateServiceStatusReceipt,
  validateServiceLifecycleRequest,
} from '@gjc-remote/shared/service-lifecycle-envelope';
import {
  STRICT_JSON_LIMITS,
  canonicalJsonBytes,
  parseCanonicalJsonBytes,
} from '@gjc-remote/shared/strict-json';

const REQUEST_LIMITS = Object.freeze({
  ...STRICT_JSON_LIMITS,
  maxBytes: SERVICE_LIFECYCLE_LIMITS.requestBytes,
  maxDepth: 64,
  maxNodes: 100_000,
});
const OPERATION_SET = new Set(SERVICE_OPERATIONS);
const MUTATION_SET = new Set(SERVICE_MUTATION_OPERATIONS);
const SAFE_ERROR_CODE = /^(?:SERVICE|DEPLOYMENT|NATIVE|RELEASE|INVENTORY)_[A-Z0-9_]{1,63}$/;
const SAFE_OPERATION = /^[a-z][a-z0-9_-]{0,63}$/;
const ERROR_MESSAGES = Object.freeze({
  SERVICE_INVALID: 'service request is invalid',
  SERVICE_STALE: 'service state is stale',
  SERVICE_PENDING: 'service recovery is pending',
  SERVICE_CAS_MISMATCH: 'service compare-and-swap precondition failed',
  SERVICE_MANUAL_CLEANUP: 'service requires manual cleanup',
  SERVICE_ACCESS_DENIED: 'service access denied',
  SERVICE_ABORTED: 'service operation aborted',
  SERVICE_OUTPUT_LIMIT: 'service receipt exceeds its size limit',
  SERVICE_IO_FAILED: 'service operation failed',
  SERVICE_FAILED: 'service operation failed',
});

function ownData(value, key) {
  if (value === null || (typeof value !== 'object' && typeof value !== 'function')) return undefined;
  const descriptor = Object.getOwnPropertyDescriptor(value, key);
  return descriptor && descriptor.enumerable && descriptor.get === undefined &&
    descriptor.set === undefined && Object.hasOwn(descriptor, 'value')
    ? descriptor.value : undefined;
}

function safeCode(value) {
  return typeof value === 'string' && SAFE_ERROR_CODE.test(value) ? value : 'SERVICE_FAILED';
}

function safeOperation(value, fallback = 'service') {
  return typeof value === 'string' && SAFE_OPERATION.test(value) ? value : fallback;
}

function writeCount(value, operation) {
  if (operation === 'status') return value === 0 ? 0 : null;
  return Number.isSafeInteger(value) && value >= 0 ? value : null;
}

function stripProtectedInput(value) {
  if (Array.isArray(value)) return value.map(stripProtectedInput);
  if (value !== null && typeof value === 'object' && Object.getPrototypeOf(value) === Object.prototype) {
    const clean = {};
    for (const [key, item] of Object.entries(value)) {
      if (key === 'servicePassword') continue;
      clean[key] = stripProtectedInput(item);
    }
    return clean;
  }
  return value;
}

function errorReceipt(error, operation) {
  const suppliedCode = safeCode(ownData(error, 'code'));
  // Never let an inner component select the public operation discriminator.
  // The CLI's parsed positional operation is authoritative (and remains
  // `service` for failures that occur before parsing).
  const actualOperation = safeOperation(operation, 'service');
  const suppliedWrites = ownData(error, 'writes');
  const count = writeCount(suppliedWrites, operation);
  // An exception with an unknown write count cannot truthfully claim the
  // original operation's code or a clean boundary.  Keep the public schema
  // explicit and bounded, and mark the refusal ambiguous rather than
  // silently treating an unknown count as zero.
  const unknownWrites = count === null;
  const code = unknownWrites ? 'SERVICE_INVALID' : suppliedCode;
  const writes = unknownWrites ? 0 : (count === null ? 0 : count);
  return Object.freeze({
    status: 'refused',
    operation: actualOperation,
    code,
    message: ERROR_MESSAGES[code] ?? ERROR_MESSAGES.SERVICE_FAILED,
    writes,
    ambiguous: ownData(error, 'ambiguous') === true || unknownWrites,
  });
}

const RESULT_KEYS = Object.freeze({
  status: Object.freeze([
    'schemaVersion', 'kind', 'component', 'serviceKey', 'platform', 'architecture',
    'serviceGeneration', 'manifestFingerprint', 'resourceProof', 'transactionFingerprint',
    'ownership', 'service', 'activation', 'tree', 'startupEvidence',
    'connectivityObservation', 'providerHealth', 'workspaceHealth', 'supervisorProvenance',
    'recovery', 'observedAtMs', 'statusFingerprint', 'writes',
  ]),
  mutation: Object.freeze(['operation', 'transactionId', 'transactionFingerprint', 'serviceGeneration', 'writes']),
  recover: Object.freeze(['operation', 'transactionId', 'transactionFingerprint', 'writes']),
});

function exactPlain(value, keys) {
  return value !== null && typeof value === 'object' && !Array.isArray(value) &&
    Object.getPrototypeOf(value) === Object.prototype &&
    Object.keys(value).length === keys.length && keys.every((key) => Object.hasOwn(value, key));
}

function safeId(value) {
  return typeof value === 'string' && /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/.test(value);
}

function safeHash(value) {
  return typeof value === 'string' && /^[0-9a-f]{64}$/.test(value);
}

function validateLifecycleResult(value, operation) {
  if (operation === 'status') {
    if (!exactPlain(value, RESULT_KEYS.status) || value.writes !== 0) throw failure('SERVICE_INVALID', operation);
    const status = { ...value };
    delete status.writes;
    try { validateServiceStatusReceipt(status); } catch (error) { throw failure('SERVICE_INVALID', operation, 0, error); }
    return Object.freeze({ status, writes: 0 });
  }
  const keys = operation === 'recover' ? RESULT_KEYS.recover : RESULT_KEYS.mutation;
  if (!exactPlain(value, keys) || value.operation !== operation ||
      !safeId(value.transactionId) || !safeHash(value.transactionFingerprint) ||
      (operation !== 'recover' && (!Number.isSafeInteger(value.serviceGeneration) || value.serviceGeneration < 1)) ||
      !Number.isSafeInteger(value.writes) || value.writes < 0) {
    throw failure('SERVICE_INVALID', operation);
  }
  return Object.freeze({ ...value });
}

function validateReceiptEnvelope(value) {
  if (exactPlain(value, ['status', 'operation', 'writes', 'receipt']) &&
      value.status === 'ok' && OPERATION_SET.has(value.operation) &&
      Number.isSafeInteger(value.writes) && value.writes >= 0 && value.receipt !== null &&
      typeof value.receipt === 'object' && !Array.isArray(value.receipt)) {
    if (value.operation === 'status') {
      if (!exactPlain(value.receipt, RESULT_KEYS.status.slice(0, -1))) throw failure('SERVICE_INVALID', value.operation);
      try { validateServiceStatusReceipt(value.receipt); } catch { throw failure('SERVICE_INVALID', value.operation); }
    } else {
      const keys = value.operation === 'recover' ? RESULT_KEYS.recover : RESULT_KEYS.mutation;
      if (!exactPlain(value.receipt, keys) || value.receipt.operation !== value.operation ||
          !safeId(value.receipt.transactionId) || !safeHash(value.receipt.transactionFingerprint) ||
          (value.operation !== 'recover' && (!Number.isSafeInteger(value.receipt.serviceGeneration) || value.receipt.serviceGeneration < 1)) ||
          !Number.isSafeInteger(value.receipt.writes) || value.receipt.writes < 0) throw failure('SERVICE_INVALID', value.operation);
    }
    return;
  }
  if (exactPlain(value, ['status', 'operation', 'code', 'message', 'writes', 'ambiguous']) &&
      value.status === 'refused' && safeOperation(value.operation) && safeCode(value.code) === value.code &&
      (ERROR_MESSAGES[value.code] ?? ERROR_MESSAGES.SERVICE_FAILED) === value.message &&
      Number.isSafeInteger(value.writes) && value.writes >= 0 &&
      typeof value.ambiguous === 'boolean') return;
  throw failure('SERVICE_INVALID', safeOperation(value?.operation));
}

function failure(code, operation, writes = 0, cause = undefined) {
  const error = new Error(ERROR_MESSAGES[code] ?? ERROR_MESSAGES.SERVICE_FAILED);
  error.name = 'ServiceCliError';
  Object.defineProperties(error, {
    code: { value: code, enumerable: true },
    operation: { value: operation, enumerable: true },
    writes: { value: writes, enumerable: true },
    ambiguous: { value: false, enumerable: true },
  });
  if (cause !== undefined) Object.defineProperty(error, 'cause', { value: cause });
  return error;
}

function platformTuple(platform = process.platform, architecture = process.arch) {
  const normalizedPlatform = platform === 'win32' ? 'win32' : platform === 'linux' ? 'linux' : platform;
  const normalizedArchitecture = architecture === 'arm64' ? 'arm64' : architecture === 'x64' ? 'x64' : architecture;
  if (!['linux', 'win32'].includes(normalizedPlatform) ||
      !['x64', 'arm64'].includes(normalizedArchitecture) ||
      (normalizedPlatform === 'win32' && normalizedArchitecture !== 'x64')) {
    throw failure('SERVICE_INVALID', 'service');
  }
  return Object.freeze({ platform: normalizedPlatform, architecture: normalizedArchitecture });
}

/** Parse the sole positional service operation. No flags or generic commands exist. */
export function parseServiceArgv(argv) {
  if (!Array.isArray(argv) || argv.length !== 1 || typeof argv[0] !== 'string' || !OPERATION_SET.has(argv[0])) {
    throw failure('SERVICE_INVALID', 'service');
  }
  return argv[0];
}

/** Parse and validate one canonical request. Passwords remain in this object only transiently. */
export function parseServiceRequest(input, operation, options = {}) {
  const bytes = Buffer.isBuffer(input) ? input : input instanceof Uint8Array ? Buffer.from(input) : null;
  if (bytes === null || bytes.length > REQUEST_LIMITS.maxBytes) throw failure('SERVICE_INVALID', operation);
  let request;
  try {
    request = parseCanonicalJsonBytes(bytes, REQUEST_LIMITS);
  } catch (error) {
    throw failure('SERVICE_INVALID', operation, 0, error);
  }
  const tuple = platformTuple(options.platform, options.architecture);
  try {
    validateServiceLifecycleRequest(operation, request, tuple);
  } catch (error) {
    throw failure('SERVICE_INVALID', operation, 0, error);
  }
  return request;
}

export function canonicalServiceReceipt(receipt) {
  try {
    validateReceiptEnvelope(receipt);
    const bytes = canonicalJsonBytes(receipt, REQUEST_LIMITS);
    if (bytes.length > REQUEST_LIMITS.maxBytes) throw failure('SERVICE_OUTPUT_LIMIT', safeOperation(receipt?.operation));
    return bytes;
  } catch (error) {
    if (error?.name === 'ServiceCliError') throw error;
    throw failure('SERVICE_OUTPUT_LIMIT', safeOperation(receipt?.operation));
  }
}

/**
 * Execute one already-selected operation through the injected lifecycle facade.
 * The facade is intentionally narrow: `{ install, status, update, rollback,
 * uninstall, recover }`, each accepting one validated request.
 */
export async function runServiceCli({
  argv = [],
  input,
  lifecycle,
  lifecycleFactory,
  effectiveConfigPreflight,
  platform = process.platform,
  architecture = process.arch,
  stdinIsTTY = false,
  signal,
} = {}) {
  let operation;
  let transientRequest = null;
  try {
    operation = parseServiceArgv(argv);
    if (stdinIsTTY === true) throw failure('SERVICE_INVALID', operation);
    if (signal?.aborted) throw failure('SERVICE_ABORTED', operation);
    const request = parseServiceRequest(input, operation, { platform, architecture });
    transientRequest = request;
    if (signal?.aborted) throw failure('SERVICE_ABORTED', operation);
    if (MUTATION_SET.has(operation) && typeof effectiveConfigPreflight === 'function') {
      await effectiveConfigPreflight({ operation, request, platform, architecture, signal });
    }
    if (signal?.aborted) throw failure('SERVICE_ABORTED', operation);
    if (lifecycle === undefined && typeof lifecycleFactory === 'function') {
      lifecycle = await lifecycleFactory({ operation, request, platform, architecture, signal });
    }
    if (lifecycle === null || (typeof lifecycle !== 'object' && typeof lifecycle !== 'function') ||
        typeof lifecycle[operation] !== 'function') throw failure('SERVICE_INVALID', operation);
    // Deliberately do not clone or log the request: a Windows servicePassword is
    // protected transient input and is passed only to the lifecycle facade.
    // This is deliberately the last check before invoking the operation.  A
    // preflight/factory may yield, so an abort observed there must not race
    // into a platform dispatch.
    if (signal?.aborted) throw failure('SERVICE_ABORTED', operation);
    const value = await lifecycle[operation](request);
    // A signal observed after the lifecycle promise settles is not an
    // interruption boundary: the transaction may already be committed.  Keep
    // the authoritative success receipt instead of reporting a false abort.
    const result = validateLifecycleResult(value, operation);
    const receipt = Object.freeze({
      status: 'ok', operation, writes: result.writes,
      receipt: stripProtectedInput(operation === 'status' ? result.status : result),
    });
    canonicalServiceReceipt(receipt);
    return receipt;
  } catch (error) {
    const refusal = error?.name === 'ServiceCliError' ? errorReceipt(error, operation ?? 'service') : errorReceipt(error, operation ?? 'service');
    canonicalServiceReceipt(refusal);
    return refusal;
  } finally {
    // Do not retain the optional Windows credential beyond the one lifecycle
    // call. It is never copied into a receipt or an error.
    if (transientRequest && Object.hasOwn(transientRequest, 'servicePassword')) {
      try { delete transientRequest.servicePassword; } catch { /* frozen test doubles remain harmless */ }
    }
  }
}

export function serviceReceiptBytes(receipt) {
  return Buffer.concat([canonicalServiceReceipt(receipt), Buffer.from('\n', 'utf8')]);
}

export { ERROR_MESSAGES, REQUEST_LIMITS };
