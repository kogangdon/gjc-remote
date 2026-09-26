#!/usr/bin/env node
import { pathToFileURL } from 'node:url';
import { createServiceNative } from './index.js';
import { createLinuxServiceDriver } from './service-linux.js';
import { createServiceAcquisition } from './service-acquisition.js';
import { createServiceLifecycle } from './service-lifecycle.js';
import { createServiceStore } from './service-store.js';
import {
  REQUEST_LIMITS,
  runServiceCli,
  serviceReceiptBytes,
} from './service-cli.js';
import {
  buildServiceStatusReceipt,
  SERVICE_MUTATION_OPERATIONS,
} from '@gjc-remote/shared/service-lifecycle-envelope';

const EXIT_CODES = Object.freeze({
  ok: 0,
  refused: 1,
  usage: 64,
  interrupted: 130,
  terminated: 143,
});

function isDirectInvocation() {
  if (!process.argv[1]) return false;
  try { return import.meta.url === pathToFileURL(process.argv[1]).href; } catch { return false; }
}

function failureReceipt(code = 'SERVICE_IO_FAILED', operation = 'service') {
  return Object.freeze({
    status: 'refused',
    operation: typeof operation === 'string' ? operation : 'service',
    code,
    message: code === 'SERVICE_OUTPUT_LIMIT' ? 'service receipt exceeds its size limit' : 'service operation failed',
    writes: 0,
    ambiguous: false,
  });
}

async function readBoundedStdin(stream, limit = REQUEST_LIMITS.maxBytes) {
  if (!stream || stream.isTTY === true) return { bytes: null, isTTY: true };
  const chunks = [];
  let size = 0;
  for await (const chunk of stream) {
    const bytes = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
    size += bytes.length;
    if (size > limit) return { bytes: null, tooLarge: true, isTTY: false };
    chunks.push(bytes);
  }
  return { bytes: Buffer.concat(chunks, size), isTTY: false };
}

function exitCodeFor(receipt, signalName = null) {
  // A signal is only an interruption when the lifecycle returned a truthful
  // non-committing boundary.  A settled success may already be committed and
  // must not be relabelled after the fact.
  if (receipt?.status !== 'ok' && signalName === 'SIGINT') return EXIT_CODES.interrupted;
  if (receipt?.status !== 'ok' && signalName === 'SIGTERM') return EXIT_CODES.terminated;
  if (receipt?.status === 'ok') return EXIT_CODES.ok;
  if (receipt?.code === 'SERVICE_INVALID') return EXIT_CODES.usage;
  return EXIT_CODES.refused;
}

const MUTATION_SET = new Set(SERVICE_MUTATION_OPERATIONS);

function productionLifecycle({ options, operation, request, platform, architecture }) {
  const unavailable = (message) => {
    const error = new Error(message);
    error.code = 'SERVICE_INVALID';
    error.writes = 0;
    throw error;
  };
  if (options === null || typeof options !== 'object' || Array.isArray(options) ||
      Object.getPrototypeOf(options) !== Object.prototype) {
    unavailable('production service configuration is unavailable');
  }
  // Every production mutation must be composed from an effective, already
  // validated configuration.  Keep this refusal before native/store
  // construction so an omitted preflight can never open protected state.
  // Read-only status is intentionally probe-only and does not require it.
  if (MUTATION_SET.has(operation) && typeof options.effectiveConfigPreflight !== 'function') {
    unavailable('effective service configuration preflight is unavailable');
  }
  // Request identity is already validated by the CLI.  Do not require
  // mutation-only configuration/acquisition/startup authorities for a
  // read-only status or recovery operation.
  const roles = request?.roles ?? options.roles;
  const target = request?.target ?? options.target;
  const mutation = MUTATION_SET.has(operation);
  const recovery = operation === 'recover';
  const needsConfiguration = operation === 'install';
  const configuration = needsConfiguration ? (request?.configuration ?? options.configuration) : undefined;
  if (!roles || !target) {
    unavailable('production service dependencies are unavailable');
  }
  if (needsConfiguration && !configuration) {
    unavailable('service configuration authority is unavailable');
  }
  if ((mutation && operation !== 'uninstall') && typeof options.observeApplication !== 'function') {
    unavailable('production mutation dependencies are unavailable');
  }
  if ((mutation && (operation === 'install' || operation === 'update')) &&
      typeof options.compatibility !== 'function') {
    unavailable('production compatibility authority is unavailable');
  }
  // Resource planning is deliberately an explicit authority.  Acquisition
  // only exposes relative manifest entrypoints until publication, so this
  // boundary cannot safely synthesize a platform descriptor or fingerprint.
  // Requiring the signed/retained planner here guarantees refusal before the
  // store is opened rather than silently planning empty evidence.
  if (mutation && operation !== 'uninstall' && typeof options.planResource !== 'function') {
    unavailable('release resource planner authority is unavailable');
  }
  // Windows drivers are bound to a per-release Launch derived by the host
  // producer (service-windows-host.js); there is no static release/shawl.
  if (platform === 'win32' && typeof options.createWindowsDriver !== 'function') {
    unavailable('windows service driver authority is unavailable');
  }
  // This is the sole production composition boundary.  Each layer receives
  // the concrete authority produced by the preceding layer; no empty facade,
  // store, acquisition, or driver is ever substituted.
  let native;
  try {
    native = options.native ?? createServiceNative({ roles });
  } catch {
    unavailable('native service authority is unavailable');
  }
  let store;
  try {
    store = createServiceStore({ native, roles, target, platform, architecture });
  } catch {
    unavailable('service store authority is unavailable');
  }
  // Recovery may replay the acquisition edges of a prepared transaction.
  // Keep this composition at the executable boundary even though recover is
  // intentionally absent from SERVICE_MUTATION_OPERATIONS; the lifecycle
  // decides whether the authority is actually needed after classification.
  const acquisition = operation === 'install' || operation === 'update' || recovery
    ? ({ session: currentSession, request: currentRequest, native: acquisitionNative }) => {
      // Recovery requests intentionally carry no source.  Resolve the
      // retained source first, then derive the native authority from that
      // source rather than from the request (which would incorrectly make an
      // online recovery look offline).
      const source = currentRequest.source ?? options.recoverySource;
      return createServiceAcquisition({
      session: currentSession,
      // Online transports authenticate their own native bundle. Offline
      // sources require the host native facade; never silently substitute an
      // empty object when the authority is unavailable.
      native: source?.kind === 'github-release' ? null : acquisitionNative,
      source,
      });
    }
    : undefined;
  const createDriver = ({ session, request, release, locks }) => {
    const common = { native, session, locks, roles, configuration: request.configuration ?? configuration };
    if (platform === 'linux') {
      if (typeof options.invoke !== 'function') unavailable('linux service driver authority is unavailable');
      return createLinuxServiceDriver({
        ...common, invoke: options.invoke, clock: options.clock, sleep: options.sleep,
        templates: options.templates ?? undefined,
      });
    }
    return options.createWindowsDriver({ session, request, release, locks });
  };
  const composed = createServiceLifecycle({
    platform, architecture, native, store, acquisition, createDriver,
    ...((mutation || recovery) ? { observeApplication: options.observeApplication, compatibility: options.compatibility, ...(acquisition ? { acquisition } : {}) } : {}),
    ...(mutation && operation !== 'uninstall' ? { planResource: options.planResource } : {}),
    clock: options.clock,
  });
  return composed;
}

/**
 * Host-local service executable boundary. The lifecycle facade is injected so
 * this layer cannot construct a shell command or bypass the native/store
 * authority. Production wiring may supply `lifecycle`; tests use a fake.
 */
export async function runServiceEntrypoint({
  argv = process.argv.slice(2),
  input,
  stdin = process.stdin,
  stdout = process.stdout,
  lifecycle,
  lifecycleOptions,
  platform = process.platform,
  architecture = process.arch,
  signal,
  signalName = null,
} = {}) {
  let bytes = input;
  let stdinIsTTY = false;
  let preflight = null;
  if (bytes === undefined) {
    try {
      preflight = await readBoundedStdin(stdin);
    } catch {
      const receipt = failureReceipt('SERVICE_IO_FAILED');
      if (stdout?.write) stdout.write(serviceReceiptBytes(receipt));
      return Object.freeze({ receipt, exitCode: EXIT_CODES.refused });
    }
    bytes = preflight.bytes;
    stdinIsTTY = preflight.isTTY === true;
  }
  if (preflight?.tooLarge) {
    const receipt = failureReceipt('SERVICE_INVALID');
    const encoded = serviceReceiptBytes(receipt);
    if (stdout?.write) stdout.write(encoded);
    return Object.freeze({ receipt, exitCode: EXIT_CODES.usage });
  }
  let receipt;
  const mutation = MUTATION_SET.has(argv?.[0]);
  // The real Windows host composes its authorities from one operation-scoped
  // producer. It is loaded only on win32 and only when nothing was injected.
  let host = null;
  if (lifecycle === undefined && lifecycleOptions === undefined && platform === 'win32') {
    const { createWindowsHostOperation } = await import('./service-windows-host.js');
    host = createWindowsHostOperation();
  }
  const hostPreflight = host !== null ? host.effectiveConfigPreflight : lifecycleOptions?.effectiveConfigPreflight;
  try {
    receipt = await runServiceCli({
      argv,
      input: bytes,
      lifecycle,
      lifecycleFactory: lifecycle === undefined
        ? (context) => productionLifecycle({
          options: host !== null ? host.lifecycleOptions(context) : lifecycleOptions,
          ...context, platform, architecture,
        })
        : undefined,
      effectiveConfigPreflight: lifecycle === undefined && mutation ? hostPreflight : undefined,
      platform,
      architecture,
      stdinIsTTY,
      signal,
    });
  } finally {
    host?.close();
  }
  let encoded = serviceReceiptBytes(receipt);
  if (encoded.length > REQUEST_LIMITS.maxBytes + 1) {
    receipt = failureReceipt('SERVICE_OUTPUT_LIMIT');
    encoded = serviceReceiptBytes(receipt);
  }
  if (stdout?.write) stdout.write(encoded);
  return Object.freeze({ receipt, exitCode: exitCodeFor(receipt, signalName) });
}

export { EXIT_CODES, readBoundedStdin };

if (isDirectInvocation()) {
  const abort = new AbortController();
  let signalName = null;
  const onSignal = (name) => {
    signalName = name;
    abort.abort();
  };
  process.once('SIGINT', () => onSignal('SIGINT'));
  process.once('SIGTERM', () => onSignal('SIGTERM'));
  try {
    const result = await runServiceEntrypoint({ signal: abort.signal, signalName });
    // `signalName` is assigned by the process handler while the lifecycle
    // promise is pending, so apply the mapping after the await as well.
    process.exitCode = exitCodeFor(result.receipt, signalName);
  } catch {
    const receipt = failureReceipt();
    process.stdout.write(serviceReceiptBytes(receipt));
    process.exitCode = EXIT_CODES.refused;
  }
}
