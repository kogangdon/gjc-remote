import dotenv from 'dotenv';
import { fileURLToPath } from 'node:url';
import { createServiceBootstrapNative } from './service-bootstrap-native.js';
import { ServiceBootstrapRefusal, evaluateServiceBootstrap } from './service-bootstrap-policy.js';

// Signed Windows service bootstrap guard. The daemon loads this exact file via
// BUN_INSPECT_PRELOAD before its entrypoint; the bot imports it first. Module
// evaluation verifies the production native addon, the self service config,
// the protected runtime config, the process epoch and the launch environment
// before any application or SDK import. A refusal throws during evaluation,
// which stops the entrypoint. Outside a service launch no work is performed.

const bootstrapPath = fileURLToPath(import.meta.url);
let bootstrapContext = null;
let consumed = false;

if (process.env.GJC_REMOTE_SERVICE_COMPONENT !== undefined) {
  const native = createServiceBootstrapNative();
  const selfConfig = native.readSelfServiceConfig();
  const epoch = native.observeSelfProcessEpoch();
  let result;
  try {
    result = evaluateServiceBootstrap({
      env: process.env,
      runtime: {
        platform: process.platform,
        execPath: process.execPath,
        argv: [...process.argv],
        execArgv: [...process.execArgv],
        versions: { node: process.versions.node, bun: process.versions.bun },
        bunRevision: globalThis.Bun?.revision,
      },
      bootstrapPath,
      selfConfig,
      epoch,
      parseDotenv: (bytes) => dotenv.parse(bytes),
    });
  } finally {
    if (selfConfig?.bytes instanceof Uint8Array) selfConfig.bytes.fill(0);
  }
  // Verified bytes become the process configuration; later dotenv/config loads
  // never override existing keys, so the application sees exactly these values.
  for (const [key, value] of result.entries) {
    if (process.env[key] === undefined) process.env[key] = value;
  }
  bootstrapContext = result.context;
}

export function consumeServiceBootstrapContext() {
  if (arguments.length !== 0 || consumed) throw new ServiceBootstrapRefusal('context-already-consumed');
  consumed = true;
  return bootstrapContext;
}
