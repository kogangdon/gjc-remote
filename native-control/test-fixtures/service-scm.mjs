import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { loadVerifiedAddon } from '../src/index.js';
import { evaluateRequiredSignature } from '../scripts/verify-build.mjs';
import { parseScmArguments, prepareScmFixture, runScmScenario } from './service-scm-scenario.mjs';

const sha256 = (bytes) => createHash('sha256').update(bytes).digest('hex');
const localPath = (relative) => fileURLToPath(new URL(relative, import.meta.url));
let fixture = null;
let stage = 'arguments';
try {
  const options = parseScmArguments(process.argv.slice(2));
  stage = 'platform';
  if (process.platform !== 'win32' || process.arch !== 'x64') throw new Error('unsupported platform');
  stage = 'fixture';
  const fixtureBytes = readFileSync(options.fixturePath);
  fixture = prepareScmFixture(fixtureBytes, options.hostMode);
  stage = 'pinned-native-signature';
  const manifestPath = localPath('../build/Release/native-control.manifest.json');
  const addonPath = localPath('../build/Release/native_control.node');
  const manifestBytes = readFileSync(manifestPath);
  const addonBytes = readFileSync(addonPath);
  const signature = evaluateRequiredSignature(manifestBytes);
  if (!signature.ok) throw new Error('pinned signature required');
  // No caller-controlled loader/trust paths or development-key bypass. The
  // normal loader additionally verifies the package/build tuple and native ABI.
  const native = loadVerifiedAddon();
  if (!manifestBytes.equals(readFileSync(manifestPath)) || !addonBytes.equals(readFileSync(addonPath)) ||
      !evaluateRequiredSignature(manifestBytes).ok) throw new Error('native artifacts changed');
  stage = 'source-evidence';
  const sourcePaths = [
    './service-scm.mjs', './service-scm-scenario.mjs', '../src/addon.cc',
    '../src/index.js', '../src/service-native.js', '../src/service-windows.js',
    '../src/native-provenance.js', '../src/capabilities.js', '../scripts/verify-build.mjs',
    '../../shared/strict-json.js', '../../shared/identity.js', '../../shared/service-lifecycle-envelope.js',
  ];
  const evidence = {
    fixtureSha256: sha256(fixtureBytes), addonSha256: sha256(addonBytes),
    manifestSha256: sha256(manifestBytes),
    nativeSignature: { status: 'verified-pinned', keyId: signature.keyId, algorithm: signature.algorithm },
    sourceSha256: Object.fromEntries(sourcePaths.map((path) => [path, sha256(readFileSync(localPath(path)))])),
  };
  stage = 'scenario';
  const receipt = await runScmScenario(fixture, native, evidence);
  process.stdout.write(`${JSON.stringify(receipt)}\n`);
  if (receipt.result !== 'passed') process.exitCode = 1;
} catch {
  // Never print caller configuration or native exception messages (which may
  // include secrets). All failures before the scenario have made zero writes.
  process.stdout.write(`${JSON.stringify({
    schemaVersion: 1, result: 'failed', stage, serviceName: fixture?.serviceName ?? null,
    serviceRole: fixture?.serviceRole ?? null, evidenceKind: fixture?.evidenceKind ?? null,
    scope: 'native-scm-primitives-only', productionProvenance: 'not-verified',
    cleanup: stage === 'scenario' ? 'uncertain-manual-reconciliation-required' : 'no-mutation',
    code: 'SCM_VERIFIER_REFUSED',
  })}\n`);
  process.exitCode = 1;
}
