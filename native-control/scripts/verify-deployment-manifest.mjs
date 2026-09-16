import { DEPLOYMENT_ENVELOPE_LIMITS } from '@gjc-remote/shared/deployment-envelope';
import { readDeploymentInputFile, verifyPinnedDeploymentProvenance } from '../src/deployment-provenance.js';

const flags = ['--purpose', '--manifest', '--signature', '--platform', '--architecture'];
const args = process.argv.slice(2);
const options = new Map();
try {
  if (args.length !== flags.length * 2) throw new Error('DEPLOYMENT_ARGUMENTS_INVALID');
  for (let index = 0; index < args.length; index += 2) {
    const flag = args[index];
    const value = args[index + 1];
    if (!flags.includes(flag) || options.has(flag) || !value || value.startsWith('--')) throw new Error('DEPLOYMENT_ARGUMENTS_INVALID');
    options.set(flag, value);
  }
  const purpose = options.get('--purpose');
  const platform = options.get('--platform');
  const architecture = options.get('--architecture');
  if (!['application', 'shawl'].includes(purpose) ||
      !['linux:x64', 'linux:arm64', 'win32:x64'].includes(`${platform}:${architecture}`) ||
      (purpose === 'shawl' && platform !== 'win32')) throw new Error('DEPLOYMENT_ARGUMENTS_INVALID');
  const result = verifyPinnedDeploymentProvenance({
    purpose,
    platform,
    architecture,
    manifestBytes: readDeploymentInputFile(options.get('--manifest'), DEPLOYMENT_ENVELOPE_LIMITS.manifestBytes),
    signatureBytes: readDeploymentInputFile(options.get('--signature'), DEPLOYMENT_ENVELOPE_LIMITS.signatureBytes),
  });
  process.stdout.write(`${JSON.stringify({
    schemaVersion: 1,
    kind: 'deployment-provenance-receipt',
    purpose: result.purpose,
    manifestFingerprint: result.manifestFingerprint,
    signingKeyFingerprint: result.signingKeyFingerprint,
    nativeAddonProvenance: result.nativeAddonProvenance,
    writes: 0,
  })}\n`);
} catch (error) {
  const code = typeof error.code === 'string' && /^DEPLOYMENT_[A-Z_]+$/.test(error.code)
    ? error.code
    : error.message === 'DEPLOYMENT_ARGUMENTS_INVALID' ? 'DEPLOYMENT_ARGUMENTS_INVALID' : 'DEPLOYMENT_VERIFICATION_FAILED';
  process.stderr.write(`${JSON.stringify({ schemaVersion: 1, kind: 'deployment-provenance-refusal', code, writes: 0 })}\n`);
  process.exitCode = 1;
}
