import { canonicalJsonHash, isHex64 } from "./strict-json.js";
import { isOpaqueIdentity, isPrincipal } from "./identity.js";

const PHASES = new Set(["prepared", "verified", "cleaned", "manual_cleanup"]);
const templateKeys = ["templateTargetIdentity", "templateTargetAclFingerprint", "templateControlIdentity", "templateControlAclFingerprint", "templateWrapperIdentity", "templateWrapperAclFingerprint"];
const templateAclKeys = ["templateTargetAclFingerprint", "templateControlAclFingerprint", "templateWrapperAclFingerprint"];
const proofKeys = ["mMutationProofFingerprint", "botReadProofFingerprint", "recoveryReadProofFingerprint", "botWriteDeniedProofFingerprint", "recoveryWriteDeniedProofFingerprint"];
const writeKeys = ["authorityWrites", "targetWrites", "controlWrites", "authorityCommittedWrites", "targetCommittedWrites", "controlCommittedWrites"];
const keys = ["version", "kind", "probeNonce", "anchorFingerprint", "parentIdentity", "targetInputState", "managementIdentity", "botIdentity", "recoveryIdentity", "mProvisioningFingerprint", "bProvisioningFingerprint", "rProvisioningFingerprint", ...templateKeys, ...proofKeys, "scratchIdentity", ...writeKeys, "phase", "probeFingerprint"];
const plain = (value) => value !== null && typeof value === "object" && !Array.isArray(value) && Object.getPrototypeOf(value) === Object.prototype;
const exact = (value, expected) => plain(value) && Object.keys(value).length === expected.length && expected.every((key) => Object.hasOwn(value, key));
const fail = (message) => { throw new TypeError(`GENESIS_PROBE_INVALID: ${message}`); };
const hex = (value) => isHex64(value);

export function genesisProbePreimage(probe) {
  if (!plain(probe)) fail("probe must be an object");
  const { probeFingerprint, ...preimage } = probe;
  return preimage;
}

export function fingerprintGenesisProbe(probe) {
  return canonicalJsonHash(genesisProbePreimage(probe));
}

export function validateGenesisProspectiveProbe(probe) {
  if (!exact(probe, keys)) fail("unknown or missing field");
  if (probe.version !== 1 || probe.kind !== "genesis-prospective-probe") fail("version or kind");
  if (!/^[0-9a-f]{32}$/.test(probe.probeNonce)) fail("probe nonce");
  if (!hex(probe.anchorFingerprint) || !isOpaqueIdentity(probe.parentIdentity) || !isOpaqueIdentity(probe.scratchIdentity)) fail("anchor or identity");
  if (probe.targetInputState !== "absent" && probe.targetInputState !== "legacy-unmigrated") fail("target input state");
  for (const name of ["managementIdentity", "botIdentity", "recoveryIdentity"]) if (!isPrincipal(probe[name])) fail(`${name} principal`);
  for (const name of ["mProvisioningFingerprint", "bProvisioningFingerprint", "rProvisioningFingerprint", ...templateAclKeys, ...proofKeys]) if (!hex(probe[name])) fail(`${name} fingerprint`);
  for (const name of ["templateTargetIdentity", "templateControlIdentity", "templateWrapperIdentity"]) if (!isOpaqueIdentity(probe[name])) fail(`${name} identity`);
  for (const name of writeKeys) if (probe[name] !== 0) fail(`${name} must remain zero`);
  if (!PHASES.has(probe.phase) || !hex(probe.probeFingerprint)) fail("phase or fingerprint");
  if (fingerprintGenesisProbe(probe) !== probe.probeFingerprint) fail("fingerprint");
  return probe;
}

export function transitionGenesisProspectiveProbe(probe, phase) {
  validateGenesisProspectiveProbe(probe);
  if (!PHASES.has(phase)) fail("phase");
  const permitted = { prepared: ["verified", "manual_cleanup"], verified: ["cleaned", "manual_cleanup"], cleaned: [], manual_cleanup: [] };
  if (!permitted[probe.phase].includes(phase)) fail("illegal phase transition");
  const next = { ...probe, phase };
  next.probeFingerprint = fingerprintGenesisProbe(next);
  return validateGenesisProspectiveProbe(next);
}

export function canCleanGenesisScratch(probe, observed) {
  try {
    validateGenesisProspectiveProbe(probe);
    return probe.phase === "verified" && exact(observed, ["probeNonce", "managementIdentity", "parentIdentity", "scratchIdentity", ...templateKeys, ...proofKeys, ...writeKeys, "probeFingerprint"])
      && observed.probeNonce === probe.probeNonce && JSON.stringify(observed.managementIdentity) === JSON.stringify(probe.managementIdentity)
      && observed.parentIdentity === probe.parentIdentity && observed.scratchIdentity === probe.scratchIdentity
      && [...templateKeys, ...proofKeys].every((key) => observed[key] === probe[key])
      && writeKeys.every((key) => observed[key] === 0) && observed.probeFingerprint === probe.probeFingerprint;
  } catch { return false; }
}
