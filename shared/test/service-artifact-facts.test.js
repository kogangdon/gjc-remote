import assert from "node:assert/strict";
import test from "node:test";
import {
  SERVICE_LIFECYCLE_LIMITS,
  validateServiceArtifactFileFacts,
  validateServiceNativeFileFacts,
} from "../service-lifecycle-envelope.js";
import { DEPLOYMENT_ENVELOPE_LIMITS } from "../deployment-envelope.js";

const common = { size: 0, sha256: "a".repeat(64), securitySha256: "b".repeat(64) };
const fixtures = {
  linux: { ...common, kind: "linux-file-v1", device: "1", inode: "2", mode: 0o100444, owner: "uid:1000" },
  win32: { ...common, kind: "win32-file-v1", volumeSerial: "1".repeat(16), fileId: "2".repeat(32), attributes: 32, owner: "S-1-5-21-1-2-3-1000" },
};

for (const [platform, fixture] of Object.entries(fixtures)) {
  test(`${platform}: artifact facts retain a separate bound from metadata`, () => {
    for (const size of [0, SERVICE_LIFECYCLE_LIMITS.protectedRecordBytes, DEPLOYMENT_ENVELOPE_LIMITS.unpackedPayloadBytes]) {
      const facts = { ...fixture, size };
      assert.equal(validateServiceArtifactFileFacts(facts, platform), facts);
    }
    const large = { ...fixture, size: SERVICE_LIFECYCLE_LIMITS.protectedRecordBytes + 1 };
    assert.equal(validateServiceArtifactFileFacts(large, platform), large);
    assert.throws(() => validateServiceNativeFileFacts(large, platform));
    const metadataMaximum = { ...fixture, size: SERVICE_LIFECYCLE_LIMITS.protectedRecordBytes };
    assert.equal(validateServiceNativeFileFacts(metadataMaximum, platform), metadataMaximum);
    for (const size of [-1, 0.5, NaN, Infinity, DEPLOYMENT_ENVELOPE_LIMITS.unpackedPayloadBytes + 1]) {
      assert.throws(() => validateServiceArtifactFileFacts({ ...fixture, size }, platform));
    }
  });

  test(`${platform}: artifact facts preserve closed identity validation`, () => {
    for (const changes of [
      { owner: "" },
      { sha256: "invalid" },
      { securitySha256: "invalid" },
      { kind: "foreign" },
      { extra: true },
    ]) {
      assert.throws(() => validateServiceArtifactFileFacts({ ...fixture, ...changes }, platform));
    }
    assert.throws(() => validateServiceArtifactFileFacts(fixture, "darwin"));
  });
}
