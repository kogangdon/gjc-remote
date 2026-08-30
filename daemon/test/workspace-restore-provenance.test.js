import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";

import { PROTOCOL_ERROR_CODES } from "@gjc-remote/shared";
import { buildWorkspaceManifest } from "../src/workspace-backup-manifest.js";
import {
  verifyRestoreProvenance,
  verifyRestoreChecksum,
  EXPECTED_AUTHORITY_KEYS,
  PROVENANCE_RECORD_KEYS,
  PROVENANCE_KIND,
} from "../src/workspace-restore-provenance.js";

// ---------- shared fixtures -------------------------------------------------

const AUTHORITY = Object.freeze({
  hostId: "host-1",
  roleFingerprint: "a".repeat(64),
  volumeIdentityFingerprint: "b".repeat(64),
  keyFingerprint: "c".repeat(64),
  manifestFingerprint: "d".repeat(64),
  restoredFromWorkspaceId: "source-workspace-1",
  restoredFromGeneration: 7,
});

function matchingRecord(overrides = {}) {
  return { version: 2, kind: PROVENANCE_KIND, ...AUTHORITY, ...overrides };
}

// io whose reader returns a fixed record (or throws when record is an Error).
function provenanceIo(record) {
  return {
    readProvenanceRecord: async () => {
      if (record instanceof Error) throw record;
      return record;
    },
  };
}

async function expectRefusal(promise, code) {
  await assert.rejects(promise, (error) => {
    assert.equal(error.code, code, `expected ${code}, got ${error.code}: ${error.message}`);
    assert.equal(error.operation, "workspace_restore_provenance");
    return true;
  });
}

// ---------- verifyRestoreProvenance: happy path -----------------------------

test("verifyRestoreProvenance: an exact v2 authority match resolves frozen trusted values", async () => {
  const result = await verifyRestoreProvenance(provenanceIo(matchingRecord()), {
    expectedAuthority: AUTHORITY,
    staged: { path: "/staging/x" },
  });
  assert.deepEqual(result, { verified: true, ...AUTHORITY });
  assert.ok(Object.isFrozen(result));
});

test("verifyRestoreProvenance: never derives authority from staged content (extra record fields rejected)", async () => {
  // A staged record carrying MORE than the exact key set is not trusted.
  await expectRefusal(
    verifyRestoreProvenance(provenanceIo(matchingRecord({ injected: true })), {
      expectedAuthority: AUTHORITY,
      staged: {},
    }),
    PROTOCOL_ERROR_CODES.WORKSPACE_PROVENANCE_MISMATCH,
  );
});

// ---------- verifyRestoreProvenance: per-field mismatch (parameterized) ------

for (const field of [
  "hostId",
  "roleFingerprint",
  "volumeIdentityFingerprint",
  "keyFingerprint",
  "manifestFingerprint",
  "restoredFromWorkspaceId",
  "restoredFromGeneration",
]) {
  test(`verifyRestoreProvenance: a mismatched ${field} refuses WORKSPACE_PROVENANCE_MISMATCH`, async () => {
    const tampered = field === "hostId" || field === "restoredFromWorkspaceId"
      ? `other-${field}`
      : field === "restoredFromGeneration" ? AUTHORITY.restoredFromGeneration + 1 : "f".repeat(64);
    await assert.rejects(
      verifyRestoreProvenance(provenanceIo(matchingRecord({ [field]: tampered })), {
        expectedAuthority: AUTHORITY,
        staged: {},
      }),
      (error) => {
        assert.equal(error.code, PROTOCOL_ERROR_CODES.WORKSPACE_PROVENANCE_MISMATCH);
        assert.equal(error.field, field);
        return true;
      },
    );
  });
}

// ---------- verifyRestoreProvenance: malformed / absent staged record --------

test("verifyRestoreProvenance: a null staged record is a mismatch (fail closed)", async () => {
  await expectRefusal(
    verifyRestoreProvenance(provenanceIo(null), { expectedAuthority: AUTHORITY, staged: {} }),
    PROTOCOL_ERROR_CODES.WORKSPACE_PROVENANCE_MISMATCH,
  );
});

test("verifyRestoreProvenance: v1 and unexpected record kinds refuse", async () => {
  for (const bad of [matchingRecord({ kind: "other" }), matchingRecord({ version: 1 })]) {
    await expectRefusal(
      verifyRestoreProvenance(provenanceIo(bad), { expectedAuthority: AUTHORITY, staged: {} }),
      PROTOCOL_ERROR_CODES.WORKSPACE_PROVENANCE_MISMATCH,
    );
  }
});

test("verifyRestoreProvenance: malformed record authority fields are mismatches", async () => {
  for (const [field, value] of [
    ["hostId", ""],
    ["roleFingerprint", "not-hex"],
    ["volumeIdentityFingerprint", "not-hex"],
    ["keyFingerprint", "not-hex"],
    ["manifestFingerprint", "not-hex"],
    ["restoredFromWorkspaceId", ""],
    ["restoredFromGeneration", 0],
  ]) {
    await expectRefusal(
      verifyRestoreProvenance(provenanceIo(matchingRecord({ [field]: value })), {
        expectedAuthority: AUTHORITY,
        staged: {},
      }),
      PROTOCOL_ERROR_CODES.WORKSPACE_PROVENANCE_MISMATCH,
    );
  }
});

test("verifyRestoreProvenance: a reader failure is a mismatch, not a soft error", async () => {
  const boom = new Error("io down");
  boom.code = "EIO";
  await expectRefusal(
    verifyRestoreProvenance(provenanceIo(boom), { expectedAuthority: AUTHORITY, staged: {} }),
    PROTOCOL_ERROR_CODES.WORKSPACE_PROVENANCE_MISMATCH,
  );
});

test("verifyRestoreProvenance: an array or null-prototype staged record is a mismatch", async () => {
  const nullProto = Object.assign(Object.create(null), matchingRecord());
  for (const bad of [[matchingRecord()], nullProto, matchingRecord({ keyFingerprint: undefined })]) {
    await expectRefusal(
      verifyRestoreProvenance(provenanceIo(bad), { expectedAuthority: AUTHORITY, staged: {} }),
      PROTOCOL_ERROR_CODES.WORKSPACE_PROVENANCE_MISMATCH,
    );
  }
});

test("verifyRestoreProvenance: a staged record missing any v2 authority key is a mismatch", async () => {
  for (const field of EXPECTED_AUTHORITY_KEYS) {
    const { [field]: unused, ...missing } = matchingRecord();
    await expectRefusal(
      verifyRestoreProvenance(provenanceIo(missing), { expectedAuthority: AUTHORITY, staged: {} }),
      PROTOCOL_ERROR_CODES.WORKSPACE_PROVENANCE_MISMATCH,
    );
  }
});

test("verifyRestoreProvenance: an over-long hostId is CONFIG_INVALID on the authority and a mismatch on the record", async () => {
  const tooLong = "h".repeat(257);
  await expectRefusal(
    verifyRestoreProvenance(provenanceIo(matchingRecord()), {
      expectedAuthority: { ...AUTHORITY, hostId: tooLong },
      staged: {},
    }),
    PROTOCOL_ERROR_CODES.CONFIG_INVALID,
  );
  await expectRefusal(
    verifyRestoreProvenance(provenanceIo(matchingRecord({ hostId: tooLong })), {
      expectedAuthority: AUTHORITY,
      staged: {},
    }),
    PROTOCOL_ERROR_CODES.WORKSPACE_PROVENANCE_MISMATCH,
  );
});

// ---------- verifyRestoreProvenance: caller contract violations --------------

test("verifyRestoreProvenance: malformed expectedAuthority fields are CONFIG_INVALID (caller bug)", async () => {
  const cases = [
    { ...AUTHORITY, hostId: "" },
    { ...AUTHORITY, roleFingerprint: "short" },
    { ...AUTHORITY, volumeIdentityFingerprint: "short" },
    { ...AUTHORITY, keyFingerprint: "short" },
    { ...AUTHORITY, manifestFingerprint: "short" },
    { ...AUTHORITY, restoredFromWorkspaceId: "" },
    { ...AUTHORITY, restoredFromGeneration: 0 },
    { hostId: "h", roleFingerprint: "a".repeat(64) }, // missing keys
    { ...AUTHORITY, extra: 1 }, // extra key
  ];
  for (const expectedAuthority of cases) {
    await expectRefusal(
      verifyRestoreProvenance(provenanceIo(matchingRecord()), { expectedAuthority, staged: {} }),
      PROTOCOL_ERROR_CODES.CONFIG_INVALID,
    );
  }
});

test("verifyRestoreProvenance: a staged self-declared key never replaces the trusted key", async () => {
  await expectRefusal(
    verifyRestoreProvenance(provenanceIo(matchingRecord({ keyFingerprint: "f".repeat(64) })), {
      expectedAuthority: AUTHORITY,
      staged: {},
    }),
    PROTOCOL_ERROR_CODES.WORKSPACE_PROVENANCE_MISMATCH,
  );
});

test("verifyRestoreProvenance: a bad io/reader or staged shape is CONFIG_INVALID", async () => {
  await expectRefusal(
    verifyRestoreProvenance({}, { expectedAuthority: AUTHORITY, staged: {} }),
    PROTOCOL_ERROR_CODES.CONFIG_INVALID,
  );
  await expectRefusal(
    verifyRestoreProvenance(provenanceIo(matchingRecord()), { expectedAuthority: AUTHORITY, staged: null }),
    PROTOCOL_ERROR_CODES.CONFIG_INVALID,
  );
});

// ---------- exported constants ----------------------------------------------

test("exported key sets are frozen and exact", () => {
  assert.deepEqual(EXPECTED_AUTHORITY_KEYS, [
    "hostId",
    "roleFingerprint",
    "volumeIdentityFingerprint",
    "keyFingerprint",
    "manifestFingerprint",
    "restoredFromWorkspaceId",
    "restoredFromGeneration",
  ]);
  assert.deepEqual(PROVENANCE_RECORD_KEYS, [
    "version",
    "kind",
    "hostId",
    "roleFingerprint",
    "volumeIdentityFingerprint",
    "keyFingerprint",
    "manifestFingerprint",
    "restoredFromWorkspaceId",
    "restoredFromGeneration",
  ]);
  assert.ok(Object.isFrozen(EXPECTED_AUTHORITY_KEYS));
  assert.ok(Object.isFrozen(PROVENANCE_RECORD_KEYS));
});

// ---------- verifyRestoreChecksum: pass-through to S4c -----------------------

const MANIFEST_BASE = {
  hostId: "host-1",
  workspaceId: "workspace-1",
  workspaceGeneration: 3,
  sourcePlatform: "windows-drive",
  rootIdentityFingerprint: "1".repeat(64),
  storageIdentityFingerprint: "2".repeat(64),
  gitGenerationFingerprint: "3".repeat(64),
};

function bytesOf(text) {
  return new TextEncoder().encode(text);
}

function checksumIo(map) {
  return {
    readBytes: async (path) => {
      if (!map.has(path)) {
        const e = new Error(`missing ${path}`);
        e.code = "ENOENT";
        throw e;
      }
      return map.get(path);
    },
  };
}

function manifestFor(map) {
  const entries = [...map.entries()].map(([path, bytes]) => ({
    path,
    size: bytes.byteLength,
    sha256: createHash("sha256").update(bytes).digest("hex"),
  }));
  return buildWorkspaceManifest({ ...MANIFEST_BASE, entries });
}

test("verifyRestoreChecksum: intact staged content verifies", async () => {
  const map = new Map([["a.txt", bytesOf("alpha")], ["b/c.txt", bytesOf("bravo")]]);
  const result = await verifyRestoreChecksum(checksumIo(map), manifestFor(map));
  assert.deepEqual(result, { ok: true, verifiedCount: 2 });
});

test("verifyRestoreChecksum: a tampered byte refuses WORKSPACE_MANIFEST_MISMATCH", async () => {
  const map = new Map([["a.txt", bytesOf("alpha")]]);
  const manifest = manifestFor(map);
  const tampered = new Map([["a.txt", bytesOf("alphb")]]); // same length, different byte
  await assert.rejects(
    verifyRestoreChecksum(checksumIo(tampered), manifest),
    (error) => {
      assert.equal(error.code, "WORKSPACE_MANIFEST_MISMATCH");
      return true;
    },
  );
});

test("verifyRestoreChecksum: a missing staged file refuses WORKSPACE_MANIFEST_MISMATCH", async () => {
  const map = new Map([["a.txt", bytesOf("alpha")]]);
  const manifest = manifestFor(map);
  await assert.rejects(
    verifyRestoreChecksum(checksumIo(new Map()), manifest),
    (error) => {
      assert.equal(error.code, "WORKSPACE_MANIFEST_MISMATCH");
      return true;
    },
  );
});
