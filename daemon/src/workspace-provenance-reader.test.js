// Tests for the durable provenance reader primitive (slice S6f.1f, #53/#81).
//
// Builds a real temp directory and drives createProvenanceReader through a
// real S6f.1c contained byte-reader - no mocking of the reparse-safe reader
// itself, so containment/escape behavior is exercised for real.

import assert from "node:assert/strict";
import { mkdtemp, writeFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";

import { createContainedByteReader } from "./workspace-contained-byte-reader.js";
import { createProvenanceReader } from "./workspace-provenance-reader.js";
import { verifyRestoreProvenance, PROVENANCE_KIND } from "./workspace-restore-provenance.js";

const HOST_ID = "host-alpha";
const ROLE_FP = "a".repeat(64);
const VOLUME_FP = "b".repeat(64);
const KEY_FP = "c".repeat(64);
const MANIFEST_FP = "d".repeat(64);
const SOURCE_WORKSPACE_ID = "workspace-source";
const SOURCE_GENERATION = 3;

function validRecord() {
  return {
    version: 2,
    kind: PROVENANCE_KIND,
    hostId: HOST_ID,
    roleFingerprint: ROLE_FP,
    volumeIdentityFingerprint: VOLUME_FP,
    keyFingerprint: KEY_FP,
    manifestFingerprint: MANIFEST_FP,
    restoredFromWorkspaceId: SOURCE_WORKSPACE_ID,
    restoredFromGeneration: SOURCE_GENERATION,
  };
}

async function withTempRoot(fn) {
  const root = await mkdtemp(join(tmpdir(), "gjc-provenance-reader-"));
  try {
    return await fn(root);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
}

function makeProvenanceReader(root) {
  const byteReader = createContainedByteReader({
    root,
    sourcePlatform: process.platform === "win32" ? "windows" : "posix",
  });
  return createProvenanceReader({ reader: byteReader });
}

test("readProvenanceRecord returns a deep-equal object for a valid record", async () => {
  await withTempRoot(async (root) => {
    const record = validRecord();
    await writeFile(join(root, "provenance.json"), JSON.stringify(record), "utf-8");

    const provenanceIo = makeProvenanceReader(root);
    const result = await provenanceIo.readProvenanceRecord({ provenancePath: "provenance.json" });
    assert.deepEqual(result, record);
  });
});

test("reader output is consumable by verifyRestoreProvenance", async () => {
  await withTempRoot(async (root) => {
    const record = validRecord();
    await writeFile(join(root, "provenance.json"), JSON.stringify(record), "utf-8");

    const provenanceIo = makeProvenanceReader(root);
    const expectedAuthority = {
      hostId: HOST_ID,
      roleFingerprint: ROLE_FP,
      volumeIdentityFingerprint: VOLUME_FP,
      keyFingerprint: KEY_FP,
      manifestFingerprint: MANIFEST_FP,
      restoredFromWorkspaceId: SOURCE_WORKSPACE_ID,
      restoredFromGeneration: SOURCE_GENERATION,
    };
    const result = await verifyRestoreProvenance(provenanceIo, {
      expectedAuthority,
      staged: { provenancePath: "provenance.json" },
    });
    assert.equal(result.verified, true);
    assert.equal(result.hostId, HOST_ID);
    assert.equal(result.roleFingerprint, ROLE_FP);
    assert.equal(result.volumeIdentityFingerprint, VOLUME_FP);
    assert.equal(result.keyFingerprint, KEY_FP);
  });
});

test("readProvenanceRecord resolves to null when the record is absent", async () => {
  await withTempRoot(async (root) => {
    const provenanceIo = makeProvenanceReader(root);
    const result = await provenanceIo.readProvenanceRecord({ provenancePath: "missing.json" });
    assert.equal(result, null);
  });
});

test("readProvenanceRecord throws on a torn (invalid JSON) record", async () => {
  await withTempRoot(async (root) => {
    await writeFile(join(root, "torn.json"), "{ not valid json", "utf-8");
    const provenanceIo = makeProvenanceReader(root);
    await assert.rejects(
      () => provenanceIo.readProvenanceRecord({ provenancePath: "torn.json" }),
      (error) => {
        assert.ok(error instanceof SyntaxError);
        return true;
      },
    );
  });
});

test("readProvenanceRecord throws on invalid UTF-8 bytes", async () => {
  await withTempRoot(async (root) => {
    // 0xFF 0xFE is not valid UTF-8 in this position.
    await writeFile(join(root, "bad-utf8.json"), Buffer.from([0xff, 0xfe, 0x00, 0x01]));
    const provenanceIo = makeProvenanceReader(root);
    await assert.rejects(
      () => provenanceIo.readProvenanceRecord({ provenancePath: "bad-utf8.json" }),
      (error) => {
        assert.ok(error instanceof TypeError);
        return true;
      },
    );
  });
});

test("readProvenanceRecord propagates WORKSPACE_ROOT_ESCAPE on a containment escape", async () => {
  await withTempRoot(async (root) => {
    // Create a sibling directory + file to make the escape target real, so
    // the assertion cannot accidentally pass via an unrelated ENOENT.
    const parent = join(root, "..");
    const outsideName = `gjc-provenance-outside-${process.pid}-${Date.now()}.json`;
    const outsidePath = join(parent, outsideName);
    await writeFile(outsidePath, JSON.stringify(validRecord()), "utf-8");
    try {
      const provenanceIo = makeProvenanceReader(root);
      await assert.rejects(
        () => provenanceIo.readProvenanceRecord({ provenancePath: `../${outsideName}` }),
        (error) => {
          assert.ok(error instanceof Error);
          assert.notEqual(error, null);
          assert.equal(error.code, "WORKSPACE_ROOT_ESCAPE");
          return true;
        },
      );
    } finally {
      await rm(outsidePath, { force: true });
    }
  });
});

test("readProvenanceRecord throws PROVENANCE_RECORD_UNREADABLE on bad staged shapes", async () => {
  await withTempRoot(async (root) => {
    const provenanceIo = makeProvenanceReader(root);
    for (const staged of [null, {}, { provenancePath: "" }]) {
      await assert.rejects(
        () => provenanceIo.readProvenanceRecord(staged),
        (error) => {
          assert.equal(error.operation, "workspace_provenance_reader");
          assert.equal(error.code, "PROVENANCE_RECORD_UNREADABLE");
          return true;
        },
      );
    }
  });
});

test("createProvenanceReader throws PROVENANCE_READER_CONFIG_INVALID without a readBytes reader", () => {
  assert.throws(
    () => createProvenanceReader({}),
    (error) => {
      assert.equal(error.operation, "workspace_provenance_reader");
      assert.equal(error.code, "PROVENANCE_READER_CONFIG_INVALID");
      return true;
    },
  );
  assert.throws(
    () => createProvenanceReader({ reader: {} }),
    (error) => {
      assert.equal(error.code, "PROVENANCE_READER_CONFIG_INVALID");
      return true;
    },
  );
});
