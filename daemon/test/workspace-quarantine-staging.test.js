import test from "node:test";
import assert from "node:assert/strict";
import { PROTOCOL_ERROR_CODES } from "@gjc-remote/shared";
import { isHex64 } from "@gjc-remote/shared/strict-json";
import {
  SOURCE_KINDS,
  buildQuarantineStagingDescriptor,
  validateQuarantineStagingDescriptor,
  assertQuarantined,
} from "../src/workspace-quarantine-staging.js";

// ---------- descriptor -------------------------------------------------------

test("buildQuarantineStagingDescriptor: frozen, self-fingerprinted, exact key set", () => {
  const descriptor = buildQuarantineStagingDescriptor({
    hostId: "host-a",
    workspaceId: "workspace-a",
    sourcePlatform: "posix",
    stagingPath: "/srv/quarantine/workspace-a/staging",
    sourceKind: "dirty-backup",
  });

  assert.ok(Object.isFrozen(descriptor));
  assert.equal(descriptor.version, 1);
  assert.equal(descriptor.kind, "workspace-quarantine-staging");
  assert.equal(descriptor.hostId, "host-a");
  assert.equal(descriptor.sourceKind, "dirty-backup");
  assert.equal(descriptor.stagingPath, "/srv/quarantine/workspace-a/staging");
  assert.ok(isHex64(descriptor.descriptorFingerprint));
  assert.deepEqual(Object.keys(descriptor).sort(), [
    "descriptorFingerprint",
    "hostId",
    "kind",
    "sourceKind",
    "sourcePlatform",
    "stagingPath",
    "version",
    "workspaceId",
  ]);
});

test("descriptor round-trip: build then validate returns the same record", () => {
  const descriptor = buildQuarantineStagingDescriptor({
    hostId: "host-a",
    workspaceId: "workspace-a",
    sourcePlatform: "windows-drive",
    stagingPath: "D:\\quarantine\\workspace-a\\staging",
    sourceKind: "restore-archive",
  });
  assert.equal(validateQuarantineStagingDescriptor(descriptor), descriptor);
});

test("descriptor fingerprint is deterministic and body-bound", () => {
  const input = {
    hostId: "host-a",
    workspaceId: "workspace-a",
    sourcePlatform: "posix",
    stagingPath: "/srv/quarantine/staging",
    sourceKind: "migration-export",
  };
  const a = buildQuarantineStagingDescriptor(input);
  const b = buildQuarantineStagingDescriptor(input);
  assert.equal(a.descriptorFingerprint, b.descriptorFingerprint);
  const c = buildQuarantineStagingDescriptor({ ...input, sourceKind: "dirty-backup" });
  assert.notEqual(a.descriptorFingerprint, c.descriptorFingerprint);
});

test("validate rejects a tampered fingerprint and an unknown sourceKind", () => {
  const descriptor = buildQuarantineStagingDescriptor({
    hostId: "host-a",
    workspaceId: "workspace-a",
    sourcePlatform: "posix",
    stagingPath: "/srv/quarantine/staging",
    sourceKind: "dirty-backup",
  });
  assert.throws(() => validateQuarantineStagingDescriptor({ ...descriptor, descriptorFingerprint: "f".repeat(64) }), (error) => {
    assert.equal(error.code, PROTOCOL_ERROR_CODES.CONFIG_INVALID);
    return true;
  });
  assert.throws(() => buildQuarantineStagingDescriptor({
    hostId: "host-a",
    workspaceId: "workspace-a",
    sourcePlatform: "posix",
    stagingPath: "/srv/quarantine/staging",
    sourceKind: "bogus-kind",
  }), (error) => {
    assert.equal(error.code, PROTOCOL_ERROR_CODES.CONFIG_INVALID);
    return true;
  });
  assert.ok(SOURCE_KINDS.has("dirty-backup"));
});

test("build rejects a non-canonical / relative / traversal staging path", () => {
  for (const bad of ["relative/staging", "/srv/../etc/staging", "/srv/staging/", "/srv//staging"]) {
    assert.throws(() => buildQuarantineStagingDescriptor({
      hostId: "host-a",
      workspaceId: "workspace-a",
      sourcePlatform: "posix",
      stagingPath: bad,
      sourceKind: "dirty-backup",
    }), (error) => {
      assert.equal(error.code, PROTOCOL_ERROR_CODES.CONFIG_INVALID, bad);
      return true;
    }, bad);
  }
});

// ---------- assertQuarantined (posix) ---------------------------------------

test("assertQuarantined: genuine sibling outside the live tree is admitted", () => {
  const result = assertQuarantined({
    stagingPath: "/srv/workspaces/workspace-a/.quarantine/staging",
    candidatePath: "/srv/workspaces/workspace-a/generations/3",
    workDir: "/srv/workspaces/workspace-a",
    sourcePlatform: "posix",
  });
  assert.deepEqual(result, { quarantined: true });
  assert.ok(Object.isFrozen(result));
});

test("assertQuarantined: staging === live candidate is refused", () => {
  assert.throws(() => assertQuarantined({
    stagingPath: "/srv/workspaces/workspace-a/generations/3",
    candidatePath: "/srv/workspaces/workspace-a/generations/3",
    workDir: "/srv/workspaces/workspace-a",
    sourcePlatform: "posix",
  }), (error) => {
    assert.equal(error.code, PROTOCOL_ERROR_CODES.WORKSPACE_STAGING_NOT_QUARANTINED);
    assert.equal(error.operation, "workspace_quarantine_staging");
    return true;
  });
});

test("assertQuarantined: staging nested under the live candidate is refused", () => {
  assert.throws(() => assertQuarantined({
    stagingPath: "/srv/workspaces/workspace-a/generations/3/staging",
    candidatePath: "/srv/workspaces/workspace-a/generations/3",
    workDir: "/srv/workspaces/workspace-a",
    sourcePlatform: "posix",
  }), (error) => {
    assert.equal(error.code, PROTOCOL_ERROR_CODES.WORKSPACE_STAGING_NOT_QUARANTINED);
    return true;
  });
});

test("assertQuarantined: a sibling whose name prefixes the live candidate is NOT a false nest", () => {
  // "/…/generations/30" must not be treated as nested under "/…/generations/3":
  // the separator-terminated prefix check rules out the string-prefix trap.
  const result = assertQuarantined({
    stagingPath: "/srv/workspaces/workspace-a/generations/30",
    candidatePath: "/srv/workspaces/workspace-a/generations/3",
    workDir: "/srv/workspaces/workspace-a",
    sourcePlatform: "posix",
  });
  assert.deepEqual(result, { quarantined: true });
});

test("assertQuarantined: a candidate outside its workspace root is CONFIG_INVALID", () => {
  assert.throws(() => assertQuarantined({
    stagingPath: "/srv/quarantine/staging",
    candidatePath: "/srv/other-workspace/generations/3",
    workDir: "/srv/workspaces/workspace-a",
    sourcePlatform: "posix",
  }), (error) => {
    assert.equal(error.code, PROTOCOL_ERROR_CODES.CONFIG_INVALID);
    return true;
  });
});

test("assertQuarantined: staging that is an ANCESTOR of the live candidate is refused", () => {
  // staging === workDir would let a delete-of-staging destroy the live tree.
  for (const stagingPath of [
    "/srv/workspaces/workspace-a",
    "/srv/workspaces/workspace-a/generations",
  ]) {
    assert.throws(() => assertQuarantined({
      stagingPath,
      candidatePath: "/srv/workspaces/workspace-a/generations/3",
      workDir: "/srv/workspaces/workspace-a",
      sourcePlatform: "posix",
    }), (error) => {
      assert.equal(error.code, PROTOCOL_ERROR_CODES.WORKSPACE_STAGING_NOT_QUARANTINED, stagingPath);
      return true;
    }, stagingPath);
  }
});

test("build/guard reject windows aliasing in a path (ADS, trailing dot/space, reserved name)", () => {
  for (const bad of [
    "D:\\workspaces\\ws\\stream:extra",
    "D:\\workspaces\\ws\\trailingdot.",
    "D:\\workspaces\\ws\\trailingspace ",
    "D:\\workspaces\\ws\\CON",
    "D:\\workspaces\\ws\\nul.txt",
  ]) {
    assert.throws(() => buildQuarantineStagingDescriptor({
      hostId: "host-a",
      workspaceId: "workspace-a",
      sourcePlatform: "windows-drive",
      stagingPath: bad,
      sourceKind: "dirty-backup",
    }), (error) => {
      assert.equal(error.code, PROTOCOL_ERROR_CODES.CONFIG_INVALID, bad);
      return true;
    }, bad);
  }
});

test("assertQuarantined: windows-unc rejects an aliased share component", () => {
  assert.throws(() => assertQuarantined({
    stagingPath: "\\\\srv\\share\\ws\\.quarantine",
    candidatePath: "\\\\srv\\bad:share\\ws\\generations\\3",
    workDir: "\\\\srv\\bad:share\\ws",
    sourcePlatform: "windows-unc",
  }), (error) => {
    assert.equal(error.code, PROTOCOL_ERROR_CODES.CONFIG_INVALID);
    return true;
  });
});

// ---------- assertQuarantined (windows case folding) ------------------------

test("assertQuarantined: windows nesting folds case (fail-closed) and is refused", () => {
  assert.throws(() => assertQuarantined({
    stagingPath: "D:\\Workspaces\\WORKSPACE-A\\Generations\\3\\Staging",
    candidatePath: "D:\\workspaces\\workspace-a\\generations\\3",
    workDir: "D:\\workspaces\\workspace-a",
    sourcePlatform: "windows-drive",
  }), (error) => {
    assert.equal(error.code, PROTOCOL_ERROR_CODES.WORKSPACE_STAGING_NOT_QUARANTINED);
    return true;
  });
});

test("assertQuarantined: windows forward-slash input is normalized before comparison", () => {
  // Forward slashes in the incoming windows paths must not defeat the guard.
  assert.throws(() => assertQuarantined({
    stagingPath: "D:/workspaces/workspace-a/generations/3/staging",
    candidatePath: "D:/workspaces/workspace-a/generations/3",
    workDir: "D:/workspaces/workspace-a",
    sourcePlatform: "windows-drive",
  }), (error) => {
    assert.equal(error.code, PROTOCOL_ERROR_CODES.WORKSPACE_STAGING_NOT_QUARANTINED);
    return true;
  });
  const ok = assertQuarantined({
    stagingPath: "D:/workspaces/workspace-a/.quarantine/staging",
    candidatePath: "D:/workspaces/workspace-a/generations/3",
    workDir: "D:/workspaces/workspace-a",
    sourcePlatform: "windows-drive",
  });
  assert.deepEqual(ok, { quarantined: true });
});

test("assertQuarantined: windows-unc sibling admitted, nested refused", () => {
  const ok = assertQuarantined({
    stagingPath: "\\\\srv\\share\\workspace-a\\.quarantine\\staging",
    candidatePath: "\\\\srv\\share\\workspace-a\\generations\\3",
    workDir: "\\\\srv\\share\\workspace-a",
    sourcePlatform: "windows-unc",
  });
  assert.deepEqual(ok, { quarantined: true });
  assert.throws(() => assertQuarantined({
    stagingPath: "\\\\srv\\share\\workspace-a\\generations\\3\\staging",
    candidatePath: "\\\\srv\\share\\workspace-a\\generations\\3",
    workDir: "\\\\srv\\share\\workspace-a",
    sourcePlatform: "windows-unc",
  }), (error) => {
    assert.equal(error.code, PROTOCOL_ERROR_CODES.WORKSPACE_STAGING_NOT_QUARANTINED);
    return true;
  });
});

// ---------- input guards -----------------------------------------------------

test("assertQuarantined: unknown platform and malformed paths refuse CONFIG_INVALID", () => {
  assert.throws(() => assertQuarantined({
    stagingPath: "/a/b",
    candidatePath: "/a",
    workDir: "/a",
    sourcePlatform: "plan9",
  }), (error) => {
    assert.equal(error.code, PROTOCOL_ERROR_CODES.CONFIG_INVALID);
    return true;
  });
  for (const bad of ["relative/staging", "/srv/../escape", "", "/srv/staging\0/x"]) {
    assert.throws(() => assertQuarantined({
      stagingPath: bad,
      candidatePath: "/srv/workspaces/workspace-a/generations/3",
      workDir: "/srv/workspaces/workspace-a",
      sourcePlatform: "posix",
    }), (error) => {
      assert.equal(error.code, PROTOCOL_ERROR_CODES.CONFIG_INVALID, JSON.stringify(bad));
      return true;
    }, JSON.stringify(bad));
  }
});
