import assert from "node:assert/strict";
import test from "node:test";
import { fingerprintManagedMappingRecord } from "../mapping-envelope.js";
import { isFullyQualifiedRouteWorkDir } from "../work-dir.js";

test("route workDirs accept fully qualified canonical path shapes", () => {
  for (const workDir of [
    "/srv/workspace",
    "/srv/a.../workspace",
    "C:\\workspace\\repo",
    "d:/workspace/repo",
    "\\\\server\\share\\workspace",
    "//server/share/workspace",
  ]) {
    assert.equal(isFullyQualifiedRouteWorkDir(workDir), true, workDir);
  }
});

test("route workDirs reject dot segments across separator styles", () => {
  for (const workDir of [
    "/srv/./workspace",
    "/srv/a/../../etc",
    "/srv/workspace/..",
    "C:\\workspace\\.\\repo",
    "C:\\workspace\\..\\repo",
    "C:/workspace/../repo",
    "\\\\server\\share\\workspace\\..\\secret",
    "//server/share/workspace/./repo",
    "/srv\\..\\etc",
  ]) {
    assert.equal(isFullyQualifiedRouteWorkDir(workDir), false, workDir);
  }
});

test("route workDirs still reject relative, empty, and padded values", () => {
  for (const workDir of ["", "relative/path", "./workspace", " /srv/workspace"]) {
    assert.equal(isFullyQualifiedRouteWorkDir(workDir), false, workDir);
  }
});

test("managed legacy mappings reject dot-segment workDirs", () => {
  const mapping = {
    mappingId: "mapping-1",
    hostId: "host-a",
    fenceGeneration: 1,
    mappingGeneration: 1,
    workspaceGeneration: 1,
    mappingVersion: 1,
    sourcePlatform: "posix",
    workspaceId: null,
    workDir: "/srv/workspace",
    sourceRoot: "/srv/workspace",
    containerRoot: null,
    volumeIdentity: "dev:42",
    casePolicy: "sensitive",
    immutableDefault: false,
  };

  assert.doesNotThrow(() => fingerprintManagedMappingRecord(mapping));
  assert.throws(
    () =>
      fingerprintManagedMappingRecord({
        ...mapping,
        workDir: "/srv/workspace/../../etc",
      }),
    /MANAGED_MAPPING_INVALID/
  );
});
