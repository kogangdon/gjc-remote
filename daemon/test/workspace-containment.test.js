import test from "node:test";
import assert from "node:assert/strict";

import { createWorkspaceContainment } from "../src/workspace-containment.js";

const POSIX_ROOT_IDENTITY = Object.freeze({ kind: "posix-root-v1", device: "2050", inode: "12" });
const POSIX_STORAGE_IDENTITY = Object.freeze({ kind: "posix-storage-v1", device: "2050" });
const WIN_ROOT_IDENTITY = Object.freeze({
  kind: "win32-root-v1",
  volumeSerial: "0123456789abcdef",
  fileId: "0123456789abcdef0123456789abcdef",
});
const WIN_STORAGE_IDENTITY = Object.freeze({
  kind: "windows-drive-storage-v1",
  volumeGuid: "\\\\?\\VOLUME{12345678-1234-1234-1234-1234567890AB}\\",
  volumeSerial: "01234567",
  fileSystem: "NTFS",
});

const LEAF_IDENTITY = Object.freeze({
  volumeSerial: 3933667438,
  fileIndexHigh: 327680,
  fileIndexLow: 3891720,
  attributes: 32,
  owner: "S-1-5-21-1-2-3-1001",
});

// Fake lowLevel modelling the REAL native contract:
//   read_workspace_root_facts(dir, sp) - returns configured facts or throws.
//   path_exists_no_follow(path)        - true when present, false when absent,
//                                        THROWS on a reparse leaf.
//   read_identity(path)                - identity when present, throws ENOENT
//                                        when absent, throws on a reparse leaf.
// `nodes` is a Map<absolutePath, { reparse?, identity? }>; a present key means
// the path exists.
function makeFake({ facts, factsError, nodes = new Map() } = {}) {
  const calls = [];
  return {
    calls,
    async read_workspace_root_facts(workDir, sourcePlatform) {
      calls.push(["read_workspace_root_facts", workDir, sourcePlatform]);
      if (factsError) throw factsError;
      return facts;
    },
    async path_exists_no_follow(path) {
      calls.push(["path_exists_no_follow", path]);
      const node = nodes.get(path);
      if (node?.reparse) {
        const error = new Error("unable to test path existence without following reparse points");
        error.code = "ERR_NATIVE_CONTROL_OPEN";
        throw error;
      }
      return node !== undefined;
    },
    async read_identity(path) {
      calls.push(["read_identity", path]);
      const node = nodes.get(path);
      if (node === undefined) {
        const error = new Error("no such entry");
        error.code = "ENOENT";
        throw error;
      }
      if (node.reparse) {
        const error = new Error("unable to open without following reparse points");
        error.code = "ERR_NATIVE_CONTROL_OPEN";
        throw error;
      }
      return node.identity ?? { ...LEAF_IDENTITY };
    },
  };
}

const posixFacts = () => ({
  sourcePlatform: "posix",
  workDir: "/srv/ws/proj",
  rootIdentity: { ...POSIX_ROOT_IDENTITY },
  storageIdentity: { ...POSIX_STORAGE_IDENTITY },
});

const windowsFacts = () => ({
  sourcePlatform: "windows-drive",
  workDir: "C:\\ws\\proj",
  rootIdentity: { ...WIN_ROOT_IDENTITY },
  storageIdentity: { ...WIN_STORAGE_IDENTITY },
});

async function expectRefusal(promise, code) {
  await assert.rejects(promise, (error) => {
    assert.equal(error.code, code, `expected code ${code} got ${error.code}`);
    assert.equal(error.operation, "verify_workspace_containment");
    assert.equal(typeof error.reason, "string");
    assert.ok(error.reason.length > 0);
    return true;
  });
}

test("createWorkspaceContainment rejects a missing or malformed lowLevel", () => {
  assert.throws(() => createWorkspaceContainment({ lowLevel: null }), TypeError);
  assert.throws(() => createWorkspaceContainment({ lowLevel: {} }), TypeError);
  assert.throws(
    () => createWorkspaceContainment({ lowLevel: { read_workspace_root_facts() {} } }),
    TypeError,
  );
});

test("identifyRoot returns the reparse-free identity for a posix root", async () => {
  const fake = makeFake({ facts: posixFacts() });
  const containment = createWorkspaceContainment({ lowLevel: fake, platform: "linux" });
  const result = await containment.identifyRoot({ workDir: "/srv/ws/proj", sourcePlatform: "posix" });
  assert.deepEqual(result.rootIdentity, POSIX_ROOT_IDENTITY);
  assert.deepEqual(result.storageIdentity, POSIX_STORAGE_IDENTITY);
  assert.ok(Object.isFrozen(result) && Object.isFrozen(result.rootIdentity));
});

test("identifyRoot returns the identity for a windows-drive root", async () => {
  const fake = makeFake({ facts: windowsFacts() });
  const containment = createWorkspaceContainment({ lowLevel: fake, platform: "win32" });
  const result = await containment.identifyRoot({ workDir: "C:\\ws\\proj", sourcePlatform: "windows-drive" });
  assert.deepEqual(result.rootIdentity, WIN_ROOT_IDENTITY);
  assert.deepEqual(result.storageIdentity, WIN_STORAGE_IDENTITY);
});

test("identifyRoot refuses windows-unc as CONTAINMENT_UNSUPPORTED before any native call", async () => {
  const fake = makeFake({ facts: posixFacts() });
  const containment = createWorkspaceContainment({ lowLevel: fake });
  await expectRefusal(
    containment.identifyRoot({ workDir: "\\\\host\\share\\ws", sourcePlatform: "windows-unc" }),
    "CONTAINMENT_UNSUPPORTED",
  );
  assert.equal(fake.calls.length, 0);
});

test("identifyRoot refuses an unknown source platform", async () => {
  const fake = makeFake({ facts: posixFacts() });
  const containment = createWorkspaceContainment({ lowLevel: fake });
  await expectRefusal(
    containment.identifyRoot({ workDir: "/srv/ws", sourcePlatform: "plan9" }),
    "CONTAINMENT_UNSUPPORTED",
  );
});

test("identifyRoot refuses a non-canonical workDir as WORKSPACE_ROOT_ESCAPE with no native call", async () => {
  const fake = makeFake({ facts: posixFacts() });
  const containment = createWorkspaceContainment({ lowLevel: fake });
  await expectRefusal(
    containment.identifyRoot({ workDir: "/srv/ws/../etc", sourcePlatform: "posix" }),
    "WORKSPACE_ROOT_ESCAPE",
  );
  await expectRefusal(
    containment.identifyRoot({ workDir: "relative/path", sourcePlatform: "posix" }),
    "WORKSPACE_ROOT_ESCAPE",
  );
  await expectRefusal(
    containment.identifyRoot({ workDir: "c:/ws/proj", sourcePlatform: "windows-drive" }),
    "WORKSPACE_ROOT_ESCAPE",
  );
  assert.equal(fake.calls.length, 0);
});

test("identifyRoot maps a malformed native identity to WORKSPACE_ROOT_UNIDENTIFIABLE", async () => {
  const facts = posixFacts();
  facts.rootIdentity = { kind: "posix-root-v1", device: "2050" }; // missing inode
  const containment = createWorkspaceContainment({ lowLevel: makeFake({ facts }) });
  await expectRefusal(
    containment.identifyRoot({ workDir: "/srv/ws/proj", sourcePlatform: "posix" }),
    "WORKSPACE_ROOT_UNIDENTIFIABLE",
  );
});

test("identifyRoot maps a native refusal to WORKSPACE_ROOT_UNIDENTIFIABLE", async () => {
  const error = new Error("refused");
  error.code = "WORKSPACE_ROOT_ESCAPE";
  error.reason = "inventory operation failed";
  const containment = createWorkspaceContainment({
    lowLevel: makeFake({ facts: posixFacts(), factsError: error }),
  });
  await expectRefusal(
    containment.identifyRoot({ workDir: "/srv/ws/proj", sourcePlatform: "posix" }),
    "WORKSPACE_ROOT_UNIDENTIFIABLE",
  );
});

test("verifyContained refuses lexical escapes before touching the filesystem", async () => {
  const cases = [
    { candidate: "sub/../../etc/passwd", label: "dot-dot traversal" },
    { candidate: "/etc/passwd", label: "absolute path outside root" },
    { candidate: "with\0nul", label: "NUL byte" },
    { candidate: "", label: "empty candidate" },
  ];
  for (const { candidate, label } of cases) {
    const fake = makeFake({ facts: posixFacts() });
    const containment = createWorkspaceContainment({ lowLevel: fake });
    await expectRefusal(
      containment.verifyContained({ workDir: "/srv/ws/proj", sourcePlatform: "posix", candidate }),
      "WORKSPACE_ROOT_ESCAPE",
    );
    assert.equal(fake.calls.length, 0, `native call happened for ${label}`);
  }
});

test("verifyContained refuses a windows-drive candidate on the wrong drive", async () => {
  const fake = makeFake({ facts: windowsFacts() });
  const containment = createWorkspaceContainment({ lowLevel: fake, platform: "win32" });
  await expectRefusal(
    containment.verifyContained({
      workDir: "C:\\ws\\proj",
      sourcePlatform: "windows-drive",
      candidate: "D:\\ws\\proj\\file.txt",
    }),
    "WORKSPACE_ROOT_ESCAPE",
  );
  assert.equal(fake.calls.length, 0);
});

test("verifyContained returns the leaf identity for a contained nested path", async () => {
  const nodes = new Map([
    ["/srv/ws/proj/src", {}],
    ["/srv/ws/proj/src/app.js", { identity: { ...LEAF_IDENTITY, fileIndexLow: 77 } }],
  ]);
  const fake = makeFake({ facts: posixFacts(), nodes });
  const containment = createWorkspaceContainment({ lowLevel: fake });
  const result = await containment.verifyContained({
    workDir: "/srv/ws/proj",
    sourcePlatform: "posix",
    candidate: "src/app.js",
  });
  assert.equal(result.identity.fileIndexLow, 77);
  assert.deepEqual(result.rootIdentity, POSIX_ROOT_IDENTITY);
  assert.ok(Object.isFrozen(result) && Object.isFrozen(result.identity));
});

test("verifyContained accepts an absolute candidate that is inside the root", async () => {
  const nodes = new Map([
    ["/srv/ws/proj/data", {}],
    ["/srv/ws/proj/data/a.bin", { identity: { ...LEAF_IDENTITY, fileIndexLow: 78 } }],
  ]);
  const fake = makeFake({ facts: posixFacts(), nodes });
  const containment = createWorkspaceContainment({ lowLevel: fake });
  const result = await containment.verifyContained({
    workDir: "/srv/ws/proj",
    sourcePlatform: "posix",
    candidate: "/srv/ws/proj/data/a.bin",
  });
  assert.equal(result.identity.fileIndexLow, 78);
});

test("verifyContained returns the root identity family when the candidate is the root itself", async () => {
  const nodes = new Map([["/srv/ws/proj", { identity: { ...LEAF_IDENTITY, fileIndexLow: 1 } }]]);
  const fake = makeFake({ facts: posixFacts(), nodes });
  const containment = createWorkspaceContainment({ lowLevel: fake });
  const result = await containment.verifyContained({
    workDir: "/srv/ws/proj",
    sourcePlatform: "posix",
    candidate: "/srv/ws/proj",
  });
  assert.equal(result.identity.fileIndexLow, 1);
});

test("verifyContained rejects a reparse point at a middle component", async () => {
  const nodes = new Map([
    ["/srv/ws/proj/link", { reparse: true }],
    ["/srv/ws/proj/link/deep", { identity: { ...LEAF_IDENTITY } }],
  ]);
  const fake = makeFake({ facts: posixFacts(), nodes });
  const containment = createWorkspaceContainment({ lowLevel: fake });
  await expectRefusal(
    containment.verifyContained({ workDir: "/srv/ws/proj", sourcePlatform: "posix", candidate: "link/deep" }),
    "REPARSE_POINT_REJECTED",
  );
  // The walk must stop AT the reparse component and never probe past it.
  assert.ok(!fake.calls.some((call) => call[1] === "/srv/ws/proj/link/deep"));
});

test("verifyContained maps a missing component to CANDIDATE_NOT_FOUND", async () => {
  const fake = makeFake({ facts: posixFacts(), nodes: new Map() });
  const containment = createWorkspaceContainment({ lowLevel: fake });
  await expectRefusal(
    containment.verifyContained({ workDir: "/srv/ws/proj", sourcePlatform: "posix", candidate: "nope/here" }),
    "CANDIDATE_NOT_FOUND",
  );
});

test("verifyContained cross-checks an expected root identity and refuses a mismatch", async () => {
  const nodes = new Map([["/srv/ws/proj/a", { identity: { ...LEAF_IDENTITY } }]]);
  const fake = makeFake({ facts: posixFacts(), nodes });
  const containment = createWorkspaceContainment({ lowLevel: fake });
  await expectRefusal(
    containment.verifyContained({
      workDir: "/srv/ws/proj",
      sourcePlatform: "posix",
      candidate: "a",
      expectedRootIdentity: { kind: "posix-root-v1", device: "9999", inode: "1" },
    }),
    "WORKSPACE_ROOT_UNIDENTIFIABLE",
  );
});

test("verifyContained accepts a matching expected root identity", async () => {
  const nodes = new Map([["/srv/ws/proj/a", { identity: { ...LEAF_IDENTITY, fileIndexLow: 6 } }]]);
  const fake = makeFake({ facts: posixFacts(), nodes });
  const containment = createWorkspaceContainment({ lowLevel: fake });
  const result = await containment.verifyContained({
    workDir: "/srv/ws/proj",
    sourcePlatform: "posix",
    candidate: "a",
    expectedRootIdentity: { ...POSIX_ROOT_IDENTITY },
  });
  assert.equal(result.identity.fileIndexLow, 6);
  assert.deepEqual(result.rootIdentity, POSIX_ROOT_IDENTITY);
});
