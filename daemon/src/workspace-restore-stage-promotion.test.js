import assert from "node:assert/strict";
import test from "node:test";

import { buildWorkspaceManifest } from "../src/workspace-backup-manifest.js";
import { createRestoreStagePromotion } from "../src/workspace-restore-stage-promotion.js";

const SHA_A = "ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb";
const SHA_B = "3e23e8160039594a33894f6564e1b1348bbd7a0088d42c4acb73eeaed59c009d";

function manifest(entries = [{ path: "one.txt", size: 1, sha256: SHA_A }]) {
  return buildWorkspaceManifest({
    hostId: "host", workspaceId: "workspace", workspaceGeneration: 1,
    sourcePlatform: "posix", rootIdentityFingerprint: "1".repeat(64),
    storageIdentityFingerprint: "2".repeat(64), gitGenerationFingerprint: "3".repeat(64),
    entries,
  });
}

function absent(path) {
  const error = new Error(`missing ${path}`);
  error.code = "ENOENT";
  return error;
}

function fakeFs({ existing = [], failOpen = null } = {}) {
  const dirs = new Set(["/", ...existing]);
  const files = new Map();
  const state = { dirs, files, rmCalls: [], mkdirCalls: [], openCalls: [], syncCalls: [] };
  return {
    state,
    async lstat(path) {
      if (dirs.has(path) || files.has(path)) return { path };
      throw absent(path);
    },
    async mkdir(path) {
      state.mkdirCalls.push(path);
      if (dirs.has(path) || files.has(path)) {
        const error = new Error("exists"); error.code = "EEXIST"; throw error;
      }
      dirs.add(path);
    },
    async open(path, flag) {
      state.openCalls.push({ path, flag });
      if (flag === "r") {
        if (!dirs.has(path)) throw absent(path);
        return {
          async sync() { state.syncCalls.push(path); },
          async close() {},
        };
      }
      if (failOpen === path || files.has(path)) {
        const error = new Error("exists"); error.code = "EEXIST"; throw error;
      }
      let bytes = null;
      return {
        async writeFile(value) { bytes = new Uint8Array(value); },
        async sync() { state.syncCalls.push(path); },
        async close() { files.set(path, bytes); },
      };
    },
    async rm(path) {
      state.rmCalls.push(path);
      for (const file of [...files.keys()]) if (file === path || file.startsWith(`${path}/`)) files.delete(file);
      for (const dir of [...dirs]) if (dir === path || dir.startsWith(`${path}/`)) dirs.delete(dir);
    },
  };
}

function setup({ entries, fs = fakeFs(), stageRead, candidateRead, resolve } = {}) {
  const record = manifest(entries);
  const stageCalls = [];
  const candidateCalls = [];
  const promotion = createRestoreStagePromotion({
    fs,
    makeStageReader: async (root, platform) => ({
      async readBytes(path) {
        stageCalls.push({ root, platform, path });
        if (stageRead) return stageRead(path);
        return new Uint8Array([path === "one.txt" ? 97 : 98]);
      },
    }),
    makeCandidateReader: async (root, platform) => ({
      async readBytes(path) {
        candidateCalls.push({ root, platform, path });
        if (candidateRead) return candidateRead(path);
        return fs.state.files.get(`${root}/${path}`);
      },
    }),
    resolveManifestPaths: async (root, platform) => resolve ? resolve(root, platform) :
      [...fs.state.files.keys()].filter((path) => path.startsWith(`${root}/`)).map((path) => path.slice(root.length + 1)).sort(),
  });
  return { promotion, record, fs, stageCalls, candidateCalls };
}

async function expectCode(promise, code) {
  await assert.rejects(promise, (error) => {
    assert.equal(error.code, code);
    return true;
  });
}

test("materializes exact manifest bytes through distinct stage and candidate readers and freezes proof", async () => {
  const { promotion, record, fs, stageCalls, candidateCalls } = setup({
    entries: [
      { path: "dir/two.txt", size: 1, sha256: SHA_B },
      { path: "one.txt", size: 1, sha256: SHA_A },
    ],
  });
  const proof = await promotion.materializeAndVerify({
    stagingPath: "/stage", candidatePath: "/candidate", sourcePlatform: "posix", manifest: record,
  });
  assert.deepEqual(proof, { manifestFingerprint: record.manifestFingerprint, verifiedCount: 2 });
  assert.ok(Object.isFrozen(proof));
  assert.deepEqual(stageCalls.map((call) => call.root), ["/stage", "/stage"]);
  assert.deepEqual(candidateCalls.map((call) => call.root), ["/candidate", "/candidate"]);
  assert.deepEqual(
    fs.state.openCalls.map((call) => call.flag),
    ["wx", "wx", "r", "r", "r"]
  );
  assert.deepEqual(fs.state.syncCalls, [
    "/candidate/dir/two.txt",
    "/candidate/one.txt",
    "/candidate/dir",
    "/candidate",
    "/",
  ]);
  assert.deepEqual(fs.state.rmCalls, []);
});

test("refuses a pre-existing candidate without removing it", async () => {
  const fs = fakeFs({ existing: ["/candidate"] });
  const { promotion, record } = setup({ fs });
  await expectCode(promotion.materializeAndVerify({
    stagingPath: "/stage", candidatePath: "/candidate", sourcePlatform: "posix", manifest: record,
  }), "RESTORE_STAGE_CANDIDATE_EXISTS");
  assert.ok(fs.state.dirs.has("/candidate"));
  assert.deepEqual(fs.state.rmCalls, []);
});

test("refuses traversal-bearing manifests before filesystem mutation", async () => {
  const { promotion, record, fs } = setup();
  const unsafe = { ...record, entries: [{ ...record.entries[0], path: "../escape" }] };
  await expectCode(promotion.materializeAndVerify({
    stagingPath: "/stage", candidatePath: "/candidate", sourcePlatform: "posix", manifest: unsafe,
  }), "WORKSPACE_MANIFEST_PATH_REJECTED");
  assert.deepEqual(fs.state.mkdirCalls, []);
});

test("cleans the candidate after stage-read failure and exclusive-write collision", async () => {
  for (const kind of ["read", "collision"]) {
    const fs = fakeFs({ failOpen: kind === "collision" ? "/candidate/one.txt" : null });
    const { promotion, record } = setup({
      fs,
      stageRead: kind === "read" ? async () => { throw new Error("sealed stage unavailable"); } : undefined,
    });
    await assert.rejects(promotion.materializeAndVerify({
      stagingPath: "/stage", candidatePath: "/candidate", sourcePlatform: "posix", manifest: record,
    }));
    assert.deepEqual(fs.state.rmCalls, ["/candidate"], kind);
    assert.ok(!fs.state.dirs.has("/candidate"), kind);
  }
});

test("cleans the candidate after every injected reader and enumeration checkpoint", async () => {
  for (const checkpoint of ["stage-factory", "resolver", "candidate-factory", "candidate-read"]) {
    const fs = fakeFs();
    const promotion = createRestoreStagePromotion({
      fs,
      makeStageReader: async () => {
        if (checkpoint === "stage-factory") throw new Error("stage factory failed");
        return { readBytes: async () => new Uint8Array([97]) };
      },
      resolveManifestPaths: async () => {
        if (checkpoint === "resolver") throw new Error("resolver failed");
        return ["one.txt"];
      },
      makeCandidateReader: async (root) => {
        if (checkpoint === "candidate-factory") throw new Error("candidate factory failed");
        return {
          readBytes: async () => {
            if (checkpoint === "candidate-read") throw new Error("candidate read failed");
            return fs.state.files.get(`${root}/one.txt`);
          },
        };
      },
    });
    await assert.rejects(promotion.materializeAndVerify({
      stagingPath: "/stage", candidatePath: "/candidate", sourcePlatform: "posix", manifest: manifest(),
    }));
    assert.deepEqual(fs.state.rmCalls, ["/candidate"], checkpoint);
    assert.ok(!fs.state.dirs.has("/candidate"), checkpoint);
  }
});

test("cleans candidate when enumeration finds extra or missing files", async () => {
  for (const paths of [["one.txt", "extra.txt"], []]) {
    const { promotion, record, fs } = setup({ resolve: async () => paths });
    await expectCode(promotion.materializeAndVerify({
      stagingPath: "/stage", candidatePath: "/candidate", sourcePlatform: "posix", manifest: record,
    }), "WORKSPACE_MANIFEST_MISMATCH");
    assert.deepEqual(fs.state.rmCalls, ["/candidate"]);
  }
});

test("cleans candidate when separately-rooted verification finds byte mismatch", async () => {
  const { promotion, record, fs } = setup({ candidateRead: async () => new Uint8Array([98]) });
  await expectCode(promotion.materializeAndVerify({
    stagingPath: "/stage", candidatePath: "/candidate", sourcePlatform: "posix", manifest: record,
  }), "WORKSPACE_MANIFEST_MISMATCH");
  assert.deepEqual(fs.state.rmCalls, ["/candidate"]);
});

test("explicit cleanup is idempotent and never removes staging or candidate parent", async () => {
  const fs = fakeFs({ existing: ["/", "/stage", "/parent"] });
  const { promotion, record } = setup({ fs });
  await promotion.materializeAndVerify({
    stagingPath: "/stage", candidatePath: "/parent/candidate", sourcePlatform: "posix", manifest: record,
  });
  await promotion.cleanup("/parent/candidate");
  await promotion.cleanup("/parent/candidate");
  assert.deepEqual(fs.state.rmCalls, ["/parent/candidate"]);
  assert.ok(fs.state.dirs.has("/stage"));
  assert.ok(fs.state.dirs.has("/parent"));
  assert.ok(!fs.state.dirs.has("/parent/candidate"));
});
