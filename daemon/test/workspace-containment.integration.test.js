import test from "node:test";
import assert from "node:assert/strict";
import { existsSync, mkdirSync, readFileSync, symlinkSync, writeFileSync } from "node:fs";
import { mkdtemp, rm } from "node:fs/promises";
import { createRequire } from "node:module";
import { fileURLToPath } from "node:url";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { validateBuildManifest } from "@gjc-remote/native-control";
import { createWorkspaceContainment } from "../src/workspace-containment.js";

const require = createRequire(import.meta.url);
const addonPath = fileURLToPath(new URL("../../native-control/build/Release/native_control.node", import.meta.url));
const manifestPath = fileURLToPath(new URL("../../native-control/build/Release/native-control.manifest.json", import.meta.url));
const packagePath = fileURLToPath(new URL("../../native-control/package.json", import.meta.url));

// Loads the signature-verified native addon or returns null after registering a
// skip on the test context. The addon exposes the low-level snake_case
// capabilities the containment module consumes directly.
function loadAddonOrSkip(t) {
  if (process.platform !== "win32") {
    t.skip("windows-drive containment integration runs on the win32 host build");
    return null;
  }
  if (!existsSync(addonPath) || !existsSync(manifestPath)) {
    t.skip("verified native addon is not built for this checkout");
    return null;
  }
  const addonBytes = readFileSync(addonPath);
  const manifest = JSON.parse(readFileSync(manifestPath, "utf8"));
  const packageJson = JSON.parse(readFileSync(packagePath, "utf8"));
  if (!validateBuildManifest(manifest, packageJson, addonBytes, process.platform, process.arch)) {
    t.skip("native build belongs to a different platform or architecture");
    return null;
  }
  return require(addonPath);
}

async function withWorkspace(run) {
  const root = await mkdtemp(join(tmpdir(), "gjc-containment-"));
  try {
    return await run(root);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
}

test("verifyContained resolves a real contained nested file to a leaf identity", async (t) => {
  const addon = loadAddonOrSkip(t);
  if (!addon) return;
  await withWorkspace(async (root) => {
    mkdirSync(join(root, "src", "inner"), { recursive: true });
    writeFileSync(join(root, "src", "inner", "app.js"), "export const x = 1;\n");
    const containment = createWorkspaceContainment({ lowLevel: addon, platform: "win32" });
    const result = await containment.verifyContained({
      workDir: root,
      sourcePlatform: "windows-drive",
      candidate: "src\\inner\\app.js",
    });
    // Leaf identity is the raw no-follow identity from read_identity.
    assert.equal(typeof result.identity, "object");
    assert.equal(typeof result.identity.owner, "string");
    assert.equal(typeof result.identity.volumeSerial, "number");
    // Root identity is the canonical mapping-proof identity from facts.
    assert.equal(result.rootIdentity.kind, "win32-root-v1");
    assert.match(result.rootIdentity.fileId, /^[a-f0-9]{32}$/);
  });
});

test("verifyContained refuses traversal through a real junction as REPARSE_POINT_REJECTED", async (t) => {
  const addon = loadAddonOrSkip(t);
  if (!addon) return;
  await withWorkspace(async (root) => {
    // A directory OUTSIDE the workspace that the junction points at.
    const outside = await mkdtemp(join(tmpdir(), "gjc-outside-"));
    try {
      writeFileSync(join(outside, "secret.txt"), "outside\n");
      // Junctions do not require elevation on Windows.
      symlinkSync(outside, join(root, "link"), "junction");
      const containment = createWorkspaceContainment({ lowLevel: addon, platform: "win32" });
      await assert.rejects(
        containment.verifyContained({
          workDir: root,
          sourcePlatform: "windows-drive",
          candidate: "link\\secret.txt",
        }),
        (error) => {
          assert.equal(error.code, "REPARSE_POINT_REJECTED");
          assert.equal(error.operation, "verify_workspace_containment");
          return true;
        },
      );
    } finally {
      await rm(outside, { recursive: true, force: true });
    }
  });
});

test("verifyContained refuses a lexical .. escape without touching the filesystem", async (t) => {
  const addon = loadAddonOrSkip(t);
  if (!addon) return;
  await withWorkspace(async (root) => {
    const containment = createWorkspaceContainment({ lowLevel: addon, platform: "win32" });
    await assert.rejects(
      containment.verifyContained({
        workDir: root,
        sourcePlatform: "windows-drive",
        candidate: "src\\..\\..\\Windows\\System32",
      }),
      (error) => {
        assert.equal(error.code, "WORKSPACE_ROOT_ESCAPE");
        return true;
      },
    );
  });
});

test("verifyContained maps a real missing child to CANDIDATE_NOT_FOUND", async (t) => {
  const addon = loadAddonOrSkip(t);
  if (!addon) return;
  await withWorkspace(async (root) => {
    const containment = createWorkspaceContainment({ lowLevel: addon, platform: "win32" });
    await assert.rejects(
      containment.verifyContained({
        workDir: root,
        sourcePlatform: "windows-drive",
        candidate: "does\\not\\exist",
      }),
      (error) => {
        assert.equal(error.code, "CANDIDATE_NOT_FOUND");
        return true;
      },
    );
  });
});

test("identifyRoot on a real workspace root yields a valid win32 identity or refuses deterministically", async (t) => {
  const addon = loadAddonOrSkip(t);
  if (!addon) return;
  await withWorkspace(async (root) => {
    const containment = createWorkspaceContainment({ lowLevel: addon, platform: "win32" });
    let outcome;
    try {
      outcome = await containment.identifyRoot({ workDir: root, sourcePlatform: "windows-drive" });
    } catch (error) {
      // A temp dir may not satisfy the native canonical reparse-free proof; the
      // module must still refuse deterministically rather than leak.
      assert.equal(error.operation, "verify_workspace_containment");
      assert.ok(
        ["WORKSPACE_ROOT_UNIDENTIFIABLE", "WORKSPACE_ROOT_ESCAPE"].includes(error.code),
        `unexpected identifyRoot refusal code ${error.code}`,
      );
      return;
    }
    assert.equal(outcome.rootIdentity.kind, "win32-root-v1");
    assert.match(outcome.rootIdentity.volumeSerial, /^[a-f0-9]{16}$/);
    assert.match(outcome.rootIdentity.fileId, /^[a-f0-9]{32}$/);
  });
});
