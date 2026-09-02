import assert from "node:assert/strict";
import { readFile, realpath } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";

const root = fileURLToPath(new URL("../../", import.meta.url));
const deploymentFiles = [
  "docs/deployment/README.md",
  "docs/deployment/bot.md",
  "docs/deployment/daemon.md",
  "docs/deployment/workspaces-and-paths.md",
  "docs/deployment/platforms/linux.md",
  "docs/deployment/platforms/macos.md",
  "docs/deployment/platforms/windows.md",
  "docs/deployment/docker/bot.md",
  "docs/deployment/docker/daemon.md",
];
const contractFiles = [
  ...deploymentFiles,
  "deploy/docker/bot/README.md",
];
const realRoot = await realpath(root);

const documents = new Map(
  await Promise.all(
    contractFiles.map(async (relativePath) => [
      relativePath,
      (await readFile(path.join(root, relativePath), "utf8")).replaceAll("\r\n", "\n"),
    ]),
  ),
);

test("deployment index links every component and platform guide", () => {
  const index = documents.get("docs/deployment/README.md");
  for (const expected of [
    "bot.md",
    "daemon.md",
    "workspaces-and-paths.md",
    "platforms/linux.md",
    "platforms/macos.md",
    "platforms/windows.md",
    "docker/bot.md",
    "docker/daemon.md",
  ]) {
    assert.match(index, new RegExp(`\\(${expected.replaceAll(".", "\\.")}\\)`));
  }
});

test("all local deployment links resolve", async () => {
  const linkPattern = /\[[^\]\n]+\]\(([^()\s]+)\)/g;
  for (const [relativePath, contents] of documents) {
    const matches = [...contents.matchAll(linkPattern)];
    assert.equal(
      matches.length,
      contents.match(/\]\(/g)?.length ?? 0,
      `${relativePath} contains an unsupported inline-link form`,
    );
    for (const match of matches) {
      const target = match[1].split("#", 1)[0];
      if (target === "" || /^https?:\/\//i.test(target) || /^mailto:/i.test(target)) continue;
      assert.doesNotMatch(target, /^[a-z][a-z0-9+.-]*:/i, `${relativePath} uses an unsafe URL scheme`);
      assert.doesNotMatch(target, /^[a-z]:[\\/]/i, `${relativePath} uses a drive-qualified link`);
      assert.doesNotMatch(target, /^[\\/]{2}/, `${relativePath} uses a UNC or network-path link`);
      assert.equal(path.isAbsolute(target), false, `${relativePath} uses an absolute local link`);
      const resolved = await realpath(path.resolve(root, path.dirname(relativePath), target));
      const relativeToRoot = path.relative(realRoot, resolved);
      assert.ok(
        relativeToRoot !== "" &&
          relativeToRoot !== ".." &&
          !relativeToRoot.startsWith(`..${path.sep}`) &&
          !path.isAbsolute(relativeToRoot),
        `${relativePath} link escapes the repository: ${match[1]}`,
      );
    }
  }
});

test("daemon guidance matches the current fail-closed serving gate", () => {
  const daemon = documents.get("docs/deployment/daemon.md");
  assert.match(daemon, /constructs and self-tests the production native reader/);
  assert.match(daemon, /GJC_NATIVE_WORKSPACE_SERVING/);
  assert.match(daemon, /default-off/);
  assert.match(daemon, /sole route authority/);
  assert.doesNotMatch(daemon, /production reader wiring is not currently present/);
});

test("platform status never promotes missing artifacts", () => {
  assert.match(documents.get("docs/deployment/platforms/linux.md"), /No checked-in systemd unit template/);
  assert.match(documents.get("docs/deployment/platforms/macos.md"), /not a supported native-control/);
  assert.match(documents.get("docs/deployment/platforms/windows.md"), /Do not use NSSM/);
});

test("Docker guidance preserves scope, authority, secrets, and rollback boundaries", () => {
  const wrapper = documents.get("docs/deployment/docker/bot.md");
  const canonical = documents.get("deploy/docker/bot/README.md");
  const daemon = documents.get("docs/deployment/docker/daemon.md");

  assert.match(wrapper, /Linux-only \*\*release candidate\*\*, not a supported published image/);
  assert.match(wrapper, /Compose fixture contains no daemon/);
  assert.match(canonical, /authenticate daemon transport identity only/);
  assert.match(canonical, /routing still resolves exclusively through the authenticated mapping/);
  assert.match(canonical, /Do not place secrets[\s\S]+environment variables/);
  assert.match(canonical, /never restore an older volume snapshot to rewind monotonic/);
  assert.doesNotMatch(canonical, /matching the selected mapping authority/);

  assert.match(daemon, /No daemon Dockerfile or Compose fixture exists/);
  assert.doesNotMatch(daemon, /`docker (?:build|compose|pull|run)/i);
  assert.match(
    daemon,
    /must contain exactly the distinct `management`, `bot`, `recovery`, `daemon`, and `system` native principals/,
  );
  assert.match(
    daemon,
    /Native serving defaults off and requires both the exact `GJC_NATIVE_WORKSPACE_SERVING="1"` opt-in/,
  );
  assert.match(daemon, /advertised receipt capability/);
  assert.match(daemon, /live serving-on evidence/);
  assert.match(daemon, /inventory is not routing authority/);
});
