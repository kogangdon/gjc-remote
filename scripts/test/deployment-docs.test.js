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
const repositoryReadme = (await readFile(path.join(root, "README.md"), "utf8")).replaceAll("\r\n", "\n");

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

test("repository deployment summary keeps evidence and platform boundaries intact", () => {
  assert.match(
    repositoryReadme,
    /Linux boot\/readiness, relay behavior,\nor transaction fault-injection has been verified\.\nExisting foreground commands/,
  );
  assert.match(repositoryReadme, /`\/srv\/apps\/foo` on Linux\)/);
  assert.doesNotMatch(repositoryReadme, /`\/srv\/apps\/foo` on Linux\/macOS/);
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

  assert.match(daemon, /Phase 3 daemon image source and a disposable/);
  assert.match(daemon, /verification\s+artifacts, not a published image or production deployment/);
  assert.match(daemon, /externally signed/);
  assert.match(daemon, /fixed identity `1004:1004`/);
  assert.match(daemon, /Docker Desktop on Windows is an unsupported target/);
  assert.match(daemon, /Phase 4 \/ issue #55 still owns published image provenance/);
  assert.match(
    daemon,
    /authenticated #44 mapping envelope remains the\s+sole route authority/,
  );
  assert.match(
    daemon,
    /`GJC_NATIVE_WORKSPACE_SERVING="0"`/,
  );
  assert.match(daemon, /not the production bot, mapping authority, or positive\s+workspace-serving evidence/);
  assert.match(daemon, /does not establish tenant\s+isolation/);
});
