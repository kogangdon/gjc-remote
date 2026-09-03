import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import test from "node:test";

const read = async (relative) => (
  await readFile(fileURLToPath(new URL(`../../${relative}`, import.meta.url)), "utf8")
).replaceAll("\r\n", "\n");
const [
  dockerfile,
  compose,
  seccompRaw,
  dockerignore,
  entrypoint,
  workflow,
  preflightProbe,
] = await Promise.all([
  read("deploy/docker/daemon/Dockerfile"),
  read("deploy/docker/daemon/compose.test.yaml"),
  read("deploy/docker/daemon/seccomp.json"),
  read(".dockerignore"),
  read("daemon/src/container-entrypoint.js"),
  read(".github/workflows/ci.yml"),
  read("deploy/docker/daemon/preflight-probe.js"),
]);
const seccomp = JSON.parse(seccompRaw);

test("daemon image pins runtime, lock, SDK, source, and signed native inputs", () => {
  assert.match(dockerfile, /oven\/bun:1\.3\.14@sha256:[0-9a-f]{64}/);
  assert.match(dockerfile, /LOCK_SHA256=[0-9a-f]{64}/);
  assert.match(dockerfile, /sha256sum --check --strict/);
  assert.match(dockerfile, /bun install --frozen-lockfile --production --ignore-scripts/);
  assert.match(dockerfile, /--filter @gjc-remote\/daemon/);
  assert.match(dockerfile, /p\.version!=="0\.12\.21"/);
  assert.match(dockerfile, /FROM native_control_bundle AS signed-native/);
  assert.equal(dockerfile.match(/COPY --chmod=0444 --from=signed-native/g)?.length, 3);
  assert.match(dockerfile, /bun native-control\/scripts\/verify-build\.mjs --require-signature/);
  assert.match(dockerfile, /test "\$\{REVISION\}" != unknown/);
  assert.doesNotMatch(dockerfile, /node-gyp|npm run build|bun run build/);
});

test("daemon image fixes the non-root identity and preflight entrypoint", () => {
  assert.match(dockerfile, /groupadd --gid 1004 gjc/);
  assert.match(dockerfile, /useradd --uid 1004 --gid 1004/);
  for (const rolePath of [
    "/workspaces",
    "/var/lib/gjc-remote/sessions",
    "/home/gjc/.gjc",
    "/var/lib/gjc-remote/state",
  ]) assert.match(dockerfile, new RegExp(rolePath.replaceAll("/", "\\/")));
  assert.match(dockerfile, /USER 1004:1004/);
  assert.match(dockerfile, /ENTRYPOINT \["\/usr\/bin\/tini", "--", "bun", "\/app\/daemon\/src\/container-entrypoint\.js"\]/);
  assert.doesNotMatch(dockerfile, /HOST_TOKEN(?:=|\s)/);
  assert.doesNotMatch(dockerfile, /VOLUME\s/);
  assert.match(dockerignore, /^!daemon\/src\/$/m);
  assert.match(dockerignore, /^!daemon\/src\/\*\*$/m);
  assert.match(dockerfile, /COPY deploy\/docker\/daemon\/persistence-probe\.js/);
});

test("Linux CI executes preflight rejection and cross-recreation persistence", () => {
  assert.match(workflow, /os: ubuntu-latest[\s\S]+platform: linux\/amd64/);
  assert.match(workflow, /os: ubuntu-24\.04-arm[\s\S]+platform: linux\/arm64/);
  assert.match(workflow, /test "\$output" = "PREFLIGHT_OK"/);
  assert.match(workflow, /persistence-probe\.js write/);
  assert.match(workflow, /persistence-probe\.js read/);
  assert.match(workflow, /without no-new-privileges/);
  assert.match(workflow, /Reject an untrusted final daemon image/);
  assert.match(workflow, /final daemon image accepted an untrusted native bundle/);
  assert.match(workflow, /Exercise disposable same-host Compose topology/);
  assert.match(workflow, /fixture-relay: daemon registered/);
  assert.match(workflow, /internal-only daemon network allowed direct external egress/);
  assert.match(workflow, /down --volumes --remove-orphans/);
});

test("container entrypoint keeps mapping, inventory, and serving fail closed", () => {
  assert.match(entrypoint, /await assertContainerSecurityPreflight\(\)/);
  assert.ok(entrypoint.indexOf("await assertContainerSecurityPreflight()") < entrypoint.indexOf('await import("./daemon.js")'));
  assert.match(entrypoint, /error instanceof ContainerPreflightError/);
  assert.match(entrypoint, /preflight failed: \$\{code\}/);
  assert.match(entrypoint, /preflight failed: environment-contract/);
  assert.match(preflightProbe, /error instanceof ContainerPreflightError/);
  assert.match(preflightProbe, /PREFLIGHT_FAILED:\$\{code\}/);
  assert.match(entrypoint, /GJC_NATIVE_INVENTORY_MODE: "off"/);
  assert.match(entrypoint, /GJC_NATIVE_WORKSPACE_SERVING: "0"/);
  assert.match(entrypoint, /GJC_NATIVE_WORKSPACE_ROOT: ROLE_PATHS\.workspace/);
  assert.doesNotMatch(entrypoint, /mapping|channels\.json|GJC_READINESS_TEST/);
});

test("pinned seccomp defaults to deny and never unconditionally allows dangerous syscalls", () => {
  assert.equal(seccomp.defaultAction, "SCMP_ACT_ERRNO");
  assert.notEqual(seccomp.defaultAction, "SCMP_ACT_ALLOW");
  const dangerous = new Set(["bpf", "kexec_load", "mount", "open_by_handle_at", "ptrace", "reboot"]);
  for (const rule of seccomp.syscalls ?? []) {
    if (rule.action !== "SCMP_ACT_ALLOW") continue;
    for (const name of rule.names ?? []) {
      if (!dangerous.has(name)) continue;
      assert.ok(
        Array.isArray(rule.includes?.caps) && rule.includes.caps.length > 0,
        `${name} must not be unconditionally allowed`,
      );
    }
  }
});

test("Compose fixture is private, bounded, non-root, and independently deployable", () => {
  const daemonService = compose.slice(
    compose.indexOf("\n  daemon:\n"),
    compose.indexOf("\nnetworks:\n")
  );
  assert.match(daemonService, /image: \$\{GJC_DAEMON_IMAGE:\?/);
  assert.match(daemonService, /pull_policy: never/);
  assert.doesNotMatch(daemonService, /^    build:/m);
  assert.match(daemonService, /restart: "on-failure:5"/);
  assert.match(daemonService, /stop_grace_period: 30s/);
  assert.match(daemonService, /read_only: true/);
  assert.match(daemonService, /user: "1004:1004"/);
  assert.match(daemonService, /cap_drop:\n      - ALL/);
  assert.match(daemonService, /no-new-privileges:true/);
  assert.match(daemonService, /seccomp=\.\/seccomp\.json/);
  assert.match(daemonService, /pids_limit: 256/);
  assert.match(daemonService, /mem_limit: 8g/);
  assert.match(daemonService, /cpus: 4\.0/);
  assert.match(daemonService, /\/tmp:rw,noexec,nosuid,nodev,size=16m/);
  assert.match(compose, /internal: true/);
  assert.match(daemonService, /BOT_WS_URL: ws:\/\/bot-fixture:7711/);
  assert.match(daemonService, /HOST_TOKEN_FILE: \/run\/secrets\/host_token/);
  assert.match(daemonService, /GJC_NATIVE_INVENTORY_MODE: "off"/);
  assert.match(daemonService, /GJC_NATIVE_WORKSPACE_SERVING: "0"/);
  assert.doesNotMatch(daemonService, /docker\.sock|privileged:\s*true|network_mode:\s*host|pid:\s*host|^\s+ports:/m);
});

test("Compose grants exactly four persistent daemon role mounts", () => {
  const daemonService = compose.slice(
    compose.indexOf("\n  daemon:\n"),
    compose.indexOf("\nnetworks:\n")
  );
  const volumeBlock = daemonService.slice(
    daemonService.indexOf("\n    volumes:\n"),
    daemonService.indexOf("\n    networks:\n")
  );
  const targets = [...volumeBlock.matchAll(/^        target: (\S+)$/gm)].map((match) => match[1]);
  assert.deepEqual(targets, [
    "/workspaces",
    "/var/lib/gjc-remote/sessions",
    "/home/gjc/.gjc",
    "/var/lib/gjc-remote/state",
  ]);
  for (const volume of ["workspace", "sessions", "provider", "state"]) {
    assert.match(compose, new RegExp(`^  ${volume}:$`, "m"));
  }
});
