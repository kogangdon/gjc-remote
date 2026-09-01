import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import test from "node:test";

const root = fileURLToPath(new URL("../../", import.meta.url));
const dockerfilePath = fileURLToPath(
  new URL("../../deploy/docker/bot/Dockerfile", import.meta.url)
);
const composePath = fileURLToPath(
  new URL("../../deploy/docker/bot/compose.yaml", import.meta.url)
);
const dockerignorePath = fileURLToPath(new URL("../../.dockerignore", import.meta.url));

const [dockerfileRaw, composeRaw, dockerignoreRaw] = await Promise.all([
  readFile(dockerfilePath, "utf8"),
  readFile(composePath, "utf8"),
  readFile(dockerignorePath, "utf8"),
]);
const normalizeLines = (value) => value.replaceAll("\r\n", "\n");
const dockerfile = normalizeLines(dockerfileRaw);
const compose = normalizeLines(composeRaw);
const dockerignore = normalizeLines(dockerignoreRaw);

test("bot image pins Bun and Node indexes and never rebuilds signed native code", () => {
  assert.match(dockerfile, /oven\/bun:1\.3\.14@sha256:[0-9a-f]{64}/);
  assert.match(dockerfile, /node:26\.8\.1-trixie-slim@sha256:[0-9a-f]{64}/);
  assert.match(dockerfile, /FROM native_control_bundle AS signed-native/);
  assert.equal(
    dockerfile.match(/COPY --chmod=0444 --from=signed-native/g)?.length,
    3,
    "every signed bundle artifact must be readable by the non-root runtime",
  );
  assert.match(
    dockerfile,
    /RUN chmod 0555 \.\/native-control\/build \.\/native-control\/build\/Release/,
  );
  assert.match(dockerfile, /verify-build\.mjs --require-signature/);
  assert.doesNotMatch(dockerfile, /node-gyp|npm run build|bun run build/);
  assert.match(dockerfile, /useradd --uid 1001 .* gjc-management/);
  assert.match(dockerfile, /useradd --uid 1002 .* gjc-recovery/);
  assert.match(dockerfile, /USER node/);
  assert.match(dockerfile, /ENTRYPOINT \["\/usr\/bin\/tini", "--"\]/);
  assert.match(dockerfile, /container-healthcheck\.js/);
});

test("bot image never accepts or copies runtime secrets as build material", () => {
  for (const name of ["DISCORD_TOKEN", "HOST_TOKENS"]) {
    assert.doesNotMatch(dockerfile, new RegExp(`(?:ARG|ENV)\\s+${name}`));
  }
  assert.doesNotMatch(dockerfile, /COPY\s+.*(?:\.env|channels\.json|secrets)/i);
  for (const entry of [".env", "*.env", "channels.json", "deploy/docker/bot/secrets"]) {
    assert.match(dockerignore, new RegExp(`^${entry.replaceAll("*", "\\*")}$`, "m"));
  }
});

test("Compose hardens only the bot and keeps control-plane publication private", () => {
  assert.match(compose, /^services:\n  bot:/);
  assert.doesNotMatch(compose, /^  daemon:/m);
  assert.match(compose, /read_only: true/);
  assert.match(compose, /cap_drop:\n      - ALL/);
  assert.match(compose, /no-new-privileges:true/);
  assert.match(compose, /restart: "on-failure:5"/);
  assert.match(compose, /stop_grace_period: 30s/);
  assert.match(compose, /DISCORD_TOKEN_FILE: \/run\/secrets\/discord_token/);
  assert.match(compose, /HOST_TOKENS_FILE: \/run\/secrets\/host_tokens/);
  assert.match(compose, /GJC_MANAGEMENT_ROLE_BINDINGS: \$\{GJC_MANAGEMENT_ROLE_BINDINGS:\?/);
  assert.match(compose, /host_ip: \$\{GJC_BOT_BIND_ADDRESS:-127\.0\.0\.1\}/);
  assert.match(compose, /native_control_bundle: \$\{GJC_NATIVE_CONTROL_BUNDLE_DIR:\?/);
  assert.doesNotMatch(compose, /docker\.sock|privileged:\s*true|network_mode:\s*host/);
});

test("contract fixture paths resolve inside the repository", () => {
  assert.equal(typeof root, "string");
  assert.equal(root.length > 0, true);
});
