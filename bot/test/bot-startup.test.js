import { createServer } from "node:net";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import test from "node:test";

const botDir = fileURLToPath(new URL("..", import.meta.url));

function withoutDotenvConfig(env) {
  return Object.fromEntries(
    Object.entries(env).filter(([key]) => !key.toUpperCase().startsWith("DOTENV_CONFIG_"))
  );
}
function startupEnv(overrides = {}) {
  return {
    ...withoutDotenvConfig(process.env),
    DISCORD_TOKEN: "definitely-invalid-token",
    HOST_TOKENS: "prod-1:secret-a,prod-2:secret-b",
    CHANNELS_CONFIG: "channels.example.json",
    HOST_WS_PORT: "0",
    ...overrides,
  };
}

test("strict mode rejects an empty allowlist before bot services start", () => {
  const result = spawnSync(process.execPath, ["src/bot.js"], {
    cwd: botDir,
    env: {
      ...withoutDotenvConfig(process.env),
      DISCORD_TOKEN: "startup-test-token",
      GJC_BOT_ALLOWED_USERS: "",
      GJC_REMOTE_REQUIRE_ALLOWLIST: "1",
      HOST_TOKENS: "",
    },
    encoding: "utf8",
    timeout: 10_000,
  });

  assert.equal(result.status, 1);
  assert.match(
    result.stderr,
    /Invalid bot environment configuration:.*GJC_BOT_ALLOWED_USERS.*GJC_REMOTE_REQUIRE_ALLOWLIST=1/
  );
  assert.doesNotMatch(`${result.stdout}\n${result.stderr}`, /HostRegistry|Loaded channel map/);
});
test("a WebSocket listen failure is reported once and exits non-zero", async () => {
  const blocker = createServer();
  await new Promise((resolve, reject) => {
    blocker.once("error", reject);
    blocker.listen(0, resolve);
  });

  try {
    const { port } = blocker.address();
    const result = spawnSync(process.execPath, ["src/bot.js"], {
      cwd: botDir,
      env: startupEnv({ HOST_WS_PORT: `${port}` }),
      encoding: "utf8",
      timeout: 15_000,
    });

    assert.equal(result.status, 1);
    const fatalLines = result.stderr.trim().split(/\r?\n/).filter((line) => line.startsWith("{"));
    assert.equal(fatalLines.length, 1);
    const fatal = JSON.parse(fatalLines[0]);
    assert.equal(fatal.level, "error");
    assert.equal(fatal.event, "host_ws_listen_failed");
    assert.equal(typeof fatal.error, "string");
    assert.doesNotMatch(result.stderr, /secret-a|secret-b|definitely-invalid-token/);
  } finally {
    await new Promise((resolve) => blocker.close(resolve));
  }
});

test("a rejected Discord login is reported once and exits non-zero", () => {
  const result = spawnSync(process.execPath, ["src/bot.js"], {
    cwd: botDir,
    env: startupEnv(),
    encoding: "utf8",
    timeout: 15_000,
  });

  assert.equal(result.status, 1);
  const fatalLines = result.stderr.trim().split(/\r?\n/).filter((line) => line.startsWith("{"));
  assert.equal(fatalLines.length, 1);
  const fatal = JSON.parse(fatalLines[0]);
  assert.equal(fatal.level, "error");
  assert.equal(fatal.event, "discord_login_failed");
  assert.match(fatal.error, /invalid token/i);
  assert.doesNotMatch(result.stderr, /secret-a|secret-b|definitely-invalid-token/);
});
