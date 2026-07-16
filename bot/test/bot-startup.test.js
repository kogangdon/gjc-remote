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
