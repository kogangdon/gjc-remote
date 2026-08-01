import { createServer } from "node:net";
import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import test from "node:test";

const botDir = fileURLToPath(new URL("..", import.meta.url));
const botEntryUrl = new URL("../src/bot.js", import.meta.url).href;
function findFreePort() {
  const server = createServer();
  server.listen(0);
  const { port } = server.address();
  server.close();
  return `${port}`;
}

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
    HOST_WS_PORT: findFreePort(),
    ...overrides,
  };
}
test("invalid HOST_WS_PORT values produce one sanitized structured startup error", () => {
  for (const HOST_WS_PORT of ["NaN", "1.5", "0", "-1", "65536", "Infinity", "not-a-port"]) {
    const result = spawnSync(process.execPath, ["src/bot.js"], {
      cwd: botDir,
      env: startupEnv({ HOST_WS_PORT }),
      encoding: "utf8",
      timeout: 10_000,
    });

    assert.equal(result.status, 1, `expected HOST_WS_PORT=${HOST_WS_PORT} to fail`);
    const fatalLines = result.stderr.trim().split(/\r?\n/).filter((line) => line.startsWith("{"));
    assert.equal(fatalLines.length, 1, `expected one structured error for HOST_WS_PORT=${HOST_WS_PORT}`);
    const fatal = JSON.parse(fatalLines[0]);
    assert.deepEqual(
      { level: fatal.level, event: fatal.event },
      { level: "error", event: "host_ws_port_invalid" }
    );
    assert.match(fatal.error, /HOST_WS_PORT must be an integer between 1 and 65535/);
    assert.doesNotMatch(result.stderr, /secret-a|secret-b|definitely-invalid-token/);
    assert.doesNotMatch(result.stderr, /HostRegistry/);
  }
});

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
test("a signal-initiated shutdown keeps exit 0 when a fatal event follows", async () => {
  const script = `
    import { Client } from "discord.js";
    let rejectLogin;
    const originalProcessOn = process.on;
    const signalHandlers = new Map();
    process.on = function (event, handler) {
      if (event === "SIGINT" || event === "SIGTERM") {
        signalHandlers.set(event, handler);
        return this;
      }
      return originalProcessOn.call(this, event, handler);
    };
    Client.prototype.login = () => new Promise((_, reject) => {
      rejectLogin = reject;
    });
    Client.prototype.destroy = () => new Promise((resolve) => setTimeout(resolve, 250));
    await import(${JSON.stringify(botEntryUrl)});
    process.on = originalProcessOn;
    signalHandlers.get("SIGTERM")();
    setTimeout(() => rejectLogin(new Error("fatal after signal definitely-invalid-token")), 25);
  `;
  const child = spawn(process.execPath, ["--input-type=module", "-e", script], {
    cwd: botDir,
    env: startupEnv({ HOST_WS_PORT: findFreePort() }),
    stdio: ["ignore", "pipe", "pipe"],
  });
  let stderr = "";
  child.stderr.setEncoding("utf8");
  child.stderr.on("data", (chunk) => {
    stderr += chunk;
  });
  const result = await new Promise((resolve, reject) => {
    const timer = setTimeout(() => {
      child.kill("SIGKILL");
      reject(new Error("signal ordering child did not exit"));
    }, 5_000);
    child.once("error", reject);
    child.once("close", (code, signal) => {
      clearTimeout(timer);
      resolve({ code, signal });
    });
  });

  assert.equal(result.code, 0, `child exited with signal ${result.signal}: ${stderr}`);
  const fatalLines = stderr.trim().split(/\r?\n/).filter((line) => line.startsWith("{"));
  assert.equal(fatalLines.length, 1);
  const fatal = JSON.parse(fatalLines[0]);
  assert.equal(fatal.event, "discord_login_failed");
  assert.doesNotMatch(stderr, /definitely-invalid-token/);
});
