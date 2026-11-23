import { createServer } from "node:net";
import { createServer as createHttpServer } from "node:http";
import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import { copyFileSync, cpSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";
import { foregroundRuntimeRefusal, nodeVersionRefusal } from "../src/runtime-policy.js";

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
  const blocker = createHttpServer();
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

    assert.equal(result.error, undefined);
    assert.equal(result.signal, null);
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

test("a service-claimed launch is refused by the bootstrap guard before dotenv or services start", () => {
  const result = spawnSync(process.execPath, ["src/bot.js"], {
    cwd: botDir,
    env: startupEnv({ GJC_REMOTE_SERVICE_COMPONENT: "bot", NODE_OPTIONS: "", NODE_PATH: "" }),
    encoding: "utf8",
    timeout: 30_000,
  });

  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /SERVICE_BOOTSTRAP_REFUSED/);
  assert.doesNotMatch(`${result.stdout}\n${result.stderr}`, /HostRegistry|Loaded channel map|Logged in/);
  assert.doesNotMatch(result.stderr, /secret-a|secret-b|definitely-invalid-token/);
});

test("foreground runtime permission uses Bun identity, exact version and Windows x64", () => {
  function bunRuntime(bun, node = "24.3.0", platform = "win32", arch = "x64") {
    return { versions: { bun, node }, version: `v${node}`, platform, arch };
  }
  for (const node of ["24.3.0", "26.0.0", "99.0.0"]) {
    const runtime = bunRuntime("1.4.5", node);
    assert.equal(foregroundRuntimeRefusal(runtime), null);
  }
  for (const bun of ["", "1.4.4", "1.4.6", "1.4.5-canary", "1.5.0"]) {
    assert.equal(foregroundRuntimeRefusal(bunRuntime(bun, "99.0.0")).event, "unsupported_bot_runtime");
  }
  for (const [platform, arch] of [["linux", "x64"], ["darwin", "arm64"], ["win32", "arm64"], ["win32", "ia32"]]) {
    assert.equal(foregroundRuntimeRefusal(bunRuntime("1.4.5", "99.0.0", platform, arch)).event, "unsupported_bot_runtime");
  }
});

test("real Node entry retains its version policy on every platform", () => {
  for (const platform of ["win32", "linux", "darwin"]) {
    for (const node of ["26.0.0", "26.2.0", "27.0.0"]) {
      const runtime = { versions: { node }, version: `v${node}`, platform, arch: "arm64" };
      assert.equal(foregroundRuntimeRefusal(runtime), null);
      assert.equal(nodeVersionRefusal(runtime), null);
    }
    for (const node of ["24.0.0", "25.9.0", "invalid", undefined]) {
      const runtime = { versions: { node }, version: `v${node}`, platform, arch: "x64" };
      assert.equal(foregroundRuntimeRefusal(runtime).event, "unsupported_node_version");
      assert.equal(nodeVersionRefusal(runtime).event, "unsupported_node_version");
    }
  }
});

test("entrypoint guards reject injected unsupported identities before application evaluation", () => {
  const cases = [
    ["bot.js", { node: "24.0.0" }, "unsupported_node_version"],
    ["bot.js", { node: "99.0.0", bun: "1.4.6" }, "unsupported_bot_runtime"],
    ["management-entrypoint.js", { node: "24.0.0" }, "unsupported_node_version"],
    ["register-commands.js", { node: "24.0.0" }, "unsupported_node_version"],
    ["management-entrypoint.js", { node: "24.0.0", bun: "1.4.5" }, "unsupported_node_version"],
    ["register-commands.js", { node: "24.0.0", bun: "1.4.5" }, "unsupported_node_version"],
  ];
  for (const [entrypoint, versions, event] of cases) {
    const script = `
      for (const [key, value] of Object.entries(${JSON.stringify(versions)})) {
        Object.defineProperty(process.versions, key, { value, configurable: true });
      }
      await import(${JSON.stringify(new URL(`../src/${entrypoint}`, import.meta.url).href)});
    `;
    // Start with a Node identity for every synthetic case. A Bun parent
    // would otherwise leave versions.bun present even in the Node-only case.
    const result = spawnSync("node", ["--input-type=module", "-e", script], {
      cwd: botDir,
      env: startupEnv({ GJC_REMOTE_REQUIRE_ALLOWLIST: "1", GJC_BOT_ALLOWED_USERS: "" }),
      encoding: "utf8",
      timeout: 10_000,
    });
    assert.ifError(result.error);
    assert.equal(result.status, 1, `${entrypoint}: ${result.stderr}`);
    assert.equal(result.stdout, "");
    const fatal = JSON.parse(result.stderr.trim());
    assert.equal(fatal.level, "error");
    assert.equal(fatal.event, event);
    assert.doesNotMatch(result.stderr, /secret-a|secret-b|definitely-invalid-token|Invalid bot environment configuration/);
  }
});

const windowsForegroundSkip = process.env.GJC_REMOTE_BOT_WINDOWS_FOREGROUND_E2E === "1"
  ? false
  : "Set GJC_REMOTE_BOT_WINDOWS_FOREGROUND_E2E=1 on Windows x64 with Bun 1.4.5 for launcher coverage.";

function runWindowsForegroundLauncher({ dotenv, env = {} }) {
  assert.equal(process.platform, "win32", "Windows foreground E2E requires Windows.");
  assert.equal(process.arch, "x64", "Windows foreground E2E requires x64.");
  assert.equal(process.versions.bun, undefined, "Run launcher coverage with real Node, not Bun.");
  const npmCli = process.env.npm_execpath;
  assert.match(npmCli ?? "", /(?:^|[\\/])(?:npm-cli|npm)\.js$/i,
    "Run launcher coverage through npm exec --workspace bot -- node --test test/bot-startup.test.js.");
  const directory = mkdtempSync(join(botDir, ".startup-windows-"));
  try {
    cpSync(join(botDir, "src"), join(directory, "src"), { recursive: true });
    copyFileSync(join(botDir, "package.json"), join(directory, "package.json"));
    writeFileSync(join(directory, ".env"), [
      "DISCORD_TOKEN=dotenv-launcher-secret",
      "HOST_TOKENS=prod-1:dotenv-host-secret",
      ...dotenv,
      "",
    ].join("\n"));
    writeFileSync(join(directory, ".env.local"), [
      "DISCORD_TOKEN=local-launcher-secret",
      "HOST_TOKENS=prod-1:local-host-secret",
      "GJC_REMOTE_REQUIRE_ALLOWLIST=0",
      "GJC_BOT_ALLOWED_USERS=123456789012345678",
      "",
    ].join("\n"));
    const cleanEnv = Object.fromEntries(Object.entries(process.env).filter(([key]) =>
      !/^(GJC_|DISCORD_|HOST_|CHANNELS_CONFIG$|DOTENV_|BUN_|NODE_ENV$|NODE_OPTIONS$|NODE_PATH$|NPM_CONFIG_)/i.test(key)
    ));
    const childEnv = { ...cleanEnv, NODE_OPTIONS: "", NODE_PATH: "", ...env };
    const bunVersion = spawnSync("bun", ["--version"], {
      cwd: directory,
      env: childEnv,
      encoding: "utf8",
      timeout: 10_000,
    });
    assert.ifError(bunVersion.error);
    assert.equal(bunVersion.status, 0, bunVersion.stderr);
    assert.equal(bunVersion.stdout.trim(), "1.4.5", "Windows foreground E2E requires Bun 1.4.5 on PATH.");
    // A real Node parent runs npm's actual CLI, never `bun run`/`bun x`, so
    // neither parent nor child can preload .env.local before dotenv/config.
    return spawnSync(process.execPath, [npmCli, "--prefix", directory, "run", "start:windows"], {
      cwd: directory,
      env: childEnv,
      encoding: "utf8",
      timeout: 30_000,
    });
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
}

test("Windows npm launcher uses dotenv .env and ignores conflicting .env.local allowlist settings", {
  skip: windowsForegroundSkip,
}, () => {
  const cases = [
    { dotenv: ["GJC_REMOTE_REQUIRE_ALLOWLIST=1", "GJC_BOT_ALLOWED_USERS="] },
    {
      dotenv: ["GJC_REMOTE_REQUIRE_ALLOWLIST=0", "GJC_BOT_ALLOWED_USERS=123456789012345678"],
      env: { GJC_REMOTE_REQUIRE_ALLOWLIST: "1", GJC_BOT_ALLOWED_USERS: " " },
    },
  ];
  for (const options of cases) {
    const result = runWindowsForegroundLauncher(options);
    assert.ifError(result.error);
    assert.equal(result.status, 1, result.stderr);
    assert.match(result.stderr, /Invalid bot environment configuration:.*GJC_BOT_ALLOWED_USERS.*GJC_REMOTE_REQUIRE_ALLOWLIST=1/);
    assert.doesNotMatch(`${result.stdout}\n${result.stderr}`, /HostRegistry|Loaded channel map|Logged in|SECURITY WARNING/);
    assert.doesNotMatch(result.stderr, /dotenv-launcher-secret|dotenv-host-secret|local-launcher-secret|local-host-secret/);
  }
});

test("Windows Bun foreground permission does not authorize a claimed service launch", {
  skip: windowsForegroundSkip,
}, () => {
  const result = runWindowsForegroundLauncher({
    dotenv: ["GJC_REMOTE_REQUIRE_ALLOWLIST=1", "GJC_BOT_ALLOWED_USERS="],
    env: { GJC_REMOTE_SERVICE_COMPONENT: "bot" },
  });
  assert.ifError(result.error);
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /SERVICE_BOOTSTRAP_REFUSED/);
  assert.doesNotMatch(`${result.stdout}\n${result.stderr}`, /Invalid bot environment configuration|HostRegistry|Loaded channel map|Logged in/);
  assert.doesNotMatch(result.stderr, /dotenv-launcher-secret|dotenv-host-secret|local-launcher-secret|local-host-secret/);
});
