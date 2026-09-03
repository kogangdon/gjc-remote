import assert from "node:assert/strict";
import { mkdtemp, mkdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { V0_LIMITS } from "@gjc-remote/shared";
import {
  DaemonConfigError,
  resolveDaemonConnectionConfig,
} from "../src/daemon-config.js";

function connectionEnv(overrides = {}) {
  return {
    HOST_ID: "daemon-1",
    HOST_TOKEN: "environment-token",
    HOST_LABEL: "Daemon one",
    BOT_WS_URL: "wss://bot.example.test/daemon",
    ...overrides,
  };
}

async function assertInvalid(promise, secretValues = []) {
  await assert.rejects(promise, (error) => {
    assert.ok(error instanceof DaemonConfigError);
    assert.deepEqual(Object.keys(error), ["code", "operation"]);
    assert.deepEqual(
      { ...error },
      {
        code: "CONFIG_INVALID",
        operation: "resolve_daemon_connection_config",
      },
    );
    for (const secret of secretValues) {
      assert.equal(error.message.includes(secret), false);
      assert.equal(error.stack.includes(secret), false);
    }
    return true;
  });
}

test("resolves a bounded environment token for native deployment", async () => {
  const config = await resolveDaemonConnectionConfig({
    env: connectionEnv(),
    readFile: () => assert.fail("environment token must not read a file"),
  });

  assert.deepEqual(config, {
    hostId: "daemon-1",
    token: "environment-token",
    hostLabel: "Daemon one",
    botWsUrl: "wss://bot.example.test/daemon",
  });
  assert.equal(Object.isFrozen(config), true);
  assert.equal(Object.getPrototypeOf(config), Object.prototype);
});

test("resolves a file token after exactly one terminal LF or CRLF", async (t) => {
  for (const [suffix, token] of [["\n", "lf-token"], ["\r\n", "crlf-token"]]) {
    await t.test(JSON.stringify(suffix), async () => {
      const path = "/run/secrets/daemon-token";
      const config = await resolveDaemonConnectionConfig({
        env: connectionEnv({ HOST_TOKEN: undefined, HOST_TOKEN_FILE: path }),
        async readFile(actualPath, maxBytes) {
          assert.equal(actualPath, path);
          assert.equal(maxBytes, V0_LIMITS.TOKEN * 4 + 2);
          return new TextEncoder().encode(`${token}${suffix}`);
        },
      });
      assert.equal(config.token, token);
    });
  }
});

test("file and environment tokens accept the same multibyte string domain", async () => {
  const token = "é".repeat(V0_LIMITS.TOKEN);
  const fromEnvironment = await resolveDaemonConnectionConfig({
    env: connectionEnv({ HOST_TOKEN: token }),
  });
  const fromFile = await resolveDaemonConnectionConfig({
    env: connectionEnv({
      HOST_TOKEN: undefined,
      HOST_TOKEN_FILE: "/run/secrets/daemon-token",
    }),
    readFile: async () => new TextEncoder().encode(`${token}\r\n`),
  });
  assert.equal(fromEnvironment.token, token);
  assert.equal(fromFile.token, token);
});

test("default token reader accepts only bounded regular files", async (t) => {
  const root = await mkdtemp(join(tmpdir(), "gjc-daemon-config-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  const tokenFile = join(root, "host-token");
  await writeFile(tokenFile, "file-secret\n", { mode: 0o600 });

  const config = await resolveDaemonConnectionConfig({
    env: connectionEnv({
      HOST_TOKEN: undefined,
      HOST_TOKEN_FILE: tokenFile,
    }),
  });
  assert.equal(config.token, "file-secret");

  const directory = join(root, "not-a-file");
  await mkdir(directory);
  await assertInvalid(
    resolveDaemonConnectionConfig({
      env: connectionEnv({
        HOST_TOKEN: undefined,
        HOST_TOKEN_FILE: directory,
      }),
    }),
    [directory],
  );
});

test("rejects absent or competing token sources without leaking either value", async (t) => {
  await t.test("none", async () => {
    await assertInvalid(
      resolveDaemonConnectionConfig({
        env: connectionEnv({ HOST_TOKEN: undefined }),
      }),
    );
  });
  await t.test("both", async () => {
    const token = "environment-secret";
    const path = "/run/secrets/daemon-token";
    await assertInvalid(
      resolveDaemonConnectionConfig({
        env: connectionEnv({ HOST_TOKEN: token, HOST_TOKEN_FILE: path }),
      }),
      [token, path],
    );
  });
});

test("rejects a relative token-file path without reading it", async () => {
  await assertInvalid(
    resolveDaemonConnectionConfig({
      env: connectionEnv({ HOST_TOKEN: undefined, HOST_TOKEN_FILE: "secrets/token" }),
      readFile: () => assert.fail("relative path must not be read"),
    }),
    ["secrets/token"],
  );
});

test("rejects an oversized file token while requesting only the limit plus one byte", async () => {
  const path = "/run/secrets/oversized-token";
  await assertInvalid(
    resolveDaemonConnectionConfig({
      env: connectionEnv({ HOST_TOKEN: undefined, HOST_TOKEN_FILE: path }),
      async readFile(actualPath, maxBytes) {
        assert.equal(actualPath, path);
        assert.equal(maxBytes, V0_LIMITS.TOKEN * 4 + 2);
        return new Uint8Array(maxBytes + 1);
      },
    }),
    [path],
  );
});

test("rejects malformed UTF-8 and token-file whitespace or controls", async (t) => {
  const path = "/run/secrets/daemon-token";
  const invalidValues = [
    new Uint8Array([0xc3, 0x28]),
    new TextEncoder().encode(" leading"),
    new TextEncoder().encode("trailing "),
    new TextEncoder().encode("token\t"),
    new TextEncoder().encode("token\n\n"),
  ];

  for (const value of invalidValues) {
    await t.test(`bytes ${Array.from(value).join(",")}`, async () => {
      await assertInvalid(
        resolveDaemonConnectionConfig({
          env: connectionEnv({ HOST_TOKEN: undefined, HOST_TOKEN_FILE: path }),
          readFile: async () => value,
        }),
        [path],
      );
    });
  }
});

test("rejects invalid host and environment token protocol values", async (t) => {
  for (const [name, env] of [
    ["host control", connectionEnv({ HOST_ID: "daemon\u0000one" })],
    ["host oversize", connectionEnv({ HOST_ID: "x".repeat(V0_LIMITS.HOST_ID + 1) })],
    ["token control", connectionEnv({ HOST_TOKEN: "token\u007fvalue" })],
    ["token oversize", connectionEnv({ HOST_TOKEN: "x".repeat(V0_LIMITS.TOKEN + 1) })],
  ]) {
    await t.test(name, async () => {
      await assertInvalid(resolveDaemonConnectionConfig({ env }));
    });
  }
});

test("rejects missing required host ID or bot websocket URL", async (t) => {
  for (const [name, env] of [
    ["host ID", connectionEnv({ HOST_ID: "" })],
    ["bot websocket URL", connectionEnv({ BOT_WS_URL: "" })],
  ]) {
    await t.test(name, async () => {
      await assertInvalid(resolveDaemonConnectionConfig({ env }));
    });
  }
});
