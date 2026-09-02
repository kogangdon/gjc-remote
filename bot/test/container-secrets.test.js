import assert from "node:assert/strict";
import test from "node:test";

import { resolveBotSecrets } from "../src/container-secrets.js";

function reader(files) {
  return (path) => {
    if (!Object.hasOwn(files, path)) {
      const error = new Error("missing secret");
      error.code = "ENOENT";
      throw error;
    }
    return files[path];
  };
}

test("direct environment secrets remain supported", () => {
  assert.deepEqual(resolveBotSecrets({
    env: { DISCORD_TOKEN: "discord", HOST_TOKENS: "host:token" },
  }), {
    DISCORD_TOKEN: "discord",
    HOST_TOKENS: "host:token",
  });
});

test("Docker secret files resolve one UTF-8 line and strip one final newline", () => {
  assert.deepEqual(resolveBotSecrets({
    env: {
      DISCORD_TOKEN_FILE: "/run/secrets/discord",
      HOST_TOKENS_FILE: "/run/secrets/hosts",
    },
    readFileSync: reader({
      "/run/secrets/discord": Buffer.from("discord\n"),
      "/run/secrets/hosts": Buffer.from("host:token\n"),
    }),
  }), {
    DISCORD_TOKEN: "discord",
    HOST_TOKENS: "host:token\n",
  });
});

test("HOST_TOKENS_FILE preserves managed LF-delimited host records", () => {
  const value = "host-a=token-a\nhost-b=token-b\n";
  assert.equal(resolveBotSecrets({
    env: { HOST_TOKENS_FILE: "/run/secrets/hosts" },
    readFileSync: reader({
      "/run/secrets/hosts": Buffer.from(value),
    }),
  }).HOST_TOKENS, value);
});

test("HOST_TOKENS_FILE preserves LF but rejects CRLF managed records", () => {
  assert.throws(() => resolveBotSecrets({
    env: { HOST_TOKENS_FILE: "/run/secrets/hosts" },
    readFileSync: reader({
      "/run/secrets/hosts": Buffer.from("host=token\r\n"),
    }),
  }), /invalid text/);
});

test("DISCORD_TOKEN_FILE rejects multiline content", () => {
  assert.throws(() => resolveBotSecrets({
    env: { DISCORD_TOKEN_FILE: "/run/secrets/discord" },
    readFileSync: reader({
      "/run/secrets/discord": Buffer.from("first\nsecond"),
    }),
  }), /exactly one non-empty line/);
});

test("direct and file forms are mutually exclusive without leaking values", () => {
  const secret = "do-not-leak";
  assert.throws(
    () => resolveBotSecrets({
      env: { DISCORD_TOKEN: secret, DISCORD_TOKEN_FILE: "/secret/path" },
    }),
    (error) => {
      assert.match(error.message, /set only one/);
      assert.doesNotMatch(error.message, new RegExp(secret));
      assert.doesNotMatch(error.message, /\/secret\/path/);
      return true;
    }
  );
});

test("unreadable, oversized, malformed UTF-8, empty, and multiline files fail closed", () => {
  const cases = [
    {},
    { "/secret": new Uint8Array(64 * 1024 + 1) },
    { "/secret": new Uint8Array([0xff]) },
    { "/secret": Buffer.from("\n") },
    { "/secret": Buffer.from("first\rsecond") },
    { "/secret": Buffer.from("nul\0byte") },
  ];
  for (const files of cases) {
    assert.throws(
      () => resolveBotSecrets({
        env: { HOST_TOKENS_FILE: "/secret" },
        readFileSync: reader(files),
      }),
      (error) => {
        assert.match(error.message, /HOST_TOKENS/);
        assert.doesNotMatch(error.message, /\/secret/);
        return true;
      }
    );
  }
});

test("empty direct values preserve existing required-secret handling", () => {
  assert.deepEqual(resolveBotSecrets({
    env: { DISCORD_TOKEN: "", HOST_TOKENS: "" },
  }), {
    DISCORD_TOKEN: "",
    HOST_TOKENS: "",
  });
});
