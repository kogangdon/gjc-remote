import assert from "node:assert/strict";
import test from "node:test";
import {
  loadChannelMapState,
  parseAllowedUsers,
  parseChannelMap,
  parseHostTokens,
  validateChannelHosts,
} from "../src/config.js";

test("parseChannelMap normalizes POSIX and Windows routes and omits _comment", () => {
  const raw = {
    _comment: "example routes",
    "123": { hostId: " posix-host ", workDir: " /srv/project " },
    "456": { hostId: " windows-host ", workDir: String.raw` C:\work\project ` },
  };

  assert.deepEqual(parseChannelMap(raw), {
    "123": { hostId: "posix-host", workDir: "/srv/project" },
    "456": { hostId: "windows-host", workDir: String.raw`C:\work\project` },
  });
});

test("parseChannelMap returns fresh objects without mutating its input", () => {
  const route = { hostId: " host ", workDir: " /workspace " };
  const raw = { "123": route };

  const parsed = parseChannelMap(raw);

  assert.notEqual(parsed, raw);
  assert.notEqual(parsed["123"], route);
  assert.deepEqual(raw, { "123": { hostId: " host ", workDir: " /workspace " } });
  parsed["123"].hostId = "changed";
  assert.equal(route.hostId, " host ");
});

test("parseChannelMap rejects malformed top-level values", () => {
  for (const raw of [null, [], "routes"]) {
    assert.throws(() => parseChannelMap(raw), {
      name: "TypeError",
      message: /CHANNEL_MAP.*plain object/,
    });
  }
  assert.throws(() => parseChannelMap({ _comment: 123 }), {
    name: "TypeError",
    message: /CHANNEL_MAP.*_comment.*string/,
  });
});

test("parseChannelMap rejects malformed routes", () => {
  for (const route of [null, [], "route"]) {
    assert.throws(() => parseChannelMap({ "123": route }), {
      name: "TypeError",
      message: /CHANNEL_MAP route "123".*plain object/,
    });
  }
});

test("parseChannelMap requires exactly the route fields", () => {
  assert.throws(
    () => parseChannelMap({ "123": { hostId: "host" } }),
    /CHANNEL_MAP route "123".*exactly hostId and workDir/
  );
  assert.throws(
    () =>
      parseChannelMap({
        "123": { hostId: "host", workDir: "/work", extra: true },
      }),
    /CHANNEL_MAP route "123".*exactly hostId and workDir/
  );
});

test("parseChannelMap rejects empty route values and relative workDir", () => {
  assert.throws(
    () => parseChannelMap({ "123": { hostId: "  ", workDir: "/work" } }),
    /CHANNEL_MAP route "123" hostId.*empty/
  );
  assert.throws(
    () => parseChannelMap({ "123": { hostId: "host", workDir: "  " } }),
    /CHANNEL_MAP route "123" workDir.*empty/
  );
  assert.throws(
    () => parseChannelMap({ "123": { hostId: "host", workDir: "relative/path" } }),
    /CHANNEL_MAP route "123" workDir.*absolute/
  );
});

test("parseChannelMap rejects non-decimal channel keys", () => {
  assert.throws(
    () => parseChannelMap({ "channel-123": { hostId: "host", workDir: "/work" } }),
    /CHANNEL_MAP route key "channel-123".*decimal Discord ID/
  );
});

test("parseHostTokens returns an empty Map for empty input", () => {
  assert.deepEqual(parseHostTokens(""), new Map());
  assert.deepEqual(parseHostTokens("  \t\n  "), new Map());
});

test("parseHostTokens trims entries and preserves colons in tokens", () => {
  assert.deepEqual(
    parseHostTokens(" host-one : token:with:colons , host-two: second-token "),
    new Map([
      ["host-one", "token:with:colons"],
      ["host-two", "second-token"],
    ])
  );
});

test("parseHostTokens rejects malformed entries without exposing their contents", () => {
  const secret = "malformed-secret";

  assert.throws(() => parseHostTokens(secret), (error) => {
    assert.match(error.message, /HOST_TOKENS entry 1.*malformed/);
    assert.doesNotMatch(error.message, new RegExp(secret));
    return true;
  });
});

test("parseHostTokens rejects empty fields without exposing token values", () => {
  const secret = "secret-token-value";

  assert.throws(() => parseHostTokens(`:${secret}`), (error) => {
    assert.match(error.message, /HOST_TOKENS entry 1.*empty host ID/);
    assert.doesNotMatch(error.message, new RegExp(secret));
    return true;
  });
  assert.throws(() => parseHostTokens("host:"), /HOST_TOKENS entry 1.*empty token/);
});

test("parseHostTokens rejects duplicate hosts without exposing token values", () => {
  const firstSecret = "first-secret";
  const secondSecret = "second-secret";

  assert.throws(() => parseHostTokens(`host:${firstSecret},host:${secondSecret}`), (error) => {
    assert.match(error.message, /HOST_TOKENS entry 2.*duplicate host ID/);
    assert.doesNotMatch(error.message, new RegExp(`${firstSecret}|${secondSecret}`));
    return true;
  });
});

test("parseAllowedUsers returns an empty array for empty input", () => {
  assert.deepEqual(parseAllowedUsers(""), []);
  assert.deepEqual(parseAllowedUsers("  \t\n  "), []);
});

test("parseAllowedUsers trims and deduplicates in first-occurrence order", () => {
  assert.deepEqual(parseAllowedUsers(" 123,456,123, 789 ,456 "), [
    "123",
    "456",
    "789",
  ]);
});

test("parseAllowedUsers rejects invalid and empty entries", () => {
  assert.throws(
    () => parseAllowedUsers("123,user-456"),
    /ALLOWED_USERS entry 2.*decimal Discord ID/
  );
  assert.throws(
    () => parseAllowedUsers("123,,456"),
    /ALLOWED_USERS entry 2.*empty/
  );
});

test("validateChannelHosts rejects unmapped credentials and allows unused tokens", () => {
  const channelMap = {
    "123": { hostId: "known", workDir: "/work" },
  };
  const tokens = new Map([
    ["known", "token"],
    ["unused", "other-token"],
  ]);

  assert.doesNotThrow(() => validateChannelHosts(channelMap, tokens));
  assert.throws(
    () => validateChannelHosts(channelMap, new Map([["other", "token"]])),
    /route "123".*unknown hostId "known"/
  );
});

test("loadChannelMapState swaps only fully valid replacements", () => {
  const current = {
    "123": { hostId: "known", workDir: "/old" },
  };
  const valid = loadChannelMapState({
    current,
    readText: () => JSON.stringify({ "456": { hostId: "known", workDir: "/new" } }),
    validate: (next) => validateChannelHosts(next, new Map([["known", "token"]])),
  });

  assert.equal(valid.ok, true);
  assert.deepEqual(valid.map, {
    "456": { hostId: "known", workDir: "/new" },
  });
  assert.notEqual(valid.map, current);

  for (const readText of [
    () => "{",
    () => JSON.stringify({ "456": { hostId: "missing", workDir: "/new" } }),
  ]) {
    const invalid = loadChannelMapState({
      current: valid.map,
      readText,
      validate: (next) => validateChannelHosts(next, new Map([["known", "token"]])),
    });

    assert.equal(invalid.ok, false);
    assert.equal(invalid.map, valid.map);
    assert.ok(invalid.error instanceof Error);
  }
});

test("loadChannelMapState reports startup failure without inventing a map", () => {
  const result = loadChannelMapState({
    current: undefined,
    readText: () => "[]",
  });

  assert.equal(result.ok, false);
  assert.equal(result.map, undefined);
  assert.match(result.error.message, /CHANNEL_MAP.*plain object/);
});
