import assert from "node:assert/strict";
import test from "node:test";
import { createAuthorizationPolicy, parseRequireAllowlist } from "../src/authorization.js";

test("parseRequireAllowlist accepts only disabled and enabled values", () => {
  for (const raw of [undefined, "", "0"]) {
    assert.equal(parseRequireAllowlist(raw), false);
  }
  assert.equal(parseRequireAllowlist("1"), true);
});

test("parseRequireAllowlist rejects every other value with a config error", () => {
  for (const raw of [null, 0, 1, false, true, "  ", "00", "true", "false", "2"]) {
    assert.throws(() => parseRequireAllowlist(raw), /GJC_REMOTE_REQUIRE_ALLOWLIST.*unset.*"0".*"1"/);
  }
});

test("createAuthorizationPolicy rejects invalid allowlist inputs", () => {
  for (const allowedUsers of [undefined, null, {}, new Set(), "user-1"]) {
    assert.throws(
      () => createAuthorizationPolicy(allowedUsers, { required: false }),
      /GJC_BOT_ALLOWED_USERS.*array/
    );
  }
  assert.throws(
    () => createAuthorizationPolicy(["user-1", 2], { required: false }),
    /GJC_BOT_ALLOWED_USERS.*string user IDs/
  );
});

test("strict policy rejects an empty allowlist", () => {
  assert.throws(
    () => createAuthorizationPolicy([], { required: true }),
    /GJC_BOT_ALLOWED_USERS.*at least one user ID.*GJC_REMOTE_REQUIRE_ALLOWLIST=1/
  );
});

test("non-strict empty policy authorizes every string user ID", () => {
  const policy = createAuthorizationPolicy([], { required: false });

  assert.equal(policy.unrestricted, true);
  assert.equal(policy.isAuthorized("user-1"), true);
  assert.equal(policy.isAuthorized(""), true);
  assert.equal(policy.isAuthorized(123), false);
  assert.equal(policy.isAuthorized(undefined), false);
});

test("non-empty policy performs exact user ID matching", () => {
  const policy = createAuthorizationPolicy(["user-1", "User-2"], { required: true });

  assert.equal(policy.unrestricted, false);
  assert.equal(policy.isAuthorized("user-1"), true);
  assert.equal(policy.isAuthorized("User-2"), true);
  assert.equal(policy.isAuthorized("USER-1"), false);
  assert.equal(policy.isAuthorized("user-1 "), false);
  assert.equal(policy.isAuthorized("user-10"), false);
});

test("policy is immutable and defensively copies the allowlist", () => {
  const allowedUsers = ["user-1"];
  const policy = createAuthorizationPolicy(allowedUsers, { required: false });
  allowedUsers.push("user-2");

  assert.equal(Object.isFrozen(policy), true);
  assert.equal(policy.isAuthorized("user-2"), false);
  assert.equal("allowedUsers" in policy, false);
  assert.equal("allowedUserIds" in policy, false);
  assert.throws(() => {
    policy.unrestricted = true;
  }, TypeError);
  assert.equal(policy.unrestricted, false);
});
