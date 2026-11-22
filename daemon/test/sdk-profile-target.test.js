import test from "node:test";
import assert from "node:assert/strict";
import { createSdkProfileTarget, SdkProfileTargetError } from "../src/sdk-profile-target.js";

const fileId = digit => `win32:${digit.repeat(16)}:${digit.repeat(32)}:${digit.repeat(16)}`;
const original = Object.freeze({
  agentDir: "C:\\Users\\fixture-manager\\.gjc\\agent",
  credentialPath: "C:\\Users\\fixture-manager\\.gjc\\agent\\agent.db",
  recipient: "S-1-5-80-100-200-300-400-500",
  configIdentity: fileId("1"),
  credentialIdentity: fileId("2"),
});

// Model the opaque native contract, not a Windows ACL/reparse proof. These
// fixtures never load the SDK, resolve a real home, or open credential files.
function fixture() {
  const authority = Object.freeze({});
  const calls = [];
  const handles = new Map();
  const state = {
    profile: { ...original },
    configPresent: false,
    recipient: original.recipient,
    targetValid: true,
    credentialOpens: 0,
  };
  function refuse(reason) {
    throw Object.assign(new Error(reason), {
      code: "ERR_SDK_PROFILE_TARGET_REFUSED",
      reason,
    });
  }
  function lease(handle) {
    const value = handles.get(handle);
    if (!value || value.closed) refuse("target-closed");
    return value;
  }
  function validate() {
    if (state.configPresent) refuse("existing-auth-config-unsupported");
    if (!state.targetValid) refuse("unsupported-target-object");
    if (state.recipient !== original.recipient) refuse("recipient-identity-changed");
  }
  const native = {
    open_sdk_profile_target(...args) {
      calls.push(["open", ...args]);
      if (args.length !== 1 || args[0] !== authority) {
        refuse("verified-bootstrap-authority-unavailable");
      }
      validate();
      state.credentialOpens++;
      const handle = Object.freeze({});
      handles.set(handle, { profile: { ...state.profile }, closed: false });
      return handle;
    },
    sdk_profile_target_facts(handle) {
      calls.push(["facts", handle]);
      return {
        layout: "win32-gjc-sqlite-only-v1",
        managementHome: "C:\\Users\\fixture-manager",
        managerIdentity: "S-1-5-21-100-200-300-1001",
        profile: { ...lease(handle).profile },
      };
    },
    assert_sdk_profile_target(handle) {
      calls.push(["assert", handle]);
      lease(handle);
      validate();
    },
    close_sdk_profile_target(handle) {
      calls.push(["close", handle]);
      lease(handle).closed = true;
    },
  };
  const target = (options = {}) => createSdkProfileTarget({
    native,
    authority,
    platform: "win32",
    env: {},
    ...options,
  });
  return { authority, calls, handles, native, state, target };
}

function refused(reason) {
  return error => error.code === "ERR_SDK_PROFILE_TARGET_REFUSED" && error.reason === reason;
}

test("selection uses opaque bootstrap authority, not HOME or a caller path", () => {
  const f = fixture();
  const env = {};
  for (const key of ["HOME", "USERPROFILE"]) {
    Object.defineProperty(env, key, {
      enumerable: true,
      get() { throw new Error("environment home was consulted"); },
    });
  }
  const lease = f.target({ env }).prepare();
  assert.deepEqual(lease.profile, original);
  assert.deepEqual(f.calls[0], ["open", f.authority]);
  assert.equal(Object.isFrozen(lease), true);
  assert.equal(Object.isFrozen(lease.profile), true);
  lease.close();
});

test("missing or fabricated authority never qualifies a target", () => {
  const f = fixture();
  for (const authority of [null, undefined, true, { enabled: true }]) {
    assert.throws(() => f.target({ authority }).prepare(),
      refused("verified-bootstrap-authority-unavailable"));
  }
  assert.equal(f.state.credentialOpens, 0);
});

test("unsupported platforms and unavailable native proofs refuse before opening", () => {
  const f = fixture();
  for (const platform of ["linux", "darwin"]) {
    assert.throws(() => f.target({ platform }).prepare(), refused("unsupported-platform"));
  }
  assert.throws(() => f.target({ native: {} }).prepare(),
    refused("verified-bootstrap-authority-unavailable"));
  assert.equal(f.calls.length, 0);
});

test("broker and directory override presence refuses without reading override values", () => {
  for (const key of [
    "GJC_CONFIG_DIR", "PI_CONFIG_DIR", "GJC_CODING_AGENT_DIR", "PI_CODING_AGENT_DIR",
    "GJC_AUTH_BROKER_URL", "GJC_AUTH_BROKER_TOKEN", "gjc_auth_broker_token",
  ]) {
    const f = fixture();
    const env = {};
    Object.defineProperty(env, key, {
      enumerable: true,
      get() { throw new Error("override or token content was read"); },
    });
    assert.throws(() => f.target({ env }).prepare(), refused("sdk-storage-override"));
    assert.equal(f.calls.length, 0);
  }
  const f = fixture();
  assert.throws(() => f.target({ env: { GJC_AUTH_BROKER_URL: "" } }).prepare(),
    refused("sdk-storage-override"));
});

test("existing configuration and unverified objects refuse before credential open", () => {
  for (const change of [{ configPresent: true }, { targetValid: false }]) {
    const f = fixture();
    Object.assign(f.state, change);
    assert.throws(() => f.target().prepare(), error =>
      error.code === "ERR_SDK_PROFILE_TARGET_REFUSED");
    assert.equal(f.state.credentialOpens, 0);
  }
});

test("reopen compares recipient and both physical identities, not just paths", () => {
  for (const change of [
    { configIdentity: fileId("3") },
    { credentialIdentity: fileId("4") },
    { recipient: "S-1-5-80-999-200-300-400-500" },
  ]) {
    const f = fixture();
    Object.assign(f.state.profile, change);
    assert.throws(() => f.target().reopen(original), refused("profile-identity-changed"));
    assert.equal(f.calls.at(-1)[0], "close");
    assert.equal([...f.handles.values()].every(handle => handle.closed), true);
  }
  const f = fixture();
  const reopened = f.target().reopen({ ...original });
  assert.deepEqual(reopened.profile, original);
  reopened.close();
});

test("untrusted reopen data cannot supply a home, alternate store, or accessor", () => {
  const f = fixture();
  const accessor = { ...original };
  Object.defineProperty(accessor, "agentDir", {
    enumerable: true,
    get() { throw new Error("caller accessor evaluated"); },
  });
  for (const profile of [
    { ...original, managementHome: "C:\\other" },
    { ...original, agentDir: "..\\other" },
    { ...original, credentialPath: "C:\\other\\agent.db" },
    { ...original, credentialIdentity: "path-only" },
    { ...original, agentDir: "C:\\Users\\fixture-manager\\.gjc\\agent." },
    accessor,
  ]) {
    assert.throws(() => f.target().reopen(profile), refused("invalid-target-evidence"));
  }
  assert.equal(f.calls.length, 0);
});

test("native evidence outside the OS-bound home is rejected and pins are released", () => {
  const f = fixture();
  f.state.profile.agentDir = "C:\\Users\\other\\.gjc\\agent";
  f.state.profile.credentialPath = `${f.state.profile.agentDir}\\agent.db`;
  assert.throws(() => f.target().prepare(), refused("profile-outside-authenticated-home"));
  assert.equal(f.calls.at(-1)[0], "close");
});

test("configuration created after selection refuses open/reopen and cannot redirect the snapshot", () => {
  const f = fixture();
  const target = f.target();
  const selected = target.prepare();
  f.state.configPresent = true;
  assert.throws(() => selected.assertCurrent(), refused("existing-auth-config-unsupported"));
  assert.throws(() => target.reopen(selected.profile), refused("existing-auth-config-unsupported"));
  assert.equal(f.state.credentialOpens, 1);
  assert.equal(selected.startupAuthConfig.broker, null);
  assert.equal(selected.startupAuthConfig.credentialStoreIdentity, `local:${original.credentialPath}`);
  assert.equal(Object.isFrozen(selected.startupAuthConfig), true);
  selected.close();
});

test("failed close leaves the live lease retryable instead of losing its pins", () => {
  const f = fixture();
  const selected = f.target().prepare();
  const close = f.native.close_sdk_profile_target;
  const failure = new Error("close failed");
  f.native.close_sdk_profile_target = () => { throw failure; };
  assert.throws(() => selected.close(), error => {
    assert.ok(error instanceof SdkProfileTargetError);
    assert.equal(error.code, "ERR_SDK_PROFILE_TARGET_REFUSED");
    assert.equal(error.reason, "target-close-failed");
    assert.strictEqual(error.cause, failure);
    return true;
  });
  assert.equal([...f.handles.values()].some(handle => !handle.closed), true);
  selected.assertCurrent();
  f.native.close_sdk_profile_target = close;
  selected.close();
  assert.equal([...f.handles.values()].every(handle => handle.closed), true);
});

test("recipient changes and later environment overrides invalidate a retained lease", () => {
  const f = fixture();
  const env = {};
  const selected = f.target({ env }).prepare();
  f.state.recipient = "S-1-5-21-999-999-999-1001";
  assert.throws(() => selected.assertCurrent(), refused("recipient-identity-changed"));
  f.state.recipient = original.recipient;
  env.GJC_CODING_AGENT_DIR = "C:\\other";
  assert.throws(() => selected.assertCurrent(), refused("sdk-storage-override"));
  selected.close();
});

test("pins live until explicit post-disposal close; closing twice does not close twice", () => {
  const f = fixture();
  const selected = f.target().prepare();
  selected.assertCurrent();
  assert.equal(f.calls.filter(call => call[0] === "close").length, 0);
  selected.close();
  selected.close();
  assert.equal(f.calls.filter(call => call[0] === "close").length, 1);
  assert.throws(() => selected.assertCurrent(), refused("target-closed"));
});

test("verification failure reports a failed pin cleanup instead of losing it", async () => {
  const f = fixture();
  const target = f.target();
  const verification = new Error("verification failed"), cleanup = new Error("cleanup failed");
  const close = f.native.close_sdk_profile_target;
  f.native.assert_sdk_profile_target = () => { throw verification; };
  f.native.close_sdk_profile_target = () => { throw cleanup; };
  assert.throws(() => target.prepare(), error => {
    assert.ok(error instanceof SdkProfileTargetError);
    assert.equal(error.code, "ERR_SDK_PROFILE_TARGET_REFUSED");
    assert.equal(error.reason, "target-verification-and-cleanup-failed");
    assert.ok(error.cause instanceof AggregateError);
    assert.deepEqual(error.cause.errors.map(value => value.code), [
      "ERR_SDK_PROFILE_TARGET_REFUSED", "ERR_SDK_PROFILE_TARGET_REFUSED",
    ]);
    assert.strictEqual(error.cause.errors[0].cause, verification);
    assert.strictEqual(error.cause.errors[1].cause, cleanup);
    return true;
  });
  assert.equal([...f.handles.values()].some(handle => !handle.closed), true);
  f.native.close_sdk_profile_target = close;
  await target.retryTargetCleanup();
  assert.equal([...f.handles.values()].every(handle => handle.closed), true);
});

test("failed qualification cleanup retries retain ownership and never close a live lease", async () => {
  const f = fixture();
  const target = f.target();
  const live = target.prepare();
  const liveHandle = [...f.handles.keys()][0];
  const assertCurrent = f.native.assert_sdk_profile_target, close = f.native.close_sdk_profile_target;
  const verification = new Error("verification failed"), cleanup = new Error("cleanup failed");
  let blocked = true, attempts = 0;
  f.native.assert_sdk_profile_target = () => { throw verification; };
  f.native.close_sdk_profile_target = handle => {
    attempts++;
    if (blocked) throw cleanup;
    close(handle);
  };
  assert.throws(() => target.prepare(), refused("target-verification-and-cleanup-failed"));
  assert.equal(attempts, 1);
  await assert.rejects(target.retryTargetCleanup(), error => {
    assert.equal(error.code, "ERR_SDK_PROFILE_TARGET_REFUSED");
    assert.equal(error.reason, "target-cleanup-failed");
    assert.strictEqual(error.cause.errors[0].cause, cleanup);
    return true;
  });
  assert.equal(attempts, 2);
  blocked = false;
  const retry = target.retryTargetCleanup();
  assert.strictEqual(target.retryTargetCleanup(), retry);
  await retry;
  assert.equal(attempts, 3);
  assert.equal(f.handles.get(liveHandle).closed, false);
  assert.equal([...f.handles.values()].filter(handle => handle.closed).length, 1);
  await target.retryTargetCleanup();
  assert.equal(attempts, 3);
  f.native.assert_sdk_profile_target = assertCurrent;
  live.assertCurrent();
  live.close();
  assert.equal(attempts, 4);
  assert.equal([...f.handles.values()].every(handle => handle.closed), true);
});

test("native open and evidence failures are target refusals, never persistence failures", () => {
  for (const method of ["open_sdk_profile_target", "sdk_profile_target_facts", "assert_sdk_profile_target"]) {
    const f = fixture();
    const failure = new Error(`${method} failed`);
    f.native[method] = () => { throw failure; };
    assert.throws(() => f.target().prepare(), error => {
      assert.ok(error instanceof SdkProfileTargetError);
      assert.equal(error.code, "ERR_SDK_PROFILE_TARGET_REFUSED");
      assert.equal(error.reason, method === "open_sdk_profile_target"
        ? "target-open-failed" : "target-verification-failed");
      assert.strictEqual(error.cause, failure);
      return true;
    });
    assert.equal(f.calls.filter(call => call[0] === "close").length,
      method === "open_sdk_profile_target" ? 0 : 1);
    assert.equal([...f.handles.values()].every(handle => handle.closed), true);
  }
});

test("native retained-lease failures preserve the original reason and cause", () => {
  const f = fixture();
  const selected = f.target().prepare();
  const failure = Object.assign(new Error("recipient changed"), {
    code: "ERR_SDK_PROFILE_TARGET_REFUSED", reason: "recipient-identity-changed",
  });
  f.native.assert_sdk_profile_target = () => { throw failure; };
  assert.throws(() => selected.assertCurrent(), error => {
    assert.ok(error instanceof SdkProfileTargetError);
    assert.equal(error.code, "ERR_SDK_PROFILE_TARGET_REFUSED");
    assert.equal(error.reason, "recipient-identity-changed");
    assert.strictEqual(error.cause, failure);
    return true;
  });
  assert.equal(f.calls.filter(call => call[0] === "close").length, 0);
  selected.close();
});

test("malformed native evidence is refused without invoking accessors and releases its handle", () => {
  const f = fixture();
  let reads = 0;
  f.native.sdk_profile_target_facts = () => ({
    layout: "win32-gjc-sqlite-only-v1",
    managementHome: "C:\\Users\\fixture-manager",
    managerIdentity: "S-1-5-21-100-200-300-1001",
    get profile() { reads++; throw new Error("untrusted evidence accessor"); },
  });
  assert.throws(() => f.target().prepare(), refused("invalid-target-evidence"));
  assert.equal(reads, 0);
  assert.equal([...f.handles.values()].every(handle => handle.closed), true);
});

test("SDK local-only auth snapshot binds the exact selected store and freezes nested policy", () => {
  const f = fixture();
  const selected = f.target().prepare();
  assert.deepEqual(selected.startupAuthConfig, {
    broker: null,
    credentialStoreIdentity: `local:${original.credentialPath}`,
    credentialRankingMode: "balanced",
    credentialPins: {},
    credentialPreferences: {},
  });
  assert.equal(Object.isFrozen(selected.startupAuthConfig.credentialPins), true);
  assert.equal(Object.isFrozen(selected.startupAuthConfig.credentialPreferences), true);
  selected.close();
});
