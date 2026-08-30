import assert from "node:assert/strict";
import test from "node:test";

import {
  RESTORE_CONTEXTS_ENV,
  resolveRestoreContextClaims,
} from "./workspace-restore-context-config.js";

test("restore contexts are disabled when the operator value is absent", () => {
  assert.deepEqual(resolveRestoreContextClaims({ env: {} }), {
    ok: true,
    enabled: false,
    claims: [],
    diagnostic: null,
  });
});

test("restore contexts parse a bounded non-empty claim array", () => {
  const claims = [{ operation: "restore" }];
  const result = resolveRestoreContextClaims({
    env: { [RESTORE_CONTEXTS_ENV]: JSON.stringify(claims) },
  });
  assert.equal(result.ok, true);
  assert.equal(result.enabled, true);
  assert.deepEqual(result.claims, claims);
});

test("restore contexts reject malformed, empty, oversized, and over-count values", () => {
  for (const raw of [
    "{",
    "{}",
    "[]",
    JSON.stringify(Array.from({ length: 65 }, () => ({}))),
    `\"${"x".repeat(1024 * 1024)}\"`,
  ]) {
    const result = resolveRestoreContextClaims({
      env: { [RESTORE_CONTEXTS_ENV]: raw },
    });
    assert.equal(result.ok, false);
    assert.equal(result.enabled, false);
    assert.equal(result.diagnostic.code, "RESTORE_CONTEXT_CONFIG_INVALID");
    assert.equal(result.diagnostic.env, RESTORE_CONTEXTS_ENV);
    assert.equal(result.diagnostic.reason.includes(raw), false);
  }
});
