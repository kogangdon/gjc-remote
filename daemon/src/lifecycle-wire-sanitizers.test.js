import assert from "node:assert/strict";
import test from "node:test";

import { whitelistProtocolCode, formatManualCleanupLog } from "../src/lifecycle-wire-sanitizers.js";
import { PROTOCOL_ERROR_CODES } from "@gjc-remote/shared";

// ---------------------------------------------------------------------------
// whitelistProtocolCode (issue #184): only an OWNED PROTOCOL_ERROR_CODES key
// crosses the wire; inherited prototype keys and unknown codes collapse to
// RUNTIME_INCOMPATIBLE.
// ---------------------------------------------------------------------------

test("whitelistProtocolCode passes through an owned protocol code", () => {
  assert.equal(
    whitelistProtocolCode("WORKSPACE_GENERATION_STALE"),
    PROTOCOL_ERROR_CODES.WORKSPACE_GENERATION_STALE,
  );
  assert.equal(
    whitelistProtocolCode("RUNTIME_INCOMPATIBLE"),
    PROTOCOL_ERROR_CODES.RUNTIME_INCOMPATIBLE,
  );
});

test("whitelistProtocolCode collapses an inherited prototype key to RUNTIME_INCOMPATIBLE", () => {
  for (const evil of ["constructor", "__proto__", "toString", "hasOwnProperty", "valueOf"]) {
    assert.equal(
      whitelistProtocolCode(evil),
      PROTOCOL_ERROR_CODES.RUNTIME_INCOMPATIBLE,
      `${evil} must not leak a truthy Function across the wire`,
    );
  }
});

test("whitelistProtocolCode collapses an unknown/non-string code to RUNTIME_INCOMPATIBLE", () => {
  assert.equal(whitelistProtocolCode("NOT_A_REAL_CODE"), PROTOCOL_ERROR_CODES.RUNTIME_INCOMPATIBLE);
  assert.equal(whitelistProtocolCode(undefined), PROTOCOL_ERROR_CODES.RUNTIME_INCOMPATIBLE);
  assert.equal(whitelistProtocolCode(null), PROTOCOL_ERROR_CODES.RUNTIME_INCOMPATIBLE);
  assert.equal(whitelistProtocolCode(42), PROTOCOL_ERROR_CODES.RUNTIME_INCOMPATIBLE);
  assert.equal(whitelistProtocolCode({}), PROTOCOL_ERROR_CODES.RUNTIME_INCOMPATIBLE);
});

// ---------------------------------------------------------------------------
// formatManualCleanupLog (issue #184): surface the partial-CAS checkpoint as a
// sanitized, bounded log line; return null for anything that is not one.
// ---------------------------------------------------------------------------

const manualCleanupResult = () =>
  Object.freeze({
    ok: false,
    code: "RUNTIME_INCOMPATIBLE",
    reason: "reset/delete requires manual cleanup",
    receipt: Object.freeze({
      operation: "delete",
      published: false,
      disposition: "manual_cleanup",
      dirtyBackupFingerprint: "a".repeat(64),
      manualCleanup: Object.freeze({ txId: "tx-9", reason: "operator-delete", anchorFingerprint: "b".repeat(64) }),
      cause: Object.freeze({ code: "IO_TERMINAL_CAS_FAILED", step: 7 }),
    }),
  });

const msg = Object.freeze({ operation: "delete", workspaceId: "workspace-1" });

test("formatManualCleanupLog returns null for a committed (ok:true) result", () => {
  assert.equal(formatManualCleanupLog(msg, { ok: true, receipt: { disposition: "committed" } }), null);
});

test("formatManualCleanupLog returns null for a routine refusal without a receipt", () => {
  assert.equal(formatManualCleanupLog(msg, { ok: false, code: "RUNTIME_INCOMPATIBLE" }), null);
});

test("formatManualCleanupLog returns null for a refusal whose receipt is not manual_cleanup", () => {
  assert.equal(
    formatManualCleanupLog(msg, { ok: false, receipt: { disposition: "committed" } }),
    null,
  );
});

test("formatManualCleanupLog surfaces the sanitized checkpoint fields the operator needs", () => {
  const line = formatManualCleanupLog(msg, manualCleanupResult());
  assert.ok(typeof line === "string");
  assert.match(line, /manual_cleanup required/);
  const payload = JSON.parse(line.slice(line.indexOf("{")));
  assert.deepEqual(payload, {
    operation: "delete",
    workspaceId: "workspace-1",
    disposition: "manual_cleanup",
    dirtyBackupFingerprint: "a".repeat(64),
    cause: { code: "IO_TERMINAL_CAS_FAILED", step: 7 },
    manualCleanup: { txId: "tx-9", reason: "operator-delete" },
  });
});

test("formatManualCleanupLog never serializes raw paths or extra authority fields", () => {
  const line = formatManualCleanupLog(msg, manualCleanupResult());
  // anchorFingerprint (an authority field) is NOT whitelisted into the log
  assert.doesNotMatch(line, /anchorFingerprint/);
  assert.doesNotMatch(line, /published/);
});

test("formatManualCleanupLog tolerates a malformed receipt (missing manualCleanup/cause)", () => {
  const line = formatManualCleanupLog(msg, {
    ok: false,
    receipt: { disposition: "manual_cleanup" },
  });
  const payload = JSON.parse(line.slice(line.indexOf("{")));
  assert.equal(payload.dirtyBackupFingerprint, null);
  assert.equal(payload.cause, null);
  assert.equal(payload.manualCleanup, null);
});
