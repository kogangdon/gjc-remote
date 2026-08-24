import test from "node:test";
import assert from "node:assert/strict";
import { V0_LIMITS } from "@gjc-remote/shared";
import { DEFAULT_MAX_IN_FLIGHT_INVOKES } from "../src/admission-budget.js";

// Two-layer, not two-authorities (#43): the bot's per-socket network guard
// (V0_LIMITS.MAX_PENDING_PER_HOST) intentionally mirrors the daemon's
// authoritative in-flight-invoke ceiling (AdmissionBudget). They are kept equal
// by convention; this in-slice guard fails CI if a future change moves one
// value without the other, rather than letting them silently drift.
test("bot MAX_PENDING_PER_HOST equals daemon AdmissionBudget in-flight ceiling", () => {
  assert.equal(V0_LIMITS.MAX_PENDING_PER_HOST, DEFAULT_MAX_IN_FLIGHT_INVOKES);
});
