import assert from "node:assert/strict";
import test from "node:test";
import {
  generationPointerBytes,
  parseGenerationPointer,
} from "../src/workspace-generation-publisher.js";
import {
  buildGenerationPointer,
  buildPromotionLineage,
  validatePromotionLineage,
  publishPromotion,
  PUBLISH_STEPS,
  LINEAGE_KEYS,
} from "../src/workspace-reversible-promotion.js";

const POINTER_KEYS = [
  "version", "kind", "hostId", "workspaceId", "sourcePlatform", "activeGeneration",
  "generationPath", "rootIdentityFingerprint", "storageIdentityFingerprint",
  "gitGenerationFingerprint", "manifestFingerprint", "priorGeneration",
  "priorPointerFingerprint", "pointerFingerprint",
];

const BASE = {
  hostId: "host-1",
  workspaceId: "workspace-1",
  sourcePlatform: "windows-drive",
  generationPath: "generations/000001",
  rootIdentityFingerprint: "1".repeat(64),
  storageIdentityFingerprint: "2".repeat(64),
  gitGenerationFingerprint: "3".repeat(64),
  manifestFingerprint: "4".repeat(64),
};

function first(overrides = {}) {
  return buildGenerationPointer({ ...BASE, activeGeneration: 1, priorGeneration: null, priorPointerFingerprint: null, ...overrides });
}

function successor(prior, overrides = {}) {
  return buildGenerationPointer({
    ...BASE,
    generationPath: "generations/000002",
    activeGeneration: prior.activeGeneration + 1,
    priorGeneration: prior.activeGeneration,
    priorPointerFingerprint: prior.pointerFingerprint,
    ...overrides,
  });
}

// Mirror of the S4d publisher fake io: a single in-memory live slot whose
// replace is one atomic assignment. `fail` injects a crash at a named step.
function fakeIo(initialBytes = null, { fail = null } = {}) {
  const state = { live: initialBytes, temp: null, order: [] };
  const mark = (step) => {
    state.order.push(step);
    if (fail === step) {
      const e = new Error(`disk lost at ${step}`);
      e.code = "EIO";
      throw e;
    }
  };
  return {
    state,
    readLivePointer: async () => { mark("readLivePointer"); return state.live; },
    writeTemp: async (bytes) => { mark("writeTemp"); state.temp = bytes; return "temp-ref"; },
    flushTemp: async (ref) => { mark("flushTemp"); assert.equal(ref, "temp-ref"); },
    replace: async (ref) => { mark("replace"); assert.equal(ref, "temp-ref"); state.live = state.temp; },
    flushParent: async () => { mark("flushParent"); },
  };
}

async function expectRefusal(promise, code) {
  await assert.rejects(promise, (error) => {
    assert.equal(error.code, code, `expected ${code}, got ${error.code}: ${error.reason ?? error.message}`);
    return true;
  });
}

const LINEAGE_INPUT = { restoredFromWorkspaceId: "workspace-src", restoredFromGeneration: 7 };

// ---------- buildPromotionLineage -------------------------------------------

test("buildPromotionLineage produces a frozen, self-fingerprinted lineage record", () => {
  const lineage = buildPromotionLineage(LINEAGE_INPUT);
  assert.equal(lineage.version, 1);
  assert.equal(lineage.kind, "workspace-promotion-lineage");
  assert.equal(lineage.restoredFromWorkspaceId, "workspace-src");
  assert.equal(lineage.restoredFromGeneration, 7);
  assert.equal(lineage.lineageFingerprint.length, 64);
  assert.deepEqual(Object.keys(lineage), LINEAGE_KEYS);
  assert.ok(Object.isFrozen(lineage));
  assert.equal(validatePromotionLineage(lineage), lineage);
});

test("lineageFingerprint changes when a bound field changes", () => {
  const a = buildPromotionLineage(LINEAGE_INPUT);
  const b = buildPromotionLineage(LINEAGE_INPUT);
  assert.equal(a.lineageFingerprint, b.lineageFingerprint);
  assert.notEqual(a.lineageFingerprint, buildPromotionLineage({ ...LINEAGE_INPUT, restoredFromGeneration: 8 }).lineageFingerprint);
  assert.notEqual(a.lineageFingerprint, buildPromotionLineage({ ...LINEAGE_INPUT, restoredFromWorkspaceId: "other" }).lineageFingerprint);
});

test("buildPromotionLineage rejects a malformed or non-exact input as CONFIG_INVALID", () => {
  const cases = [
    null,
    [],
    Object.assign(Object.create(null), LINEAGE_INPUT),
    { restoredFromWorkspaceId: "", restoredFromGeneration: 1 },
    { restoredFromWorkspaceId: "w", restoredFromGeneration: 0 },
    { restoredFromWorkspaceId: "w", restoredFromGeneration: 1.5 },
    { restoredFromWorkspaceId: "w" }, // missing key
    { ...LINEAGE_INPUT, extra: 1 }, // extra key
  ];
  for (const bad of cases) {
    assert.throws(() => buildPromotionLineage(bad), (e) => {
      assert.equal(e.code, "CONFIG_INVALID");
      assert.equal(e.operation, "workspace_reversible_promotion");
      return true;
    }, JSON.stringify(bad));
  }
});

test("validatePromotionLineage rejects a tampered fingerprint", () => {
  const lineage = buildPromotionLineage(LINEAGE_INPUT);
  assert.throws(() => validatePromotionLineage({ ...lineage, lineageFingerprint: "0".repeat(64) }),
    (e) => e.code === "CONFIG_INVALID");
  assert.throws(() => validatePromotionLineage({ ...lineage, restoredFromGeneration: 99 }),
    (e) => e.code === "CONFIG_INVALID");
});

// ---------- publishPromotion: thin pass-through to S4d -----------------------

test("publishPromotion publishes a standard S4d pointer and runs the exact PUBLISH_STEPS order", async () => {
  const io = fakeIo(null);
  const pointer = first();
  const proof = await publishPromotion(io, pointer);
  assert.deepEqual(proof, {
    published: true,
    activeGeneration: 1,
    priorGeneration: null,
    pointerFingerprint: pointer.pointerFingerprint,
    priorPointerFingerprint: null,
  });
  assert.deepEqual(parseGenerationPointer(io.state.live), { ...pointer });
  assert.deepEqual(io.state.order, ["readLivePointer", ...PUBLISH_STEPS]);
});

test("publishPromotion chains a successor onto the live pointer (reversible promotion)", async () => {
  const p1 = first();
  const io = fakeIo(generationPointerBytes(p1));
  const p2 = successor(p1);
  const proof = await publishPromotion(io, p2);
  assert.equal(proof.activeGeneration, 2);
  assert.equal(proof.priorGeneration, 1);
  assert.deepEqual(parseGenerationPointer(io.state.live), { ...p2 });
});

test("the published pointer carries EXACTLY POINTER_KEYS and NO lineage fields (JSON-scan)", async () => {
  const io = fakeIo(null);
  const pointer = first();
  await publishPromotion(io, pointer);
  const published = parseGenerationPointer(io.state.live);
  assert.deepEqual(Object.keys(published).sort(), [...POINTER_KEYS].sort());
  // Lineage must never ride the pointer bytes.
  const text = Buffer.from(io.state.live).toString("utf8");
  assert.ok(!/restoredFrom/i.test(text), "published pointer bytes must not contain restore lineage");
  assert.ok(!/promotion-lineage/i.test(text));
});

test("publishPromotion refuses a lineage-contaminated pointer via S4d exact-key validation", async () => {
  const io = fakeIo(null);
  const contaminated = { ...first(), restoredFromWorkspaceId: "w", restoredFromGeneration: 1 };
  await expectRefusal(publishPromotion(io, contaminated), "WORKSPACE_GENERATION_INVALID");
  // No I/O past the pre-flight validation.
  assert.deepEqual(io.state.order, []);
  assert.equal(io.state.live, null);
});

// ---------- CAS + crash-sim (S4d semantics, unmodified) ----------------------

test("publishPromotion refuses a stale CAS base without mutating the live slot", async () => {
  const p1 = first();
  const other = first({ manifestFingerprint: "a".repeat(64) });
  const io = fakeIo(generationPointerBytes(other));
  const liveBefore = io.state.live;
  await expectRefusal(publishPromotion(io, successor(p1)), "WORKSPACE_GENERATION_CAS_CONFLICT");
  assert.equal(io.state.live, liveBefore, "live slot must be untouched on a CAS conflict");
});

test("crash-sim: a throw at or before replace leaves the prior live pointer; after replace leaves the new one", async () => {
  const p1 = first();
  const liveBytes = generationPointerBytes(p1);
  const p2 = successor(p1);
  for (const step of PUBLISH_STEPS) {
    const io = fakeIo(liveBytes, { fail: step });
    await expectRefusal(publishPromotion(io, p2), "WORKSPACE_GENERATION_IO_FAILED");
    // S4d semantics: replace is the single linearization point.
    const stepIndex = PUBLISH_STEPS.indexOf(step);
    const replaceIndex = PUBLISH_STEPS.indexOf("replace");
    if (stepIndex <= replaceIndex) {
      assert.deepEqual(parseGenerationPointer(io.state.live), { ...p1 }, `throw at ${step}: slot must be the PRIOR pointer`);
    } else {
      assert.deepEqual(parseGenerationPointer(io.state.live), { ...p2 }, `throw at ${step}: slot must be the NEW pointer`);
    }
  }
});
