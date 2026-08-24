import assert from "node:assert/strict";
import test from "node:test";
import { createHash } from "node:crypto";
import {
  buildGenerationPointer,
  validateGenerationPointer,
  generationPointerBytes,
  parseGenerationPointer,
  readLiveGeneration,
  publishGeneration,
  PUBLISH_STEPS,
} from "../src/workspace-generation-publisher.js";

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

async function expectRefusal(promiseOrFn, code) {
  try {
    await (typeof promiseOrFn === "function" ? promiseOrFn() : promiseOrFn);
    assert.fail(`expected refusal ${code} but resolved`);
  } catch (error) {
    assert.equal(error.code, code, `expected ${code}, got ${error.code}: ${error.reason ?? error.message}`);
    assert.equal(error.operation, "workspace_generation_publish");
    assert.equal(typeof error.reason, "string");
    assert.ok(error.message.startsWith("workspace_generation_publish:"));
    return error;
  }
}

// A fake io backed by a single in-memory "live pointer" slot whose replace is a
// single atomic assignment. `fail` names a step to throw at (crash sim); `raw`
// makes that throw a raw (non-module) error to exercise IO_FAILED wrapping.
function fakeIo(initialBytes = null, { fail = null, raw = true } = {}) {
  const state = { live: initialBytes, temp: null, order: [] };
  const boom = (step) => {
    if (raw) {
      const e = new Error(`disk lost at ${step}`);
      e.code = "EIO";
      throw e;
    }
    const e = new Error("workspace_generation_publish: injected");
    e.code = "WORKSPACE_GENERATION_PATH_REJECTED";
    e.operation = "workspace_generation_publish";
    e.reason = "injected";
    throw e;
  };
  const mark = (step) => { state.order.push(step); if (fail === step) boom(step); };
  return {
    state,
    readLivePointer: async () => { mark("readLivePointer"); return state.live; },
    writeTemp: async (bytes) => { mark("writeTemp"); state.temp = bytes; return "temp-ref"; },
    flushTemp: async (ref) => { mark("flushTemp"); assert.equal(ref, "temp-ref"); },
    replace: async (ref) => { mark("replace"); assert.equal(ref, "temp-ref"); state.live = state.temp; },
    flushParent: async () => { mark("flushParent"); },
  };
}

test("build produces a frozen, validated first-publication pointer", () => {
  const p = first();
  assert.equal(p.kind, "workspace-generation-pointer");
  assert.equal(p.version, 1);
  assert.equal(p.activeGeneration, 1);
  assert.equal(p.priorGeneration, null);
  assert.equal(p.priorPointerFingerprint, null);
  assert.equal(p.pointerFingerprint.length, 64);
  assert.ok(Object.isFrozen(p));
  assert.equal(validateGenerationPointer(p), p);
});

test("build produces a validated successor pointer chained to its prior", () => {
  const p1 = first();
  const p2 = successor(p1);
  assert.equal(p2.activeGeneration, 2);
  assert.equal(p2.priorGeneration, 1);
  assert.equal(p2.priorPointerFingerprint, p1.pointerFingerprint);
  validateGenerationPointer(p2);
});

test("pointerFingerprint is deterministic and changes when any bound field changes", () => {
  const a = first();
  const b = first();
  assert.equal(a.pointerFingerprint, b.pointerFingerprint);
  assert.notEqual(a.pointerFingerprint, first({ manifestFingerprint: "9".repeat(64) }).pointerFingerprint);
  assert.notEqual(a.pointerFingerprint, first({ gitGenerationFingerprint: "9".repeat(64) }).pointerFingerprint);
  assert.notEqual(a.pointerFingerprint, first({ rootIdentityFingerprint: "9".repeat(64) }).pointerFingerprint);
  assert.notEqual(a.pointerFingerprint, first({ generationPath: "generations/000009" }).pointerFingerprint);
});

test("validate rejects a tampered fingerprint or unmatched body", () => {
  const p = first();
  assert.throws(() => validateGenerationPointer({ ...p, pointerFingerprint: "0".repeat(64) }),
    (e) => e.code === "WORKSPACE_GENERATION_INVALID");
  assert.throws(() => validateGenerationPointer({ ...p, activeGeneration: 5 }),
    (e) => e.code === "WORKSPACE_GENERATION_INVALID");
});

test("validate enforces the first-publication invariants", () => {
  // First publication with a non-null prior fingerprint.
  assert.throws(
    () => buildGenerationPointer({ ...BASE, activeGeneration: 1, priorGeneration: null, priorPointerFingerprint: "a".repeat(64) }),
    (e) => e.code === "WORKSPACE_GENERATION_INVALID",
  );
  // priorGeneration null but activeGeneration !== 1.
  assert.throws(
    () => buildGenerationPointer({ ...BASE, activeGeneration: 2, priorGeneration: null, priorPointerFingerprint: null }),
    (e) => e.code === "WORKSPACE_GENERATION_INVALID",
  );
});

test("validate enforces the successor invariants", () => {
  const p1 = first();
  // Successor with a null prior fingerprint.
  assert.throws(
    () => buildGenerationPointer({ ...BASE, generationPath: "generations/000002", activeGeneration: 2, priorGeneration: 1, priorPointerFingerprint: null }),
    (e) => e.code === "WORKSPACE_GENERATION_INVALID",
  );
  // activeGeneration != priorGeneration + 1.
  assert.throws(
    () => buildGenerationPointer({ ...BASE, generationPath: "generations/000003", activeGeneration: 3, priorGeneration: 1, priorPointerFingerprint: p1.pointerFingerprint }),
    (e) => e.code === "WORKSPACE_GENERATION_INVALID",
  );
});

test("rejects reserved/absolute/escaping/aliasing generationPath values", () => {
  const cases = ["/abs", "..", "a/../b", "C:\\x", "win\\sep", "a//b", "has\0nul", "", "gen:ads", "CON", "trail. ", "ctrl\u0001x"];
  for (const bad of cases) {
    assert.throws(
      () => buildGenerationPointer({ ...BASE, activeGeneration: 1, priorGeneration: null, priorPointerFingerprint: null, generationPath: bad }),
      (e) => e.code === "WORKSPACE_GENERATION_PATH_REJECTED",
      `generationPath ${JSON.stringify(bad)} should be rejected`,
    );
  }
});

test("bytes round-trip through parseGenerationPointer", () => {
  const p = successor(first());
  const parsed = parseGenerationPointer(generationPointerBytes(p));
  assert.equal(parsed.pointerFingerprint, p.pointerFingerprint);
  assert.deepEqual({ ...parsed }, { ...p });
});

test("parse rejects non-canonical bytes and a __proto__ key", () => {
  assert.throws(() => parseGenerationPointer(Buffer.from("{not json")), (e) => e.code === "WORKSPACE_GENERATION_INVALID");
  assert.throws(() => parseGenerationPointer(Buffer.from('{"__proto__":{"x":1}}', "utf8")), (e) => e.code === "WORKSPACE_GENERATION_INVALID");
  assert.equal({}.x, undefined);
});

test("publishGeneration performs a first publication and records step order", async () => {
  const io = fakeIo(null);
  const p = first();
  const proof = await publishGeneration(io, p);
  assert.deepEqual(proof, {
    published: true,
    activeGeneration: 1,
    priorGeneration: null,
    pointerFingerprint: p.pointerFingerprint,
    priorPointerFingerprint: null,
  });
  // The live slot now holds exactly the new pointer bytes.
  assert.deepEqual(parseGenerationPointer(io.state.live), { ...p });
  // Native steps run in the exact protocol order after the CAS read.
  assert.deepEqual(io.state.order, ["readLivePointer", ...PUBLISH_STEPS]);
});

test("publishGeneration performs a successor publication chained to the live pointer", async () => {
  const p1 = first();
  const io = fakeIo(generationPointerBytes(p1));
  const p2 = successor(p1);
  const proof = await publishGeneration(io, p2);
  assert.equal(proof.activeGeneration, 2);
  assert.equal(proof.priorGeneration, 1);
  assert.deepEqual(parseGenerationPointer(io.state.live), { ...p2 });
});

test("publishGeneration refuses a first publication when a pointer is already live", async () => {
  const io = fakeIo(generationPointerBytes(first()));
  await expectRefusal(publishGeneration(io, first()), "WORKSPACE_GENERATION_CAS_CONFLICT");
});

test("publishGeneration refuses a successor when no pointer is live", async () => {
  const io = fakeIo(null);
  await expectRefusal(publishGeneration(io, successor(first())), "WORKSPACE_GENERATION_CAS_CONFLICT");
});

test("publishGeneration refuses a successor whose prior fingerprint does not match the live pointer", async () => {
  const p1 = first();
  const other = first({ manifestFingerprint: "a".repeat(64) }); // different live pointer
  const io = fakeIo(generationPointerBytes(other));
  // p2 chains onto p1, but the live pointer is `other` -> CAS conflict.
  await expectRefusal(publishGeneration(io, successor(p1)), "WORKSPACE_GENERATION_CAS_CONFLICT");
});

test("publishGeneration refuses a successor whose host/workspace drifts from the live pointer", async () => {
  const p1 = first();
  const io = fakeIo(generationPointerBytes(p1));
  const drifted = buildGenerationPointer({
    ...BASE,
    workspaceId: "workspace-2",
    generationPath: "generations/000002",
    activeGeneration: 2,
    priorGeneration: 1,
    priorPointerFingerprint: p1.pointerFingerprint,
  });
  await expectRefusal(publishGeneration(io, drifted), "WORKSPACE_GENERATION_CAS_CONFLICT");
});

test("publishGeneration wraps a raw native failure as WORKSPACE_GENERATION_IO_FAILED without leaking a message", async () => {
  const io = fakeIo(null, { fail: "replace", raw: true });
  const err = await expectRefusal(publishGeneration(io, first()), "WORKSPACE_GENERATION_IO_FAILED");
  assert.equal(err.step, "replace");
  assert.equal(err.cause, "EIO");
  assert.ok(!/disk lost/.test(err.reason), "raw message must not leak into the refusal reason");
});

test("publishGeneration rethrows a module refusal from a native op unchanged", async () => {
  const io = fakeIo(null, { fail: "writeTemp", raw: false });
  const err = await expectRefusal(publishGeneration(io, first()), "WORKSPACE_GENERATION_PATH_REJECTED");
  assert.equal(err.reason, "injected");
});

test("readLiveGeneration returns null when absent, parses when present, refuses non-bytes", async () => {
  assert.equal(await readLiveGeneration(fakeIo(null)), null);
  const p = first();
  const parsed = await readLiveGeneration(fakeIo(generationPointerBytes(p)));
  assert.deepEqual({ ...parsed }, { ...p });
  await expectRefusal(readLiveGeneration({ readLivePointer: async () => "not bytes" }), "WORKSPACE_GENERATION_IO_FAILED");
});

test("publishGeneration validates io shape and the pointer before any I/O", async () => {
  await expectRefusal(publishGeneration({ readLivePointer() {} }, first()), "WORKSPACE_GENERATION_INVALID");
  await expectRefusal(publishGeneration(fakeIo(null), { not: "a pointer" }), "WORKSPACE_GENERATION_INVALID");
});
