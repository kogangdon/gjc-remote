import assert from "node:assert/strict";
import test from "node:test";
import { SdkLiveInputRouter, scopeKey } from "../src/sdk-live-input-router.js";

const scope = (generation, attemptId = `attempt-${generation}`) => ({ attemptId, generation, lineage: "main" });

function harness() {
  const listeners = new Set();
  const rawListeners = new Set();
  const failures = [];
  const primaryEvents = [];
  const primary = { onEvent: (event) => primaryEvents.push(event) };
  const router = new SdkLiveInputRouter({
    subscribe(listener) { listeners.add(listener); return () => listeners.delete(listener); },
    agent: {
      subscribe(listener) { rawListeners.add(listener); return () => rawListeners.delete(listener); },
    },
  }, {
    classifyTerminal: (event, failure) => ({ disposition: failure ? "failed" : event.stopReason, ...(failure ? { code: failure.code } : {}) }),
    sanitizeFailure: (error) => ({ code: error?.code ?? "prompt_failed" }),
    isTerminal: (event) => event?.type === "agent_end",
    onFatal: (error) => failures.push(error),
  });
  const cohort = router.openPrimary(primary);
  const emit = (event) => { for (const listener of listeners) listener(event); };
  const emitRaw = (event) => { for (const listener of rawListeners) listener(event); };
  return { router, listeners, rawListeners, failures, primaryEvents, primary, cohort, emit, emitRaw };
}

const end = (attemptScope, stopReason = "completed") => ({ type: "agent_end", scope: attemptScope, stopReason });

test("scope identity includes attemptId, safe generation, and lineage", () => {
  const identity = scope(1);
  assert.notEqual(scopeKey(identity), scopeKey({ ...identity, generation: 2 }));
  assert.notEqual(scopeKey(identity), scopeKey({ ...identity, lineage: "child" }));
  assert.notEqual(scopeKey(identity), scopeKey({ ...identity, attemptId: "other" }));
  assert.equal(scopeKey({ ...identity, generation: Number.MAX_SAFE_INTEGER + 1 }), undefined);
  assert.equal(scopeKey({ ...identity, attemptId: "" }), undefined);
  assert.equal(scopeKey({ ...identity, lineage: "" }), undefined);
});

test("one listener routes changing provider-turn scopes to the original joined cohort", async () => {
  const h = harness();
  h.emit({ type: "agent_start", scope: scope(1) });
  const steer = {};
  const followUp = {};
  h.router.expectExecution(steer);
  h.router.expectExecution(followUp);
  const followerEvents = [];
  const follower = { onEvent: (event) => followerEvents.push(event) };
  h.emit({ type: "turn_start", scope: scope(2) });
  assert.equal(h.router.bindExecution(steer, { disposition: "joined-current-run", attemptScope: scope(2) }, follower), h.cohort);
  assert.equal(h.router.bindExecution(followUp, { disposition: "joined-current-run", attemptScope: scope(2) }, follower), h.cohort);
  h.emit({ type: "turn_start", scope: scope(3) });
  h.emit({ type: "message_update", scope: scope(3), value: "shared" });
  const terminal = h.router.finalTerminal(h.cohort, scope(3));
  h.emit(end(scope(3), "paused"));
  assert.deepEqual(await terminal, { disposition: "paused" });
  assert.equal(h.listeners.size, 1);
  assert.equal(h.primaryEvents.at(-1).value, "shared");
  assert.deepEqual(followerEvents, []);
  h.router.release();
  h.router.release();
  h.router.release();
  assert.equal(h.listeners.size, 0);
  assert.equal(h.router.scopes.size, 0);
  assert.deepEqual(h.failures, []);
});

test("synchronous successor events wait for promoted proof while old scope terminals stay old", async () => {
  const h = harness();
  const old = scope(1);
  const next = scope(2, "next");
  h.emit({ type: "agent_start", scope: old });
  const token = {};
  h.router.expectExecution(token);
  h.emit({ type: "agent_start", scope: next });
  h.emit({ type: "message_update", scope: next, value: "private successor" });
  assert.equal(h.primaryEvents.some((event) => event.value === "private successor"), false);
  const successorEvents = [];
  const owner = { onEvent: (event) => successorEvents.push(event) };
  const successor = h.router.bindExecution(token, { disposition: "promoted-to-run", attemptScope: next }, owner);
  assert.equal(successorEvents.at(-1).value, "private successor");
  h.emit({ type: "agent_failed", scope: old, error: { code: "old_failure", message: "raw secret" } });
  h.emit(end(old));
  assert.deepEqual(await h.cohort.terminal, { disposition: "failed", code: "old_failure" });
  assert.equal(successor.ended, false);
  h.emit({ type: "turn_start", scope: scope(3, "next-final") });
  const terminal = h.router.finalTerminal(successor, scope(3, "next-final"));
  h.emit(end(scope(3, "next-final")));
  assert.deepEqual(await terminal, { disposition: "completed" });
  assert.equal(h.primaryEvents.some((event) => event.value === "private successor"), false);
  assert.doesNotMatch(JSON.stringify([...h.router.scopes.values()]), /raw secret/);
  h.router.close();
});

test("a joined receipt can precede promotion proof without stealing the primary", () => {
  const h = harness();
  h.emit({ type: "agent_start", scope: scope(1) });
  const promoted = {};
  const joined = {};
  h.router.expectExecution(promoted);
  h.router.expectExecution(joined);
  const next = scope(2, "next");
  h.emit({ type: "agent_start", scope: next });
  h.emit({ type: "turn_start", scope: scope(3, "next-turn") });
  const joinEvents = [];
  const joinedCohort = h.router.bindExecution(joined, { disposition: "joined-current-run", attemptScope: scope(3, "next-turn") }, { onEvent: (event) => joinEvents.push(event) });
  assert.notEqual(joinedCohort, h.cohort);
  const promotedEvents = [];
  const promotedCohort = h.router.bindExecution(promoted, { disposition: "promoted-to-run", attemptScope: next }, { onEvent: (event) => promotedEvents.push(event) });
  assert.equal(promotedCohort, joinedCohort);
  assert.deepEqual(joinEvents, []);
  assert.deepEqual(promotedEvents.map((event) => event.type), ["agent_start", "turn_start"]);
  h.router.close();
});

test("queued followers cannot take gates and a unique promoted gate waits for its receipt", () => {
  const h = harness();
  h.emit({ type: "agent_start", scope: scope(1) });
  const token = {};
  h.router.expectExecution(token);
  const owners = [];
  h.router.gate({ gate_id: "primary-gate" }, (owner) => owners.push(owner));
  assert.deepEqual(owners, [h.primary]);
  const next = scope(2);
  h.emit(end(scope(1)));
  h.emit({ type: "agent_start", scope: next });
  h.router.gate({ gate_id: "next-gate", runtime_turn_id: "sdk-host-owned" }, (owner) => owners.push(owner));
  assert.equal(h.router.hasPendingGate(), true);
  const successorOwner = { onEvent: () => {} };
  h.router.bindExecution(token, { disposition: "promoted-to-run", attemptScope: next }, successorOwner);
  assert.deepEqual(owners, [h.primary, successorOwner]);
  assert.equal(h.router.hasPendingGate(), false);
  h.router.close();
});

test("gate ambiguity at emission is not retroactively reassigned after an old terminal", () => {
  const h = harness();
  h.emit({ type: "agent_start", scope: scope(1) });
  const token = {};
  h.router.expectExecution(token);
  h.emit({ type: "agent_start", scope: scope(2) });
  const owners = [];
  h.router.gate({ gate_id: "ambiguous" }, (owner) => owners.push(owner));
  h.router.bindExecution(token, { disposition: "promoted-to-run", attemptScope: scope(2) }, { onEvent: () => {} });
  h.emit(end(scope(1)));
  assert.deepEqual(owners, []);
  assert.equal(h.router.hasPendingGate(), true);
  h.router.close();
});

test("unproven unrelated successor never streams to primary or borrows gate authority", () => {
  const h = harness();
  h.emit({ type: "agent_start", scope: scope(1) });
  h.emit({ type: "agent_start", scope: scope(2, "unrelated") });
  h.emit({ type: "message_update", scope: scope(2, "unrelated"), value: "unrelated" });
  let gates = 0;
  h.router.gate({ gate_id: "unproven" }, () => { gates += 1; });
  h.emit(end(scope(1)));
  assert.equal(gates, 0);
  assert.equal(h.router.hasPendingGate(), true);
  assert.equal(h.primaryEvents.some((event) => event.value === "unrelated"), false);
  h.router.close();
  assert.equal(h.listeners.size, 0);
  assert.equal(h.router.buffer.length, 0);
});

test("pre-start foreign scopes never borrow the later primary boundary", async () => {
  const h = harness();
  const old = scope(1, "old");
  const root = scope(2, "root");
  h.emit({ type: "message_update", scope: old, value: "old private output" });
  h.emit(end(old));
  h.emitRaw(end(old));
  assert.equal(h.primaryEvents.length, 0);
  assert.equal(h.cohort.ended, false);
  h.emit({ type: "agent_start", scope: root });
  h.emit({ type: "message_update", scope: root, value: "own output" });
  h.emitRaw(end(root));
  assert.deepEqual(await h.router.primaryResult(h.cohort), { disposition: "completed" });
  assert.equal(h.cohort.ended, false);
  assert.equal(h.router.scopes.get(scopeKey(old)).cohort, undefined);
  assert.equal(h.router.scopes.get(scopeKey(old)).terminal, undefined);
  assert.deepEqual(h.primaryEvents.filter((event) => event.value).map((event) => event.value), ["own output"]);
  h.router.release();
  assert.equal(h.failures[0]?.code, "SDK_TRACKED_INPUT_CONTRACT");
  h.router.close();
  assert.equal(h.listeners.size, 0);
  assert.equal(h.rawListeners.size, 0);
});

test("buffered scoped output needs its exact first root boundary", () => {
  const h = harness();
  const root = scope(1);
  h.emit({ type: "message_update", scope: root, value: "own buffered output" });
  assert.equal(h.primaryEvents.length, 0);
  assert.equal(h.router.scopes.get(scopeKey(root)).cohort, undefined);
  h.emit({ type: "agent_start", scope: root });
  assert.equal(h.primaryEvents.filter((event) => event.value === "own buffered output").length, 1);
  assert.equal(h.router.scopes.get(scopeKey(root)).cohort, h.cohort);
  assert.equal(h.router.buffer.length, 0);
  h.router.release();
  assert.equal(h.listeners.size, 0);
  assert.equal(h.rawListeners.size, 0);
  assert.deepEqual(h.failures, []);
});

test("post-start unseen tuples stay quarantined through later primary flushes", async (t) => {
  const root = scope(1);
  for (const foreign of [
    { ...root, attemptId: "foreign" },
    { ...root, generation: 2 },
    { ...root, lineage: "child" },
  ]) await t.test(scopeKey(foreign), async () => {
    const h = harness();
    h.emit({ type: "agent_start", scope: root });
    h.emit({ type: "message_update", scope: foreign, value: "foreign output" });
    h.emit({ type: "agent_failed", scope: foreign, error: { code: "foreign_failure", message: "private diagnostic" } });
    h.emit(end(foreign));
    h.emitRaw(end(foreign));
    h.emit({ type: "message_update", scope: root, value: "own output" });
    h.emit({ type: "turn_start", scope: root });
    h.router.flush();
    const record = h.router.scopes.get(scopeKey(foreign));
    assert.equal(record.cohort, undefined);
    assert.equal(record.terminal, undefined);
    assert.deepEqual(record.failure, { code: "foreign_failure" });
    assert.equal(h.cohort.ended, false);
    assert.equal(h.cohort.rawOutcome, undefined);
    assert.equal(h.router.buffer.length, 2);
    assert.deepEqual(h.primaryEvents.filter((event) => event.value).map((event) => event.value), ["own output"]);
    assert.doesNotMatch(JSON.stringify([record, h.router.buffer]), /private diagnostic/);
    const result = h.router.primaryResult(h.cohort);
    let settled = false;
    void result.then(() => { settled = true; });
    await Promise.resolve();
    assert.equal(settled, false);
    h.emit(end(root));
    assert.deepEqual(await result, { disposition: "completed" });
    assert.equal(record.cohort, undefined);
    h.router.release();
    assert.equal(h.failures[0]?.code, "SDK_TRACKED_INPUT_CONTRACT");
    h.router.close();
    assert.equal(h.listeners.size, 0);
    assert.equal(h.rawListeners.size, 0);
    assert.equal(h.router.buffer.length, 0);
    assert.equal(h.router.bufferBytes, 0);
  });
});

test("an exact public turn start can authorize previously quarantined provider output", () => {
  const h = harness();
  h.emit({ type: "agent_start", scope: scope(1) });
  h.emit({ type: "message_update", scope: scope(2), value: "provider continuation" });
  h.router.flush();
  assert.equal(h.primaryEvents.some((event) => event.value), false);
  h.emit({ type: "turn_start", scope: scope(2) });
  assert.equal(h.router.scopes.get(scopeKey(scope(2))).cohort, h.cohort);
  assert.equal(h.primaryEvents.at(-1).value, "provider continuation");
  assert.equal(h.router.buffer.length, 0);
  h.router.release();
  assert.deepEqual(h.failures, []);
});

test("an exact final receipt binds an unseen final tuple only after public terminal buffering", async () => {
  const h = harness();
  h.emit({ type: "agent_start", scope: scope(1) });
  const final = scope(2, "final");
  h.emit({ type: "message_update", scope: final, value: "final output" });
  h.emit(end(final));
  assert.equal(h.cohort.ended, false);
  assert.equal(h.router.scopes.get(scopeKey(final)).cohort, undefined);
  assert.equal(h.primaryEvents.some((event) => event.value), false);
  assert.deepEqual(await h.router.finalTerminal(h.cohort, final), { disposition: "completed" });
  assert.equal(h.cohort.finalKey, scopeKey(final));
  assert.equal(h.primaryEvents.at(-1).value, "final output");
  assert.equal(h.router.buffer.length, 0);
  h.router.release();
  assert.deepEqual(h.failures, []);
});

test("unowned scoped diagnostics remain sanitized until an exact joined execution proves ownership", async () => {
  const h = harness();
  const root = scope(1);
  const joined = scope(2);
  h.emit({ type: "agent_start", scope: root });
  h.emit({ type: "agent_failed", scope: joined, error: { code: "joined_failure", message: "private diagnostic" } });
  h.emitRaw(end(joined));
  const record = h.router.scopes.get(scopeKey(joined));
  assert.equal(record.cohort, undefined);
  assert.equal(h.cohort.rawOutcome, undefined);
  assert.equal(h.cohort.unscopedFailure, undefined);
  assert.deepEqual(record.failure, { code: "joined_failure" });
  assert.equal(h.router.buffer.length, 0);
  assert.doesNotMatch(JSON.stringify(record), /private diagnostic/);
  const token = {};
  h.router.expectExecution(token);
  assert.equal(h.router.bindExecution(token, { disposition: "joined-current-run", attemptScope: joined }, {
    onEvent: () => {},
  }), h.cohort);
  h.emit(end(joined));
  assert.deepEqual(await h.router.finalTerminal(h.cohort, joined), { disposition: "failed", code: "joined_failure" });
  h.router.release();
  h.router.release();
  assert.deepEqual(h.failures, []);
  assert.equal(h.listeners.size, 0);
  assert.equal(h.rawListeners.size, 0);
});

test("final receipt proof preserves exact tuple mismatches and duplicate terminal errors", async (t) => {
  for (const change of [
    { attemptId: "other" }, { generation: 3 }, { lineage: "child" },
  ]) await t.test(JSON.stringify(change), async () => {
    const h = harness();
    h.emit({ type: "agent_start", scope: scope(1) });
    const final = scope(2);
    const foreign = { ...final, ...change };
    h.emit(end(foreign));
    const terminal = h.router.finalTerminal(h.cohort, final);
    let settled = false;
    void terminal.then(() => { settled = true; });
    await Promise.resolve();
    assert.equal(settled, false);
    assert.equal(h.router.scopes.get(scopeKey(foreign)).cohort, undefined);
    h.emit(end(final));
    assert.deepEqual(await terminal, { disposition: "completed" });
    assert.throws(() => h.router.finalTerminal(h.cohort, foreign), /terminal receipt does not match/);
    h.router.close();
  });
  const h = harness();
  h.emit({ type: "agent_start", scope: scope(1) });
  h.emit(end(scope(2)));
  h.emit(end(scope(2)));
  assert.throws(() => h.router.finalTerminal(h.cohort, scope(2)), /duplicate terminal attempt scope/);
  h.router.close();
  assert.equal(h.listeners.size, 0);
  assert.equal(h.rawListeners.size, 0);
  assert.equal(h.router.buffer.length, 0);
});

test("buffered unscoped diagnostics never acquire a promoted start's scope", async () => {
  const h = harness();
  h.emit({ type: "agent_start", scope: scope(1) });
  h.emit(end(scope(1)));
  const token = {};
  h.router.expectExecution(token);
  const next = scope(2);
  h.emit({ type: "agent_start", scope: next });
  h.emit({ type: "agent_failed", error: { code: "unscoped_failure", message: "private diagnostic" } });
  assert.doesNotMatch(JSON.stringify(h.router.buffer), /private diagnostic/);
  const events = [];
  const successor = h.router.bindExecution(token, { disposition: "promoted-to-run", attemptScope: next }, {
    onEvent: (event) => events.push(event),
  });
  assert.equal(h.router.scopes.get(scopeKey(next)).failure, undefined);
  assert.deepEqual(successor.unscopedFailure, { code: "unscoped_failure" });
  assert.doesNotMatch(JSON.stringify(events), /agent_failed|private|unscoped_failure/);
  h.emit(end(next));
  assert.deepEqual(await h.router.finalTerminal(successor, next), { disposition: "completed" });
  h.router.release();
  h.router.release();
  assert.equal(h.listeners.size, 0);
  assert.equal(h.rawListeners.size, 0);
  assert.deepEqual(h.failures, []);
});

test("unscoped terminals cannot settle tracked ownership and global notices do not cross overlap", () => {
  const h = harness();
  h.emit({ type: "agent_start", scope: scope(1) });
  h.router.expectExecution({});
  h.emit({ type: "agent_end", stopReason: "completed" });
  assert.equal(h.failures[0].code, "SDK_TRACKED_INPUT_CONTRACT");
  assert.equal(h.cohort.ended, false);
  const token = {};
  h.router.expectExecution(token);
  const successor = scope(2, "successor");
  h.emit({ type: "agent_start", scope: successor });
  h.emit({ type: "notice", message: "session-global-not-owned" });
  const events = [];
  h.router.bindExecution(token, { disposition: "promoted-to-run", attemptScope: successor }, {
    onEvent: (event) => events.push(event),
  });
  assert.equal(h.primaryEvents.some((event) => event.message === "session-global-not-owned"), false);
  assert.equal(events.some((event) => event.message === "session-global-not-owned"), false);
  h.router.close();
});

test("receipt-race buffers snapshot mutable SDK output before ownership reactions", () => {
  const h = harness();
  h.emit({ type: "agent_start", scope: scope(1) });
  const token = {};
  h.router.expectExecution(token);
  const successor = scope(2, "successor");
  h.emit({ type: "agent_start", scope: successor });
  const event = { type: "message_update", scope: successor, content: { text: "observed" } };
  h.emit(event);
  event.content.text = "x".repeat(512 * 1024);
  const events = [];
  h.router.bindExecution(token, { disposition: "promoted-to-run", attemptScope: successor }, {
    onEvent: (value) => events.push(value),
  });
  assert.equal(events.find((value) => value.type === "message_update").content.text, "observed");
  assert.equal(h.router.bufferBytes, 0);
  h.router.close();
});

test("receipt-race buffers are bounded by event count and payload size", () => {
  for (const large of [false, true]) {
    const h = harness();
    h.emit({ type: "agent_start", scope: scope(1) });
    h.emit({ type: "agent_start", scope: scope(2, "unproven") });
    if (large) h.emit({ type: "message_update", scope: scope(2, "unproven"), value: "x".repeat(256 * 1024) });
    else for (let index = 0; index < 130; index += 1) h.emit({ type: "message_update", scope: scope(2, "unproven"), value: index });
    assert.ok(h.failures.length > 0);
    assert.equal(h.failures[0].code, "SDK_TRACKED_INPUT_CONTRACT");
    assert.ok(h.router.buffer.length <= 128);
    assert.ok(h.router.bufferBytes <= 256 * 1024);
    h.router.close();
  }
});

test("unseen non-start output exhausts the same bounded quarantine without gaining ownership", () => {
  const h = harness();
  h.emit({ type: "agent_start", scope: scope(1) });
  const foreign = scope(2, "foreign");
  for (let index = 0; index < 129; index += 1) {
    h.emit({ type: "message_update", scope: foreign, value: index });
  }
  assert.equal(h.router.scopes.get(scopeKey(foreign)).cohort, undefined);
  assert.equal(h.primaryEvents.some((event) => event.value !== undefined), false);
  assert.equal(h.failures[0]?.code, "SDK_TRACKED_INPUT_CONTRACT");
  assert.equal(h.router.buffer.length, 128);
  assert.ok(h.router.bufferBytes <= 256 * 1024);
  h.router.close();
  assert.equal(h.router.buffer.length, 0);
  assert.equal(h.listeners.size, 0);
  assert.equal(h.rawListeners.size, 0);
});

test("sanitized unowned diagnostic records remain scope-bounded without leaking failure to primary", () => {
  const h = harness();
  h.emit({ type: "agent_start", scope: scope(1) });
  for (let index = 0; index < 512; index += 1) h.emit({
    type: "agent_failed", scope: scope(index + 2),
    error: { code: "foreign_failure", message: "private diagnostic" },
  });
  assert.equal(h.router.scopes.size, 512);
  assert.equal(h.router.buffer.length, 0);
  assert.equal(h.router.scopes.get(scopeKey(scope(1))).failure, undefined);
  assert.equal(h.failures[0]?.code, "SDK_TRACKED_INPUT_CONTRACT");
  assert.match(h.failures[0].message, /scope buffer exhausted/);
  assert.doesNotMatch(JSON.stringify([...h.router.scopes.values()]), /private diagnostic/);
  h.router.close();
  assert.equal(h.router.scopes.size, 0);
  assert.equal(h.listeners.size, 0);
  assert.equal(h.rawListeners.size, 0);
});

test("raw root evidence neither binds scopes nor publishes SDK readiness or output", async () => {
  const h = harness();
  const root = scope(1);
  h.emitRaw({ type: "agent_start", scope: root });
  h.emitRaw(end(root));
  assert.equal(h.router.scopes.size, 0);
  h.emit({ type: "agent_start", scope: root });
  for (const foreign of [undefined, scope(2), { ...root, lineage: "foreign" }, { ...root, attemptId: "foreign" }]) {
    h.emitRaw(end(foreign));
  }
  assert.equal(h.cohort.rawOutcome, undefined);
  assert.equal(h.router.scopes.size, 1);
  const sdkTerminal = h.router.finalTerminal(h.cohort, root);
  let published = false;
  void sdkTerminal.then(() => { published = true; });
  h.emitRaw({ type: "message_update", scope: root, value: "raw-only secret" });
  h.emitRaw({ ...end(root), messages: [{ content: "raw-only secret" }] });
  assert.deepEqual(await h.router.primaryResult(h.cohort), { disposition: "completed" });
  assert.equal(published, false);
  assert.equal(h.cohort.ended, false);
  assert.equal(h.cohort.outcome, undefined);
  assert.equal(h.router.record(root).terminal, undefined);
  assert.deepEqual(h.primaryEvents.map((event) => event.type), ["agent_start"]);
  assert.doesNotMatch(JSON.stringify([...h.router.scopes.values(), h.cohort.rawOutcome]), /raw-only secret/);
  // A later SDK publication is genuine, not a duplicate of the raw lane.
  h.emit(end(root));
  assert.deepEqual(await sdkTerminal, { disposition: "completed" });
  assert.deepEqual(h.failures, []);
  h.router.release();
  assert.equal(h.listeners.size, 0);
  assert.equal(h.rawListeners.size, 0);
});

test("late exact scoped diagnostics override raw completion without publishing readiness", async (t) => {
  for (const lane of ["public", "raw"]) await t.test(lane, async () => {
    const h = harness();
    const root = scope(1);
    h.emit({ type: "agent_start", scope: root });
    h.emitRaw({ ...end(root), messages: [{ text: "private raw body" }] });
    const diagnostic = {
      type: "agent_failed", scope: root,
      error: { code: "late_provider_failure", message: "private diagnostic body" },
    };
    if (lane === "public") h.emit(diagnostic);
    else h.emitRaw(diagnostic);
    assert.deepEqual(await h.router.primaryResult(h.cohort), { disposition: "failed", code: "late_provider_failure" });
    assert.equal(h.cohort.ended, false);
    assert.equal(h.cohort.outcome, undefined);
    assert.equal(h.router.record(root).terminal, undefined);
    assert.deepEqual(h.primaryEvents.map((event) => event.type), ["agent_start"]);
    assert.doesNotMatch(JSON.stringify([...h.router.scopes.values(), h.cohort.rawOutcome, h.cohort.rawFailure]), /private|messages/);
    h.router.release();
    assert.equal(h.listeners.size, 0);
    assert.equal(h.rawListeners.size, 0);
  });
});

test("late unscoped or foreign diagnostics cannot override owned raw completion", async (t) => {
  for (const lane of ["public", "raw"]) await t.test(lane, async () => {
    const h = harness();
    const root = scope(1);
    h.emit({ type: "agent_start", scope: root });
    h.emitRaw(end(root));
    for (const foreign of [undefined, scope(2), { ...root, lineage: "foreign" }, { ...root, attemptId: "foreign" }]) {
      const event = { type: "agent_failed", scope: foreign, error: { code: "foreign_failure", message: "private foreign body" } };
      if (lane === "public") h.emit(event);
      else h.emitRaw(event);
    }
    assert.deepEqual(await h.router.primaryResult(h.cohort), { disposition: "completed" });
    assert.equal(h.cohort.ended, false);
    assert.equal(h.router.record(root).terminal, undefined);
    assert.doesNotMatch(JSON.stringify([...h.router.scopes.values(), h.cohort.rawOutcome, h.cohort.rawFailure]), /private/);
    h.router.close();
  });
});

test("late scoped diagnostics preserve classified paused cancelled and failed raw outcomes", async (t) => {
  for (const disposition of ["paused", "cancelled", "failed"]) await t.test(disposition, async () => {
    const h = harness();
    const root = scope(1);
    h.emit({ type: "agent_start", scope: root });
    h.emitRaw(end(root, disposition));
    for (const emit of [h.emit, h.emitRaw]) emit({
      type: "agent_failed", scope: root, error: { code: "late_failure", message: "private body" },
    });
    assert.deepEqual(await h.router.primaryResult(h.cohort), { disposition });
    assert.equal(h.cohort.ended, false);
    assert.equal(h.router.record(root).terminal, undefined);
    h.router.close();
  });
});

test("a proven primary continuation invalidates an earlier raw terminal", async () => {
  const h = harness();
  h.emit({ type: "agent_start", scope: scope(1) });
  h.emitRaw(end(scope(1)));
  h.emit({ type: "turn_start", scope: scope(2) });
  assert.equal(h.cohort.rawOutcome, undefined);
  const result = h.router.primaryResult(h.cohort);
  let settled = false;
  void result.then(() => { settled = true; });
  h.emitRaw(end(scope(1)));
  h.emitRaw(end(scope(3, "unknown")));
  await Promise.resolve();
  assert.equal(settled, false);
  h.emitRaw(end(scope(2), "paused"));
  assert.deepEqual(await result, { disposition: "paused" });
  assert.equal(h.cohort.ended, false);
  h.router.close();
  assert.equal(h.listeners.size, 0);
  assert.equal(h.rawListeners.size, 0);
});

test("raw result proof cannot retire an overlapping SDK gate candidate", async () => {
  const h = harness();
  h.emit({ type: "agent_start", scope: scope(1) });
  const token = {};
  h.router.expectExecution(token);
  h.emit({ type: "agent_start", scope: scope(2) });
  h.router.bindExecution(token, { disposition: "promoted-to-run", attemptScope: scope(2) }, { onEvent: () => {} });
  h.emitRaw(end(scope(1)));
  assert.deepEqual(await h.router.primaryResult(h.cohort), { disposition: "completed" });
  const owners = [];
  h.router.gate({ gate_id: "still-overlapping" }, (owner) => owners.push(owner));
  assert.deepEqual(owners, []);
  assert.equal(h.router.hasPendingGate(), true);
  h.emit(end(scope(1)));
  assert.deepEqual(owners, []);
  h.router.close();
  assert.equal(h.rawListeners.size, 0);
});

test("both subscriptions are released even when the SDK unsubscribe throws", () => {
  const h = harness();
  const unsubscribe = h.router.unsubscribe;
  h.router.unsubscribe = () => { unsubscribe(); throw new Error("unsubscribe failed"); };
  h.router.release();
  assert.equal(h.listeners.size, 0);
  assert.equal(h.rawListeners.size, 0);
  assert.match(h.failures[0].message, /unsubscribe failed/);
  h.router.close();
});
