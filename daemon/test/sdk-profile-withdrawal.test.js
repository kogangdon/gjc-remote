import assert from "node:assert/strict";
import { join, resolve, sep } from "node:path";
import test from "node:test";

import { createSdkProfileAdmission } from "../src/sdk-profile-admission.js";
import { createProfileDecisionState, nextProfileDecision } from "../src/sdk-profile-decision.js";
import { SdkProfileTargetError } from "../src/sdk-profile-target.js";
import { createSdkSession, SdkSession } from "../src/sdk-session.js";
import { SessionPool } from "../src/session-pool.js";

const WORK_DIR = resolve("test-only-withdrawal-workspace");
const ALIAS_WORK_DIR = `${WORK_DIR}${sep}.`;

function deferred() {
  let resolvePromise;
  let rejectPromise;
  const promise = new Promise((resolve, reject) => {
    resolvePromise = resolve;
    rejectPromise = reject;
  });
  return { promise, resolve: resolvePromise, reject: rejectPromise };
}

function observe(promise) {
  const observation = { settlements: 0, status: "pending" };
  observation.result = promise.then(
    (value) => {
      observation.settlements += 1;
      observation.status = "fulfilled";
      return { status: "fulfilled", value };
    },
    (reason) => {
      observation.settlements += 1;
      observation.status = "rejected";
      return { status: "rejected", reason };
    }
  );
  return observation;
}

function disposalDeadline() {
  const error = new Error("synthetic SDK caller disposal deadline");
  error.name = "SessionDisposalIncompleteError";
  return error;
}

// Only the transport is synthetic. Queue ownership, input routing, factory
// activation, admission generations, and pool retirement use the local code.
class SyntheticSdkTransport {
  constructor() {
    this.listeners = new Set();
    this.rawListeners = new Set();
    this.calls = [];
    this.holds = new Map();
    this.disposeCalls = 0;
    this.abortCalls = 0;
    this.completionCalls = 0;
    this.disposeCompletion = Promise.resolve();
    this.completionEntered = deferred();
    this.settings = { get: (key) => key === "modelProfile.default" ? "synthetic-profile" : undefined };
    this.agent = {
      subscribe: (listener) => {
        this.rawListeners.add(listener);
        return () => this.rawListeners.delete(listener);
      },
      abort: () => { this.abortCalls += 1; },
    };
  }

  subscribe(listener) {
    this.listeners.add(listener);
    return () => this.listeners.delete(listener);
  }

  emit(event) {
    for (const listener of this.listeners) listener(event);
  }

  holdPrompt(message) {
    const hold = { started: deferred(), completion: deferred() };
    this.holds.set(message, hold);
    return hold;
  }

  async prompt(message) {
    this.calls.push({ type: "prompt", message });
    const scope = { attemptId: `synthetic-${this.calls.length}`, generation: this.calls.length, lineage: "main" };
    this.emit({ type: "agent_start", scope });
    this.emit({ type: "message_update", scope, value: message });
    const hold = this.holds.get(message);
    hold?.started.resolve();
    if (hold) await hold.completion.promise;
    this.emit({
      type: "agent_end",
      scope,
      stopReason: "completed",
      messages: [{ role: "assistant", content: [{ type: "text", text: message }], stopReason: "stop" }],
    });
  }

  submitUserMessage(message) {
    this.calls.push({ type: "submitUserMessage", message });
    throw new Error("guarded live input must not reach the synthetic SDK");
  }

  async activateModelProfileForControl() {
    return true;
  }

  async dispose() {
    this.disposeCalls += 1;
    if (this.disposeError) throw this.disposeError;
  }

  async awaitDisposeCompletion() {
    this.completionCalls += 1;
    this.completionEntered.resolve();
    await this.disposeCompletion;
  }
}

function fixture({ targetGate, sdkGate, publicationGate, poolOptions } = {}) {
  const profile = Object.freeze({
    agentDir: resolve("test-only-withdrawal-profile"),
    credentialPath: join(resolve("test-only-withdrawal-profile"), "agent.db"),
    recipient: "synthetic-recipient",
    configIdentity: "synthetic-config-identity",
    credentialIdentity: "synthetic-credential-identity",
  });
  const decisions = createProfileDecisionState();
  let record = nextProfileDecision(null, profile);
  decisions.apply(record);
  const listeners = new Set();
  const leases = [];
  const transports = [];
  const sdkOptions = [];
  const targetEntered = deferred();
  const sdkEntered = deferred();
  const publicationEntered = deferred();
  function publish(selection) {
    record = nextProfileDecision(record, selection);
    decisions.apply(record);
  }
  const admission = createSdkProfileAdmission({
    store: {
      capture: decisions.capture,
      isCurrent: decisions.isCurrent,
      subscribe(listener) {
        listeners.add(listener);
        const remove = decisions.subscribe(listener);
        return () => { remove(); listeners.delete(listener); };
      },
    },
    sessionRoot: resolve("test-only-withdrawal-transcripts"),
    async openTarget(expected) {
      assert.deepEqual(expected, profile);
      const lease = {
        profile,
        startupAuthConfig: Object.freeze({ broker: null, credentialStoreIdentity: `local:${profile.credentialPath}` }),
        closeCalls: 0,
        assertCurrent() {
          if (this.failure) throw this.failure;
          assert.equal(this.closeCalls, 0, "a closed target cannot be consulted");
        },
        close() { this.closeCalls += 1; },
      };
      leases.push(lease);
      targetEntered.resolve();
      if (targetGate) await targetGate.promise;
      return lease;
    },
    async createSession(workDir, unusedLoader, options) {
      assert.equal(unusedLoader, undefined);
      const session = await createSdkSession(workDir, async () => ({
        SessionManager: { create: (cwd, directory) => ({ cwd, directory }) },
        async createAgentSession(value) {
          const transport = new SyntheticSdkTransport();
          transports.push(transport);
          sdkOptions.push(value);
          sdkEntered.resolve();
          if (sdkGate) await sdkGate.promise;
          return { session: transport };
        },
      }), options);
      publicationEntered.resolve();
      if (publicationGate) await publicationGate.promise;
      return session;
    },
  });
  const pool = new SessionPool({
    sessionFactory: (workDir, binding) => admission.create(workDir, binding),
    statSyncFn: () => ({ isDirectory: () => true }),
    realpathSyncFn: () => WORK_DIR,
    ...poolOptions,
  });
  return {
    profile, admission, pool, leases, transports, sdkOptions, listeners,
    targetEntered, sdkEntered, publicationEntered,
    withdraw: () => publish(null),
    regrant: () => publish(profile),
  };
}

test("pool withdrawal rejects B/C once across identical regrant while running A drains; fresh work uses a new session", { timeout: 5_000 }, async (t) => {
  const f = fixture();
  t.after(() => f.pool.shutdown());
  const oldBinding = f.admission.capture();
  const session = await f.pool.ensureSession(WORK_DIR, { profileBinding: oldBinding });
  assert.ok(session instanceof SdkSession);
  assert.strictEqual(await f.pool.ensureSession(ALIAS_WORK_DIR, { profileBinding: oldBinding }), session);
  assert.equal(f.sdkOptions[0].agentDir, f.profile.agentDir);
  assert.equal(f.sdkOptions[0].profileAuthority, "custom");
  assert.strictEqual(f.sdkOptions[0].startupAuthConfig, f.leases[0].startupAuthConfig);
  const sdk = f.transports[0];
  const hold = sdk.holdPrompt("A");
  t.after(() => hold.completion.resolve());
  const events = [];
  const a = session.sendOwned("owner-A", { type: "prompt", message: "A" }, (event) => events.push(event));
  const running = observe(a.result);
  await hold.started.promise;
  const activations = [0, 0];
  const queuedEvents = [];
  const tickets = ["B", "C"].map((message, index) => session.sendOwned(
    `owner-${message}`, { type: "prompt", message }, (event) => queuedEvents.push(event), undefined,
    { onActivate: () => { activations[index] += 1; } }
  ));
  const queued = tickets.map((ticket) => observe(ticket.result));
  f.withdraw();
  f.withdraw();
  f.regrant();
  const newBinding = f.admission.capture();
  assert.notStrictEqual(newBinding, oldBinding);
  assert.strictEqual(f.admission.capture(), newBinding);
  for (const [index, observation] of queued.entries()) {
    const result = await observation.result;
    assert.equal(result.status, "rejected");
    assert.equal(result.reason.code, "SDK_PROFILE_WITHDRAWN");
    assert.equal(observation.settlements, 1);
    assert.equal(tickets[index].phase, "terminal");
    assert.equal(tickets[index].revokeBeforeStart(), false);
  }
  assert.equal(running.status, "pending");
  assert.equal(a.phase, "active");
  assert.equal(session.closed, false);
  assert.equal(sdk.disposeCalls, 0);
  assert.equal(sdk.abortCalls, 0);
  assert.equal(f.leases[0].closeCalls, 0);
  sdk.emit({ type: "message_update", value: "A continues after withdrawal" });
  assert.ok(events.some((event) => event.value === "A continues after withdrawal"));
  await assert.rejects(f.pool.ensureSession(WORK_DIR, { profileBinding: oldBinding }), { code: "SDK_PROFILE_WITHDRAWN" });
  await assert.rejects(f.pool.ensureSession(WORK_DIR, { profileBinding: newBinding }), { code: "LEASE_CONFLICT" });
  await assert.rejects(session.send({ type: "prompt", message: "stale cached work" }, () => {}), { code: "SDK_PROFILE_WITHDRAWN" });
  assert.equal(f.transports.length, 1);
  hold.completion.resolve();
  assert.deepEqual(await running.result, { status: "fulfilled", value: { disposition: "completed" } });
  await session.queue;
  assert.equal(session.isBusy(), false);
  assert.deepEqual(activations, [0, 0]);
  assert.deepEqual(queuedEvents, []);
  assert.deepEqual(queued.map((observation) => observation.settlements), [1, 1]);
  assert.deepEqual(sdk.calls, [{ type: "prompt", message: "A" }]);
  assert.equal(sdk.disposeCalls, 0);
  const replacement = await f.pool.ensureSession(WORK_DIR, { profileBinding: newBinding });
  assert.notStrictEqual(replacement, session);
  assert.equal(sdk.disposeCalls, 1);
  assert.equal(sdk.completionCalls, 1);
  assert.equal(f.leases[0].closeCalls, 1);
  assert.deepEqual(await replacement.send({ type: "prompt", message: "fresh D" }, () => {}), { disposition: "completed" });
  await assert.rejects(session.send({ type: "prompt", message: "stale after replacement" }, () => {}));
  assert.deepEqual(sdk.calls, [{ type: "prompt", message: "A" }]);
  assert.deepEqual(f.transports[1].calls, [{ type: "prompt", message: "fresh D" }]);
  await f.pool.shutdown();
  assert.equal(f.leases[1].closeCalls, 1);
  assert.equal(f.listeners.size, 0);
});

test("shared pending target, SDK, and adapter publication cannot revive work after identical regrant", { timeout: 5_000 }, async (t) => {
  for (const phase of ["target", "sdk", "publication"]) await t.test(phase, async (t) => {
    const gate = deferred();
    const f = fixture({
      targetGate: phase === "target" ? gate : undefined,
      sdkGate: phase === "sdk" ? gate : undefined,
      publicationGate: phase === "publication" ? gate : undefined,
    });
    t.after(async () => { gate.resolve(); await f.pool.shutdown(); });
    const binding = f.admission.capture();
    const first = observe(f.pool.ensureSession(WORK_DIR, { profileBinding: binding }));
    await ({ target: f.targetEntered, sdk: f.sdkEntered, publication: f.publicationEntered })[phase].promise;
    const joined = observe(f.pool.ensureSession(ALIAS_WORK_DIR, { profileBinding: binding }));
    const transition = observe(f.pool.sessionTransitions.get(WORK_DIR).operation);
    f.withdraw();
    f.regrant();
    const freshBinding = f.admission.capture();
    for (const caller of [first, joined]) {
      const result = await caller.result;
      assert.equal(result.status, "rejected");
      assert.equal(result.reason.code, "SDK_PROFILE_WITHDRAWN");
      assert.equal(caller.settlements, 1);
    }
    assert.equal(f.leases.length, 1);
    assert.equal(f.leases[0].closeCalls, 0);
    assert.equal(f.pool.sessions.get(WORK_DIR).session, undefined);
    await assert.rejects(f.pool.ensureSession(WORK_DIR, { profileBinding: freshBinding }), { code: "LEASE_CONFLICT" });
    gate.resolve();
    const settled = await transition.result;
    assert.equal(settled.status, "rejected");
    assert.equal(settled.reason.code, "SDK_PROFILE_WITHDRAWN");
    assert.equal(f.leases[0].closeCalls, 1);
    assert.equal(f.pool.sessions.size, 0);
    assert.equal(f.pool.sessionTransitions.size, 0);
    assert.equal(f.pool.creationHolds.size, 0);
    assert.equal(f.pool.retirements.size, 0);
    for (const sdk of f.transports) {
      assert.deepEqual(sdk.calls, []);
      assert.equal(sdk.disposeCalls, 1);
    }
    const fresh = await f.pool.ensureSession(WORK_DIR, { profileBinding: freshBinding });
    assert.deepEqual(await fresh.send({ type: "prompt", message: "fresh after pending withdrawal" }, () => {}), { disposition: "completed" });
    assert.deepEqual(f.transports.at(-1).calls, [{ type: "prompt", message: "fresh after pending withdrawal" }]);
    assert.deepEqual([first.settlements, joined.settlements], [1, 1]);
  });
});

test("guarded live controls refuse while idle or active, and withdrawal retains its distinct refusal", { timeout: 5_000 }, async (t) => {
  const f = fixture();
  t.after(() => f.pool.shutdown());
  const session = await f.pool.ensureSession(WORK_DIR, { profileBinding: f.admission.capture() });
  const sdk = f.transports[0];
  for (const type of ["steer", "follow_up"]) {
    await assert.rejects(session.send({ type, message: `idle ${type}` }, () => {}), { code: "SDK_PROFILE_LIVE_UNSUPPORTED" });
  }
  assert.deepEqual(sdk.calls, []);
  const hold = sdk.holdPrompt("running root");
  t.after(() => hold.completion.resolve());
  const running = observe(session.send({ type: "prompt", message: "running root" }, () => {}));
  await hold.started.promise;
  for (const type of ["steer", "follow_up"]) {
    let activated = false;
    const ticket = session.sendOwned(type, { type, message: `active ${type}` }, () => {}, undefined,
      { onActivate: () => { activated = true; } });
    await assert.rejects(ticket.result, { code: "SDK_PROFILE_LIVE_UNSUPPORTED" });
    assert.equal(activated, false);
  }
  f.withdraw();
  f.regrant();
  for (const type of ["steer", "follow_up"]) {
    await assert.rejects(session.send({ type, message: `stale ${type}` }, () => {}), { code: "SDK_PROFILE_WITHDRAWN" });
  }
  assert.equal(running.status, "pending");
  assert.equal(sdk.disposeCalls, 0);
  assert.deepEqual(sdk.calls, [{ type: "prompt", message: "running root" }]);
  hold.completion.resolve();
  assert.equal((await running.result).status, "fulfilled");
});

test("a pinned target refusal is not relabeled as grant withdrawal or sent to the SDK", { timeout: 5_000 }, async (t) => {
  const f = fixture();
  t.after(() => f.pool.shutdown());
  const binding = f.admission.capture();
  const session = await f.pool.ensureSession(WORK_DIR, { profileBinding: binding });
  const refusal = new SdkProfileTargetError("synthetic-target-changed");
  f.leases[0].failure = refusal;
  await assert.rejects(session.send({ type: "prompt", message: "refused target" }, () => {}), (error) => {
    assert.strictEqual(error, refusal);
    assert.equal(error.code, "ERR_SDK_PROFILE_TARGET_REFUSED");
    return true;
  });
  assert.strictEqual(f.admission.capture(), binding, "target failure does not revoke the management grant");
  f.leases[0].failure = undefined;
  await assert.rejects(session.send({ type: "prompt", message: "stale target reuse" }, () => {}), (error) => error === refusal);
  assert.deepEqual(f.transports[0].calls, []);
  await session.queue;
  f.withdraw();
  f.regrant();
  await assert.rejects(f.pool.ensureSession(WORK_DIR, { profileBinding: binding }), { code: "SDK_PROFILE_WITHDRAWN" });
  const fresh = await f.pool.ensureSession(WORK_DIR, { profileBinding: f.admission.capture() });
  assert.deepEqual(await fresh.send({ type: "prompt", message: "requalified target" }, () => {}), { disposition: "completed" });
});

test("managed retirement joins retained SDK teardown before pin release and cached replacement", { timeout: 5_000 }, async (t) => {
  for (const initialResult of ["deadline", "success"]) await t.test(initialResult, async (t) => {
    const completion = deferred();
    const f = fixture({ poolOptions: { sessionDisposeTimeoutMs: 5 } });
    t.after(async () => { completion.resolve(); await f.pool.shutdown(); });
    const binding = f.admission.capture();
    const session = await f.pool.ensureSession(WORK_DIR, { profileBinding: binding });
    const sdk = f.transports[0];
    sdk.disposeError = initialResult === "deadline" ? disposalDeadline() : undefined;
    sdk.disposeCompletion = completion.promise;
    const retiring = observe(f.pool.retireSession(session));
    await sdk.completionEntered.promise;
    assert.equal(f.leases[0].closeCalls, 0);
    const result = await retiring.result;
    assert.equal(result.status, "rejected");
    assert.equal(result.reason.code, "SESSION_RETIREMENT_PENDING");
    await assert.rejects(f.pool.ensureSession(WORK_DIR, { profileBinding: binding }), { code: "SESSION_RETIREMENT_PENDING" });
    completion.resolve();
    await result.reason.pendingCleanup;
    await session.dispose();
    assert.equal(f.leases[0].closeCalls, 1);
    assert.equal(sdk.disposeCalls, 1);
    assert.equal(sdk.completionCalls, 1);
    assert.equal(f.pool.retirements.size, 0);
    const fresh = await f.pool.ensureSession(WORK_DIR, { profileBinding: binding });
    assert.notStrictEqual(fresh, session);
    assert.deepEqual(await fresh.send({ type: "prompt", message: "after confirmed teardown" }, () => {}), { disposition: "completed" });
  });
});

test("failed managed teardown retains pins and prevents identical regrant from bypassing retirement", { timeout: 5_000 }, async (t) => {
  for (const failureAt of ["dispose", "completion", "missing-completion"]) await t.test(failureAt, async (t) => {
    const completion = deferred();
    const f = fixture();
    t.after(() => f.pool.shutdown());
    const binding = f.admission.capture();
    const session = await f.pool.ensureSession(WORK_DIR, { profileBinding: binding });
    const sdk = f.transports[0];
    const failure = failureAt === "missing-completion" ? undefined : new Error("synthetic owned store teardown failed");
    sdk.disposeError = failureAt === "completion" ? disposalDeadline() : failure;
    if (failureAt === "missing-completion") sdk.awaitDisposeCompletion = undefined;
    sdk.disposeCompletion = completion.promise;
    const retiring = observe(f.pool.retireSession(session));
    if (failureAt === "completion") {
      await sdk.completionEntered.promise;
      assert.equal(f.leases[0].closeCalls, 0);
      completion.reject(failure);
    } else {
      completion.resolve();
    }
    const result = await retiring.result;
    assert.equal(result.status, "rejected");
    assert.equal(result.reason.code, "SESSION_RETIREMENT_FAILED");
    await assert.rejects(session.dispose(), (error) =>
      error.sdkDisposalState === "unconfirmed" &&
      (failureAt === "missing-completion" ? error instanceof TypeError : error === failure)
    );
    assert.equal(sdk.disposeCalls, 1);
    assert.equal(sdk.completionCalls, failureAt === "completion" ? 1 : 0);
    assert.equal(f.leases[0].closeCalls, 0);
    assert.equal(f.pool.retirements.get(WORK_DIR).state, "failed");
    f.withdraw();
    f.regrant();
    await assert.rejects(f.pool.ensureSession(WORK_DIR, { profileBinding: f.admission.capture() }), { code: "SESSION_RETIREMENT_FAILED" });
    assert.equal(f.transports.length, 1);
  });
});

test("withdrawn unpublished SDK creation joins late teardown and fences a failed completion", { timeout: 5_000 }, async (t) => {
  for (const outcome of ["fulfilled", "rejected"]) await t.test(outcome, async (t) => {
    const creation = deferred();
    const completion = deferred();
    const f = fixture({ sdkGate: creation });
    t.after(async () => { creation.resolve(); completion.resolve(); await f.pool.shutdown(); });
    const binding = f.admission.capture();
    const caller = observe(f.pool.ensureSession(WORK_DIR, { profileBinding: binding }));
    await f.sdkEntered.promise;
    const transition = observe(f.pool.sessionTransitions.get(WORK_DIR).operation);
    const sdk = f.transports[0];
    sdk.disposeError = disposalDeadline();
    sdk.disposeCompletion = completion.promise;
    f.withdraw();
    f.regrant();
    const withdrawn = await caller.result;
    assert.equal(withdrawn.status, "rejected");
    assert.equal(withdrawn.reason.code, "SDK_PROFILE_WITHDRAWN");
    creation.resolve();
    await sdk.completionEntered.promise;
    assert.equal(f.leases[0].closeCalls, 0);
    assert.equal(transition.status, "pending");
    await assert.rejects(f.pool.ensureSession(WORK_DIR, { profileBinding: f.admission.capture() }), { code: "LEASE_CONFLICT" });
    if (outcome === "fulfilled") completion.resolve();
    else completion.reject(new Error("synthetic unpublished teardown failed"));
    const result = await transition.result;
    assert.equal(result.status, "rejected");
    assert.equal(result.reason.code, "SDK_PROFILE_WITHDRAWN");
    assert.equal(result.reason.sdkDisposalState, outcome === "fulfilled" ? "disposed" : "unconfirmed");
    assert.deepEqual(sdk.calls, []);
    assert.equal(sdk.disposeCalls, 1);
    assert.equal(sdk.completionCalls, 1);
    assert.equal(f.leases[0].closeCalls, outcome === "fulfilled" ? 1 : 0);
    if (outcome === "fulfilled") {
      const fresh = await f.pool.ensureSession(WORK_DIR, { profileBinding: f.admission.capture() });
      assert.deepEqual(await fresh.send({ type: "prompt", message: "after unpublished cleanup" }, () => {}), { disposition: "completed" });
    } else {
      await assert.rejects(f.pool.ensureSession(WORK_DIR, { profileBinding: f.admission.capture() }), { code: "SESSION_RETIREMENT_FAILED" });
    }
  });
});

test("ordinary sessions keep caller-deadline disposal behavior without joining managed-profile cleanup", { timeout: 5_000 }, async () => {
  const sdk = new SyntheticSdkTransport();
  sdk.disposeError = disposalDeadline();
  let releases = 0;
  const session = new SdkSession(sdk, { onSdkDisposed: () => { releases += 1; } });
  await assert.rejects(session.dispose(), (error) => error === sdk.disposeError && error.sdkDisposalState === "unconfirmed");
  assert.equal(sdk.disposeCalls, 1);
  assert.equal(sdk.completionCalls, 0);
  assert.equal(releases, 0);
});
