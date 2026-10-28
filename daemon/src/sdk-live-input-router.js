// Public SDK events are session-wide. A tracked input is a member of a logical
// run, not an independent prompt subscriber. Keep only bounded receipt-race
// buffers and sanitized terminal metadata here; never correlate by input text.
const MAX_BUFFERED_EVENTS = 128;
const MAX_BUFFERED_BYTES = 256 * 1024;
const MAX_SCOPES = 512;

export function trackedInputError(detail) {
  const error = new Error(`Invalid SDK tracked input contract: ${detail}`);
  error.code = "SDK_TRACKED_INPUT_CONTRACT";
  return error;
}

export function scopeKey(scope) {
  if (
    !scope || typeof scope !== "object" || Array.isArray(scope) ||
    typeof scope.attemptId !== "string" || scope.attemptId.length === 0 ||
    !Number.isSafeInteger(scope.generation) ||
    typeof scope.lineage !== "string" || scope.lineage.length === 0
  ) return undefined;
  return JSON.stringify([scope.attemptId, scope.generation, scope.lineage]);
}

export class SdkLiveInputRouter {
  constructor(session, { classifyTerminal, sanitizeFailure, isTerminal, onFatal }) {
    this.session = session;
    this.classifyTerminal = classifyTerminal;
    this.sanitizeFailure = sanitizeFailure;
    this.isTerminal = isTerminal;
    this.onFatal = onFatal;
    this.scopes = new Map();
    this.cohorts = new Set();
    this.pending = new Set();
    this.buffer = [];
    this.bufferBytes = 0;
    this.currentScope = undefined;
    this.primary = undefined;
    this.unsubscribe = undefined;
    this.rawUnsubscribe = undefined;
    this.references = 0;
    this.closed = false;
    this.sawPrimaryStart = false;
    this.flushing = false;
  }

  retain() {
    if (this.references === 0) {
      try {
        if (typeof this.session.agent?.subscribe !== "function") {
          throw trackedInputError("public AgentSession.agent.subscribe is unavailable");
        }
        this.unsubscribe = this.session.subscribe((event) => {
          try { this.route(event); } catch (error) { this.onFatal(error); }
        });
        if (typeof this.unsubscribe !== "function") {
          throw trackedInputError("session subscription lacks disposal");
        }
        this.rawUnsubscribe = this.session.agent.subscribe((event) => {
          try { this.observeRaw(event); } catch {
            this.onFatal(trackedInputError("invalid core execution evidence"));
          }
        });
        if (typeof this.rawUnsubscribe !== "function") {
          throw trackedInputError("core subscription lacks disposal");
        }
      } catch (error) {
        try { this.releaseSubscriptions(); } catch {
          // Fatal session disposal is the final containment boundary.
        }
        this.onFatal(error);
        throw error;
      }
    }
    this.references += 1;
  }

  releaseSubscriptions() {
    let failure;
    for (const key of ["unsubscribe", "rawUnsubscribe"]) {
      const unsubscribe = this[key];
      this[key] = undefined;
      try { if (typeof unsubscribe === "function") unsubscribe(); } catch (error) {
        failure ??= error;
      }
    }
    if (failure) throw failure;
  }

  release() {
    this.references -= 1;
    if (this.references !== 0 || this.closed) return;
    if (this.buffer.length > 0) {
      this.onFatal(trackedInputError("unowned successor events remained after command settlement"));
      return;
    }
    try { this.releaseSubscriptions(); } catch (error) {
      this.onFatal(error);
      return;
    }
    this.scopes.clear();
    this.cohorts.clear();
    this.buffer.length = 0;
    this.bufferBytes = 0;
    this.primary = undefined;
    this.currentScope = undefined;
    this.sawPrimaryStart = false;
  }

  openPrimary(owner) {
    this.retain();
    const cohort = this.createCohort(owner);
    this.primary = cohort;
    return cohort;
  }

  // Root execution proof is not SDK readiness or a tracked terminal receipt.
  // Call only after settlement of this cohort's exact public root prompt, so a
  // later SDK-owned continuation invalidates earlier raw evidence first.
  primaryResult(cohort) {
    const outcome = this.primaryResultOutcome(cohort);
    if (outcome !== undefined) return Promise.resolve(outcome);
    let waiter;
    const rawResult = new Promise((resolve) => {
      waiter = resolve;
      cohort.resultWaiters.push(resolve);
    });
    return Promise.race([cohort.terminal, rawResult]).finally(() => {
      const index = cohort.resultWaiters.indexOf(waiter);
      if (index >= 0) cohort.resultWaiters.splice(index, 1);
    });
  }

  primaryResultOutcome(cohort) {
    if (cohort.ended) return cohort.outcome;
    const outcome = cohort.rawOutcome;
    const record = this.scopes.get(cohort.resultKey);
    const failure = record?.cohort === cohort
      ? record.failure ?? cohort.rawFailure : undefined;
    // Diagnostics may arrive after the raw end but before root prompt
    // settlement. Reconcile only completed execution proof, preserving explicit
    // pause/cancellation and already-classified maintenance/provider failures.
    return outcome?.disposition === "completed" && failure
      ? { disposition: "failed", code: failure.code } : outcome;
  }

  resolvePrimaryResult(cohort) {
    const outcome = this.primaryResultOutcome(cohort);
    if (outcome === undefined) return;
    for (const resolve of cohort.resultWaiters.splice(0)) resolve(outcome);
  }

  observeRaw(event) {
    if (this.closed || !this.primary) return;
    if (event?.type !== "agent_end" && event?.type !== "agent_failed") return;
    // Lookup only: raw scopes never create records or establish ownership.
    const record = this.scopes.get(scopeKey(event?.scope));
    const cohort = this.primary;
    if (!record || record.cohort !== cohort || cohort.resultKey !== record.key) return;
    if (event?.type === "agent_failed") {
      cohort.rawFailure = this.sanitizeFailure(event.error);
    } else if (this.isTerminal(event)) {
      // Classify immediately; never retain mutable messages or stream raw output.
      cohort.rawOutcome = this.classifyTerminal(event, record.failure ?? cohort.rawFailure);
      this.resolvePrimaryResult(cohort);
    } else {
      // A continuing maintenance checkpoint is not a final execution result.
      cohort.rawOutcome = undefined;
    }
  }

  createCohort(owner) {
    let resolveTerminal;
    const terminal = new Promise((resolve) => { resolveTerminal = resolve; });
    const cohort = { owner, members: new Set(owner ? [owner] : []), terminal, resolveTerminal, ended: false, outcome: undefined, resultWaiters: [] };
    this.cohorts.add(cohort);
    return cohort;
  }

  expectExecution(token) {
    this.retain();
    this.pending.add(token);
  }

  forgetExecution(token) {
    this.pending.delete(token);
    this.flush();
  }

  record(scope) {
    const key = scopeKey(scope);
    if (key === undefined) return undefined;
    let record = this.scopes.get(key);
    if (!record) {
      if (this.scopes.size >= MAX_SCOPES) throw trackedInputError("scope buffer exhausted");
      record = { key, cohort: undefined, boundary: false, failure: undefined, terminal: undefined, waiters: [] };
      this.scopes.set(key, record);
    }
    return record;
  }

  bind(record, cohort) {
    if (record.cohort && record.cohort !== cohort) {
      throw trackedInputError("conflicting logical-run scope");
    }
    record.cohort = cohort;
  }

  bindExecution(token, receipt, owner, onBind) {
    const record = this.record(receipt.attemptScope);
    if (!record) throw trackedInputError("missing execution attempt scope");
    let cohort;
    if (receipt.disposition === "promoted-to-run") {
      cohort = record.boundary ? record.cohort : this.createCohort();
      if (cohort.owner) throw trackedInputError("duplicate promoted run owner");
      cohort.owner = owner;
      record.boundary = true;
    } else {
      cohort = record.cohort ?? this.cohortBefore(record);
      if (!cohort) throw trackedInputError("joined execution has no originating run");
    }
    cohort.members.add(owner);
    this.bind(record, cohort);
    this.pending.delete(token);
    onBind?.();
    this.flush();
    return cohort;
  }

  cohortBefore(target) {
    let cohort;
    for (const record of this.scopes.values()) {
      if (record.boundary) cohort = record.cohort;
      if (record === target) return cohort;
    }
    return undefined;
  }

  finalTerminal(cohort, scope) {
    const record = this.record(scope);
    if (!record) throw trackedInputError("missing terminal attempt scope");
    if (cohort.ended && cohort.finalKey !== record.key) {
      throw trackedInputError("terminal receipt does not match the owning run terminal");
    }
    this.bind(record, cohort);
    this.flush();
    if (record.terminal !== undefined) return Promise.resolve(record.terminal);
    return new Promise((resolve) => { record.waiters.push(resolve); });
  }

  route(event) {
    if (this.closed || !this.primary) return;
    const record = this.record(event?.scope);
    if (!record && this.isTerminal(event) && (this.references > 1 || this.cohorts.size > 1)) {
      throw trackedInputError("unscoped terminal cannot settle tracked ownership");
    }
    if (!record && [...this.cohorts].filter((cohort) => !cohort.ended).length > 1) {
      // Session-global notices are not per-submission output. No latest-run
      // inference can authorize forwarding an unscoped event across overlap.
      return;
    }
    if (event?.type === "agent_start" && record) {
      if (!this.sawPrimaryStart) {
        this.sawPrimaryStart = true;
        record.boundary = true;
        if (!record.cohort) this.bind(record, this.primary);
      } else if (!record.cohort) {
        // agent_start opens a logical run; turn_start only changes provider
        // attempt scope. An unproven successor is never primary output.
        record.boundary = true;
        this.bind(record, this.createCohort());
      }
    }
    if (event?.type === "turn_start" && record && !record.cohort) {
      // Only a public start can extend a known run to a new provider tuple.
      // Data, diagnostics and terminals may precede an exact receipt instead;
      // their arrival order is not evidence that they belong to this run.
      const cohort = this.cohortBefore(record);
      if (cohort) this.bind(record, cohort);
    }
    if (event?.type === "agent_start" || event?.type === "turn_start") {
      this.currentScope = record;
    }
    const target = record ?? this.currentScope;
    // An already-known old scope always stays with its original cohort, even
    // after a promoted successor has started before the old public terminal.
    const cohort = target?.cohort ?? (!target ? this.primary : undefined);
    if (record && cohort === this.primary &&
        (event?.type === "agent_start" || event?.type === "turn_start")) {
      // Only an SDK-scoped primary start proves the exact raw execution tuple.
      // Refresh even on a repeated scope: a new attempt needs a new terminal.
      cohort.resultKey = record.key;
      cohort.rawOutcome = undefined;
      cohort.rawFailure = undefined;
    }
    if (!cohort?.owner) {
      if (event?.type === "agent_failed") {
        // Quarantine only sanitized metadata, preserving the original scope.
        // A diagnostic is not ownership proof or streamable output.
        const failure = this.sanitizeFailure(event.error);
        if (record) record.failure = failure;
        else this.bufferEvent({ event: { type: "agent_failed", error: failure }, record, target });
        return;
      }
      this.bufferEvent({ event, record, target });
      return;
    }
    this.deliver(event, record, cohort);
    this.flush();
  }

  deliver(event, record, cohort) {
    for (const member of cohort.members) member.controller?.arm();
    if (event?.type === "agent_start") cohort.owner.sawAgentStart = true;
    if (event?.type === "agent_failed") {
      // An unscoped diagnostic cannot authorize a scoped terminal failure.
      if (record) record.failure = this.sanitizeFailure(event.error);
      else cohort.unscopedFailure = this.sanitizeFailure(event.error);
      return;
    }
    if (this.isTerminal(event)) {
      if (cohort.ended && cohort.finalKey !== record?.key) {
        throw trackedInputError("multiple final scopes for one logical run");
      }
      const outcome = this.classifyTerminal(event, record ? record.failure : cohort.unscopedFailure);
      if (record) {
        if (record.terminal !== undefined) throw trackedInputError("duplicate terminal attempt scope");
        record.terminal = outcome;
        for (const resolve of record.waiters.splice(0)) resolve(outcome);
      }
      cohort.ended = true;
      cohort.finalKey = record?.key;
      cohort.outcome = outcome;
      cohort.resolveTerminal(outcome);
      return;
    }
    if (event?.type === "agent_end") return;
    try { cohort.owner.onEvent(event); } catch (error) {
      cohort.owner.eventConsumerError ??= error instanceof Error
        ? error : new Error("SDK event consumer failed");
    }
  }

  bufferEvent(item) {
    const payloadKey = item.present ? "gate" : "event";
    let serialized;
    let size;
    try {
      serialized = JSON.stringify(item[payloadKey]);
      size = Buffer.byteLength(serialized, "utf8");
    } catch {
      throw trackedInputError("unbufferable public event");
    }
    if (this.buffer.length >= MAX_BUFFERED_EVENTS || this.bufferBytes + size > MAX_BUFFERED_BYTES) {
      throw trackedInputError("public event receipt-race buffer exhausted");
    }
    // SDK streaming objects can be mutated after delivery. Snapshot the same
    // bounded wire representation we measured instead of retaining that alias.
    this.buffer.push({ ...item, [payloadKey]: JSON.parse(serialized), size });
    this.bufferBytes += size;
  }

  gate(gate, present) {
    if (this.buffer.some((item) => item.present && item.gate?.gate_id === gate?.gate_id)) return;
    const candidates = [...this.cohorts].filter((cohort) => !cohort.ended);
    if (this.closed || !this.primary || (candidates.length === 0 && this.pending.size === 0)) {
      present(undefined);
      return;
    }
    // A single proven live cohort owns joined-input gates. Multiple live
    // cohorts have no public gate->attempt mapping (runtime_turn_id belongs to
    // the SDK host); never replace its provider or guess the latest input.
    if (candidates.length === 1 && candidates[0].owner) {
      present(candidates[0].owner);
      return;
    }
    // Freeze the only candidate at emission time. If there were two live
    // cohorts then, a later terminal cannot retroactively prove which emitted
    // this unscoped gate. Its existing answer-window timer fails explicitly.
    this.bufferEvent({ gate, cohort: candidates.length === 1 ? candidates[0] : undefined, present });
    this.flush();
  }

  flush() {
    if (this.closed || this.flushing) return;
    this.flushing = true;
    try {
    const buffered = this.buffer;
    this.buffer = [];
    this.bufferBytes = 0;
    for (const item of buffered) {
      if (item.present) {
        if (item.cohort?.ended) item.present(undefined);
        else if (item.cohort?.owner) item.present(item.cohort.owner);
        else this.bufferEvent(item);
      } else {
        // Routing an unscoped event through a pending start does not give it
        // that start's scope (in particular, not for failure classification).
        const cohort = item.target ? item.target.cohort : this.primary;
        if (cohort?.owner) this.deliver(item.event, item.record, cohort);
        else this.bufferEvent(item);
      }
    }
    } finally { this.flushing = false; }
  }

  hasPendingGate() {
    return this.buffer.some((item) => item.present);
  }

  pendingGateValues() {
    return this.buffer.filter((item) => item.present).map((item) => item.gate);
  }

  close() {
    this.closed = true;
    try { this.releaseSubscriptions(); } catch {
      // The underlying SDK disposal is the remaining containment boundary.
    }
    this.buffer.length = 0;
    this.bufferBytes = 0;
    for (const record of this.scopes.values()) record.waiters.length = 0;
    for (const cohort of this.cohorts) cohort.resultWaiters.length = 0;
    this.scopes.clear();
    this.pending.clear();
    this.cohorts.clear();
    this.primary = undefined;
    this.currentScope = undefined;
  }
}
