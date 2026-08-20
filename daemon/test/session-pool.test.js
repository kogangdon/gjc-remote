import assert from "node:assert/strict";
import test from "node:test";

import { SessionPool } from "../src/session-pool.js";

class FakeSession {
  constructor() {
    this.closed = false;
    this.disposeCalls = 0;
  }

  async dispose() {
    this.disposeCalls += 1;
    this.closed = true;
  }
}

const WORK_DIR = process.platform === "win32" ? String.raw`C:\work` : "/work";
const ALIAS_WORK_DIR = process.platform === "win32" ? "C:/work/." : "/work/.";

function createPool(overrides = {}) {
  return new SessionPool({
    statSyncFn: () => ({ isDirectory: () => true }),
    realpathSyncFn: () => WORK_DIR,
    ...overrides,
  });
}

function receiptIdentity(socketGeneration, bindingId, digit) {
  return {
    socketGeneration,
    bindingId,
    bindingFingerprint: digit.repeat(64),
  };
}

test("a closed SDK session is disposed and replaced", async () => {
  const created = [];
  const pool = createPool({
    sessionFactory: async () => {
      const session = new FakeSession();
      created.push(session);
      return session;
    },
  });

  try {
    const closed = await pool.ensureSession(WORK_DIR);
    closed.closed = true;

    const replacement = await pool.ensureSession(WORK_DIR);

    assert.notStrictEqual(replacement, closed);
    assert.equal(closed.disposeCalls, 1);
    assert.equal(created.length, 2);
    assert.strictEqual(await pool.ensureSession(WORK_DIR), replacement);
  } finally {
    await pool.shutdown();
  }
});

test("closed managed session disposal rejection permanently fences reuse", async () => {
  const session = new FakeSession();
  const pool = createPool({ sessionFactory: async () => session });
  const identity = receiptIdentity(1, "binding-a", "a");
  try {
    await pool.ensureSession(WORK_DIR, { receiptIdentity: identity });
    session.closed = true;
    session.dispose = async () => {
      session.disposeCalls += 1;
      throw new Error("dispose failed");
    };
    await assert.rejects(
      pool.ensureSession(WORK_DIR, { receiptIdentity: identity }),
      (error) => error?.code === "LEASE_CONFLICT"
    );
    await assert.rejects(
      pool.ensureSession(WORK_DIR, { receiptIdentity: identity }),
      (error) => error?.code === "LEASE_CONFLICT"
    );
  } finally {
    session.dispose = FakeSession.prototype.dispose;
    await pool.shutdown();
  }
});

test("closed managed session disposal timeout fences reuse until settlement", async () => {
  let releaseDisposal;
  const disposalGate = new Promise((resolve) => {
    releaseDisposal = resolve;
  });
  const original = new FakeSession();
  const replacement = new FakeSession();
  let factoryCalls = 0;
  const pool = createPool({
    sessionDisposeTimeoutMs: 1,
    sessionFactory: async () => {
      factoryCalls += 1;
      return factoryCalls === 1 ? original : replacement;
    },
  });
  const identity = receiptIdentity(1, "binding-a", "a");
  try {
    await pool.ensureSession(WORK_DIR, { receiptIdentity: identity });
    original.closed = true;
    original.dispose = async () => {
      original.disposeCalls += 1;
      await disposalGate;
    };
    let transitionError;
    try {
      await pool.ensureSession(WORK_DIR, { receiptIdentity: identity });
    } catch (error) {
      transitionError = error;
    }
    assert.equal(transitionError?.code, "LEASE_CONFLICT");
    await assert.rejects(
      pool.ensureSession(WORK_DIR, { receiptIdentity: identity }),
      (error) => error?.code === "LEASE_CONFLICT"
    );
    releaseDisposal();
    await transitionError.pendingCleanup;
    assert.strictEqual(
      await pool.ensureSession(WORK_DIR, { receiptIdentity: identity }),
      replacement
    );
  } finally {
    releaseDisposal();
    await pool.shutdown();
  }
});

test("managed sessions reuse only the exact binding identity", async () => {
  const created = [];
  const pool = createPool({
    sessionFactory: async () => {
      const session = new FakeSession();
      created.push(session);
      return session;
    },
  });

  try {
    const original = await pool.ensureSession(WORK_DIR, {
      managedIdentity: "binding-a",
    });
    assert.strictEqual(
      await pool.ensureSession(WORK_DIR, { managedIdentity: "binding-a" }),
      original
    );

    const replacement = await pool.ensureSession(WORK_DIR, {
      managedIdentity: "binding-b",
    });
    assert.notStrictEqual(replacement, original);
    assert.equal(original.disposeCalls, 1);
    assert.equal(created.length, 2);
  } finally {
    await pool.shutdown();
  }
});

test("receipt identities are structured, exact, and collision resistant", async () => {
  const created = [];
  const pool = createPool({
    sessionFactory: async () => {
      const session = new FakeSession();
      created.push(session);
      return session;
    },
  });
  const a = receiptIdentity(1, "ab", "a");
  const b = receiptIdentity(1, "a", "b");
  try {
    const first = await pool.ensureSession(WORK_DIR, { receiptIdentity: a });
    assert.strictEqual(
      await pool.ensureSession(WORK_DIR, { receiptIdentity: a }),
      first
    );
    const second = await pool.ensureSession(WORK_DIR, { receiptIdentity: b });
    assert.notStrictEqual(second, first);
    assert.equal(first.disposeCalls, 1);
    assert.equal(created.length, 2);
    await assert.rejects(
      pool.ensureSession(WORK_DIR, {
        receiptIdentity: { ...a, bindingFingerprint: "not-a-fingerprint" },
      }),
      /receiptIdentity is invalid/
    );
  } finally {
    await pool.shutdown();
  }
});

test("retiring a receipt disposes only its exact managed session", async () => {
  const otherWorkDir =
    process.platform === "win32" ? String.raw`C:\other` : "/other";
  const created = [];
  const pool = createPool({
    realpathSyncFn: (workDir) => workDir,
    sessionFactory: async () => {
      const session = new FakeSession();
      created.push(session);
      return session;
    },
  });
  const retired = receiptIdentity(1, "binding-a", "a");
  const unrelated = receiptIdentity(1, "binding-b", "b");
  try {
    const oldSession = await pool.ensureSession(WORK_DIR, { receiptIdentity: retired });
    const unrelatedSession = await pool.ensureSession(otherWorkDir, {
      receiptIdentity: unrelated,
    });
    await pool.retireManagedReceipt(WORK_DIR, retired);
    assert.equal(oldSession.disposeCalls, 1);
    assert.equal(unrelatedSession.disposeCalls, 0);
    assert.strictEqual(
      await pool.ensureSession(otherWorkDir, { receiptIdentity: unrelated }),
      unrelatedSession
    );
    assert.equal(created.length, 2);
  } finally {
    await pool.shutdown();
  }
});

test("rejected receipt retirement permanently fences the workDir", async () => {
  const session = new FakeSession();
  session.dispose = async () => {
    session.disposeCalls += 1;
    throw new Error("dispose failed");
  };
  const pool = createPool({ sessionFactory: async () => session });
  const retired = receiptIdentity(1, "binding-a", "a");
  try {
    await pool.ensureSession(WORK_DIR, { receiptIdentity: retired });
    await assert.rejects(
      pool.retireManagedReceipt(WORK_DIR, retired),
      (error) => error?.code === "LEASE_CONFLICT"
    );
    await assert.rejects(
      pool.ensureSession(WORK_DIR, {
        receiptIdentity: receiptIdentity(2, "binding-b", "b"),
      }),
      (error) => error?.code === "LEASE_CONFLICT"
    );
  } finally {
    session.dispose = FakeSession.prototype.dispose;
    await pool.shutdown();
  }
});

test("timed-out receipt retirement blocks replacement until cleanup settles", async () => {
  let releaseDisposal;
  const disposalGate = new Promise((resolve) => {
    releaseDisposal = resolve;
  });
  const retiredSession = new FakeSession();
  retiredSession.dispose = async () => {
    retiredSession.disposeCalls += 1;
    await disposalGate;
    retiredSession.closed = true;
  };
  const replacement = new FakeSession();
  let factoryCalls = 0;
  const pool = createPool({
    sessionDisposeTimeoutMs: 1,
    sessionFactory: async () => {
      factoryCalls += 1;
      return factoryCalls === 1 ? retiredSession : replacement;
    },
  });
  const retired = receiptIdentity(1, "binding-a", "a");
  const successor = receiptIdentity(2, "binding-b", "b");
  try {
    await pool.ensureSession(WORK_DIR, { receiptIdentity: retired });
    let retirementError;
    try {
      await pool.retireManagedReceipt(WORK_DIR, retired);
    } catch (error) {
      retirementError = error;
    }
    assert.equal(retirementError?.code, "LEASE_CONFLICT");
    await assert.rejects(
      pool.ensureSession(WORK_DIR, { receiptIdentity: successor }),
      (error) => error?.code === "LEASE_CONFLICT"
    );
    releaseDisposal();
    await retirementError.pendingCleanup;
    assert.strictEqual(
      await pool.ensureSession(WORK_DIR, { receiptIdentity: successor }),
      replacement
    );
  } finally {
    releaseDisposal();
    await pool.shutdown();
  }
});

test("receipt retirement waits for timed-out creation cleanup", async () => {
  let releaseCreation;
  const creationGate = new Promise((resolve) => {
    releaseCreation = resolve;
  });
  const lateSession = new FakeSession();
  const pool = createPool({
    sessionCreateTimeoutMs: 1,
    sessionFactory: async () => {
      await creationGate;
      return lateSession;
    },
  });
  const identity = receiptIdentity(1, "binding-a", "a");
  try {
    await assert.rejects(
      pool.ensureSession(WORK_DIR, { receiptIdentity: identity }),
      /creation timed out/
    );
    let retired = false;
    const retirement = pool.retireManagedReceipt(WORK_DIR, identity).then(() => {
      retired = true;
    });
    await new Promise((resolve) => setImmediate(resolve));
    assert.equal(retired, false);
    releaseCreation();
    await retirement;
    assert.equal(lateSession.disposeCalls, 1);
  } finally {
    releaseCreation();
    await pool.shutdown();
  }
});

test("receipt retirement rejects when timed-out creation cleanup fails", async () => {
  let releaseCreation;
  const creationGate = new Promise((resolve) => {
    releaseCreation = resolve;
  });
  const lateSession = new FakeSession();
  lateSession.dispose = async () => {
    lateSession.disposeCalls += 1;
    throw new Error("late cleanup failed");
  };
  const pool = createPool({
    sessionCreateTimeoutMs: 1,
    sessionFactory: async () => {
      await creationGate;
      return lateSession;
    },
  });
  const identity = receiptIdentity(1, "binding-a", "a");
  try {
    await assert.rejects(
      pool.ensureSession(WORK_DIR, { receiptIdentity: identity }),
      /creation timed out/
    );
    const retirement = pool.retireManagedReceipt(WORK_DIR, identity);
    releaseCreation();
    await assert.rejects(
      retirement,
      (error) => error?.code === "LEASE_CONFLICT"
    );
  } finally {
    releaseCreation();
    await pool.shutdown();
  }
});

test("managed identity replacement rejects while prior creation is pending", async () => {
  let releaseCreation;
  const creationGate = new Promise((resolve) => {
    releaseCreation = resolve;
  });
  const original = new FakeSession();
  const replacement = new FakeSession();
  const events = [];
  original.dispose = async () => {
    events.push("dispose");
    original.disposeCalls += 1;
    original.closed = true;
  };
  let factoryCalls = 0;
  const pool = createPool({
    sessionFactory: async () => {
      factoryCalls += 1;
      if (factoryCalls === 1) {
        await creationGate;
        events.push("original-created");
        return original;
      }
      events.push("replacement-created");
      return replacement;
    },
  });

  try {
    const pendingOriginal = pool.ensureSession(WORK_DIR, {
      managedIdentity: "binding-a",
    });
    await assert.rejects(
      pool.ensureSession(WORK_DIR, { managedIdentity: "binding-b" }),
      (error) => error?.code === "LEASE_CONFLICT"
    );
    await assert.rejects(
      pool.ensureSession(WORK_DIR),
      (error) => error?.code === "LEASE_CONFLICT"
    );
    releaseCreation();

    assert.strictEqual(await pendingOriginal, original);
    assert.strictEqual(
      await pool.ensureSession(WORK_DIR, { managedIdentity: "binding-b" }),
      replacement
    );
    assert.deepEqual(events, [
      "original-created",
      "dispose",
      "replacement-created",
    ]);
  } finally {
    releaseCreation();
    await pool.shutdown();
  }
});

test("managed replacement disposal failure permanently fences managed reuse", async () => {
  const original = new FakeSession();
  original.dispose = async () => {
    original.disposeCalls += 1;
    throw new Error("dispose failed");
  };
  let factoryCalls = 0;
  const pool = createPool({
    sessionFactory: async () => {
      factoryCalls += 1;
      return original;
    },
  });

  try {
    await pool.ensureSession(WORK_DIR, { managedIdentity: "binding-a" });
    await assert.rejects(
      pool.ensureSession(WORK_DIR, { managedIdentity: "binding-b" }),
      (error) => error?.code === "LEASE_CONFLICT"
    );
    assert.equal(factoryCalls, 1);
    await assert.rejects(
      pool.ensureSession(WORK_DIR, { managedIdentity: "binding-a" }),
      (error) => error?.code === "LEASE_CONFLICT"
    );
  } finally {
    original.dispose = FakeSession.prototype.dispose;
    await pool.shutdown();
  }
});

test("rejected managed disposal fails closed and cannot be bypassed", async () => {
  const original = new FakeSession();
  let disposalAttempts = 0;
  original.dispose = async () => {
    disposalAttempts += 1;
    throw new Error("dispose failed");
    original.closed = true;
  };
  const replacement = new FakeSession();
  let factoryCalls = 0;
  const pool = createPool({
    sessionFactory: async () => {
      factoryCalls += 1;
      return factoryCalls === 1 ? original : replacement;
    },
  });

  try {
    await pool.ensureSession(WORK_DIR, { managedIdentity: "binding-a" });
    const rejectedTransition = pool.ensureSession(WORK_DIR, {
      managedIdentity: "binding-b",
    });
    await assert.rejects(
      pool.ensureSession(WORK_DIR, { managedIdentity: "binding-c" }),
      (error) => error?.code === "LEASE_CONFLICT"
    );
    await assert.rejects(
      rejectedTransition,
      (error) => error?.code === "LEASE_CONFLICT"
    );
    assert.equal(factoryCalls, 1);

    await assert.rejects(
      pool.ensureSession(WORK_DIR, { managedIdentity: "binding-c" }),
      (error) => error?.code === "LEASE_CONFLICT"
    );
    assert.equal(disposalAttempts, 1);
    assert.equal(factoryCalls, 1);
  } finally {
    original.dispose = FakeSession.prototype.dispose;
    await pool.shutdown();
  }
});

test("managed replacement disposal timeout creates no replacement session", async () => {
  const original = new FakeSession();
  let releaseDisposal;
  const disposalGate = new Promise((resolve) => {
    releaseDisposal = resolve;
  });
  let disposalAttempts = 0;
  original.dispose = async () => {
    disposalAttempts += 1;
    if (disposalAttempts === 1) await disposalGate;
    original.closed = true;
  };
  const replacement = new FakeSession();
  let factoryCalls = 0;
  const pool = createPool({
    sessionDisposeTimeoutMs: 1,
    sessionFactory: async () => {
      factoryCalls += 1;
      return factoryCalls === 1 ? original : replacement;
    },
  });

  try {
    await pool.ensureSession(WORK_DIR, { managedIdentity: "binding-a" });
    await assert.rejects(
      pool.ensureSession(WORK_DIR, { managedIdentity: "binding-b" }),
      (error) => error?.code === "LEASE_CONFLICT"
    );
    await assert.rejects(
      pool.ensureSession(WORK_DIR, { managedIdentity: "binding-c" }),
      (error) => error?.code === "LEASE_CONFLICT"
    );
    assert.equal(factoryCalls, 1);

    releaseDisposal();
    await new Promise((resolve) => setImmediate(resolve));
    assert.strictEqual(
      await pool.ensureSession(WORK_DIR, { managedIdentity: "binding-c" }),
      replacement
    );
    assert.equal(disposalAttempts, 2);
    assert.equal(factoryCalls, 2);
  } finally {
    releaseDisposal();
    await pool.shutdown();
  }
});

test("managed replacement timeout with late rejection permanently fences", async () => {
  let releaseDisposal;
  const disposalGate = new Promise((resolve) => {
    releaseDisposal = resolve;
  });
  const original = new FakeSession();
  original.dispose = async () => {
    original.disposeCalls += 1;
    await disposalGate;
    throw new Error("late disposal failure");
  };
  let factoryCalls = 0;
  const pool = createPool({
    sessionDisposeTimeoutMs: 1,
    sessionFactory: async () => {
      factoryCalls += 1;
      return original;
    },
  });
  try {
    await pool.ensureSession(WORK_DIR, { managedIdentity: "binding-a" });
    let replacementError;
    try {
      await pool.ensureSession(WORK_DIR, { managedIdentity: "binding-b" });
    } catch (error) {
      replacementError = error;
    }
    assert.equal(replacementError?.code, "LEASE_CONFLICT");
    releaseDisposal();
    await assert.rejects(
      replacementError.pendingCleanup,
      (error) => error?.code === "LEASE_CONFLICT"
    );
    await assert.rejects(
      pool.ensureSession(WORK_DIR, { managedIdentity: "binding-c" }),
      (error) => error?.code === "LEASE_CONFLICT"
    );
    assert.equal(factoryCalls, 1);
  } finally {
    releaseDisposal();
    original.dispose = FakeSession.prototype.dispose;
    await pool.shutdown();
  }
});

test("managed identity change is fenced until late creation cleanup settles", async () => {
  let releaseCreation;
  const creationGate = new Promise((resolve) => {
    releaseCreation = resolve;
  });
  const late = new FakeSession();
  let releaseDisposal;
  const disposalGate = new Promise((resolve) => {
    releaseDisposal = resolve;
  });
  late.dispose = async () => {
    late.disposeCalls += 1;
    await disposalGate;
    late.closed = true;
  };
  const replacement = new FakeSession();
  let factoryCalls = 0;
  const pool = createPool({
    sessionDisposeTimeoutMs: 1,
    sessionCreateTimeoutMs: 1,
    sessionFactory: async () => {
      factoryCalls += 1;
      if (factoryCalls === 1) {
        await creationGate;
        return late;
      }
      return replacement;
    },
  });

  try {
    await assert.rejects(
      pool.ensureSession(WORK_DIR, { managedIdentity: "binding-a" }),
      /session creation timed out/
    );
    await assert.rejects(
      pool.ensureSession(WORK_DIR, { managedIdentity: "binding-b" }),
      (error) => error?.code === "LEASE_CONFLICT"
    );
    assert.equal(factoryCalls, 1);

    releaseCreation();
    await new Promise((resolve) => setTimeout(resolve, 5));
    assert.equal(late.disposeCalls, 1);
    await assert.rejects(
      pool.ensureSession(WORK_DIR, { managedIdentity: "binding-b" }),
      (error) => error?.code === "LEASE_CONFLICT"
    );

    releaseDisposal();
    await new Promise((resolve) => setImmediate(resolve));
    assert.strictEqual(
      await pool.ensureSession(WORK_DIR, { managedIdentity: "binding-b" }),
      replacement
    );
    await pool.shutdown();
  } finally {
    releaseCreation();
    releaseDisposal();
  }
});

test("session admission rejects a ninth workspace before SDK creation", async () => {
  const created = [];
  const workDirs = Array.from({ length: 9 }, (_, index) =>
    process.platform === "win32" ? `C:\\work-${index}` : `/work-${index}`
  );
  const pool = new SessionPool({
    statSyncFn: () => ({ isDirectory: () => true }),
    realpathSyncFn: (workDir) => workDir,
    sessionFactory: async (workDir) => {
      created.push(workDir);
      return new FakeSession();
    },
  });

  try {
    for (const workDir of workDirs.slice(0, 8)) {
      await pool.ensureSession(workDir);
    }
    await assert.rejects(
      pool.ensureSession(workDirs[8]),
      (error) => error?.code === "SESSION_LIMIT"
    );
    assert.equal(created.length, 8);
  } finally {
    await pool.shutdown();
  }
});

test("concurrent session admission reserves all eight slots before creation settles", async () => {
  let releaseCreation;
  const creationGate = new Promise((resolve) => {
    releaseCreation = resolve;
  });
  const workDirs = Array.from({ length: 9 }, (_, index) =>
    process.platform === "win32" ? `C:\\pending-${index}` : `/pending-${index}`
  );
  const pool = new SessionPool({
    statSyncFn: () => ({ isDirectory: () => true }),
    realpathSyncFn: (workDir) => workDir,
    sessionFactory: async () => {
      await creationGate;
      return new FakeSession();
    },
  });

  try {
    const admitted = workDirs.slice(0, 8).map((workDir) => pool.ensureSession(workDir));
    await assert.rejects(
      pool.ensureSession(workDirs[8]),
      (error) => error?.code === "SESSION_LIMIT"
    );
    assert.deepEqual(pool.getAdmissionSnapshot(), {
      activeSessions: 0,
      pendingSessions: 8,
      admittedWorkspaces: 8,
      maxSessions: 8,
    });

    releaseCreation();
    await Promise.all(admitted);
    assert.deepEqual(pool.getAdmissionSnapshot(), {
      activeSessions: 8,
      pendingSessions: 0,
      admittedWorkspaces: 8,
      maxSessions: 8,
    });
  } finally {
    releaseCreation();
    await pool.shutdown();
  }
});

test("session admission validates configured bounds", async () => {
  assert.throws(() => createPool({ maxSessions: 0 }), /positive safe integer/);
  assert.throws(
    () => createPool({ maxSessions: Number.MAX_SAFE_INTEGER + 1 }),
    /positive safe integer/
  );
  const pool = createPool({ maxSessions: 1 });
  await pool.shutdown();
});
test("idle reaper skips busy sessions and reaps them after work settles", async () => {
  const session = new FakeSession();
  let busy = true;
  let now = 0;
  let reap;
  session.isBusy = () => busy;
  const pool = createPool({
    nowFn: () => now,
    idleTimeoutMs: 5,
    reapIntervalMs: 5,
    setIntervalFn: (callback) => {
      reap = callback;
      return { unref() {} };
    },
    clearIntervalFn: () => {},
    sessionFactory: async () => session,
  });

  try {
    await pool.ensureSession(WORK_DIR);
    now += 6;
    reap();
    await Promise.resolve();
    assert.equal(session.disposeCalls, 0);

    busy = false;
    now += 6;
    reap();
    await Promise.resolve();
    assert.equal(session.disposeCalls, 1);
  } finally {
    await pool.shutdown();
  }
});

test("replacement creation proceeds when closed-session disposal stalls", async () => {
  const created = [];
  const pool = createPool({
    sessionDisposeTimeoutMs: 1,
    sessionFactory: async () => {
      const session = new FakeSession();
      created.push(session);
      return session;
    },
  });

  try {
    const stuck = await pool.ensureSession(WORK_DIR);
    stuck.closed = true;
    stuck.dispose = () => {
      stuck.disposeCalls += 1;
      return new Promise(() => {});
    };

    const replacement = await pool.ensureSession(WORK_DIR);

    assert.notStrictEqual(replacement, stuck);
    assert.equal(stuck.disposeCalls, 1);
    assert.equal(created.length, 2);
  } finally {
    await pool.shutdown();
  }
});

test("a workDir that resolves to a file is rejected before SDK session creation", async () => {
  let factoryCalls = 0;
  const pool = createPool({
    statSyncFn: () => ({ isDirectory: () => false }),
    sessionFactory: async () => {
      factoryCalls += 1;
      return new FakeSession();
    },
  });

  try {
    await assert.rejects(
      pool.ensureSession(WORK_DIR),
      (error) => error.message === `workDir is not a directory on this host: ${WORK_DIR}`
    );
    assert.equal(factoryCalls, 0);
  } finally {
    await pool.shutdown();
  }
});

test("a nonexistent workDir is rejected before SDK session creation", async () => {
  let factoryCalls = 0;
  const pool = createPool({
    statSyncFn: () => {
      const error = new Error("ENOENT: no such file or directory");
      error.code = "ENOENT";
      throw error;
    },
    sessionFactory: async () => {
      factoryCalls += 1;
      return new FakeSession();
    },
  });

  try {
    await assert.rejects(
      pool.ensureSession(WORK_DIR),
      (error) => error.message === `workDir does not exist on this host: ${WORK_DIR}`
    );
    assert.equal(factoryCalls, 0);
  } finally {
    await pool.shutdown();
  }
});

test("canonical workDir aliases reuse one SDK session after filesystem revalidation", async () => {
  const factoryCalls = [];
  let statCalls = 0;
  let realpathCalls = 0;
  const pool = createPool({
    statSyncFn: () => {
      statCalls += 1;
      return { isDirectory: () => true };
    },
    realpathSyncFn: () => {
      realpathCalls += 1;
      return WORK_DIR;
    },
    sessionFactory: async (workDir) => {
      factoryCalls.push(workDir);
      return new FakeSession();
    },
  });

  try {
    const first = await pool.ensureSession(ALIAS_WORK_DIR);
    const second = await pool.ensureSession(WORK_DIR);

    assert.strictEqual(second, first);
    assert.equal(statCalls, 2);
    assert.equal(realpathCalls, 2);
    assert.deepEqual(factoryCalls, [WORK_DIR]);
  } finally {
    await pool.shutdown();
  }
});

test("a retargeted workDir alias routes to the new canonical directory", async () => {
  const firstTarget = process.platform === "win32" ? String.raw`C:\first` : "/first";
  const secondTarget = process.platform === "win32" ? String.raw`C:\second` : "/second";
  let resolvedTarget = firstTarget;
  const factoryCalls = [];
  const pool = createPool({
    realpathSyncFn: () => resolvedTarget,
    sessionFactory: async (workDir) => {
      factoryCalls.push(workDir);
      return new FakeSession();
    },
  });

  try {
    const first = await pool.ensureSession(ALIAS_WORK_DIR);
    resolvedTarget = secondTarget;
    const second = await pool.ensureSession(ALIAS_WORK_DIR);

    assert.notStrictEqual(second, first);
    assert.deepEqual(factoryCalls, [firstTarget, secondTarget]);
  } finally {
    await pool.shutdown();
  }
});

test("concurrent first requests share one in-flight SDK session creation", async () => {
  let release;
  const gate = new Promise((resolve) => {
    release = resolve;
  });
  let factoryCalls = 0;
  const session = new FakeSession();
  const pool = createPool({
    sessionFactory: async () => {
      factoryCalls += 1;
      await gate;
      return session;
    },
  });

  try {
    const first = pool.ensureSession(ALIAS_WORK_DIR);
    const second = pool.ensureSession(WORK_DIR);
    release();

    assert.strictEqual(await first, session);
    assert.strictEqual(await second, session);
    assert.equal(factoryCalls, 1);
  } finally {
    await pool.shutdown();
  }
});

test("Windows native realpaths normalize extended prefixes and case aliases", async () => {
  const cases = [
    {
      first: String.raw`c:\work`,
      second: String.raw`C:\WORK`,
      resolved: String.raw`\\?\C:\Work`,
      canonical: String.raw`C:\Work`,
    },
    {
      first: String.raw`\\server\share\work`,
      second: String.raw`\\SERVER\SHARE\WORK`,
      resolved: String.raw`\\?\UNC\Server\Share\Work`,
      canonical: String.raw`\\Server\Share\Work`,
    },
  ];

  for (const { first, second, resolved, canonical } of cases) {
    const factoryCalls = [];
    const pool = createPool({
      platform: "win32",
      realpathSyncFn: () => resolved,
      sessionFactory: async (workDir) => {
        factoryCalls.push(workDir);
        return new FakeSession();
      },
    });

    try {
      const original = await pool.ensureSession(first);
      assert.strictEqual(await pool.ensureSession(second), original);
      assert.deepEqual(factoryCalls, [canonical]);
    } finally {
      await pool.shutdown();
    }
  }
});

test("an unresolvable workDir fails before SDK session creation", async () => {
  let factoryCalls = 0;
  const failure = new Error("realpath failed");
  const pool = createPool({
    realpathSyncFn: () => {
      throw failure;
    },
    sessionFactory: async () => {
      factoryCalls += 1;
      return new FakeSession();
    },
  });

  try {
    await assert.rejects(
      pool.ensureSession(WORK_DIR),
      (error) =>
        error.message === `workDir cannot be resolved on this host: ${WORK_DIR}` &&
        error.cause === failure
    );
    assert.equal(factoryCalls, 0);
  } finally {
    await pool.shutdown();
  }
});

test("shutdown completes when session disposal stalls", async () => {
  const session = new FakeSession();
  session.dispose = () => {
    session.disposeCalls += 1;
    return new Promise(() => {});
  };
  const pool = createPool({
    sessionDisposeTimeoutMs: 1,
    sessionFactory: async () => session,
  });

  await pool.ensureSession(WORK_DIR);
  await pool.shutdown();

  assert.equal(session.disposeCalls, 1);
});
test("shutdown exposes pending work directories while disposal is in flight", async () => {
  const session = new FakeSession();
  let releaseDisposal;
  session.dispose = () =>
    new Promise((resolve) => {
      releaseDisposal = resolve;
    });
  const pool = createPool({
    sessionDisposeTimeoutMs: 20,
    sessionFactory: async () => session,
  });

  await pool.ensureSession(WORK_DIR);
  const shutdown = pool.shutdown();
  assert.deepEqual(pool.getPendingShutdownOperations(), [
    { workDir: WORK_DIR, operation: "shutdown session disposal" },
  ]);
  await shutdown;
  assert.deepEqual(pool.getPendingShutdownOperations(), [
    { workDir: WORK_DIR, operation: "shutdown session disposal" },
  ]);
  releaseDisposal();
  await new Promise((resolve) => setImmediate(resolve));
  assert.deepEqual(pool.getPendingShutdownOperations(), []);
});

test("shutdown during SDK creation disposes the late session", async () => {
  let release;
  const gate = new Promise((resolve) => {
    release = resolve;
  });
  const session = new FakeSession();
  const pool = createPool({
    sessionFactory: async () => {
      await gate;
      return session;
    },
  });

  const creation = pool.ensureSession(WORK_DIR);
  const shutdown = pool.shutdown();
  release();

  await assert.rejects(creation, /shut down during session creation/);
  await shutdown;
  assert.equal(session.disposeCalls, 1);
});

test("shutdown completes when late-created session disposal stalls", async () => {
  let release;
  const gate = new Promise((resolve) => {
    release = resolve;
  });
  const session = new FakeSession();
  session.dispose = () => {
    session.disposeCalls += 1;
    return new Promise(() => {});
  };
  const pool = createPool({
    sessionDisposeTimeoutMs: 1,
    sessionFactory: async () => {
      await gate;
      return session;
    },
  });

  const creation = pool.ensureSession(WORK_DIR);
  const shutdown = pool.shutdown();
  release();

  await assert.rejects(creation, /shut down during session creation/);
  await shutdown;
  assert.equal(session.disposeCalls, 1);
});

test("shutdown completes when SDK session creation stalls", async () => {
  const pool = createPool({
    sessionDisposeTimeoutMs: 1,
    sessionCreateTimeoutMs: 1,
    sessionFactory: () => new Promise(() => {}),
  });

  const creation = pool.ensureSession(WORK_DIR);
  const creationRejection = assert.rejects(creation, /session creation timed out/);
  await pool.shutdown();
  await creationRejection;
});

test("timed-out session creation is evicted and late sessions are disposed", async () => {
  let release;
  const gate = new Promise((resolve) => {
    release = resolve;
  });
  const late = new FakeSession();
  const replacement = new FakeSession();
  let factoryCalls = 0;
  const pool = createPool({
    sessionDisposeTimeoutMs: 1,
    sessionCreateTimeoutMs: 1,
    sessionFactory: async () => {
      factoryCalls += 1;
      if (factoryCalls === 1) {
        await gate;
        return late;
      }
      return replacement;
    },
  });

  try {
    await assert.rejects(pool.ensureSession(WORK_DIR), /session creation timed out/);
    assert.strictEqual(await pool.ensureSession(WORK_DIR), replacement);

    release();
    await new Promise((resolve) => setImmediate(resolve));

    assert.equal(factoryCalls, 2);
    assert.equal(late.disposeCalls, 1);
  } finally {
    await pool.shutdown();
  }
});

test("managed creation timeout permanently fences after late disposal rejection", async () => {
  let releaseCreation;
  const creationGate = new Promise((resolve) => {
    releaseCreation = resolve;
  });
  const lateSession = new FakeSession();
  lateSession.dispose = async () => {
    lateSession.disposeCalls += 1;
    throw new Error("late dispose failed");
  };
  const pool = createPool({
    sessionCreateTimeoutMs: 1,
    sessionDisposeTimeoutMs: 10,
    sessionFactory: async () => {
      await creationGate;
      return lateSession;
    },
  });
  const identity = receiptIdentity(1, "binding-a", "a");
  try {
    let creationError;
    try {
      await pool.ensureSession(WORK_DIR, { receiptIdentity: identity });
    } catch (error) {
      creationError = error;
    }
    releaseCreation();
    await assert.rejects(
      creationError.pendingCleanup,
      (error) => error?.code === "LEASE_CONFLICT"
    );
    await assert.rejects(
      pool.ensureSession(WORK_DIR, {
        receiptIdentity: receiptIdentity(2, "binding-b", "b"),
      }),
      (error) => error?.code === "LEASE_CONFLICT"
    );
  } finally {
    releaseCreation();
    await pool.shutdown();
  }
});

test("session creation is bounded by the create timeout, not the dispose timeout", async () => {
  const pool = createPool({
    sessionDisposeTimeoutMs: 10_000,
    sessionCreateTimeoutMs: 1,
    sessionFactory: () => new Promise(() => {}),
  });

  const creation = pool.ensureSession(WORK_DIR);
  const creationRejection = assert.rejects(creation, /session creation timed out/);
  await pool.shutdown();
  await creationRejection;
});

test("a creation slower than the dispose timeout still succeeds under a generous create timeout", async () => {
  const session = new FakeSession();
  const pool = createPool({
    sessionDisposeTimeoutMs: 1,
    sessionCreateTimeoutMs: 1_000,
    sessionFactory: () =>
      new Promise((resolve) => setTimeout(() => resolve(session), 20)),
  });

  try {
    assert.strictEqual(await pool.ensureSession(WORK_DIR), session);
  } finally {
    await pool.shutdown();
  }
});
