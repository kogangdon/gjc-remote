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
    existsSyncFn: () => true,
    realpathSyncFn: () => WORK_DIR,
    ...overrides,
  });
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

test("canonical workDir aliases reuse one SDK session after filesystem revalidation", async () => {
  const factoryCalls = [];
  let existsCalls = 0;
  let realpathCalls = 0;
  const pool = createPool({
    existsSyncFn: () => {
      existsCalls += 1;
      return true;
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
    assert.equal(existsCalls, 2);
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
