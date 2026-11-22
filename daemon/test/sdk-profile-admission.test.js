import assert from 'node:assert/strict';
import test from 'node:test';
import { createSdkProfileAdmission } from '../src/sdk-profile-admission.js';

function fixture() {
  const profile = Object.freeze({ agentDir: '/sdk-profile', credentialPath: '/sdk-profile/agent.db',
    recipient: 'test', configIdentity: 'config', credentialIdentity: 'db' });
  let record = Object.freeze({ grantId: 7, profile });
  const listeners = new Set();
  return {
    profile,
    listeners,
    store: {
      capture: () => record,
      isCurrent: value => record !== null && record === value,
      subscribe(fn) { listeners.add(fn); return () => listeners.delete(fn); },
    },
    set(value) { record = value; for (const fn of listeners) fn(); },
  };
}

function deferred() {
  let resolve;
  const promise = new Promise(done => { resolve = done; });
  return { promise, resolve };
}

function targetLease(profile, overrides = {}) {
  return {
    profile,
    startupAuthConfig: Object.freeze({ broker: null, credentialStoreIdentity: `local:${profile.credentialPath}` }),
    assertCurrent() {},
    close() {},
    ...overrides,
  };
}

test('an allowed profile without a worker factory cannot open a target or use the embedded SDK', () => {
  const { store } = fixture();
  let opens = 0;
  const admission = createSdkProfileAdmission({ store, openTarget() { opens++; } });
  assert.throws(() => admission.capture(), { code: 'SDK_PROFILE_UNAVAILABLE' });
  assert.equal(opens, 0);
});

test('withdrawal subscriptions detach once, including stale and throwing subscribers', () => {
  const { store, profile, listeners, set } = fixture();
  const admission = createSdkProfileAdmission({ store, openTarget() {}, createSession() {} });
  const binding = admission.capture();
  let notified = 0;
  const stop = binding.subscribeWithdrawal(() => {
    notified++;
    assert.equal(listeners.size, 0);
  });
  assert.equal(listeners.size, 1);
  set(null);
  set(Object.freeze({ grantId: 8, profile }));
  assert.equal(notified, 1);
  stop();
  const stopStale = binding.subscribeWithdrawal(() => { notified++; });
  assert.equal(notified, 2);
  assert.equal(listeners.size, 0);
  stopStale();
  assert.throws(() => binding.subscribeWithdrawal(() => { throw new Error('subscriber failed'); }),
    /subscriber failed/);
  assert.throws(() => binding.subscribeWithdrawal(null), /subscriber must be a function/);
  assert.equal(listeners.size, 0);
});

test('regrant between capture and target qualification cannot load an SDK', async () => {
  const { store, profile, set } = fixture();
  let finish;
  const qualification = new Promise(resolve => { finish = resolve; });
  let created = 0, closed = 0;
  const admission = createSdkProfileAdmission({ store, openTarget: () => qualification,
    createSession: () => { created++; } });
  const first = admission.capture();
  assert.equal(admission.capture(), first);
  const result = admission.create('/work', first);
  set(null);
  assert.throws(() => admission.capture(), { code: 'SDK_PROFILE_UNAVAILABLE' });
  set(Object.freeze({ grantId: 8, profile }));
  finish({ profile, assertCurrent() {}, close() { closed++; } });
  await assert.rejects(result, { code: 'SDK_PROFILE_WITHDRAWN' });
  assert.notEqual(admission.capture(), first);
  assert.equal(created, 0);
  assert.equal(closed, 1);
});

test('late target-open rejection belongs to the withdrawn grant, not the identical regrant', async () => {
  const { store, profile, set } = fixture();
  const gate = deferred();
  const nativeError = new Error('failed to open old target');
  let attempts = 0, creates = 0;
  const admission = createSdkProfileAdmission({
    store,
    async openTarget() {
      if (++attempts === 1) { await gate.promise; throw nativeError; }
      return targetLease(profile);
    },
    createSession(_work, _loader, { onSdkDisposed }) {
      creates++;
      return { dispose: onSdkDisposed };
    },
  });
  const old = admission.create('/work', admission.capture());
  set(null);
  set(Object.freeze({ grantId: 8, profile }));
  const fresh = await admission.create('/work', admission.capture());
  gate.resolve();
  await assert.rejects(old, error => {
    assert.equal(error.code, 'SDK_PROFILE_WITHDRAWN');
    assert.equal(error.sdkDisposalState, 'not_created');
    assert.strictEqual(error.cause.cause, nativeError);
    return true;
  });
  assert.equal(creates, 1);
  await fresh.dispose();
});

test('successful handoff retains target through withdrawal until underlying disposal', async () => {
  const { store, profile, set } = fixture();
  const startupAuthConfig = Object.freeze({ broker: null });
  let closed = 0, notified = 0, options;
  const session = { async dispose() { await options.onSdkDisposed(); } };
  const admission = createSdkProfileAdmission({ store,
    sessionRoot: '/transcripts',
    openTarget: expected => {
      assert.strictEqual(expected, profile);
      return targetLease(profile, { startupAuthConfig, close() { closed++; } });
    },
    createSession: (workDir, loadSdk, value) => {
      assert.equal(workDir, '/work');
      assert.equal(loadSdk, undefined);
      options = value;
      return session;
    } });
  assert.strictEqual(await admission.create('/work', admission.capture()), session);
  const { profileBinding, onSdkDisposed } = options;
  assert.equal(options.sessionRoot, '/transcripts');
  assert.equal(profileBinding.agentDir, profile.agentDir);
  assert.strictEqual(profileBinding.startupAuthConfig, startupAuthConfig);
  assert.equal(Object.isFrozen(profileBinding), true);
  const stop = profileBinding.subscribeWithdrawal(() => notified++);
  set(null);
  assert.equal(notified, 1);
  assert.throws(() => profileBinding.assertCurrent(), { code: 'SDK_PROFILE_WITHDRAWN' });
  assert.equal(closed, 0);
  stop();
  await Promise.all([session.dispose(), onSdkDisposed()]);
  assert.equal(closed, 1);
});

test('every selected identity must match before the exact target can reach the factory', async t => {
  for (const field of ['agentDir', 'credentialPath', 'recipient', 'configIdentity', 'credentialIdentity']) {
    await t.test(field, async () => {
      const { store, profile } = fixture();
      let created = 0, closed = 0;
      const admission = createSdkProfileAdmission({ store,
        openTarget: () => targetLease({ ...profile, [field]: `${profile[field]}-other` },
          { close() { closed++; } }),
        createSession: () => { created++; } });
      await assert.rejects(admission.create('/work', admission.capture()), {
        code: 'ERR_SDK_PROFILE_TARGET_REFUSED', reason: 'profile-identity-changed',
        sdkDisposalState: 'not_created',
      });
      assert.equal(created, 0);
      assert.equal(closed, 1);
    });
  }
});

test('a missing or mutable startup auth snapshot refuses rather than using ambient auth', async () => {
  for (const startupAuthConfig of [undefined, null, { broker: null }]) {
    const { store, profile } = fixture();
    let created = 0, closed = 0;
    const admission = createSdkProfileAdmission({ store,
      openTarget: () => targetLease(profile, { startupAuthConfig, close() { closed++; } }),
      createSession: () => { created++; } });
    await assert.rejects(admission.create('/work', admission.capture()), {
      code: 'ERR_SDK_PROFILE_TARGET_REFUSED', reason: 'invalid-target-lease',
    });
    assert.equal(created, 0);
    assert.equal(closed, 1);
  }
});

test('target open and final verification errors stay target refusals, with their cause', async t => {
  for (const phase of ['open', 'assert']) await t.test(phase, async () => {
    const { store, profile } = fixture();
    const failure = new Error('native failure');
    let created = 0, closed = 0;
    const admission = createSdkProfileAdmission({ store,
      openTarget: () => {
        if (phase === 'open') throw failure;
        return targetLease(profile, { assertCurrent() { throw failure; }, close() { closed++; } });
      },
      createSession: () => { created++; } });
    await assert.rejects(admission.create('/work', admission.capture()), error => {
      assert.equal(error.code, 'ERR_SDK_PROFILE_TARGET_REFUSED');
      assert.strictEqual(error.cause, failure);
      return true;
    });
    assert.equal(created, 0);
    assert.equal(closed, phase === 'open' ? 0 : 1);
  });
});

test('a stale creation is disposed before rejection and never replaces active work', async () => {
  const { store, profile, set } = fixture();
  const factory = deferred(), creating = deferred(), disposal = deferred(), disposing = deferred();
  let created = 0, activeDisposed = 0, staleDisposed = 0, closed = 0, options, activeOptions;
  const active = { async dispose() { activeDisposed++; await activeOptions.onSdkDisposed(); } };
  const stale = {
    async dispose() {
      staleDisposed++;
      disposing.resolve();
      await disposal.promise;
      await options.onSdkDisposed();
    },
  };
  const admission = createSdkProfileAdmission({ store,
    openTarget: () => targetLease(profile, { close() { closed++; } }),
    createSession: (_, __, value) => {
      created++;
      if (created === 1) {
        activeOptions = value;
        return active;
      }
      options = value;
      creating.resolve();
      return factory.promise;
    } });
  const binding = admission.capture();
  assert.strictEqual(await admission.create('/active-work', binding), active);
  const result = admission.create('/stale-work', binding);
  let settled = false;
  const rejected = assert.rejects(result, {
    code: 'SDK_PROFILE_WITHDRAWN', sdkDisposalState: 'disposed',
  }).then(() => { settled = true; });
  await creating.promise;
  set(null);
  set(Object.freeze({ grantId: 8, profile }));
  factory.resolve(stale);
  await disposing.promise;
  assert.equal(staleDisposed, 1);
  assert.equal(activeDisposed, 0);
  assert.equal(closed, 0);
  assert.equal(settled, false);
  disposal.resolve();
  await rejected;
  assert.equal(closed, 1);
  assert.equal(activeDisposed, 0);
  await active.dispose();
  assert.equal(closed, 2);
});

test('a changed target after creation disposes only that unpublished session', async () => {
  const { store, profile } = fixture();
  const failure = new Error('identity changed');
  let current = true, closed = 0, disposed = 0, options;
  const admission = createSdkProfileAdmission({ store,
    openTarget: () => targetLease(profile, {
      assertCurrent() { if (!current) throw failure; }, close() { closed++; },
    }),
    createSession: (_, __, value) => {
      options = value;
      current = false;
      return { async dispose() { disposed++; await options.onSdkDisposed(); } };
    } });
  await assert.rejects(admission.create('/work', admission.capture()), error => {
    assert.equal(error.code, 'ERR_SDK_PROFILE_TARGET_REFUSED');
    assert.strictEqual(error.cause, failure);
    assert.equal(error.sdkDisposalState, 'disposed');
    return true;
  });
  assert.equal(disposed, 1);
  assert.equal(closed, 1);
});

test('explicit no-live-SDK evidence releases a rejected factory lease immediately', async () => {
  for (const sdkDisposalState of ['not_created', 'disposed']) {
    const { store, profile } = fixture();
    const failure = Object.freeze(Object.assign(new Error('factory refused without a live SDK'), {
      code: 'FACTORY_REFUSED', sdkDisposalState,
    }));
    let closed = 0;
    const admission = createSdkProfileAdmission({ store,
      openTarget: () => targetLease(profile, { close() { closed++; } }),
      createSession: () => { throw failure; } });
    await assert.rejects(admission.create('/work', admission.capture()), {
      code: 'FACTORY_REFUSED', sdkDisposalState, cause: failure,
    });
    assert.equal(closed, 1);
  }
});

test('an unconfirmed factory rejection retains the lease until its late disposal hook', async () => {
  const { store, profile } = fixture();
  const failure = Object.freeze(Object.assign(new Error('factory rejected after SDK entry'), { code: 'FACTORY_FAILED' }));
  let closed = 0, options;
  const admission = createSdkProfileAdmission({ store,
    openTarget: () => targetLease(profile, { close() { closed++; } }),
    createSession: (_, __, value) => { options = value; throw failure; } });
  await assert.rejects(admission.create('/work', admission.capture()), {
    code: 'FACTORY_FAILED', sdkDisposalState: 'unconfirmed', cause: failure,
  });
  await admission.retryTargetCleanup();
  assert.equal(closed, 0);
  await Promise.all([options.onSdkDisposed(), options.onSdkDisposed()]);
  assert.equal(closed, 1);
});

test('a factory without a disposable session cannot publish or imply SDK teardown', async () => {
  for (const session of [undefined, null, {}]) {
    const { store, profile } = fixture();
    let closed = 0, options;
    const admission = createSdkProfileAdmission({ store,
      openTarget: () => targetLease(profile, { close() { closed++; } }),
      createSession: (_, __, value) => { options = value; return session; } });
    await assert.rejects(admission.create('/work', admission.capture()), {
      code: 'ERR_SDK_PROFILE_TARGET_REFUSED', reason: 'invalid-session-lifecycle',
      sdkDisposalState: 'unconfirmed',
    });
    assert.equal(closed, 0);
    await options.onSdkDisposed();
    assert.equal(closed, 1);
  }
});

test('adapter disposal alone is not SDK close proof and cannot release stale creation pins', async () => {
  const { store, profile, set } = fixture();
  let closed = 0, disposed = 0, options;
  const admission = createSdkProfileAdmission({ store,
    openTarget: () => targetLease(profile, { close() { closed++; } }),
    createSession: (_, __, value) => {
      options = value;
      set(null);
      return { async dispose() { disposed++; } };
    } });
  await assert.rejects(admission.create('/work', admission.capture()), {
    code: 'SDK_PROFILE_WITHDRAWN', sdkDisposalState: 'unconfirmed',
  });
  assert.equal(disposed, 1);
  assert.equal(closed, 0);
  await options.onSdkDisposed();
  assert.equal(closed, 1);
});

test('failed stale-session teardown preserves both failures and keeps its target pinned', async () => {
  const { store, profile, set } = fixture();
  const failure = new Error('underlying teardown failed');
  let closed = 0, options;
  const admission = createSdkProfileAdmission({ store,
    openTarget: () => targetLease(profile, { close() { closed++; } }),
    createSession: (_, __, value) => {
      options = value;
      set(null);
      return { async dispose() { throw failure; } };
    } });
  await assert.rejects(admission.create('/work', admission.capture()), error => {
    assert.ok(error instanceof AggregateError);
    assert.equal(error.code, 'SDK_PROFILE_WITHDRAWN');
    assert.equal(error.sdkDisposalState, 'unconfirmed');
    assert.equal(error.errors[0].code, 'SDK_PROFILE_WITHDRAWN');
    assert.strictEqual(error.errors[1], failure);
    return true;
  });
  assert.equal(closed, 0);
  await options.onSdkDisposed();
  assert.equal(closed, 1);
});

test('a failed post-disposal target close is retryable and successful close is idempotent', async () => {
  const { store, profile } = fixture();
  const failure = new Error('native close failed');
  let attempts = 0, options;
  const admission = createSdkProfileAdmission({ store,
    openTarget: () => targetLease(profile, {
      close() { if (++attempts === 1) throw failure; },
    }),
    createSession: (_, __, value) => { options = value; return { dispose() {} }; } });
  await admission.create('/work', admission.capture());
  await assert.rejects(options.onSdkDisposed(), {
    code: 'ERR_SDK_PROFILE_TARGET_REFUSED', reason: 'target-close-failed', cause: failure,
  });
  assert.equal(attempts, 1);
  const retry = admission.retryTargetCleanup();
  assert.strictEqual(admission.retryTargetCleanup(), retry);
  await retry;
  await admission.retryTargetCleanup();
  await options.onSdkDisposed();
  assert.equal(attempts, 2);
});

test('failed pre-session cleanup retains an explicit retry owner until close succeeds', async () => {
  const { store, profile } = fixture();
  const failure = new Error('native close failed');
  let blocked = true, attempts = 0, created = 0;
  const admission = createSdkProfileAdmission({ store,
    openTarget: () => targetLease({ ...profile, credentialIdentity: 'different-db' }, {
      close() { attempts++; if (blocked) throw failure; },
    }),
    createSession: () => { created++; } });
  await assert.rejects(admission.create('/work', admission.capture()), error => {
    assert.equal(error.code, 'ERR_SDK_PROFILE_TARGET_REFUSED');
    assert.equal(error.reason, 'target-cleanup-failed');
    assert.equal(error.sdkDisposalState, 'not_created');
    assert.ok(error.cause instanceof AggregateError);
    assert.equal(error.cause.errors[0].reason, 'profile-identity-changed');
    assert.strictEqual(error.cause.errors[1].cause, failure);
    assert.equal(Object.hasOwn(error, 'retryTargetCleanup'), false);
    return true;
  });
  assert.equal(created, 0);
  assert.equal(attempts, 1);
  await assert.rejects(admission.retryTargetCleanup(), error => {
    assert.equal(error.code, 'ERR_SDK_PROFILE_TARGET_REFUSED');
    assert.equal(error.reason, 'target-cleanup-failed');
    assert.strictEqual(error.cause.errors[0].cause, failure);
    return true;
  });
  assert.equal(attempts, 2);
  blocked = false;
  const retry = admission.retryTargetCleanup();
  assert.strictEqual(admission.retryTargetCleanup(), retry);
  await retry;
  await admission.retryTargetCleanup();
  assert.equal(attempts, 3);
});
