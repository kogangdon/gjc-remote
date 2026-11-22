import { SdkProfileTargetError } from './sdk-profile-target.js';

function refusal(code) {
  return Object.assign(new Error(code), { code });
}

function targetFailure(error, reason) {
  return error?.code === 'ERR_SDK_PROFILE_TARGET_REFUSED'
    ? error
    : new SdkProfileTargetError(reason, { cause: error });
}

function creationFailure(error, sdkDisposalState) {
  try {
    Object.defineProperty(error, 'sdkDisposalState', { value: sdkDisposalState, configurable: true });
    return error;
  } catch {
    const failure = new Error('SDK profile session creation failed', { cause: error });
    try {
      if (typeof error?.code === 'string') failure.code = error.code;
    } catch {
      // Keep a rejection with unreadable properties as the cause.
    }
    failure.sdkDisposalState = sdkDisposalState;
    return failure;
  }
}

// One instance per managed daemon. Captures identify one effective allow in
// this process. A configured path is never used as a substitute for a pin.
// The worker factory owns teardown even when creation rejects: it must invoke
// onSdkDisposed only after actual completion, or provide trusted not_created /
// disposed error evidence. Its returned adapter must have an awaitable dispose.
export function createSdkProfileAdmission({ store, openTarget, sessionRoot, createSession }) {
  const bindings = new WeakMap();
  const records = new WeakMap();
  // A rejected SDK factory need not return a session. In that case there is
  // no session object to keep native pin handles from being finalized by GC.
  const retainedLeases = new Set();
  // Once SDK absence is proven, failed native closes have a separate retry
  // owner. Neither a public disposal timeout nor factory rejection enters it.
  const pendingTargetCleanup = new Set();
  let retryingCleanup;

  function retryTargetCleanup() {
    retryingCleanup ??= Promise.allSettled([...pendingTargetCleanup].map(release => release()))
      .then(results => {
        const failures = results.filter(result => result.status === 'rejected').map(result => result.reason);
        if (failures.length) {
          throw new SdkProfileTargetError('target-cleanup-failed', {
            cause: new AggregateError(failures, 'SDK profile target cleanup retry failed'),
          });
        }
      }).finally(() => { retryingCleanup = undefined; });
    return retryingCleanup;
  }

  function capture() {
    const record = store.capture();
    // Verifying a target alone must never opt a shared profile into the
    // embedded SDK running under the control daemon's writer identity.
    if (record === null || typeof openTarget !== 'function' || typeof createSession !== 'function') {
      throw refusal('SDK_PROFILE_UNAVAILABLE');
    }
    let binding = bindings.get(record);
    if (!binding) {
      binding = Object.freeze({
        assertCurrent() {
          if (!store.isCurrent(record)) throw refusal('SDK_PROFILE_WITHDRAWN');
        },
        subscribeWithdrawal(fn) {
          if (typeof fn !== 'function') throw new TypeError('withdrawal subscriber must be a function');
          let notified = false;
          let unsubscribe;
          const notify = () => {
            if (!notified && !store.isCurrent(record)) {
              notified = true;
              unsubscribe?.();
              fn();
            }
          };
          unsubscribe = store.subscribe(notify);
          try {
            notify();
          } catch (error) {
            unsubscribe();
            throw error;
          }
          if (notified) unsubscribe();
          return unsubscribe;
        },
      });
      bindings.set(record, binding);
      records.set(binding, record);
    }
    return binding;
  }

  async function create(workDir, binding) {
    const record = records.get(binding);
    if (!record) throw refusal('SDK_PROFILE_UNAVAILABLE');
    binding.assertCurrent();
    // The authority owns physical identity, recipient, access and resolver
    // checks. A verified lease lasts through *actual* underlying disposal.
    let lease;
    try {
      lease = await openTarget(record.profile);
    } catch (error) {
      const failure = targetFailure(error, 'target-open-failed');
      // An old open can fail after a new grant is already serving. Its error
      // is not a readiness observation about the replacement grant.
      if (!store.isCurrent(record)) {
        throw creationFailure(Object.assign(new Error('SDK_PROFILE_WITHDRAWN', { cause: failure }),
          { code: 'SDK_PROFILE_WITHDRAWN' }), 'not_created');
      }
      throw creationFailure(failure, 'not_created');
    }
    let handedOff = false;
    let sdkDisposed = false;
    let released = false;
    let closing;
    const release = () => {
      if (released) return Promise.resolve();
      retainedLeases.delete(lease);
      pendingTargetCleanup.add(release);
      closing ??= Promise.resolve().then(() => lease.close()).then(
        () => {
          released = true;
          pendingTargetCleanup.delete(release);
        },
        error => {
          closing = undefined;
          throw targetFailure(error, 'target-close-failed');
        },
      );
      return closing;
    };
    // This hook is a proof of underlying teardown, not a notification that
    // adapter.dispose() was called or reached its public timeout. SDK 0.20.0's
    // retained teardown owner is AgentSession.awaitDisposeCompletion().
    const onSdkDisposed = () => {
      sdkDisposed = true;
      return release();
    };
    const assertTargetCurrent = () => {
      try {
        lease.assertCurrent();
      } catch (error) {
        throw targetFailure(error, 'target-verification-failed');
      }
    };
    try {
      binding.assertCurrent();
      const profile = lease?.profile;
      const startupAuthConfig = lease?.startupAuthConfig;
      if (!lease || typeof lease.close !== 'function' || typeof lease.assertCurrent !== 'function' ||
          !profile || !Object.hasOwn(lease, 'startupAuthConfig') ||
          startupAuthConfig === null || typeof startupAuthConfig !== 'object' ||
          !Object.isFrozen(startupAuthConfig)) {
        throw new SdkProfileTargetError('invalid-target-lease');
      }
      const { agentDir, credentialPath, recipient, configIdentity, credentialIdentity } = profile;
      if (agentDir !== record.profile.agentDir ||
          credentialPath !== record.profile.credentialPath ||
          recipient !== record.profile.recipient ||
          configIdentity !== record.profile.configIdentity ||
          credentialIdentity !== record.profile.credentialIdentity) {
        throw new SdkProfileTargetError('profile-identity-changed');
      }
      assertTargetCurrent();
      const profileBinding = Object.freeze({
        agentDir,
        startupAuthConfig,
        assertCurrent() { binding.assertCurrent(); assertTargetCurrent(); },
        subscribeWithdrawal: binding.subscribeWithdrawal,
      });
      retainedLeases.add(lease);
      handedOff = true;
      const session = await createSession(workDir, undefined, { sessionRoot, profileBinding, onSdkDisposed });
      if (!session || typeof session.dispose !== 'function') {
        throw new SdkProfileTargetError('invalid-session-lifecycle');
      }
      try {
        // The factory may complete after withdrawal/regrant. Only this newly
        // created, unpublished session is ours to dispose; never return it for
        // caching or dispose another session's already-admitted work.
        profileBinding.assertCurrent();
      } catch (error) {
        try {
          await session.dispose();
        } catch (disposalError) {
          const failure = new AggregateError([error, disposalError],
            'SDK profile session refusal and disposal failed', { cause: error });
          failure.code = error.code;
          throw failure;
        }
        throw error;
      }
      return session;
    } catch (error) {
      if (!handedOff && error?.code !== 'SDK_PROFILE_WITHDRAWN') {
        error = targetFailure(error, 'invalid-target-lease');
      }
      const state = !handedOff || error?.sdkDisposalState === 'not_created'
        ? 'not_created'
        : sdkDisposed || error?.sdkDisposalState === 'disposed' ? 'disposed' : 'unconfirmed';
      if (state !== 'unconfirmed') {
        try {
          await release();
        } catch (cleanupError) {
          throw creationFailure(new SdkProfileTargetError('target-cleanup-failed', {
            cause: new AggregateError([error, cleanupError], 'SDK profile refusal and pin cleanup failed'),
          }), state);
        }
      }
      throw creationFailure(error, state);
    }
  }
  return Object.freeze({ capture, create, retryTargetCleanup });
}
