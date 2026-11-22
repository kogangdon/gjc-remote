import { canonicalJsonBytes, parseStrictJsonBytes } from '@gjc-remote/shared/strict-json';
import { hostStateDirectory } from './host-state-directory.js';
import {
  createProfileDecisionState,
  nextProfileDecision,
  normalizeProfileDecision,
} from './sdk-profile-decision.js';

export const SDK_PROFILE_FILE_NAME = 'sdk-profile-sharing.json';
export const SDK_PROFILE_FILE_LIMITS = Object.freeze({ maxBytes: 64 * 1024, maxDepth: 4, maxNodes: 32 });

function refusal(code) {
  return Object.assign(new Error(code), { code });
}

function sameRecord(left, right) {
  return left === right || (left !== null && right !== null &&
    canonicalJsonBytes(left).equals(canonicalJsonBytes(right)));
}

function sameProfile(left, right) {
  return canonicalJsonBytes(left.profile).equals(canonicalJsonBytes(right.profile));
}

function regresses(candidate, baseline) {
  return baseline !== null && candidate.grantId <= baseline.grantId &&
    (candidate.grantId < baseline.grantId || !sameProfile(candidate, baseline) || (candidate.allowed && !baseline.allowed));
}

async function readCurrent(boundary) {
  const handle = await boundary.openCurrent();
  if (handle === null) {
    await boundary.verifyCurrent(null);
    return { record: null, reason: 'SDK_PROFILE_RECORD_MISSING' };
  }
  let bytes;
  try {
    const before = await handle.stat();
    if (!before.isFile() || before.nlink !== 1) throw refusal('SDK_PROFILE_FILE_UNQUALIFIED');
    if (!Number.isSafeInteger(before.size) || before.size < 0 || before.size > SDK_PROFILE_FILE_LIMITS.maxBytes) {
      await boundary.verifyCurrent(handle);
      return { record: null, reason: 'SDK_PROFILE_RECORD_INVALID' };
    }
    // Never read an unbounded file, including one which grows after stat().
    bytes = Buffer.alloc(SDK_PROFILE_FILE_LIMITS.maxBytes + 1);
    let offset = 0;
    while (offset < bytes.length) {
      const { bytesRead } = await handle.read(bytes, offset, bytes.length - offset, offset);
      if (!Number.isSafeInteger(bytesRead) || bytesRead < 0 || bytesRead > bytes.length - offset) {
        throw refusal('SDK_PROFILE_AUTHORITY_INVALID');
      }
      if (bytesRead === 0) break;
      offset += bytesRead;
    }
    const after = await handle.stat();
    await boundary.verifyCurrent(handle);
    if (['dev', 'ino', 'size', 'mtimeMs', 'ctimeMs'].some(key => before[key] !== after[key]) || offset !== after.size) {
      throw refusal('SDK_PROFILE_FILE_CHANGED');
    }
    if (offset > SDK_PROFILE_FILE_LIMITS.maxBytes) return { record: null, reason: 'SDK_PROFILE_RECORD_INVALID' };
    bytes = bytes.subarray(0, offset);
  } finally {
    await handle.close();
  }
  try {
    return { record: normalizeProfileDecision(parseStrictJsonBytes(bytes, SDK_PROFILE_FILE_LIMITS)), reason: null };
  } catch {
    return { record: null, reason: 'SDK_PROFILE_RECORD_INVALID' };
  }
}

/**
 * Fixed-file decision authority. Only admitted management requests may call
 * setDecision(); no request-supplied permission or "trusted" flag is accepted.
 * getDecision() retains withdrawn high-water history after failures, but that
 * synthetic record is NOT proof of persistence: getStatus().error remains
 * DECISION_UNAVAILABLE until a qualified, acceptable record is read.
 *
 * REQUIRED production authority adapter (trusted platform code, not JSON):
 *
 * withQualifiedFile({directory, fileName, write}, callback) returns a Promise
 * for callback(boundary)'s result and must await it before releasing authority.
 * It qualifies the fixed directory, ancestors and current entry against OS ownership,
 * ACLs and replacement/reparse/hard-link attacks before invoking callback. A
 * workload-writable directory is NOT qualified, even with a read-only file.
 * Retain the qualified namespace/handles for the callback's lifetime and
 * revalidate each operation. `write` requests an operation; it proves no right.
 * There is no settings lock, installer reauthentication or per-dispatch I/O.
 *
 * The callback boundary provides:
 * - openCurrent(): qualified regular FileHandle, or null for absence;
 * - verifyCurrent(handleOrNull): reject if its protected directory entry,
 *   object identity, security or snapshot changed; null verifies absence;
 * - writeTemp(bytes): exclusive protected same-directory temp, returning a ref;
 * - flushTemp(ref): flush ALL bytes and close its handle;
 * - replace(ref): single atomic same-volume replace/create, no copy fallback;
 * - flushParent(): complete the platform's durable publication operation;
 * - discardTemp(ref): idempotently close/remove only this operation's temp,
 *   never live data.
 * Failed writeTemp must clean up its own partial temp. No durability/authority
 * operation may silently degrade to a no-op on an unsupported platform.
 *
 * watch({directory,fileName,onChange,onError}) watches the parent, including
 * replacement/deletion, and returns {close()}. Notifications are only hints:
 * every notification and periodic tick requalifies and rereads complete bytes.
 * Watch errors revoke immediately; periodic reconciliation retries the watch.
 * Direct authorized edits must publish atomically too. They are not locked
 * out: a detected pre/post-publication conflict is applied, never acknowledged
 * as this request's success. No adapter => management-only, never a raw-fs
 * fallback. Production Windows ACL/retained-handle/durable-replace and POSIX
 * protected namespace implementations must be supplied by platform wiring.
 */
export function createSdkProfileStore({ authority = null, reconciliationIntervalMs = 5000, timers = globalThis } = {}) {
  if (!Number.isSafeInteger(reconciliationIntervalMs) || reconciliationIntervalMs < 1 || reconciliationIntervalMs > 0x7fffffff ||
      typeof timers?.setInterval !== 'function' || typeof timers?.clearInterval !== 'function') {
    throw new TypeError('Invalid SDK profile reconciliation schedule');
  }
  const location = Object.freeze({ directory: hostStateDirectory(), fileName: SDK_PROFILE_FILE_NAME });
  const state = createProfileDecisionState();
  let record = null;
  let error = Object.freeze({ code: 'DECISION_UNAVAILABLE', reason: 'SDK_PROFILE_NOT_STARTED' });
  let changed = false;
  let queue = Promise.resolve();
  let started = false;
  let closed = false;
  let startPromise;
  let timer;
  let watcher;
  let watchToken;
  let watchEpoch = 0;
  let scheduled = null;

  const getStatus = () => Object.freeze({ record, binding: state.capture(), changed, error });
  const assertOpen = () => { if (closed) throw refusal('SDK_PROFILE_STORE_CLOSED'); };
  function enqueue(operation) {
    const pending = queue.then(() => { assertOpen(); return operation(); });
    queue = pending.catch(() => {});
    return pending;
  }
  function unavailable(reason, publishedRecord = null) {
    if (publishedRecord !== null && (record === null || publishedRecord.grantId > record.grantId)) record = publishedRecord;
    record = nextProfileDecision(record, null);
    error = Object.freeze({ code: 'DECISION_UNAVAILABLE', reason });
    changed = state.apply(record);
    return getStatus();
  }
  function apply(observed) {
    assertOpen();
    const candidate = observed.record;
    if (candidate === null) return unavailable(observed.reason);
    if (regresses(candidate, record)) {
      return unavailable('SDK_PROFILE_DECISION_STALE');
    }
    // Publish full management history before state notifies session consumers.
    record = candidate;
    error = null;
    changed = state.apply(candidate);
    return getStatus();
  }
  async function qualified(write, operation) {
    if (typeof authority?.withQualifiedFile !== 'function') throw refusal('SDK_PROFILE_AUTHORITY_UNAVAILABLE');
    let called = false;
    return authority.withQualifiedFile({ ...location, write }, async boundary => {
      if (called) throw refusal('SDK_PROFILE_AUTHORITY_INVALID');
      called = true;
      assertOpen();
      const methods = ['openCurrent', 'verifyCurrent', ...(write ? ['writeTemp', 'flushTemp', 'replace', 'flushParent', 'discardTemp'] : [])];
      if (methods.some(name => typeof boundary?.[name] !== 'function')) throw refusal('SDK_PROFILE_AUTHORITY_INVALID');
      return operation(boundary);
    }).then(value => {
      if (!called) throw refusal('SDK_PROFILE_AUTHORITY_INVALID');
      return value;
    });
  }
  async function reread(boundary, publishedRecord = null) {
    for (let attempt = 0; attempt < 3; attempt += 1) {
      const epoch = watchEpoch;
      const observed = await readCurrent(boundary);
      assertOpen();
      if (!watcher) throw refusal('SDK_PROFILE_WATCH_FAILED');
      if (epoch !== watchEpoch) continue;
      // Our successful replace is known history even if another writer has
      // already hidden it. Never apply a rollback or same-ID substitution as
      // a fresh allow, and never reuse an ID we actually published.
      if (publishedRecord !== null && (observed.record === null || regresses(observed.record, publishedRecord))) {
        return unavailable(observed.reason ?? 'SDK_PROFILE_DECISION_STALE', publishedRecord);
      }
      return apply(observed);
    }
    throw refusal('SDK_PROFILE_FILE_CHANGED');
  }
  function schedule() {
    if (!started || closed || scheduled !== null) return;
    scheduled = enqueue(reconcileNow).finally(() => { scheduled = null; });
    // Event/timer callbacks have no caller to receive a rejected closed-store read.
    scheduled.catch(() => {});
  }
  function dropWatcher() {
    const previous = watcher;
    watcher = undefined;
    watchToken = undefined;
    if (previous) {
      try { previous.close(); } catch { /* Requalification, not watcher cleanup, owns authority. */ }
    }
  }
  async function ensureWatcher() {
    if (watcher) return;
    if (typeof authority?.watch !== 'function') throw refusal('SDK_PROFILE_AUTHORITY_UNAVAILABLE');
    const token = {};
    watchToken = token;
    const pending = await authority.watch({
      ...location,
      onChange() {
        if (closed || watchToken !== token) return;
        watchEpoch += 1;
        schedule();
      },
      onError() {
        if (closed || watchToken !== token) return;
        watchEpoch += 1;
        dropWatcher();
        unavailable('SDK_PROFILE_WATCH_FAILED');
        schedule();
      },
    });
    if (!pending || typeof pending.close !== 'function') throw refusal('SDK_PROFILE_AUTHORITY_INVALID');
    if (closed) {
      pending.close();
      throw refusal('SDK_PROFILE_STORE_CLOSED');
    }
    if (watchToken !== token) {
      pending.close();
      throw refusal('SDK_PROFILE_WATCH_FAILED');
    }
    watcher = pending;
  }
  async function reconcileNow() {
    try {
      await ensureWatcher();
      await qualified(false, reread);
      return getStatus();
    } catch (failure) {
      if (closed) throw refusal('SDK_PROFILE_STORE_CLOSED');
      return unavailable(failure?.code ?? 'SDK_PROFILE_READ_FAILED');
    }
  }
  function start() {
    if (closed) return Promise.reject(refusal('SDK_PROFILE_STORE_CLOSED'));
    if (started) return startPromise.then(getStatus);
    started = true;
    if (typeof authority?.withQualifiedFile === 'function') {
      timer = timers.setInterval(() => { schedule(); }, reconciliationIntervalMs);
      timer?.unref?.();
    }
    startPromise = enqueue(reconcileNow);
    return startPromise;
  }
  function reconcile() {
    return started ? enqueue(reconcileNow) : start();
  }
  async function publishDecision(expectedRecord, profileOrNull, repairStale) {
    // Detach request data before awaiting or joining the write queue.
    const expected = expectedRecord === null ? null : normalizeProfileDecision(expectedRecord);
    const profile = profileOrNull === null ? null : nextProfileDecision(null, profileOrNull).profile;
    function assertExpected() {
      // A retained denial after a failed read is not a persisted decision.
      // Only explicit recovery may compare against stale high-water history.
      const eligible = repairStale
        ? expected?.allowed === false && error?.reason === 'SDK_PROFILE_DECISION_STALE'
        : expected === null ? error?.reason === 'SDK_PROFILE_RECORD_MISSING' : error === null;
      if (!eligible || !sameRecord(record, expected)) {
        throw refusal('SDK_PROFILE_DECISION_CONFLICT');
      }
    }
    if (!started) await start();
    return enqueue(async () => {
      let publishedRecord = null;
      try {
        await ensureWatcher();
        const saved = await qualified(true, async boundary => {
          await reread(boundary);
          assertExpected();
          const intended = nextProfileDecision(record, profile);
          if (intended === null) return null; // Withdrawal without any history is a no-op, not a persistence receipt.
          const bytes = canonicalJsonBytes(intended, SDK_PROFILE_FILE_LIMITS);
          if (bytes.length > SDK_PROFILE_FILE_LIMITS.maxBytes) throw refusal('SDK_PROFILE_RECORD_TOO_LARGE');
          if (sameRecord(intended, record) && error === null) {
            await reread(boundary);
            if (!sameRecord(record, intended) || error !== null) throw refusal('SDK_PROFILE_DECISION_CONFLICT');
            return record;
          }
          let temp;
          try {
            temp = await boundary.writeTemp(bytes);
            await boundary.flushTemp(temp);
            await reread(boundary);
            assertExpected();
            assertOpen();
            await boundary.replace(temp);
            publishedRecord = intended;
            await boundary.flushParent();
            // Cleanup can await platform I/O; it must precede the final read.
            await boundary.discardTemp(temp);
            temp = undefined;
            await reread(boundary, publishedRecord);
            if (!sameRecord(record, intended) || error !== null) throw refusal('SDK_PROFILE_DECISION_CONFLICT');
            return record;
          } finally {
            if (temp !== undefined) await boundary.discardTemp(temp);
          }
        });
        // The platform may await handle cleanup when leaving the write
        // boundary. Requalify after that cleanup too, before acknowledging.
        await qualified(false, boundary => reread(boundary, publishedRecord));
        assertOpen();
        if (!sameRecord(record, saved) ||
            (saved === null ? error?.reason !== 'SDK_PROFILE_RECORD_MISSING' : error !== null)) {
          throw refusal('SDK_PROFILE_DECISION_CONFLICT');
        }
        return saved;
      } catch (failure) {
        // Conflicts already applied (or rejected) the observed decision. Other
        // failures cannot preserve an allow or erase an actually published ID.
        if (!closed && failure?.code !== 'SDK_PROFILE_RECORD_TOO_LARGE' && failure?.code !== 'SDK_PROFILE_DECISION_CONFLICT') {
          unavailable(failure?.code ?? 'SDK_PROFILE_WRITE_FAILED', publishedRecord);
        }
        throw failure;
      }
    });
  }
  function close() {
    if (!closed) {
      closed = true;
      if (timer !== undefined) timers.clearInterval(timer);
      dropWatcher();
      unavailable('SDK_PROFILE_STORE_CLOSED');
    }
    return queue;
  }
  return Object.freeze({
    start, reconcile, close, getStatus,
    setDecision: (expected, profile) => publishDecision(expected, profile, false),
    repairStaleDecision: (expected, profile) => publishDecision(expected, profile, true),
    getDecision: () => record,
    capture: () => state.capture(),
    isCurrent: binding => state.isCurrent(binding),
    subscribe: listener => state.subscribe(listener),
  });
}
