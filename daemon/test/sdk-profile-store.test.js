import test from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { constants } from 'node:fs';
import { copyFile, link, lstat, mkdir, mkdtemp, open, readFile, rename, rm, unlink, utimes, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { hostStateDirectory } from '../src/host-state-directory.js';
import {
  createSdkProfileStore,
  SDK_PROFILE_FILE_LIMITS,
  SDK_PROFILE_FILE_NAME,
} from '../src/sdk-profile-store.js';

const failure = code => Object.assign(new Error(code), { code });
const copy = value => JSON.parse(JSON.stringify(value));
function deferred() {
  let resolve;
  const promise = new Promise(done => { resolve = done; });
  return { promise, resolve };
}
function nextBinding(store, predicate) {
  return new Promise(resolve => {
    const stop = store.subscribe(binding => {
      if (predicate(binding)) { stop(); resolve(binding); }
    });
  });
}

// This trusted test adapter maps the fixed production request to one temp
// namespace. Its callbacks MODEL native authority/durability receipts. It is
// deliberately not a production ACL, retained-directory or Windows durability
// implementation. No test opens a real host-state directory or SDK profile.
// Pinned-read mode uses a separate temp snapshot and modeled namespace identity,
// not proof that Windows permits replacing a genuinely open production handle.
async function fixture(t, { initial, raw } = {}) {
  const root = await mkdtemp(join(tmpdir(), 'gjc-sdk-profile-store-'));
  const file = join(root, SDK_PROFILE_FILE_NAME);
  const profile = Object.freeze({
    agentDir: join(root, 'agent'),
    credentialPath: join(root, 'agent', 'agent.db'),
    recipient: 'fixture-service-account',
    configIdentity: 'fixture-config-object',
    credentialIdentity: 'fixture-credential-object',
  });
  const allow = (grantId = 7, changes = {}) => ({ version: 1, grantId, allowed: true, profile: { ...profile, ...changes } });
  const denied = (grantId = 7, changes = {}) => ({ ...allow(grantId, changes), allowed: false });
  const calls = [];
  const hooks = {};
  const controls = { qualified: true, writable: true, watchUnavailable: false, pinRead: false };
  const handles = new Set();
  const snapshots = new Set();
  const pinnedEntries = new WeakMap();
  const temps = new Set();
  const watchers = [];
  const intervals = new Set();
  let active = 0;
  let maxActive = 0;
  let bytesRead = 0;
  let namespaceGeneration = 0;
  let store;

  function qualified(write = false) {
    if (!controls.qualified || (write && !controls.writable)) throw failure('EACCES');
  }
  async function entry() {
    qualified();
    let stat;
    try { stat = await lstat(file); } catch (error) { if (error.code === 'ENOENT') return null; throw error; }
    if (!stat.isFile() || stat.isSymbolicLink() || stat.nlink !== 1) throw failure('SDK_PROFILE_FILE_UNQUALIFIED');
    return stat;
  }
  async function publish(value, mtime) {
    const path = join(root, `.direct-${randomUUID()}.tmp`);
    const bytes = typeof value === 'string' || value instanceof Uint8Array ? value : JSON.stringify(value);
    await writeFile(path, bytes, { flag: 'wx', mode: 0o600 });
    if (mtime !== undefined) await utimes(path, mtime, mtime);
    await rename(path, file);
    namespaceGeneration += 1;
  }
  if (raw !== undefined) await publish(raw);
  else if (initial !== undefined) await publish(initial === null ? 'null' : allow(initial));

  const authority = {
    async withQualifiedFile(request, operation) {
      assert.equal(request.directory, hostStateDirectory());
      assert.equal(request.fileName, SDK_PROFILE_FILE_NAME);
      assert.equal(typeof request.write, 'boolean');
      calls.push(request.write ? 'qualify-write' : 'qualify-read');
      qualified(request.write);
      active += 1;
      maxActive = Math.max(maxActive, active);
      try {
        await hooks.qualified?.(request);
        return await operation({
          async openCurrent() {
            calls.push('open');
            const before = await entry();
            if (before === null) return null;
            const generation = namespaceGeneration;
            let handle;
            let wrapper;
            let pinnedPath;
            let closed = false;
            async function close() {
              if (closed) return;
              closed = true;
              try { await handle?.close(); } finally {
                handles.delete(wrapper);
                if (pinnedPath) {
                  await unlink(pinnedPath);
                  snapshots.delete(pinnedPath);
                }
              }
            }
            try {
              let readPath = file;
              if (controls.pinRead) {
                const path = join(root, `.pinned-${randomUUID()}.tmp`);
                await copyFile(file, path, constants.COPYFILE_EXCL);
                pinnedPath = path;
                snapshots.add(path);
                readPath = path;
              }
              handle = await open(readPath, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0));
              const opened = await handle.stat();
              if (!pinnedPath && (before.dev !== opened.dev || before.ino !== opened.ino)) throw failure('SDK_PROFILE_FILE_CHANGED');
              wrapper = {
                stat: () => handle.stat(),
                async read(...args) {
                  await hooks.read?.();
                  const result = await handle.read(...args);
                  bytesRead += result.bytesRead;
                  return result;
                },
                close,
              };
              handles.add(wrapper);
              if (pinnedPath) pinnedEntries.set(wrapper, { stat: before, generation });
              await hooks.opened?.(wrapper);
              return wrapper;
            } catch (error) {
              await close();
              throw error;
            }
          },
          async verifyCurrent(handle) {
            calls.push('verify');
            const current = await entry();
            if (handle === null) {
              if (current !== null) throw failure('SDK_PROFILE_FILE_CHANGED');
            } else {
              const pinned = pinnedEntries.get(handle);
              const opened = pinned?.stat ?? await handle.stat();
              if (current === null || current.dev !== opened.dev || current.ino !== opened.ino ||
                  (pinned && pinned.generation !== namespaceGeneration)) throw failure('SDK_PROFILE_FILE_CHANGED');
            }
          },
          async writeTemp(bytes) {
            calls.push('writeTemp');
            qualified(true);
            await hooks.writeTemp?.();
            const path = join(root, `${SDK_PROFILE_FILE_NAME}.${randomUUID()}.tmp`);
            const handle = await open(path, 'wx', 0o600);
            const ref = { path, handle, closed: false };
            temps.add(ref);
            try { await handle.writeFile(bytes); } catch (error) {
              await handle.close();
              await unlink(path);
              temps.delete(ref);
              throw error;
            }
            return ref;
          },
          async flushTemp(ref) {
            calls.push('flushTemp');
            try { await ref.handle.sync(); } finally { await ref.handle.close(); ref.closed = true; }
            await hooks.flushTemp?.();
          },
          async replace(ref) {
            calls.push('replace');
            qualified(true);
            await rename(ref.path, file);
            namespaceGeneration += 1;
            await hooks.replace?.();
          },
          async flushParent() {
            calls.push('flushParent');
            await hooks.flushParent?.();
            // Actual file flush, plus a MODELED platform publication receipt;
            // this does not claim directory durability on Windows.
            const handle = await open(file, 'r+');
            try { await handle.sync(); } finally { await handle.close(); }
          },
          async discardTemp(ref) {
            calls.push('discardTemp');
            if (!ref.closed) { await ref.handle.close(); ref.closed = true; }
            try { await unlink(ref.path); } catch (error) { if (error.code !== 'ENOENT') throw error; }
            temps.delete(ref);
            await hooks.discardTemp?.();
          },
        });
      } finally {
        try { await hooks.released?.(request); } finally { active -= 1; }
      }
    },
    watch(request) {
      assert.equal(request.directory, hostStateDirectory());
      assert.equal(request.fileName, SDK_PROFILE_FILE_NAME);
      calls.push('watch');
      if (controls.watchUnavailable) throw failure('EIO');
      const watcher = { ...request, closed: false, close() { this.closed = true; } };
      watchers.push(watcher);
      hooks.watch?.(watcher);
      return watcher;
    },
  };
  const timers = {
    setInterval(callback, milliseconds) {
      const timer = { callback, milliseconds, unref() {} };
      intervals.add(timer);
      return timer;
    },
    clearInterval(timer) { intervals.delete(timer); },
  };
  store = createSdkProfileStore({ authority, timers, reconciliationIntervalMs: 50 });
  t.after(async () => {
    try {
      await store.close();
      assert.equal(handles.size, 0, 'all qualified read handles are closed');
      assert.equal(snapshots.size, 0, 'all modeled pinned snapshots are cleaned');
      assert.equal(temps.size, 0, 'only operation-owned temps are cleaned');
    } finally { await rm(root, { recursive: true, force: true }); }
  });
  return {
    store, root, file, profile, allow, denied, calls, hooks, controls, watchers, intervals, publish,
    tick() { for (const timer of intervals) timer.callback(); },
    notify() { watchers.at(-1).onChange(); },
    get maxActive() { return maxActive; },
    get bytesRead() { return bytesRead; },
    get openHandles() { return handles.size; },
    get pinnedCopies() { return snapshots.size; },
  };
}

async function assertRefusal(promise, code) {
  await assert.rejects(promise, error => { assert.equal(error.code, code); return true; });
}

test('missing or self-declared storage authority is management-only and never grants writes', async t => {
  const f = await fixture(t);
  for (const authority of [null, { trusted: true, directory: f.root }]) {
    const store = createSdkProfileStore({ authority });
    t.after(() => store.close());
    const status = await store.start();
    assert.equal(status.binding, null);
    assert.equal(status.error.code, 'DECISION_UNAVAILABLE');
    assert.equal(status.error.reason, 'SDK_PROFILE_AUTHORITY_UNAVAILABLE');
    await assertRefusal(store.setDecision(null, f.profile), 'SDK_PROFILE_AUTHORITY_UNAVAILABLE');
    assert.equal(store.capture(), null);
  }
  assert.deepEqual(f.calls, []);
});

test('startup loads the qualified fixed file and publishes before notifying without per-capture reads', async t => {
  const f = await fixture(t, { initial: 7 });
  const observed = [];
  const stop = f.store.subscribe(binding => {
    assert.equal(f.store.capture(), binding);
    assert.deepEqual(f.store.getDecision(), binding);
    assert.equal(f.store.getStatus().error, null);
    observed.push(binding);
  });
  const status = await f.store.start();
  assert.deepEqual(status.record, f.allow());
  const binding = f.store.capture();
  const calls = f.calls.length;
  assert.equal(Object.isFrozen(binding), true);
  assert.equal(Object.isFrozen(binding.profile), true);
  assert.equal(f.store.isCurrent(binding), true);
  assert.equal(f.store.isCurrent(copy(binding)), false);
  assert.equal(f.store.capture(), binding);
  assert.equal(f.calls.length, calls);
  assert.deepEqual(observed, [binding]);
  stop();
  await f.publish(f.denied());
  await f.store.reconcile();
  assert.deepEqual(observed, [binding]);
  assert.equal(f.store.isCurrent(binding), false);
});

test('equivalent rewrites do not notify, but same-size same-mtime replacement is fully reread', async t => {
  const f = await fixture(t, { initial: 7 });
  const timestamp = new Date('2025-01-01T00:00:00Z');
  await utimes(f.file, timestamp, timestamp);
  const events = [];
  f.store.subscribe(binding => events.push(binding));
  await f.store.start();
  const original = f.store.capture();
  const reordered = { profile: Object.fromEntries(Object.entries(f.profile).reverse()), allowed: true, grantId: 7, version: 1 };
  await f.publish(reordered, timestamp);
  await f.store.reconcile();
  assert.equal(f.store.capture(), original);
  assert.equal(events.length, 1);
  const before = await lstat(f.file);
  const originalBytes = await readFile(f.file);
  const replaced = reordered;
  replaced.grantId = 8;
  await f.publish(replaced, timestamp);
  const after = await lstat(f.file);
  assert.equal(after.size, before.size);
  assert.equal(after.mtimeMs, before.mtimeMs);
  assert.notDeepEqual(await readFile(f.file), originalBytes);
  await f.store.reconcile();
  assert.equal(f.store.capture().grantId, 8);
  assert.equal(f.store.isCurrent(original), false);
  assert.equal(events.length, 2);
});

test('strict bounded parsing revokes on duplicate keys, bad encoding, invalid schema and trailing data', async t => {
  const f = await fixture(t, { initial: 7 });
  const json = JSON.stringify(f.allow());
  const invalid = [
    json.replace('"allowed":true', '"allowed":true,"allowed":false'),
    Buffer.concat([Buffer.from([0xef, 0xbb, 0xbf]), Buffer.from(json)]),
    Buffer.from([0xff, 0xfe]),
    `${json} false`,
    JSON.stringify({ ...f.allow(), version: 2 }),
    JSON.stringify({ ...f.allow(), trusted: true }),
    JSON.stringify({ ...f.allow(), profile: null }),
    json.replace('"grantId":7', '"grantId":-0'),
    '['.repeat(6) + 'null' + ']'.repeat(6),
    '[' + Array(40).fill('null').join(',') + ']',
    JSON.stringify(f.allow(7, { recipient: 'line\nbreak' })),
    JSON.stringify(f.allow(7, { credentialPath: 'relative/agent.db' })),
    Buffer.alloc(SDK_PROFILE_FILE_LIMITS.maxBytes + 1, 0x20),
  ];
  await f.store.start();
  const old = f.store.capture();
  for (const raw of invalid) {
    await f.publish(raw);
    const status = await f.store.reconcile();
    assert.equal(status.error.code, 'DECISION_UNAVAILABLE');
    assert.equal(status.error.reason, 'SDK_PROFILE_RECORD_INVALID');
    assert.equal(f.store.capture(), null);
    assert.deepEqual(f.store.getDecision(), f.denied());
  }
  await f.publish(f.allow());
  const replay = await f.store.reconcile();
  assert.equal(replay.error.reason, 'SDK_PROFILE_DECISION_STALE');
  assert.equal(f.store.isCurrent(old), false);
});

test('growth after stat is bounded to the byte cap plus one and never preserves an allow', async t => {
  const f = await fixture(t, { initial: 7 });
  await f.store.start();
  const before = f.bytesRead;
  let grew = false;
  f.hooks.read = async () => {
    if (grew) return;
    grew = true;
    await writeFile(f.file, Buffer.alloc(SDK_PROFILE_FILE_LIMITS.maxBytes * 2, 0x20));
  };
  const status = await f.store.reconcile();
  assert.equal(status.error.code, 'DECISION_UNAVAILABLE');
  assert.equal(f.store.capture(), null);
  assert.ok(f.bytesRead - before <= SDK_PROFILE_FILE_LIMITS.maxBytes + 1);
});

test('replacement during an open read is rejected instead of applying bytes from a stale entry', async t => {
  const f = await fixture(t, { initial: 7 });
  await f.store.start();
  const original = f.store.capture();
  f.controls.pinRead = true;
  let replaced = false;
  f.hooks.opened = async () => {
    if (replaced) return;
    await f.publish(f.allow(8));
    replaced = true;
  };
  const status = await f.store.reconcile();
  assert.equal(replaced, true, 'publication completed before asserting replacement behavior');
  assert.deepEqual(JSON.parse(await readFile(f.file, 'utf8')), f.allow(8));
  assert.equal(status.error.reason, 'SDK_PROFILE_FILE_CHANGED');
  assert.equal(f.store.capture(), null);
  assert.equal(f.store.isCurrent(original), false);
  assert.equal(f.openHandles, 0);
  assert.equal(f.pinnedCopies, 0);
  assert.deepEqual((await f.store.reconcile()).record, f.allow(8));
});

test('a throwing opened hook closes its modeled pinned handle and removes its snapshot', async t => {
  const f = await fixture(t, { initial: 7 });
  await f.store.start();
  f.controls.pinRead = true;
  f.hooks.opened = () => { throw failure('EIO'); };
  const status = await f.store.reconcile();
  assert.equal(status.error.reason, 'EIO');
  assert.equal(f.store.capture(), null);
  assert.equal(f.openHandles, 0);
  assert.equal(f.pinnedCopies, 0);
});

test('absence, lost qualification and replay retain withdrawn high-water recovery history', async t => {
  const f = await fixture(t, { initial: 7 });
  await f.store.start();
  const original = f.store.capture();
  await unlink(f.file);
  assert.equal((await f.store.reconcile()).error.reason, 'SDK_PROFILE_RECORD_MISSING');
  assert.deepEqual(f.store.getDecision(), f.denied());
  assert.equal(f.store.isCurrent(original), false);
  await f.publish(f.allow());
  assert.equal((await f.store.reconcile()).error.reason, 'SDK_PROFILE_DECISION_STALE');
  await assertRefusal(f.store.setDecision(null, f.profile), 'SDK_PROFILE_DECISION_CONFLICT');
  f.controls.qualified = false;
  await assertRefusal(f.store.setDecision(f.denied(), f.profile), 'EACCES');
  assert.equal(f.store.getStatus().error.code, 'DECISION_UNAVAILABLE');
  f.controls.qualified = true;
  await assertRefusal(f.store.setDecision(f.denied(), f.profile), 'SDK_PROFILE_DECISION_CONFLICT');
  const renewed = await f.store.repairStaleDecision(f.denied(), f.profile);
  assert.deepEqual(renewed, f.allow(8));
  assert.equal(f.store.getStatus().error, null);
  assert.equal(f.store.isCurrent(original), false);
  f.controls.qualified = false;
  await f.store.reconcile();
  assert.equal(f.store.capture(), null);
  assert.deepEqual(f.store.getDecision(), f.denied(8));
});

test('unqualified hard-linked or non-file entries cannot be read or published over', async t => {
  const f = await fixture(t, { initial: 7 });
  await f.store.start();
  await link(f.file, join(f.root, 'other-link'));
  assert.equal((await f.store.reconcile()).error.reason, 'SDK_PROFILE_FILE_UNQUALIFIED');
  await assertRefusal(f.store.setDecision(f.denied(), f.profile), 'SDK_PROFILE_FILE_UNQUALIFIED');
  await unlink(f.file);
  await mkdir(f.file);
  assert.equal((await f.store.reconcile()).error.reason, 'SDK_PROFILE_FILE_UNQUALIFIED');
  assert.equal(f.store.capture(), null);
  assert.equal(f.calls.includes('writeTemp'), false);
});

test('a first grant cannot overwrite invalid bytes that appeared after qualified absence', async t => {
  for (const phase of ['before-write', 'after-temp-flush']) await t.test(phase, async t => {
    const f = await fixture(t);
    assert.equal((await f.store.start()).error.reason, 'SDK_PROFILE_RECORD_MISSING');
    const malformed = '{"version":';
    const edit = () => writeFile(f.file, malformed, { flag: 'wx' });
    if (phase === 'before-write') await edit();
    else f.hooks.flushTemp = edit;
    await assertRefusal(f.store.setDecision(null, f.profile), 'SDK_PROFILE_DECISION_CONFLICT');
    assert.equal(f.calls.includes('replace'), false);
    assert.equal(await readFile(f.file, 'utf8'), malformed);
    assert.equal(f.store.capture(), null);
  });
});

test('empty-history withdrawal cannot acknowledge absence if invalid bytes appear on boundary release', async t => {
  const f = await fixture(t);
  await f.store.start();
  f.hooks.released = async request => {
    if (request.write) await writeFile(f.file, '{', { flag: 'wx' });
  };
  await assertRefusal(f.store.setDecision(null, null), 'SDK_PROFILE_DECISION_CONFLICT');
  assert.equal(f.calls.includes('writeTemp'), false);
  assert.equal(f.store.getStatus().error.reason, 'SDK_PROFILE_RECORD_INVALID');
});

test('regrant preserves an intervening invalid edit to a persisted denial', async t => {
  const f = await fixture(t, { initial: 7 });
  await f.publish(f.denied());
  const status = await f.store.start();
  assert.equal(status.error, null);
  assert.equal(status.record.allowed, false);
  assert.equal(status.record.grantId, 7);
  const edit = '{"unfinished":';
  f.hooks.flushTemp = () => writeFile(f.file, edit);
  await assertRefusal(f.store.setDecision(status.record, f.profile), 'SDK_PROFILE_DECISION_CONFLICT');
  assert.equal(f.store.capture(), null);
  assert.equal(await readFile(f.file, 'utf8'), edit);
  assert.equal(f.calls.includes('replace'), false);
});

test('first authorized write acknowledges only after durable publication, cleanup, reread and application', async t => {
  const f = await fixture(t);
  assert.equal((await f.store.start()).error.reason, 'SDK_PROFILE_RECORD_MISSING');
  const flushing = deferred();
  const release = deferred();
  f.hooks.flushParent = async () => { flushing.resolve(); await release.promise; };
  let acknowledged = false;
  const events = [];
  f.store.subscribe(binding => { assert.deepEqual(f.store.getDecision(), binding); events.push(binding); });
  const pending = f.store.setDecision(null, f.profile).then(record => { acknowledged = true; return record; });
  await flushing.promise;
  assert.deepEqual(JSON.parse(await readFile(f.file, 'utf8')), f.allow(1));
  assert.equal(acknowledged, false);
  assert.equal(f.store.capture(), null);
  release.resolve();
  const saved = await pending;
  assert.deepEqual(saved, f.allow(1));
  assert.deepEqual(f.store.capture(), saved);
  assert.equal(f.store.getStatus().error, null);
  assert.equal(events.length, 1);
  const steps = f.calls.filter(name => ['writeTemp', 'flushTemp', 'replace', 'flushParent', 'discardTemp'].includes(name));
  assert.deepEqual(steps, ['writeTemp', 'flushTemp', 'replace', 'flushParent', 'discardTemp']);
  assert.ok(f.calls.lastIndexOf('verify') > f.calls.lastIndexOf('discardTemp'));
  const binding = f.store.capture();
  await f.store.setDecision(copy(saved), copy(f.profile));
  assert.equal(f.calls.filter(name => name === 'replace').length, 1);
  assert.equal(f.store.capture(), binding);
  assert.equal(events.length, 1);
});

test('withdrawal retains the ID and requires the complete denied expected record to regrant', async t => {
  const f = await fixture(t, { initial: 7 });
  await f.store.start();
  const original = f.store.capture();
  const denied = await f.store.setDecision(f.allow(), null);
  assert.deepEqual(denied, f.denied());
  assert.equal(f.store.capture(), null);
  assert.deepEqual(JSON.parse(await readFile(f.file, 'utf8')), denied);
  await assertRefusal(f.store.setDecision(null, f.profile), 'SDK_PROFILE_DECISION_CONFLICT');
  await assertRefusal(f.store.setDecision(f.allow(), f.profile), 'SDK_PROFILE_DECISION_CONFLICT');
  const renewed = await f.store.setDecision(denied, f.profile);
  assert.deepEqual(renewed, f.allow(8));
  assert.equal(f.store.isCurrent(original), false);
});

test('oversized writes and malformed request data are rejected without changing the current grant', async t => {
  const f = await fixture(t, { initial: 7 });
  await f.store.start();
  const original = f.store.capture();
  const tooLarge = { ...f.profile, agentDir: join(f.root, 'x'.repeat(SDK_PROFILE_FILE_LIMITS.maxBytes)) };
  await assertRefusal(f.store.setDecision(f.allow(), tooLarge), 'SDK_PROFILE_RECORD_TOO_LARGE');
  await assert.rejects(f.store.setDecision({ ...f.allow(), extra: true }, f.profile), TypeError);
  assert.equal(f.store.capture(), original);
  assert.equal(f.store.getStatus().error, null);
  assert.equal(f.calls.includes('writeTemp'), false);
  assert.deepEqual(JSON.parse(await readFile(f.file, 'utf8')), f.allow());
});

test('serialized competing writes compare full fresh records and detach caller-owned request data', async t => {
  const f = await fixture(t, { initial: 7 });
  await f.store.start();
  const first = f.store.setDecision(f.allow(), null);
  const second = f.store.setDecision(f.allow(), { ...f.profile, recipient: 'second-manager-choice' });
  const rejected = assertRefusal(second, 'SDK_PROFILE_DECISION_CONFLICT');
  assert.deepEqual(await first, f.denied());
  await rejected;
  assert.equal(f.maxActive, 1);
  const entered = deferred();
  const release = deferred();
  f.hooks.qualified = async request => { if (request.write) { entered.resolve(); await release.promise; } };
  const expected = f.denied();
  const selected = { ...f.profile };
  const pending = f.store.setDecision(expected, selected);
  expected.grantId = 99;
  selected.recipient = 'mutated-after-admission';
  await entered.promise;
  release.resolve();
  assert.deepEqual(await pending, f.allow(8));
});

test('a conflicting direct edit before replace is applied and preserves the direct publication', async t => {
  const f = await fixture(t, { initial: 7 });
  await f.store.start();
  f.hooks.flushTemp = () => f.publish(f.denied());
  await assertRefusal(f.store.setDecision(f.allow(), { ...f.profile, recipient: 'new-recipient' }), 'SDK_PROFILE_DECISION_CONFLICT');
  assert.deepEqual(JSON.parse(await readFile(f.file, 'utf8')), f.denied());
  assert.equal(f.store.capture(), null);
  assert.equal(f.store.getStatus().error, null);
  assert.equal(f.calls.includes('replace'), false);
});

test('a conflicting direct edit after replace is reconciled before returning conflict, not success', async t => {
  const f = await fixture(t, { initial: 7 });
  await f.store.start();
  const selected = { ...f.profile, recipient: 'new-recipient' };
  f.hooks.flushParent = () => f.publish(f.denied(8, selected));
  await assertRefusal(f.store.setDecision(f.allow(), selected), 'SDK_PROFILE_DECISION_CONFLICT');
  assert.deepEqual(f.store.getDecision(), f.denied(8, selected));
  assert.equal(f.store.capture(), null);
  assert.deepEqual(JSON.parse(await readFile(f.file, 'utf8')), f.denied(8, selected));
});

test('restoring the old allow over a just-published withdrawal cannot preserve its stale capture', async t => {
  const f = await fixture(t, { initial: 7 });
  await f.store.start();
  const original = f.store.capture();
  f.hooks.flushParent = () => f.publish(f.allow());
  await assertRefusal(f.store.setDecision(f.allow(), null), 'SDK_PROFILE_DECISION_CONFLICT');
  assert.equal(f.store.capture(), null);
  assert.equal(f.store.isCurrent(original), false);
  assert.deepEqual(f.store.getDecision(), f.denied());
  assert.equal(f.store.getStatus().error.code, 'DECISION_UNAVAILABLE');
  assert.equal((await f.store.reconcile()).error.reason, 'SDK_PROFILE_DECISION_STALE');
});

test('changes during asynchronous temp cleanup are included in the final freshness read', async t => {
  const f = await fixture(t, { initial: 7 });
  await f.store.start();
  const selected = { ...f.profile, recipient: 'new-recipient' };
  f.hooks.discardTemp = () => f.publish(f.denied(8, selected));
  await assertRefusal(f.store.setDecision(f.allow(), selected), 'SDK_PROFILE_DECISION_CONFLICT');
  assert.equal(f.store.capture(), null);
  assert.deepEqual(f.store.getDecision(), f.denied(8, selected));
});

test('write-boundary teardown cannot acknowledge a grant superseded during awaited cleanup', async t => {
  const f = await fixture(t, { initial: 7 });
  await f.store.start();
  const selected = { ...f.profile, recipient: 'new-recipient' };
  f.hooks.released = async request => {
    if (request.write) await f.publish(f.denied(8, selected));
  };
  await assertRefusal(f.store.setDecision(f.allow(), selected), 'SDK_PROFILE_DECISION_CONFLICT');
  assert.equal(f.store.capture(), null);
  assert.deepEqual(f.store.getDecision(), f.denied(8, selected));
});

test('read-only authority rejects writes and publication failures revoke without leaking temps', async t => {
  const f = await fixture(t, { initial: 7 });
  await f.store.start();
  f.controls.writable = false;
  await assertRefusal(f.store.setDecision(f.allow(), null), 'EACCES');
  assert.equal(f.store.capture(), null);
  assert.equal(f.store.getStatus().error.code, 'DECISION_UNAVAILABLE');
  f.controls.writable = true;
  f.hooks.flushTemp = () => { throw failure('EIO'); };
  await assertRefusal(f.store.repairStaleDecision(f.denied(), f.profile), 'EIO');
  assert.equal(f.store.capture(), null);
  assert.deepEqual(JSON.parse(await readFile(f.file, 'utf8')), f.allow());
  assert.equal(f.calls.includes('replace'), false);
});

test('watch notifications and periodic missed-event reconciliation reread complete qualified bytes', { timeout: 5000 }, async t => {
  const f = await fixture(t);
  await f.store.start();
  const first = nextBinding(f.store, binding => binding?.grantId === 1);
  await f.publish(f.allow(1));
  f.notify();
  await first;
  const original = f.store.capture();
  const periodic = nextBinding(f.store, binding => binding?.grantId === 2);
  await f.publish(f.allow(2));
  // No watch notification: the periodic pass must discover this publication.
  f.tick();
  await periodic;
  assert.equal(f.store.isCurrent(original), false);
  assert.equal(f.intervals.size, 1);
  assert.equal([...f.intervals][0].milliseconds, 50);
});

test('watch failures revoke immediately, periodic recovery reinstalls the watch and old callbacks are ignored', { timeout: 5000 }, async t => {
  const f = await fixture(t, { initial: 7 });
  await f.store.start();
  const original = f.store.capture();
  const oldWatcher = f.watchers.at(-1);
  f.controls.watchUnavailable = true;
  oldWatcher.onError(failure('EIO'));
  assert.equal(f.store.capture(), null);
  assert.equal(f.store.isCurrent(original), false);
  assert.equal(oldWatcher.closed, true);
  await f.store.reconcile();
  f.controls.watchUnavailable = false;
  await f.publish(f.allow(8));
  const recovered = nextBinding(f.store, binding => binding?.grantId === 8);
  f.tick();
  await recovered;
  assert.equal(f.watchers.length, 2);
  const fresh = f.store.capture();
  oldWatcher.onError(failure('EIO'));
  assert.equal(f.store.capture(), fresh);
  assert.equal(f.store.getStatus().error, null);
});

test('watch failure during installation cannot leave a dead watcher accepted', async t => {
  const f = await fixture(t, { initial: 7 });
  let first = true;
  f.hooks.watch = watcher => {
    if (!first) return;
    first = false;
    f.controls.watchUnavailable = true;
    watcher.onError(failure('EIO'));
  };
  const status = await f.store.start();
  assert.equal(status.error.code, 'DECISION_UNAVAILABLE');
  assert.equal(f.store.capture(), null);
  assert.equal(f.watchers[0].closed, true);
  await f.store.reconcile();
  f.controls.watchUnavailable = false;
  const recovered = await f.store.reconcile();
  assert.equal(recovered.error, null);
  assert.equal(f.watchers.length, 2);
  assert.deepEqual(f.store.capture(), f.allow());
});

test('close synchronously revokes, drains in-flight work, releases watch/timer and cannot acknowledge a late allow', async t => {
  const f = await fixture(t, { initial: 7 });
  await f.store.start();
  const flushing = deferred();
  const release = deferred();
  f.hooks.flushParent = async () => { flushing.resolve(); await release.promise; };
  const pending = f.store.setDecision(f.allow(), { ...f.profile, recipient: 'new-recipient' });
  const rejected = assertRefusal(pending, 'SDK_PROFILE_STORE_CLOSED');
  await flushing.promise;
  const closed = f.store.close();
  assert.equal(f.store.capture(), null);
  assert.equal(f.intervals.size, 0);
  assert.equal(f.watchers.at(-1).closed, true);
  release.resolve();
  await rejected;
  await closed;
  await assertRefusal(f.store.start(), 'SDK_PROFILE_STORE_CLOSED');
  await assertRefusal(f.store.reconcile(), 'SDK_PROFILE_STORE_CLOSED');
  await f.store.close();
});
