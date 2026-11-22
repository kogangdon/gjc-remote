import test from 'node:test';
import assert from 'node:assert/strict';
import { join, sep } from 'node:path';
import {
  createProfileDecisionState,
  nextProfileDecision,
  normalizeProfileDecision,
} from '../src/sdk-profile-decision.js';

// Pure fixtures: these paths are never created or opened.
const root = process.platform === 'win32' ? 'C:\\sdk-profile-fixture' : '/sdk-profile-fixture';
const profile = Object.freeze({
  agentDir: join(root, 'agent'),
  credentialPath: join(root, 'agent', 'agent.db'),
  recipient: 'fixture-recipient',
  configIdentity: 'fixture-config-object',
  credentialIdentity: 'fixture-credential-object',
});
const copy = value => JSON.parse(JSON.stringify(value));
const allow = (grantId = 1, selected = profile) => ({ version: 1, grantId, allowed: true, profile: { ...selected } });
const withdrawn = (grantId = 1, selected = profile) => ({ ...allow(grantId, selected), allowed: false });

test('normalization returns detached immutable records and ignores property order', () => {
  const input = allow();
  const normalized = normalizeProfileDecision(input);
  const reordered = {
    profile: Object.fromEntries(Object.entries(profile).reverse()),
    allowed: true,
    grantId: 1,
    version: 1,
  };
  assert.deepEqual(normalized, normalizeProfileDecision(reordered));
  assert.notEqual(normalized, input);
  assert.notEqual(normalized.profile, input.profile);
  assert.equal(Object.isFrozen(normalized), true);
  assert.equal(Object.isFrozen(normalized.profile), true);
  input.grantId = 2;
  input.profile.recipient = 'changed-input';
  assert.equal(normalized.grantId, 1);
  assert.equal(normalized.profile.recipient, profile.recipient);
  assert.throws(() => { normalized.allowed = false; }, TypeError);
  assert.throws(() => { normalized.profile.agentDir = root; }, TypeError);
});

test('decision schema rejects missing, extra, non-JSON, and invalid scalar fields', () => {
  const invalid = [
    null, undefined, true, 1, 'decision', [], Object.create(null), new Date(0),
    { ...allow(), version: 2 },
    { ...allow(), version: '1' },
    { ...allow(), allowed: 1 },
    { ...allow(), profile: null },
    { ...allow(), extra: true },
    { ...allow(), profile: { ...profile, extra: true } },
    ...[0, -1, 1.5, NaN, Infinity, Number.MAX_SAFE_INTEGER + 1, '1', 1n].map(grantId => ({ ...allow(), grantId })),
  ];
  for (const key of ['version', 'grantId', 'allowed', 'profile']) {
    const missing = allow();
    delete missing[key];
    invalid.push(missing);
  }
  for (const key of Object.keys(profile)) {
    const missing = allow();
    delete missing.profile[key];
    invalid.push(missing);
  }
  const accessor = allow();
  Object.defineProperty(accessor, 'allowed', { enumerable: true, get() { throw new Error('must not read getters'); } });
  invalid.push(accessor);
  const symbolic = allow();
  symbolic[Symbol('extra')] = true;
  invalid.push(symbolic);
  const hidden = allow();
  Object.defineProperty(hidden.profile, 'hidden', { value: true });
  invalid.push(hidden);
  for (const value of invalid) assert.throws(() => normalizeProfileDecision(value));
});

test('profile identities are nonempty strict text bounded by UTF-8 bytes', () => {
  for (const key of ['recipient', 'configIdentity', 'credentialIdentity']) {
    for (const value of ['', ' ', ' padded', 'padded ', null, 7, 'x\n', 'x\0', '\uD800', 'x'.repeat(1025), 'é'.repeat(513)]) {
      assert.throws(() => normalizeProfileDecision(allow(1, { ...profile, [key]: value })), undefined, key);
    }
    assert.equal(normalizeProfileDecision(allow(1, { ...profile, [key]: 'é'.repeat(512) })).profile[key], 'é'.repeat(512));
  }
});

test('profile paths must already be canonical and absolute on this platform', () => {
  const invalid = [
    '', null, 7, 'relative', '.', '..', ` ${root}`, `${root} `,
    `${root}${sep}.${sep}agent`, `${root}${sep}nested${sep}..${sep}agent`,
    `${root}${sep}${sep}agent`, `${root}${sep}agent${sep}`,
    `${root}\0`, `${root}\n`, `${root}\uD800`,
  ];
  if (process.platform === 'win32') {
    invalid.push(
      '\\root-relative', '/root-relative', 'C:drive-relative', '/posix/profile',
      'C:/forward/slashes', '\\\\?\\C:\\profile', '\\\\.\\C:\\profile',
      `${root}\\agent.`, `${root}\\agent \\file`, `${root}\\agent.db:auth`,
      `${root}\\NUL`, `${root}\\COM1.txt`, `${root}\\invalid?name`,
    );
  } else {
    invalid.push('C:\\windows\\profile', '//sdk-profile-fixture/agent');
  }
  for (const key of ['agentDir', 'credentialPath']) {
    for (const value of invalid) {
      assert.throws(() => normalizeProfileDecision(allow(1, { ...profile, [key]: value })), undefined, `${key}: ${String(value)}`);
    }
  }
  if (process.platform === 'win32') {
    const unc = { ...profile, agentDir: '\\\\fixture-server\\fixture-share\\agent', credentialPath: '\\\\fixture-server\\fixture-share\\agent\\agent.db' };
    assert.deepEqual(normalizeProfileDecision(allow(1, unc)).profile, unc);
  }
});

test('equivalent allow and withdrawn saves do not invalidate captures or notify again', () => {
  const state = createProfileDecisionState();
  const events = [];
  state.subscribe(binding => {
    assert.equal(state.capture(), binding);
    events.push(binding);
  });
  assert.equal(state.apply(allow(7)), true);
  const captured = state.capture();
  assert.equal(state.isCurrent(captured), true);
  assert.equal(state.isCurrent(copy(captured)), false);
  assert.equal(state.apply(copy(allow(7))), false);
  assert.equal(state.capture(), captured);
  assert.equal(state.apply(withdrawn(7)), true);
  assert.equal(state.isCurrent(captured), false);
  assert.equal(state.apply(copy(withdrawn(7))), false);
  assert.equal(state.apply(null), false);
  assert.deepEqual(events, [captured, null]);
});

test('coalesced withdrawal and regrant invalidates old work even for the same target', () => {
  const state = createProfileDecisionState();
  const events = [];
  state.subscribe(binding => events.push(binding));
  state.apply(allow(2));
  const old = state.capture();
  const regrant = nextProfileDecision(nextProfileDecision(allow(2), null), profile);
  assert.equal(regrant.grantId, 3);
  // A watcher sees only the final allow, not the intervening denied record.
  assert.equal(state.apply(regrant), true);
  const fresh = state.capture();
  assert.notEqual(fresh, old);
  assert.equal(state.isCurrent(old), false);
  assert.equal(state.isCurrent(fresh), true);
  assert.equal(state.apply(allow(20)), true);
  assert.equal(state.isCurrent(fresh), false);
  assert.deepEqual(events.map(binding => binding.grantId), [2, 3, 20]);
});

test('normal withdrawal and failed reads cannot be undone by restoring the same grant', () => {
  const failures = [null, undefined, { ...allow(100), extra: true }, allow(4), withdrawn(4), withdrawn(5)];
  for (const failure of failures) {
    const state = createProfileDecisionState();
    const events = [];
    state.subscribe(binding => events.push(binding));
    state.apply(allow(5));
    const old = state.capture();
    assert.equal(state.apply(failure), true);
    assert.equal(state.capture(), null);
    assert.equal(state.isCurrent(old), false);
    assert.equal(state.apply(copy(allow(5))), false);
    assert.equal(state.capture(), null);
    assert.equal(state.apply(withdrawn(5)), false);
    assert.equal(state.apply(allow(6)), true);
    const fresh = state.capture();
    assert.equal(state.isCurrent(old), false);
    assert.equal(state.isCurrent(fresh), true);
    assert.deepEqual(events, [old, null, fresh]);
  }
});

test('a regressing observation disables a newer allow and never lowers the high water', () => {
  const state = createProfileDecisionState();
  state.apply(allow(10));
  const original = state.capture();
  assert.equal(state.apply(allow(9)), true);
  assert.equal(state.apply(allow(2)), false);
  assert.equal(state.apply(allow(10)), false);
  assert.equal(state.capture(), null);
  assert.equal(state.apply(allow(11)), true);
  assert.equal(state.isCurrent(original), false);
});

test('same-ID target and recipient substitutions fail closed until a fresh grant', () => {
  for (const key of Object.keys(profile)) {
    const changed = { ...profile, [key]: key === 'agentDir' || key === 'credentialPath' ? join(root, `other-${key}`) : `other-${key}` };
    const state = createProfileDecisionState();
    state.apply(allow(3));
    const original = state.capture();
    assert.equal(state.apply(allow(3, changed)), true, key);
    assert.equal(state.capture(), null);
    assert.equal(state.apply(allow(3)), false);
    assert.equal(state.apply(allow(3, changed)), false);
    assert.equal(state.apply(allow(4, changed)), true);
    assert.equal(state.isCurrent(original), false);
    assert.deepEqual(state.capture().profile, changed);
  }
});

test('denied-to-denied updates retain higher history without notifying session subscribers', () => {
  const state = createProfileDecisionState();
  const events = [];
  state.subscribe(binding => events.push(binding));
  assert.equal(state.apply(withdrawn(7)), false);
  assert.equal(state.apply(copy(withdrawn(7))), false);
  assert.equal(state.apply(withdrawn(8)), false);
  assert.equal(state.apply(allow(7)), false);
  assert.equal(state.apply(allow(8)), false);
  assert.equal(state.capture(), null);
  assert.deepEqual(events, []);
  const next = nextProfileDecision(withdrawn(8), profile);
  assert.equal(next.grantId, 9);
  assert.equal(state.apply(next), true);
  assert.equal(events.length, 1);
  assert.equal(events[0].grantId, 9);
});

test('capture identity is process-state-local and cannot be restored by reusing an input object', () => {
  const first = createProfileDecisionState();
  const second = createProfileDecisionState();
  const input = allow();
  first.apply(input);
  const captured = first.capture();
  second.apply(captured);
  assert.equal(second.isCurrent(captured), false);
  first.apply(null);
  input.grantId = 2;
  first.apply(input);
  assert.equal(first.isCurrent(captured), false);
  assert.equal(first.isCurrent(first.capture()), true);
  assert.equal(first.isCurrent(null), false);
  assert.equal(first.isCurrent(undefined), false);
});

test('subscriptions are removable and a throwing consumer cannot block revocation', () => {
  const state = createProfileDecisionState();
  const received = [];
  const unsubscribe = state.subscribe(binding => received.push(binding));
  const stopThrowing = state.subscribe(() => { throw new Error('fixture consumer failure'); });
  const afterThrow = [];
  state.subscribe(binding => {
    assert.equal(state.capture(), binding);
    afterThrow.push(binding);
  });
  state.apply(allow());
  const captured = state.capture();
  unsubscribe();
  unsubscribe();
  assert.equal(state.apply(null), true);
  assert.deepEqual(received, [captured]);
  assert.deepEqual(afterThrow, [captured, null]);
  stopThrowing();
  assert.throws(() => state.subscribe(null), TypeError);
});

test('next decision mints, retains equivalent values, withdraws, and regrants without mutating input', () => {
  assert.equal(nextProfileDecision(null, null), null);
  const first = nextProfileDecision(null, { ...profile });
  assert.deepEqual(first, allow(1));
  assert.equal(Object.isFrozen(first), true);
  assert.equal(Object.isFrozen(first.profile), true);
  assert.deepEqual(nextProfileDecision(copy(first), copy(profile)), first);
  const denied = nextProfileDecision(first, null);
  assert.deepEqual(denied, withdrawn(1));
  assert.deepEqual(nextProfileDecision(copy(denied), null), denied);
  assert.deepEqual(first, allow(1));
  assert.deepEqual(nextProfileDecision(denied, copy(profile)), allow(2));
  const different = { ...profile, credentialIdentity: 'replacement-object' };
  assert.deepEqual(nextProfileDecision(first, different), allow(2, different));
  assert.throws(() => nextProfileDecision({ ...first, grantId: 0 }, profile));
  assert.throws(() => nextProfileDecision(undefined, profile));
  assert.throws(() => nextProfileDecision(first, undefined));
  assert.throws(() => nextProfileDecision(first, { ...profile, extra: true }));
});

test('overflow refuses new grants but equivalent saves and withdrawal remain possible', () => {
  const max = Number.MAX_SAFE_INTEGER;
  const first = nextProfileDecision(allow(max - 1), { ...profile, configIdentity: 'new-object' });
  assert.equal(first.grantId, max);
  assert.deepEqual(nextProfileDecision(allow(max), profile), allow(max));
  const denied = nextProfileDecision(allow(max), null);
  assert.deepEqual(denied, withdrawn(max));
  assert.deepEqual(nextProfileDecision(denied, null), denied);
  assert.throws(() => nextProfileDecision(denied, profile), RangeError);
  assert.throws(() => nextProfileDecision(allow(max), { ...profile, recipient: 'other-recipient' }), RangeError);
  const state = createProfileDecisionState();
  state.apply(allow(max));
  assert.equal(state.capture().grantId, max);
  state.apply(null);
  assert.equal(state.apply(allow(max)), false);
  assert.equal(state.apply(allow(max + 1)), false);
  assert.equal(state.capture(), null);
});
