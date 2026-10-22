import assert from 'node:assert/strict';
import { createHash, randomUUID } from 'node:crypto';
import { existsSync, readFileSync, realpathSync, renameSync } from 'node:fs';
import { createRequire } from 'node:module';
import { basename, dirname, isAbsolute, join, resolve } from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

// Explicit isolated test output only. Never discover or load build/Release,
// refresh trust, authenticate, inspect accounts, or create a service here.
const packageRoot = fileURLToPath(new URL('..', import.meta.url));
let addonPath = process.env.GJC_NATIVE_LINEAGE_TEST_ADDON;
let childPath = process.env.GJC_NATIVE_LINEAGE_TEST_CHILD;
if (addonPath === undefined && childPath === undefined) {
  // Committed local flow: scripts/build-lineage-owned-fixture.mjs output.
  const fallback = join(packageRoot, 'build', 'owned-lineage-fixture');
  const candidateAddon = join(fallback, 'owned-lineage.node');
  const candidateChild = join(fallback, 'owned-child.exe');
  if (existsSync(candidateAddon) && existsSync(candidateChild)) {
    addonPath = candidateAddon;
    childPath = candidateChild;
  }
}
const supplied = addonPath !== undefined || childPath !== undefined;
const enabled = process.platform === 'win32' && supplied;
let native;
if (supplied) {
  assert.equal(process.platform, 'win32');
  for (const path of [addonPath, childPath]) {
    assert.equal(typeof path, 'string');
    assert.equal(isAbsolute(path), true);
    assert.equal(realpathSync(path).toLowerCase(), resolve(path).toLowerCase());
    // Only the owned fixture build directory (or a grant-scoped isolated
    // build directory) is ever loaded; never a release or trust path.
    const parent = basename(dirname(path)).toLowerCase();
    assert.ok(parent === 'owned-lineage-fixture' || parent.startsWith('native-lineage-build-'),
      'fixture binaries must come from the owned lineage fixture build');
  }
  const buildReceipt = join(dirname(addonPath), 'build.json');
  let receiptPin;
  if (existsSync(buildReceipt)) {
    // A stale fixture build fails loudly instead of testing old code.
    const receipt = JSON.parse(readFileSync(buildReceipt, 'utf8'));
    const hashFile = path => createHash('sha256').update(readFileSync(path)).digest('hex');
    const actual = new Map([[addonPath, 'owned-lineage.node'], [childPath, 'owned-child.exe']]
      .map(([path, name]) => [name, hashFile(path)]));
    for (const output of receipt.outputs) {
      assert.equal(actual.get(output.name), output.sha256,
        `stale fixture output ${output.name}; rerun scripts/build-lineage-owned-fixture.mjs`);
    }
    for (const source of Object.values(receipt.sources)) {
      assert.equal(hashFile(join(packageRoot, source.path)), source.sha256,
        `stale fixture source ${source.path}; rerun scripts/build-lineage-owned-fixture.mjs`);
    }
    receiptPin = receipt.outputs.find(output => output.name === 'owned-lineage.node')?.sha256;
  }
  // An explicit environment pin always wins; otherwise the freshly verified
  // build receipt is the pin. One of the two is mandatory.
  const expected = process.env.GJC_NATIVE_LINEAGE_TEST_ADDON_SHA256 ?? receiptPin;
  assert.match(expected, /^[a-f0-9]{64}$/);
  assert.equal(createHash('sha256').update(readFileSync(addonPath)).digest('hex'), expected);
  native = createRequire(import.meta.url)(addonPath);
}
const options = { skip: enabled ? false : 'requires the owned lineage fixture build (scripts/build-lineage-owned-fixture.mjs) or explicit isolated paths' };
const delay = ms => new Promise(resolve => setTimeout(resolve, ms));
const imagePath = value => resolve(value.replace(/^\\\\\?\\/, '')).toLowerCase();
function binding() {
  return {
    serviceKey: 'owned-lineage-' + randomUUID(),
    bootId: native.currentBootId(),
    configFingerprint: createHash('sha256').update(randomUUID()).digest('hex'),
    roleSid: native.currentRoleSid(),
    lifetimeId: randomUUID(),
  };
}
function operation() { return randomUUID(); }
function create(t, args) {
  const expected = binding();
  const scope = native.createScope({ executable: childPath, args, binding: expected });
  t.after(() => {
    // Only this exact owned scope may be terminated on test failure. Normal
    // grace tests reach kernel zero before cleanup and never invoke force.
    const state = native.observeScope(scope, expected, operation());
    if (!state.closed) native.terminateScope(scope, expected, operation(), 5000);
    native.closeScope(scope);
  });
  return { scope, expected };
}
function invariants(receipt, expected, op) {
  assert.equal(receipt.operationId, op);
  assert.deepEqual(receipt.binding, expected);
  // An inheritance-only scope must never claim complete causal-lineage
  // coverage: alternate-parent creation outside the job is not preventable
  // without an enforced creation-authority boundary (test06 counterexample).
  assert.equal(receipt.coverageComplete, false);
  assert.equal(receipt.sealed, true);
  assert.equal(imagePath(receipt.rootExecutable), imagePath(childPath));
  assert.equal(receipt.rootOwner, expected.roleSid);
  assert.ok(Number.isSafeInteger(receipt.rootPid) && receipt.rootPid > 0);
  assert.ok(String(receipt.rootStartTime).length > 0);
}
async function until(scope, expected, predicate, timeout = 10000) {
  const deadline = Date.now() + timeout;
  let receipt;
  do {
    const op = operation();
    receipt = native.observeScope(scope, expected, op);
    invariants(receipt, expected, op);
    // No test except the spoof-parent probe may trip the escape detector.
    assert.equal(receipt.escapeDetected, false);
    if (predicate(receipt)) return receipt;
    await delay(10);
  } while (Date.now() < deadline);
  assert.fail(`owned lineage did not reach requested state: ${JSON.stringify(receipt)}`);
}
function diagnostic(t, value) { t.diagnostic(JSON.stringify(value)); }

test('owned native lineage survives root exit without falsely closing a live descendant', options, async t => {
  const { scope, expected } = create(t, ['spawn-exit', '1800']);
  const survivor = await until(scope, expected, state => state.rootExitCode === 0 && state.activeProcesses > 0);
  assert.equal(survivor.closed, false);
  assert.equal(survivor.forced, false);
  assert.equal(survivor.terminationCalls, 0);
  assert.ok(survivor.totalProcesses >= 2);
  diagnostic(t, survivor);
  const closed = await until(scope, expected, state => state.closed);
  assert.equal(closed.activeProcesses, 0);
  assert.equal(closed.rootExitCode, 0);
  assert.equal(closed.forced, false);
  assert.equal(closed.terminationCalls, 0);
  assert.equal(closed.scopeId, survivor.scopeId);
  assert.equal(closed.rootStartTime, survivor.rootStartTime);
  diagnostic(t, closed);
});

test('owned native lineage retains late descendants after intermediate and root exits', options, async t => {
  const { scope, expected } = create(t, ['late', '1500', '1200']);
  const initial = await until(scope, expected, state => state.rootExitCode === 0 && state.activeProcesses > 0);
  const firstMembers = native.liveMembers(scope, expected, operation());
  const intermediate = firstMembers.find(member => imagePath(member.executable) === imagePath(childPath));
  assert.ok(intermediate && intermediate.pid !== initial.rootPid);
  let lateMembers;
  const late = await until(scope, expected, state => {
    lateMembers = native.liveMembers(scope, expected, operation());
    return !state.closed && !lateMembers.some(member => member.pid === intermediate.pid) &&
      lateMembers.some(member => imagePath(member.executable) === imagePath(childPath) && member.pid !== intermediate.pid);
  });
  assert.equal(late.scopeId, initial.scopeId);
  assert.equal(late.terminationCalls, 0);
  assert.equal(late.forced, false);
  assert.ok(late.totalProcesses > initial.totalProcesses);
  diagnostic(t, { intermediate, lateMembers, diagnosticsAreNotClosureProof: true });
  diagnostic(t, late);
  const closed = await until(scope, expected, state => state.closed);
  assert.ok(closed.totalProcesses >= 3);
  assert.equal(closed.terminationCalls, 0);
  diagnostic(t, closed);
});

test('graceful observation neither forces a survivor nor closes from root absence', options, async t => {
  const { scope, expected } = create(t, ['wait', '1300']);
  const alive = native.observeScope(scope, expected, operation());
  await delay(100);
  const stillAlive = native.observeScope(scope, expected, operation());
  for (const state of [alive, stillAlive]) {
    assert.equal(state.closed, false);
    assert.ok(state.activeProcesses >= 1);
    assert.equal(state.forced, false);
    assert.equal(state.terminationCalls, 0);
  }
  diagnostic(t, stillAlive);
  const closed = await until(scope, expected, state => state.closed);
  assert.equal(closed.forced, false);
  assert.equal(closed.terminationCalls, 0);
});

test('explicit native force closes only the validated kernel scope including grandchildren', options, async t => {
  const { scope, expected } = create(t, ['tree', '10000']);
  let members;
  await until(scope, expected, state => {
    members = native.liveMembers(scope, expected, operation());
    return !state.closed && members.filter(member => imagePath(member.executable) === imagePath(childPath)).length === 3;
  });
  diagnostic(t, { beforeForceMembers: members, diagnosticsAreNotClosureProof: true });
  const op = operation();
  const closed = native.terminateScope(scope, expected, op, 5000);
  assert.equal(closed.operationId, op);
  assert.deepEqual(closed.binding, expected);
  assert.equal(closed.closed, true);
  assert.equal(closed.activeProcesses, 0);
  assert.equal(closed.forced, true);
  assert.equal(closed.terminationCalls, 1);
  assert.ok(closed.totalProcesses >= 3);
  diagnostic(t, closed);
});

test('kernel breakaway cannot create an uncontained child or a success fallback', options, async t => {
  const { scope, expected } = create(t, ['breakaway', '700']);
  await delay(100);
  const members = native.liveMembers(scope, expected, operation());
  assert.equal(members.filter(member => imagePath(member.executable) === imagePath(childPath)).length, 1);
  diagnostic(t, { deniedAttemptMembers: members, diagnosticsAreNotClosureProof: true });
  const closed = await until(scope, expected, state => state.closed);
  assert.equal(closed.rootExitCode, 0, 'helper exits nonzero if explicit breakaway unexpectedly succeeds');
  // Console companions are kernel members too; do not omit them or assert
  // that a single fixture executable must be the only historical process.
  assert.ok(closed.totalProcesses >= members.length);
  assert.equal(closed.forced, false);
  assert.equal(closed.terminationCalls, 0);
  diagnostic(t, closed);
});

test('native identity binding and opaque handles reject forged or stale authority before effects', options, async t => {
  const { scope, expected } = create(t, ['wait', '1000']);
  for (const key of Object.keys(expected)) {
    const wrong = { ...expected, [key]: key === 'configFingerprint' ? 'a'.repeat(64) : expected[key] + '-stale' };
    assert.throws(() => native.observeScope(scope, wrong, operation()), error => /LINEAGE_(?:STALE|INVALID)/.test(error.code) && error.writes === 0);
    assert.throws(() => native.terminateScope(scope, wrong, operation(), 1), error => /LINEAGE_(?:STALE|INVALID)/.test(error.code) && error.writes === 0);
  }
  assert.throws(() => native.observeScope({}, expected, operation()), error => error.code === 'LINEAGE_INVALID');
  assert.throws(() => native.observeScope(scope, expected, ''), error => error.code === 'LINEAGE_INVALID');
  assert.throws(() => native.observeScope(scope, expected, 'bad\0operation'), error => error.code === 'LINEAGE_INVALID');
  const live = native.observeScope(scope, expected, operation());
  assert.equal(live.terminationCalls, 0);
  assert.equal(live.forced, false);
  diagnostic(t, await until(scope, expected, state => state.closed));
});

test('invalid creation arguments and stale boot never launch an uncontained payload', options, () => {
  const expected = binding();
  for (const value of [
    { executable: childPath, args: [], binding: { ...expected, bootId: 'win32:1' } },
    { executable: childPath, args: ['wait', '1\0bad'], binding: expected },
    { executable: childPath, args: [], binding: { ...expected, roleSid: '' } },
    { executable: childPath, args: [], binding: { ...expected, extra: 'untrusted' } },
  ]) assert.throws(() => native.createScope(value), error => /LINEAGE_(?:INVALID|STALE)/.test(error.code) && error.writes === 0);
});

test('wrong native token owner is rejected and only the never-resumed owned root is cleaned up', options, t => {
  const expected = { ...binding(), roleSid: 'S-1-5-18' };
  assert.notEqual(expected.roleSid, native.currentRoleSid(), 'fixture requires an ordinary non-SYSTEM owner');
  assert.throws(() => native.createScope({ executable: childPath, args: ['wait', '1'], binding: expected }), error => {
    diagnostic(t, { code: error.code, rootPid: error.rootPid, effects: error.effects, writes: error.writes, ambiguous: error.ambiguous });
    return error.code === 'LINEAGE_INVALID' && error.writes === 1 && error.ambiguous === false &&
      error.rootPid > 0 && error.effects.rootCreated === true && error.effects.rootResumed === false &&
      error.effects.cleanupTerminationCalls === 1;
  });
  const probe = childPath + '.rollback-probe-' + randomUUID();
  renameSync(childPath, probe);
  renameSync(probe, childPath);
});

test('native validation never evaluates accessor authority or accepts sparse argument arrays', options, () => {
  let getterCalls = 0;
  const withGetter = { executable: childPath, args: ['wait', '1'], get binding() { getterCalls += 1; return binding(); } };
  assert.throws(() => native.createScope(withGetter), error => error.code === 'LINEAGE_INVALID' && error.writes === 0);
  assert.equal(getterCalls, 0);
  const sparse = new Array(2);
  sparse[1] = '1';
  assert.throws(() => native.createScope({ executable: childPath, args: sparse, binding: binding() }), error => error.code === 'LINEAGE_INVALID' && error.writes === 0);
});

test('released native capabilities cannot be reused or reconstructed from plain data', options, async () => {
  const expected = binding();
  const scope = native.createScope({ executable: childPath, args: ['wait', '10'], binding: expected });
  try {
    await until(scope, expected, state => state.closed);
  } catch (error) {
    native.terminateScope(scope, expected, operation(), 5000);
    throw error;
  } finally {
    native.closeScope(scope);
  }
  assert.throws(() => native.observeScope(scope, expected, operation()), error => error.code === 'LINEAGE_STALE' && error.writes === 0);
  assert.throws(() => native.terminateScope(scope, expected, operation(), 1), error => error.code === 'LINEAGE_STALE' && error.writes === 0);
  assert.throws(() => native.closeScope(scope), error => error.code === 'LINEAGE_STALE' && error.writes === 0);
});

test('creation-time job scope fails closed when an owned child escapes through a spoofed outside parent', options, async t => {
  // Only this exact test worker is offered as outside parent. The helper owns
  // and waits its finite probe child; no unrelated PID is launched or killed.
  // The adversarial attempt is unchanged. The normative demand: the receipt
  // must never claim complete coverage while containment is unprovable — the
  // scope either really contains the child (root exit 0) or detects and
  // reports the escape (root exit 93, sticky escapeDetected, coverageComplete
  // false on every receipt). A dishonest coverageComplete===true fails here.
  const { scope, expected } = create(t, ['spoof-parent', String(process.pid), '1200']);
  const receipts = [];
  let closed;
  const deadline = Date.now() + 15000;
  do {
    const op = operation();
    const receipt = native.observeScope(scope, expected, op);
    invariants(receipt, expected, op);
    receipts.push(receipt);
    if (receipt.closed) { closed = receipt; break; }
    await delay(10);
  } while (Date.now() < deadline);
  assert.ok(closed, 'owned lineage scope did not reach kernel-zero closure');
  diagnostic(t, closed);
  if (closed.rootExitCode === 0) {
    // The escape was denied by ambient authority on this host. The scope has
    // no enforced boundary, so even a denied attempt is not claimed coverage.
    assert.equal(closed.escapeDetected, false);
  } else {
    // A live child existed outside the exact job. Fail-closed contract: the
    // tripwire fired while the escaped child was alive and stays sticky after
    // the root waited for its natural terminal.
    assert.equal(closed.rootExitCode, 93, 'unexpected fixture exit classification');
    assert.equal(closed.escapeDetected, true, 'an escape occurred but the receipt failed to fail closed');
    assert.ok(receipts.some(receipt => receipt.escapeDetected && !receipt.closed),
      'tripwire must fire while the escaped child is demonstrably alive, not only after closure');
  }
  assert.equal(closed.forced, false);
  assert.equal(closed.terminationCalls, 0);
});
