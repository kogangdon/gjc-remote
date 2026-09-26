import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';
import { runWindowsHostSmoke, WINDOWS_HOST_SMOKE_EVIDENCE_CLASS } from '../windows-host-smoke.js';

test('bot fixture reaches readiness only with the exact configured connected-host set', async () => {
  const ready = await runWindowsHostSmoke({ component: 'bot', scenario: 'ready' });
  assert.equal(ready.ready, true);
  assert.equal(ready.evidenceClass, WINDOWS_HOST_SMOKE_EVIDENCE_CLASS);
  assert.equal(ready.actualServiceLifecycle, false);
  assert.equal(ready.writes, 0);
  const partial = await runWindowsHostSmoke({ component: 'bot', scenario: 'partial-hosts' });
  assert.equal(partial.ready, false);
  assert.ok(partial.sequence > 0);
});

test('daemon fixture reaches readiness only on accepted current-target registration', async () => {
  assert.equal((await runWindowsHostSmoke({ component: 'daemon', scenario: 'ready' })).ready, true);
  assert.equal((await runWindowsHostSmoke({ component: 'daemon', scenario: 'denied' })).ready, false);
});

test('fixture failures refuse instead of reporting readiness', async () => {
  await assert.rejects(runWindowsHostSmoke({ component: 'bot', scenario: 'unknown' }), /fixture exited 1/);
});

test('smoke and fixture never load service authority, credentials or SCM surfaces', async () => {
  const sources = await Promise.all([
    readFile(new URL('../windows-host-smoke.js', import.meta.url), 'utf8'),
    readFile(new URL('../../native-control/test-fixtures/windows-host-runtime.mjs', import.meta.url), 'utf8'),
  ]);
  for (const source of sources) {
    assert.doesNotMatch(source, /service-bootstrap|service-native|createServiceNative|sc\.exe|discord\.js|process\.env\.[A-Z_]*TOKEN/);
  }
});
