import assert from 'node:assert/strict';
import test from 'node:test';
import { createServiceLifecycle } from '../src/service-lifecycle.js';
import {
  buildServiceCandidateProof,
  buildServiceFinalProof,
  buildServiceOldProof,
  buildServicePlatformState,
  buildServiceTransaction,
  buildServiceTransitionProof,
  serviceConfigurationFingerprint,
  serviceRolesFingerprint,
} from '@gjc-remote/shared/service-lifecycle-envelope';
import { canonicalJsonHash } from '@gjc-remote/shared/strict-json';

const roles = Object.freeze({
  management: { kind: 'uid', value: 'uid:1001' },
  bot: { kind: 'uid', value: 'uid:1002' },
  recovery: { kind: 'uid', value: 'uid:1003' },
  daemon: { kind: 'uid', value: 'uid:1004' },
  system: { kind: 'uid', value: 'uid:0' },
});
const windowsRoles = Object.freeze({
  management: { kind: 'sid', value: 'S-1-5-21-1001' },
  bot: { kind: 'sid', value: 'S-1-5-21-1002' },
  recovery: { kind: 'sid', value: 'S-1-5-21-1003' },
  daemon: { kind: 'sid', value: 'S-1-5-21-1004' },
  system: { kind: 'sid', value: 'S-1-5-18' },
});

function recoveryTransaction(phase, operation = 'install') {
  const old = buildServiceOldProof({ disposition: 'absent', manifestFingerprint: null, resourceProof: null, applicationManifestFingerprint: null, shawlManifestFingerprint: null, serviceGeneration: 0, activation: 'disabled-not-startable' }, 'linux');
  const candidate = buildServiceCandidateProof({ disposition: 'release', applicationManifestFingerprint: 'a'.repeat(64), shawlManifestFingerprint: null, releaseSequence: 1, releaseTreeFingerprint: 'b'.repeat(64), compatibilityFingerprint: 'c'.repeat(64) }, 'linux');
  const transition = buildServiceTransitionProof({ oldFingerprint: old.oldFingerprint, candidateFingerprint: candidate.candidateFingerprint, expectedBeforeResourceFingerprint: null, expectedAfterResourceFingerprint: 'd'.repeat(64), platformResourceFingerprint: 'e'.repeat(64), platformState: buildServicePlatformState('linux', 'trial') }, 'linux');
  const final = buildServiceFinalProof({ disposition: 'stable', manifestFingerprint: 'f'.repeat(64), resourceProof: '1'.repeat(64), applicationManifestFingerprint: 'a'.repeat(64), shawlManifestFingerprint: null, serviceGeneration: 1, activation: 'enabled' }, 'linux');
  return buildServiceTransaction({ transactionId: 'tx-recover', transactionNonce: '2'.repeat(32), operation, component: 'bot', serviceKey: 'bot', platform: 'linux', architecture: 'x64', serviceGeneration: 1, old, candidate, transition, final, phase, substep: phase === 'prepared' ? 'none' : 'intent', previousJournalFingerprint: null });
}

function readOnlyFixture() {
  const calls = [];
  const session = {
    platform: 'linux', architecture: 'x64', component: 'bot', serviceKey: 'bot', writes: 0,
    readManifest: () => ({ present: false, value: null }),
    readResourceProof: () => ({ present: false, value: null }),
    readStartupProof: () => ({ present: false, value: null }),
    readManualCleanup: () => ({ present: false, value: null }),
    readJournal: () => ({ entries: [], head: { present: false, value: null }, pending: null }),
    close: () => {},
  };
  return { calls, session, store: { openReadOnly: () => session }, driver: { probe: () => { calls.push('probe'); return { platformPhase: 'absent' }; } } };
}

test('status is read-only, bounded, and reports an absent service', async () => {
  const fixture = readOnlyFixture();
  const lifecycle = createServiceLifecycle({
    platform: 'linux', architecture: 'x64', store: fixture.store, driver: fixture.driver,
  });
  const receipt = await lifecycle.status({ schemaVersion: 1, target: { component: 'bot' }, roles });
  assert.equal(receipt.kind, 'service-status');
  assert.equal(receipt.ownership, 'absent');
  assert.equal(receipt.service, 'missing');
  assert.equal(receipt.activation, 'disabled-not-startable');
  assert.deepEqual(fixture.calls, []);
  assert.equal(fixture.session.writes, 0);
});

test('status does not construct a mutation driver when the store is absent', async () => {
  const lifecycle = createServiceLifecycle({
    platform: 'linux', architecture: 'x64', store: { openReadOnly: () => null },
  });
  const receipt = await lifecycle.status({ schemaVersion: 1, target: { component: 'bot' }, roles });
  assert.equal(receipt.ownership, 'absent');
  assert.equal(receipt.writes, 0);
});

test('status derives owned state from matching durable metadata and never reads an undefined absence fallback', async () => {
  const manifestFingerprint = 'a'.repeat(64);
  const resourceProof = 'b'.repeat(64);
  const platformResourceFingerprint = 'c'.repeat(64);
  const manifest = {
    component: 'bot', serviceKey: 'bot', serviceGeneration: 3,
    manifestFingerprint, resourceProof, applicationManifestFingerprint: 'd'.repeat(64),
    roles, rolesFingerprint: serviceRolesFingerprint(roles, 'linux'),
  };
  const resource = {
    resourceProof, platformResourceFingerprint,
  };
  const session = {
    platform: 'linux', architecture: 'x64', component: 'bot', serviceKey: 'bot', writes: 0,
    readManifest: () => ({ present: true, value: manifest }),
    readResourceProof: () => ({ present: true, value: resource }),
    readStartupProof: () => ({ present: false, value: null }),
    readManualCleanup: () => ({ present: false, value: null }),
    readJournal: () => ({ entries: [{ phase: 'committed' }], head: { present: true, value: { phase: 'committed' } }, pending: null }),
    close: () => {},
  };
  const lifecycle = createServiceLifecycle({
    platform: 'linux', architecture: 'x64', store: { openReadOnly: () => session },
    driver: { probe: () => ({ platformPhase: 'final', resourceFingerprint: platformResourceFingerprint, service: 'stopped', activation: 'enabled', tree: 'empty' }) },
  });
  const receipt = await lifecycle.status({ schemaVersion: 1, target: { component: 'bot' }, roles });
  assert.equal(receipt.ownership, 'owned');
  assert.equal(receipt.serviceGeneration, 3);
  assert.equal(receipt.manifestFingerprint, manifestFingerprint);
  assert.equal(receipt.resourceProof, resourceProof);
  assert.equal(receipt.service, 'stopped');
  assert.equal(receipt.activation, 'enabled');
  assert.equal(receipt.tree, 'empty');
  assert.equal(receipt.startupEvidence, 'unavailable');
});

test('status does not promote persisted startup proof when the live service is stopped', async () => {
  const manifestFingerprint = 'e'.repeat(64);
  const resourceProof = 'f'.repeat(64);
  const platformResourceFingerprint = '1'.repeat(64);
  const manifest = {
    component: 'bot', serviceKey: 'bot', serviceGeneration: 4,
    manifestFingerprint, resourceProof, applicationManifestFingerprint: '2'.repeat(64),
    roles, rolesFingerprint: serviceRolesFingerprint(roles, 'linux'),
  };
  const resource = { resourceProof, platformResourceFingerprint };
  const startup = {
    serviceGeneration: 4, resourceProof,
    applicationManifestFingerprint: manifest.applicationManifestFingerprint,
    bootFingerprint: canonicalJsonHash({ kind: 'linux-boot/v1', bootId: 'boot-1' }), expiresAtMs: 10_000,
  };
  const session = {
    platform: 'linux', architecture: 'x64', component: 'bot', serviceKey: 'bot', writes: 0,
    readManifest: () => ({ present: true, value: manifest }),
    readResourceProof: () => ({ present: true, value: resource }),
    readStartupProof: () => ({ present: true, value: startup }),
    readManualCleanup: () => ({ present: false, value: null }),
    readJournal: () => ({ entries: [{ phase: 'committed' }], head: { present: true, value: { phase: 'committed' } }, pending: null }),
    close: () => {},
  };
  const lifecycle = createServiceLifecycle({
    platform: 'linux', architecture: 'x64', clock: () => 100,
    store: { openReadOnly: () => session },
    driver: { probe: () => ({ platformPhase: 'final', resourceFingerprint: platformResourceFingerprint, bootId: 'boot-1', service: 'stopped', activation: 'enabled', tree: 'empty' }) },
  });
  const receipt = await lifecycle.status({ schemaVersion: 1, target: { component: 'bot' }, roles });
  assert.equal(receipt.service, 'stopped');
  assert.equal(receipt.tree, 'empty');
  assert.equal(receipt.startupEvidence, 'historical-current-epoch');
});

test('rollback refuses before driver construction when retained publication authority is unavailable', async () => {
  const calls = [];
  const currentManifestFingerprint = '4'.repeat(64);
  const predecessorManifestFingerprint = '5'.repeat(64);
  const resourceProof = '6'.repeat(64);
  const configuration = {
    runtimePath: '/runtime', workingDirectory: '/work', homeDirectory: '/home', logDirectory: '/log',
    channelsConfig: '/channels', expectedHostSetFingerprint: '7'.repeat(64), expectedHostCount: 0,
  };
  const current = {
    component: 'bot', serviceKey: 'bot', platform: 'linux', architecture: 'x64', serviceGeneration: 2,
    manifestFingerprint: currentManifestFingerprint, resourceProof, applicationManifestFingerprint: '8'.repeat(64),
    roles, rolesFingerprint: serviceRolesFingerprint(roles, 'linux'),
    configuration, configurationFingerprint: serviceConfigurationFingerprint(configuration, { component: 'bot', platform: 'linux' }),
  };
  const session = {
    platform: 'linux', architecture: 'x64', component: 'bot', serviceKey: 'bot', writes: 0,
    readManifest: () => ({ present: true, value: current }),
    readResourceProof: () => ({ present: true, value: { resourceProof, platformResourceFingerprint: '9'.repeat(64), rolesFingerprint: current.rolesFingerprint, configurationFingerprint: current.configurationFingerprint } }),
    readReferences: () => ({ present: true, value: { previous: { serviceGeneration: 1, artifacts: [{ artifactKind: 'application', manifestFingerprint: predecessorManifestFingerprint }] } } }),
    readSiblingReferences: () => [],
    readJournal: () => ({ entries: [{ phase: 'committed' }], head: { present: true, value: { phase: 'committed' } }, pending: null }),
    readManualCleanup: () => ({ present: false, value: null }),
    readStartupProof: () => ({ present: false, value: null }),
    readRetainedDeploymentEnvelope: () => ({ manifest: { manifestFingerprint: predecessorManifestFingerprint, releaseSequence: 1, inventory: { treeFingerprint: 'a'.repeat(64) }, compatibilityFingerprint: 'b'.repeat(64), entrypointPath: '/runtime/bin' } }),
    readPublicationReceipt: () => ({ artifactKind: 'application', manifestFingerprint: predecessorManifestFingerprint }),
    acceptProvisionalMetadata: () => { calls.push('provisional'); },
    publishCurrentMetadata: () => { calls.push('publish'); },
    close: () => {},
  };
  const lifecycle = createServiceLifecycle({
    platform: 'linux', architecture: 'x64', native: {}, store: { openMutation: () => session },
    driver: { probe: () => calls.push('probe') }, observeApplication: () => {}, planResource: () => { calls.push('plan'); },
  });
  const request = {
    schemaVersion: 1, target: { component: 'bot' }, roles,
    expected: { serviceGeneration: 2, resourceProof, currentManifestFingerprint, predecessorManifestFingerprint },
    acceptServiceDisruption: true,
  };
  await assert.rejects(lifecycle.rollback(request), (error) => error.code === 'SERVICE_PENDING');
  assert.deepEqual(calls, []);
  assert.equal(session.writes, 0);
});

test('unknown operation and extra status fields refuse before opening the store', async () => {
  let opened = false;
  const lifecycle = createServiceLifecycle({
    platform: 'linux', architecture: 'x64', store: { openReadOnly: () => { opened = true; throw new Error('unexpected'); } }, driver: { probe: () => ({ platformPhase: 'absent' }) },
  });
  await assert.rejects(lifecycle.status({ schemaVersion: 1, target: { component: 'bot' }, roles, extra: true }), (error) => error.code === 'SERVICE_INVALID');
  await assert.rejects(lifecycle.run('bogus', {}), (error) => error.code === 'SERVICE_INVALID');
  assert.equal(opened, false);
});

test('all mutation schemas reject unknown fields before acquiring a session', async () => {
  const calls = [];
  const lifecycle = createServiceLifecycle({
    platform: 'linux', architecture: 'x64',
    store: { openMutation: () => { calls.push('open'); throw new Error('must not open'); } },
  });
  const base = { schemaVersion: 1, target: { component: 'bot' }, roles, unexpected: true };
  for (const operation of ['install', 'update', 'rollback', 'uninstall']) {
    await assert.rejects(lifecycle[operation](base), (error) => error.code === 'SERVICE_INVALID');
  }
  const recovery = { schemaVersion: 1, target: { component: 'bot' }, roles, expected: { transactionId: 'tx', journalFingerprint: '0'.repeat(64) }, acceptServiceDisruption: false, unexpected: true };
  await assert.rejects(lifecycle.recover(recovery), (error) => error.code === 'SERVICE_INVALID');
  assert.deepEqual(calls, []);
});

test('mutation dependency gaps refuse before opening the store', async () => {
  let opened = false;
  const lifecycle = createServiceLifecycle({
    platform: 'linux', architecture: 'x64',
    store: { openMutation: () => { opened = true; throw new Error('must not open'); } },
    driver: {},
  });
  const request = {
    schemaVersion: 1, target: { component: 'bot' }, roles,
    source: { kind: 'offline', applicationManifestPath: '/m', applicationSignaturePath: '/s', applicationArchivePath: '/a' },
    configuration: { runtimePath: '/runtime', workingDirectory: '/work', homeDirectory: '/home', logDirectory: '/log', channelsConfig: '/channels', expectedHostSetFingerprint: '0'.repeat(64), expectedHostCount: 0 },
    expected: { serviceGeneration: 0, resourceProof: null, applicationSequenceFloor: 0 },
  };
  await assert.rejects(lifecycle.install(request), (error) => error.code === 'SERVICE_INVALID');
  assert.equal(opened, false);
});

test('recovery refuses an unknown classifier without replay or synthetic proof', async () => {
  const calls = [];
  const head = { transactionId: 'tx', transactionFingerprint: '0'.repeat(64), phase: 'trial-start-intent' };
  const session = {
    platform: 'linux', architecture: 'x64', component: 'bot', serviceKey: 'bot', writes: 0,
    readJournal: () => ({ entries: [head], head, pending: null }),
    readManifest: () => ({ present: false, value: null }),
    close: () => {},
  };
  const lifecycle = createServiceLifecycle({
    platform: 'linux', architecture: 'x64', native: {},
    store: { openRecovery: () => session },
    driver: { recoverTrialState: () => { calls.push('classify'); return { classification: 'unknown', phase: head.phase }; } },
  });
  const request = {
    schemaVersion: 1, target: { component: 'bot' }, roles,
    expected: { transactionId: head.transactionId, journalFingerprint: head.transactionFingerprint },
    acceptServiceDisruption: false,
  };
  await assert.rejects(lifecycle.recover(request), (error) => error.code === 'SERVICE_PENDING');
  assert.deepEqual(calls, ['classify']);
  assert.equal(session.writes, 0);
});

test('recovery refuses not-in-trial before any replay write', async () => {
  const calls = [];
  const head = { transactionId: 'tx', transactionFingerprint: '3'.repeat(64), phase: 'trial-start-intent' };
  const session = {
    platform: 'linux', architecture: 'x64', component: 'bot', serviceKey: 'bot', writes: 0,
    readJournal: () => ({ entries: [head], head, pending: null }),
    readManifest: () => ({ present: false, value: null }),
    close: () => {},
  };
  const lifecycle = createServiceLifecycle({
    platform: 'linux', architecture: 'x64', native: {},
    store: { openRecovery: () => session },
    driver: { recoverTrialState: () => { calls.push('classify'); return { classification: 'not-in-trial', phase: head.phase }; } },
  });
  const request = {
    schemaVersion: 1, target: { component: 'bot' }, roles,
    expected: { transactionId: head.transactionId, journalFingerprint: head.transactionFingerprint },
    acceptServiceDisruption: false,
  };
  await assert.rejects(lifecycle.recover(request), (error) => error.code === 'SERVICE_PENDING');
  assert.deepEqual(calls, ['classify']);
  assert.equal(session.writes, 0);
});

test('prepared recovery rejects a relative publication root before driver construction', async () => {
  const calls = [];
  const head = recoveryTransaction('prepared');
  const session = {
    platform: 'linux', architecture: 'x64', component: 'bot', serviceKey: 'bot', writes: 0,
    readJournal: () => ({ entries: [head], head: { present: true, value: head }, pending: null }),
    readManifest: () => ({ present: false, value: null }),
    readRetainedDeploymentEnvelope: () => ({ manifest: {
      manifestFingerprint: head.candidate.applicationManifestFingerprint,
      releaseSequence: 1, inventory: { treeFingerprint: head.candidate.releaseTreeFingerprint },
      compatibilityFingerprint: head.candidate.compatibilityFingerprint, entrypointPath: 'bin/bot.js',
    } }),
    readPublicationReceipt: () => ({ publishedPath: 'relative-release-root' }),
    close: () => {},
  };
  const lifecycle = createServiceLifecycle({
    platform: 'linux', architecture: 'x64', native: {}, store: { openRecovery: () => session },
    driver: { recoverTrialState: () => { calls.push('classify'); return { classification: 'continue', phase: 'prepared' }; } },
  });
  const request = {
    schemaVersion: 1, target: { component: 'bot' }, roles,
    expected: { transactionId: head.transactionId, journalFingerprint: head.transactionFingerprint },
    acceptServiceDisruption: false,
  };
  await assert.rejects(lifecycle.recover(request), (error) => error.code === 'SERVICE_PENDING');
  assert.deepEqual(calls, []);
  assert.equal(session.writes, 0);
});

test('recovery refuses a named continuation when the journal head is not a complete transaction', async () => {
  const calls = [];
  const head = { transactionId: 'tx', transactionFingerprint: '1'.repeat(64), phase: 'transition-marker-intent' };
  const session = {
    platform: 'linux', architecture: 'x64', component: 'bot', serviceKey: 'bot', writes: 0,
    readJournal: () => ({ entries: [head], head, pending: null }),
    readManifest: () => ({ present: false, value: null }),
    close: () => {},
  };
  const lifecycle = createServiceLifecycle({
    platform: 'linux', architecture: 'x64', native: {},
    store: { openRecovery: () => session },
    driver: { recoverTrialState: () => { calls.push('classify'); return { classification: 'continue', phase: head.phase }; } },
  });
  const request = {
    schemaVersion: 1, target: { component: 'bot' }, roles,
    expected: { transactionId: head.transactionId, journalFingerprint: head.transactionFingerprint },
    acceptServiceDisruption: false,
  };
  await assert.rejects(lifecycle.recover(request), (error) => error.code === 'SERVICE_PENDING');
  assert.deepEqual(calls, ['classify']);
  assert.equal(session.writes, 0);
});

test('recovery refuses a prepared continuation without acquisition and compatibility authorities', async () => {
  const head = recoveryTransaction('prepared');
  const session = {
    platform: 'linux', architecture: 'x64', component: 'bot', serviceKey: 'bot', writes: 0,
    readJournal: () => ({ entries: [head], head: { present: true, value: head }, pending: null }),
    readManifest: () => ({ present: false, value: null }), close: () => {},
  };
  const lifecycle = createServiceLifecycle({
    platform: 'linux', architecture: 'x64', native: {}, store: { openRecovery: () => session },
    driver: { recoverTrialState: () => ({ classification: 'continue', phase: 'prepared' }) },
  });
  const request = {
    schemaVersion: 1, target: { component: 'bot' }, roles,
    expected: { transactionId: head.transactionId, journalFingerprint: head.transactionFingerprint },
    acceptServiceDisruption: false,
  };
  await assert.rejects(lifecycle.recover(request), (error) => error.code === 'SERVICE_PENDING');
  assert.equal(session.writes, 0);
});

test('windows status authenticates the SCM resource fingerprint, never a Linux byte hash', async () => {
  const manifestFingerprint = 'a'.repeat(64);
  const resourceProof = 'b'.repeat(64);
  const platformResourceFingerprint = 'c'.repeat(64);
  const manifest = {
    component: 'bot', serviceKey: 'bot', serviceGeneration: 1,
    manifestFingerprint, resourceProof, applicationManifestFingerprint: 'd'.repeat(64), shawlManifestFingerprint: 'e'.repeat(64),
    roles: windowsRoles, rolesFingerprint: serviceRolesFingerprint(windowsRoles, 'win32'),
  };
  const session = {
    platform: 'win32', architecture: 'x64', component: 'bot', serviceKey: 'bot', writes: 0,
    readManifest: () => ({ present: true, value: manifest }),
    readResourceProof: () => ({ present: true, value: { resourceProof, platformResourceFingerprint, rolesFingerprint: manifest.rolesFingerprint } }),
    readStartupProof: () => ({ present: false, value: null }), readManualCleanup: () => ({ present: false, value: null }),
    readJournal: () => ({ entries: [{ phase: 'committed' }], head: { present: true, value: { phase: 'committed' } }, pending: null }),
    readRetainedDeploymentEnvelope: () => ({ manifest: { manifestFingerprint: manifest.applicationManifestFingerprint, entrypointPath: 'C:/ProgramData/GJC/releases/current/bot.js' } }),
    close: () => {},
  };
  const lifecycle = createServiceLifecycle({
    platform: 'win32', architecture: 'x64', store: { openReadOnly: () => session },
    driver: { probe: () => ({ platformPhase: 'final', resourceFingerprint: platformResourceFingerprint, resourceDescriptor: { botUnitSha256: 'f'.repeat(64) }, service: 'stopped', activation: 'enabled', tree: 'empty' }) },
  });
  const receipt = await lifecycle.status({ schemaVersion: 1, target: { component: 'bot' }, roles: windowsRoles });
  assert.equal(receipt.ownership, 'owned');
  assert.equal(receipt.resourceProof, resourceProof);
  const wrappedSession = {
    ...session,
    readRetainedDeploymentEnvelope: () => ({
      value: { manifest: { manifestFingerprint: manifest.applicationManifestFingerprint, entrypointPath: 'C:/ProgramData/GJC/releases/current/bot.js' } },
    }),
  };
  const wrappedLifecycle = createServiceLifecycle({
    platform: 'win32', architecture: 'x64', store: { openReadOnly: () => wrappedSession },
    driver: { probe: () => ({ platformPhase: 'final', resourceFingerprint: platformResourceFingerprint, resourceDescriptor: { botUnitSha256: 'f'.repeat(64) }, service: 'stopped', activation: 'enabled', tree: 'empty' }) },
  });
  await assert.rejects(
    wrappedLifecycle.status({ schemaVersion: 1, target: { component: 'bot' }, roles: windowsRoles }),
    (error) => error.code === 'SERVICE_PENDING',
  );
});
