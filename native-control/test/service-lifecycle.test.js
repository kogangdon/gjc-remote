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

function windowsApplicationManifest({
  manifestFingerprint = '5'.repeat(64),
  archiveSha256 = 'a'.repeat(64),
  entrypoint = 'bot/src/bot.js',
  treeFingerprint = 'b'.repeat(64),
  releaseSequence = 1,
  compatibilityFingerprint = 'c'.repeat(64),
} = {}) {
  return Object.freeze({
    manifestFingerprint,
    archive: Object.freeze({ sha256: archiveSha256 }),
    entrypoints: Object.freeze({ bot: entrypoint }),
    inventory: Object.freeze({ treeFingerprint }),
    releaseSequence,
    compatibilityFingerprint,
  });
}

function windowsLocationPath(manifest) {
  return `C:\\ProgramData\\gjc-remote\\releases\\${manifest.archive.sha256}\\${manifest.entrypoints.bot.replaceAll('/', '\\')}`;
}

function windowsLocationIntent(manifest) {
  const absoluteRoot = 'C:\\ProgramData\\gjc-remote\\releases';
  const absolutePath = windowsLocationPath(manifest);
  const fields = {
    schemaVersion: 1,
    rootKind: 'releases',
    artifactFingerprint: manifest.archive.sha256,
    relativePath: manifest.entrypoints.bot,
    absoluteRoot,
    absolutePath,
    anchorIdentityFingerprint: 'd'.repeat(64),
    missingSegments: [manifest.archive.sha256, ...manifest.entrypoints.bot.split('/')],
    existingDirectoryIdentity: null,
    writes: 0,
  };
  return Object.freeze({ ...fields, intentFingerprint: canonicalJsonHash(fields) });
}

function windowsApplicationPublication(manifest, {
  publishedPath = manifest.entrypoints.bot,
  absolutePath = windowsLocationPath(manifest),
  artifactFingerprint = manifest.archive.sha256,
  fileSha256 = 'e'.repeat(64),
} = {}) {
  const directoryIdentity = Object.freeze({ profile: 'service-release-directory' });
  const fileIdentity = Object.freeze({ profile: 'service-release-file' });
  const binding = Object.freeze({
    schemaVersion: 1,
    kind: 'service-artifact-binding',
    artifactKind: 'application',
    rootKind: 'releases',
    artifactFingerprint,
    manifestFingerprint: manifest.manifestFingerprint,
    treeFingerprint: manifest.inventory.treeFingerprint,
    directoryIdentity,
    directoryIdentityFingerprint: 'f'.repeat(64),
    bindingFingerprint: '1'.repeat(64),
  });
  const location = Object.freeze({
    binding,
    schemaVersion: 1,
    publishedPath,
    absolutePath,
    directoryIdentity,
    fileIdentity,
    fileSha256,
    writes: 0,
  });
  return Object.freeze({ binding, locations: Object.freeze([location]) });
}

function windowsShawlManifest({
  manifestFingerprint = '4'.repeat(64),
  sha256 = '8'.repeat(64),
  name = 'shawl.exe',
} = {}) {
  return Object.freeze({
    manifestFingerprint,
    executable: Object.freeze({ name, sha256 }),
  });
}

function windowsShawlPublication(manifest) {
  const directoryIdentity = Object.freeze({ profile: 'service-release-directory' });
  const fileIdentity = Object.freeze({ profile: 'service-release-executable' });
  const binding = Object.freeze({
    schemaVersion: 1,
    kind: 'service-artifact-binding',
    artifactKind: 'shawl',
    rootKind: 'shawl',
    artifactFingerprint: manifest.executable.sha256,
    manifestFingerprint: manifest.manifestFingerprint,
    treeFingerprint: null,
    directoryIdentity,
    directoryIdentityFingerprint: '9'.repeat(64),
    bindingFingerprint: '1'.repeat(64),
  });
  const location = Object.freeze({
    binding,
    schemaVersion: 1,
    publishedPath: manifest.executable.name,
    absolutePath: `C:\\ProgramData\\gjc-remote\\shawl\\${manifest.executable.sha256}\\${manifest.executable.name}`,
    directoryIdentity,
    fileIdentity,
    fileSha256: manifest.executable.sha256,
    writes: 0,
  });
  return Object.freeze({ binding, locations: Object.freeze([location]) });
}

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

test('Windows rollback retains its authenticated Shawl publication through release planning', async () => {
  const calls = [];
  const stoppedAtPlanner = new Error('fixture stops before mutation');
  const configuration = {
    runtimePath: 'C:/runtime', workingDirectory: 'C:/work', homeDirectory: 'C:/home',
    logDirectory: 'C:/log', channelsConfig: 'C:/channels',
    expectedHostSetFingerprint: '7'.repeat(64), expectedHostCount: 0,
  };
  const current = {
    component: 'bot', serviceKey: 'bot', platform: 'win32', architecture: 'x64',
    serviceGeneration: 2, manifestFingerprint: '4'.repeat(64), resourceProof: '6'.repeat(64),
    applicationManifestFingerprint: '8'.repeat(64), shawlManifestFingerprint: '9'.repeat(64),
    roles: windowsRoles, rolesFingerprint: serviceRolesFingerprint(windowsRoles, 'win32'),
    configuration,
    configurationFingerprint: serviceConfigurationFingerprint(configuration, { component: 'bot', platform: 'win32' }),
  };
  const application = {
    manifestFingerprint: '5'.repeat(64), releaseSequence: 1,
    archive: { sha256: 'a'.repeat(64) },
    entrypoints: { bot: 'bot/src/bot.js' },
    inventory: { treeFingerprint: 'b'.repeat(64) },
    compatibilityFingerprint: 'c'.repeat(64),
  };
  const shawl = windowsShawlManifest({ manifestFingerprint: 'e'.repeat(64) });
  const applicationPublication = windowsApplicationPublication(application);
  const shawlPublication = windowsShawlPublication(shawl);
  const shawlBinding = shawlPublication.binding;
  const publications = {
    application: applicationPublication,
    shawl: shawlPublication,
  };
  const absent = () => ({ present: false, value: null });
  const session = {
    platform: 'win32', architecture: 'x64', component: 'bot', serviceKey: 'bot', writes: 0,
    readManifest: () => ({ present: true, value: current }),
    readResourceProof: () => ({ present: true, value: {
      resourceProof: current.resourceProof, platformResourceFingerprint: 'c'.repeat(64),
      rolesFingerprint: current.rolesFingerprint, configurationFingerprint: current.configurationFingerprint,
    } }),
    readReferences: () => ({ present: true, value: {
      previous: { serviceGeneration: 1, artifacts: [applicationPublication.binding, shawlBinding] },
    } }),
    readJournal: () => ({ entries: [], head: absent(), pending: null }),
    readManualCleanup: absent, readStartupProof: absent,
    readRetainedDeploymentEnvelope: ({ purpose }) => ({ manifest: purpose === 'application' ? application : shawl }),
    readPublicationReceipt: ({ slot, artifactKind }) => {
      assert.equal(slot, 'previous');
      return publications[artifactKind];
    },
    assertApplicationRollback: ({ manifest, publication }) => {
      assert.equal(manifest, application);
      assert.equal(publication, publications.application);
      calls.push('application-verified');
    },
    assertShawlRollback: ({ manifest, publication }) => {
      assert.equal(manifest, shawl);
      assert.equal(publication, publications.shawl);
      calls.push('shawl-verified');
    },
    acceptProvisionalMetadata: () => assert.fail('fixture stops before metadata writes'),
    publishCurrentMetadata: () => assert.fail('fixture stops before metadata writes'),
    close: () => calls.push('close'),
  };
  const lifecycle = createServiceLifecycle({
    platform: 'win32', architecture: 'x64', native: {}, store: { openMutation: () => session },
    driver: { probe: () => assert.fail('fixture stops before the driver') },
    observeApplication: () => assert.fail('fixture stops before startup'),
    planResource: ({ release }) => {
      assert.equal(release.shawlManifest, shawl);
      assert.equal(release.entrypointPath, windowsLocationPath(application));
      assert.equal(release.entrypointSha256, applicationPublication.locations[0].fileSha256);
      assert.equal(release.supervisorPath, shawlPublication.locations[0].absolutePath);
      assert.equal(release.supervisorSha256, shawl.executable.sha256);
      assert.equal(release.publicationReceipts.application.publication, applicationPublication);
      assert.equal(release.publicationReceipts.application.location, applicationPublication.locations[0]);
      assert.equal(release.publicationReceipts.shawl.publication, shawlPublication);
      assert.equal(release.publicationReceipts.shawl.location, shawlPublication.locations[0]);
      calls.push('plan');
      throw stoppedAtPlanner;
    },
  });
  await assert.rejects(lifecycle.rollback({
    schemaVersion: 1, target: { component: 'bot' }, roles: windowsRoles,
    expected: {
      serviceGeneration: 2, resourceProof: current.resourceProof,
      currentManifestFingerprint: current.manifestFingerprint,
      predecessorManifestFingerprint: application.manifestFingerprint,
    },
    acceptServiceDisruption: true,
  }), (error) => error === stoppedAtPlanner);
  assert.deepEqual(calls, ['application-verified', 'shawl-verified', 'plan', 'close']);
  assert.equal(session.writes, 0);
});

function windowsShawlIntent(manifest) {
  const relativePath = manifest.executable.name;
  const fields = {
    schemaVersion: 1,
    rootKind: 'shawl',
    artifactFingerprint: manifest.executable.sha256,
    relativePath,
    absoluteRoot: 'C:\\ProgramData\\gjc-remote\\shawl',
    absolutePath: `C:\\ProgramData\\gjc-remote\\shawl\\${manifest.executable.sha256}\\${relativePath}`,
    anchorIdentityFingerprint: 'd'.repeat(64),
    missingSegments: [manifest.executable.sha256, relativePath],
    existingDirectoryIdentity: null,
    writes: 0,
  };
  return Object.freeze({ ...fields, intentFingerprint: canonicalJsonHash(fields) });
}

function windowsCandidateFixture(signedEntrypoint) {
  const calls = [];
  const stoppedAtPlanner = new Error('stopped at planner');
  const manifest = windowsApplicationManifest({
    manifestFingerprint: '2'.repeat(64),
    archiveSha256: '3'.repeat(64),
  });
  const shawl = windowsShawlManifest({ manifestFingerprint: '4'.repeat(64) });
  const intents = { application: windowsLocationIntent(manifest), shawl: windowsShawlIntent(shawl) };
  const absent = () => ({ present: false, value: null });
  const floor = () => ({ floor: { committedSequence: 0 } });
  const session = {
    platform: 'win32', architecture: 'x64', component: 'bot', serviceKey: 'bot', writes: 0,
    readManifest: absent,
    readResourceProof: absent,
    readReferences: absent,
    readManualCleanup: absent,
    readStartupProof: absent,
    readSiblingReferences: () => [],
    readJournal: () => ({ entries: [], head: absent(), pending: null }),
    assertFloorCas: () => ({ application: floor(), shawl: floor() }),
    planArtifactLocation(input) {
      assert.equal(this.writes, 0);
      const expected = input.purpose === 'application'
        ? [manifest, manifest.entrypoints.bot]
        : [shawl, shawl.executable.name];
      assert.equal(input.manifest, expected[0]);
      assert.equal(input.relativePath, expected[1]);
      calls.push(`plan-location:${input.purpose}`);
      return intents[input.purpose];
    },
    acceptProvisionalMetadata: () => assert.fail('fixture stops before metadata writes'),
    publishCurrentMetadata: () => assert.fail('fixture stops before metadata writes'),
    close: () => calls.push('session-close'),
  };
  const acquisition = {
    readManifests: () => Object.freeze({ application: manifest, shawl, signedEntrypoint }),
    reserve: () => assert.fail('must not reserve before the prepared transaction'),
    publish: () => assert.fail('must not publish before the prepared transaction'),
    close: () => calls.push('acquisition-close'),
  };
  const lifecycle = createServiceLifecycle({
    platform: 'win32', architecture: 'x64', native: {},
    store: { openMutation: () => session }, acquisition,
    compatibility: () => assert.fail('must not continue past planning'),
    observeApplication: () => assert.fail('must not start'),
    driver: () => assert.fail('must not construct a driver before planning'),
    planResource: ({ release }) => {
      assert.equal(session.writes, 0);
      assert.equal(release.shawlManifest, shawl);
      assert.equal(release.entrypointPath, intents.application.absolutePath);
      assert.equal(release.entrypointSha256, signedEntrypoint.sha256);
      assert.equal(release.supervisorPath, intents.shawl.absolutePath);
      assert.equal(release.supervisorSha256, shawl.executable.sha256);
      calls.push('plan');
      throw stoppedAtPlanner;
    },
  });
  const request = {
    schemaVersion: 1,
    target: { component: 'bot' },
    roles: windowsRoles,
    configuration: {
      runtimePath: 'C:/runtime', workingDirectory: 'C:/work', homeDirectory: 'C:/home',
      logDirectory: 'C:/log', channelsConfig: 'C:/channels',
      expectedHostSetFingerprint: '7'.repeat(64), expectedHostCount: 0,
    },
    source: {
      kind: 'offline', applicationManifestPath: 'C:/m',
      applicationSignaturePath: 'C:/s', applicationArchivePath: 'C:/a',
      shawlManifestPath: 'C:/sm', shawlSignaturePath: 'C:/ss',
      shawlExecutablePath: 'C:/sa',
    },
    expected: { serviceGeneration: 0, resourceProof: null, applicationSequenceFloor: 0, shawlSequenceFloor: 0 },
  };
  return { calls, session, lifecycle, request, stoppedAtPlanner };
}

test('Windows candidate launch plans the signed entrypoint digest over write-free intents', async () => {
  const fixture = windowsCandidateFixture(Object.freeze({ path: 'bot/src/bot.js', sha256: '6'.repeat(64), size: 42 }));
  await assert.rejects(fixture.lifecycle.install(fixture.request), (error) => error === fixture.stoppedAtPlanner);
  assert.deepEqual(fixture.calls, ['plan-location:application', 'plan-location:shawl', 'plan', 'acquisition-close', 'session-close']);
  assert.equal(fixture.session.writes, 0);
});

test('Windows candidate without an authenticated signed entrypoint digest fails closed before planning', async () => {
  for (const signedEntrypoint of [
    null,
    Object.freeze({ path: 'bot/src/other.js', sha256: '6'.repeat(64), size: 42 }),
    Object.freeze({ path: 'bot/src/bot.js', sha256: 'not-a-hash', size: 42 }),
    { path: 'bot/src/bot.js', sha256: '6'.repeat(64), size: 42 },
    Object.freeze({ path: 'bot/src/bot.js', sha256: '6'.repeat(64), size: 42, extra: true }),
  ]) {
    const fixture = windowsCandidateFixture(signedEntrypoint);
    await assert.rejects(fixture.lifecycle.install(fixture.request), (error) => error.code === 'SERVICE_PENDING' && error.writes === 0);
    assert.deepEqual(fixture.calls, ['plan-location:application', 'plan-location:shawl', 'acquisition-close', 'session-close']);
    assert.equal(fixture.session.writes, 0);
  }
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

for (const markerPersists of [true, false]) {
    test(`linux mutation retains its transaction for manual cleanup (receipt ${markerPersists})`, async () => {
      const platform = 'linux';
      const calls = [];
      const entries = [];
      let manualRecord;
      const absent = () => ({ present: false, value: null });
      const floor = () => ({ floor: { committedSequence: 0 } });
      const prefix = '';
      const configuration = {
        runtimePath: `${prefix}/runtime`, workingDirectory: `${prefix}/work`,
        homeDirectory: `${prefix}/home`, logDirectory: `${prefix}/log`,
        channelsConfig: `${prefix}/channels`,
        expectedHostSetFingerprint: '0'.repeat(64), expectedHostCount: 0,
      };
      const session = {
        platform, architecture: 'x64', component: 'bot', serviceKey: 'bot', writes: 0,
        readManifest: absent, readResourceProof: absent, readReferences: absent,
        readManualCleanup: absent, readStartupProof: absent,
        readSiblingReferences: () => [],
        readJournal: () => ({
          entries,
          head: entries.length ? { present: true, value: entries.at(-1) } : absent(),
          pending: null,
        }),
        assertFloorCas: () => ({ application: floor() }),
        appendJournal(value) { entries.push(value); this.writes += 1; return value; },
        acceptProvisionalMetadata() {
          throw Object.assign(new Error('injected metadata drift'), { code: 'SERVICE_STALE', ambiguous: true });
        },
        publishCurrentMetadata: () => assert.fail('must not activate a failed mutation'),
        publishManualCleanup(value) {
          manualRecord = value;
          this.writes += 1;
          return markerPersists ? { present: true, value } : absent();
        },
        close: () => calls.push('session-close'),
      };
      const acquisition = {
        readManifests: () => ({
          application: {
            manifestFingerprint: 'a'.repeat(64), releaseSequence: 1,
            releaseTreeFingerprint: 'b'.repeat(64), compatibilityFingerprint: 'c'.repeat(64),
            archive: { sha256: 'd'.repeat(64) },
            inventory: { treeFingerprint: 'b'.repeat(64) },
            entrypoints: { bot: 'bot/src/bot.js' },
            entrypointPath: `${prefix}/release/bot.js`,
          },
        }),
        reserve: () => assert.fail('must not reserve after metadata failure'),
        publish: () => assert.fail('must not publish after metadata failure'),
        close: () => calls.push('acquisition-close'),
      };
      const lifecycle = createServiceLifecycle({
        platform, architecture: 'x64', native: {}, store: { openMutation: () => session },
        acquisition, compatibility: () => { calls.push('compatibility'); },
        observeApplication: () => assert.fail('must not start a failed mutation'),
        driver: { probe: () => ({ platformPhase: 'absent' }) },
        planResource: () => ({
          trial: { resourceFingerprint: 'e'.repeat(64), resourceDescriptor: { name: 'gjc-remote-bot' } },
          final: { resourceFingerprint: 'f'.repeat(64), resourceDescriptor: { name: 'gjc-remote-bot' } },
        }),
      });
      const source = {
        kind: 'offline', applicationManifestPath: `${prefix}/m`,
        applicationSignaturePath: `${prefix}/s`, applicationArchivePath: `${prefix}/a`,
      };
      await assert.rejects(lifecycle.install({
        schemaVersion: 1, target: { component: 'bot' },
        roles, configuration, source,
        expected: { serviceGeneration: 0, resourceProof: null, applicationSequenceFloor: 0 },
      }), (error) => {
        assert.equal(error.code, markerPersists ? 'SERVICE_STALE' : 'SERVICE_MANUAL_CLEANUP');
        assert.equal(error.ambiguous, true);
        assert.equal(error.writes, 2);
        return true;
      });
      assert.equal(entries.length, 1);
      assert.equal(manualRecord.transactionId, entries[0].transactionId);
      assert.equal(manualRecord.journalFingerprint, entries[0].transactionFingerprint);
      assert.equal(manualRecord.phase, 'prepared');
      assert.equal(manualRecord.expectedDisposition, 'absent');
      assert.equal(manualRecord.observedDisposition, 'torn');
      assert.equal(manualRecord.observedFingerprint, null);
      assert.deepEqual(calls, ['compatibility', 'acquisition-close', 'session-close']);
    });
}

test('a compatibility refusal precedes the transaction, journal head, provisional metadata and manual marker', async () => {
  const platform = 'linux';
  const calls = [];
  const entries = [];
  let manualRecord;
  const absent = () => ({ present: false, value: null });
  const floor = () => ({ floor: { committedSequence: 0 } });
  const prefix = '';
  const configuration = {
    runtimePath: `${prefix}/runtime`, workingDirectory: `${prefix}/work`,
    homeDirectory: `${prefix}/home`, logDirectory: `${prefix}/log`,
    channelsConfig: `${prefix}/channels`,
    expectedHostSetFingerprint: '0'.repeat(64), expectedHostCount: 0,
  };
  const session = {
    platform, architecture: 'x64', component: 'bot', serviceKey: 'bot', writes: 0,
    readManifest: absent, readResourceProof: absent, readReferences: absent,
    readManualCleanup: absent, readStartupProof: absent,
    readSiblingReferences: () => [],
    readJournal: () => ({
      entries,
      head: entries.length ? { present: true, value: entries.at(-1) } : absent(),
      pending: null,
    }),
    assertFloorCas: () => ({ application: floor() }),
    appendJournal(value) { entries.push(value); this.writes += 1; return value; },
    acceptProvisionalMetadata() {
      assert.fail('compatibility refusal must precede provisional metadata');
    },
    publishCurrentMetadata: () => assert.fail('must not activate a failed mutation'),
    publishManualCleanup(value) {
      manualRecord = value;
      this.writes += 1;
      return { present: true, value };
    },
    close: () => calls.push('session-close'),
  };
  const acquisition = {
    readManifests: () => ({
      application: {
        manifestFingerprint: 'a'.repeat(64), releaseSequence: 1,
        releaseTreeFingerprint: 'b'.repeat(64), compatibilityFingerprint: 'c'.repeat(64),
        archive: { sha256: 'd'.repeat(64) },
        inventory: { treeFingerprint: 'b'.repeat(64) },
        entrypoints: { bot: 'bot/src/bot.js' },
        entrypointPath: `${prefix}/release/bot.js`,
      },
    }),
    reserve: () => assert.fail('must not reserve after metadata failure'),
    publish: () => assert.fail('must not publish after metadata failure'),
    close: () => calls.push('acquisition-close'),
  };
  const lifecycle = createServiceLifecycle({
    platform, architecture: 'x64', native: {}, store: { openMutation: () => session },
    acquisition, compatibility: () => { throw Object.assign(new Error('retained envelope drift'), { code: 'SERVICE_STALE', ambiguous: true, writes: 0 }); },
    observeApplication: () => assert.fail('must not start a failed mutation'),
    driver: { probe: () => ({ platformPhase: 'absent' }) },
    planResource: () => ({
      trial: { resourceFingerprint: 'e'.repeat(64), resourceDescriptor: { name: 'gjc-remote-bot' } },
      final: { resourceFingerprint: 'f'.repeat(64), resourceDescriptor: { name: 'gjc-remote-bot' } },
    }),
  });
  const source = {
    kind: 'offline', applicationManifestPath: `${prefix}/m`,
    applicationSignaturePath: `${prefix}/s`, applicationArchivePath: `${prefix}/a`,
  };
  await assert.rejects(lifecycle.install({
    schemaVersion: 1, target: { component: 'bot' },
    roles, configuration, source,
    expected: { serviceGeneration: 0, resourceProof: null, applicationSequenceFloor: 0 },
  }), { code: 'SERVICE_STALE' });
  assert.equal(entries.length, 0);
  assert.equal(manualRecord, undefined);
  assert.equal(session.writes, 0);
  assert.deepEqual(calls, ['acquisition-close', 'session-close']);
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
  const retainedApplication = windowsApplicationManifest({
    manifestFingerprint: manifest.applicationManifestFingerprint,
    archiveSha256: '7'.repeat(64),
  });
  const retainedShawl = windowsShawlManifest({
    manifestFingerprint: manifest.shawlManifestFingerprint,
  });
  const applicationPublication = windowsApplicationPublication(retainedApplication);
  const shawlPublication = windowsShawlPublication(retainedShawl);
  const driverLocks = Object.freeze({ kind: 'driver-locks' });
  const session = {
    platform: 'win32', architecture: 'x64', component: 'bot', serviceKey: 'bot', writes: 0,
    handoffDriverLocks: () => driverLocks,
    readManifest: () => ({ present: true, value: manifest }),
    readResourceProof: () => ({ present: true, value: { resourceProof, platformResourceFingerprint, rolesFingerprint: manifest.rolesFingerprint } }),
    readStartupProof: () => ({ present: false, value: null }), readManualCleanup: () => ({ present: false, value: null }),
    readJournal: () => ({ entries: [{ phase: 'committed' }], head: { present: true, value: { phase: 'committed' } }, pending: null }),
    readRetainedDeploymentEnvelope: ({ purpose }) => ({
      manifest: purpose === 'application' ? retainedApplication : retainedShawl,
    }),
    readPublicationReceipt: ({ slot, artifactKind }) => {
      assert.equal(slot, 'current');
      return artifactKind === 'application' ? applicationPublication : shawlPublication;
    },
    close: () => {},
  };
  const lifecycle = createServiceLifecycle({
    platform: 'win32', architecture: 'x64', store: { openReadOnly: () => session },
    driver: ({ release, publicationReceipts, locks }) => {
      assert.equal(locks, driverLocks);
      assert.equal(release.entrypointPath, applicationPublication.locations[0].absolutePath);
      assert.equal(release.entrypointSha256, applicationPublication.locations[0].fileSha256);
      assert.equal(release.supervisorPath, shawlPublication.locations[0].absolutePath);
      assert.equal(release.supervisorSha256, shawlPublication.locations[0].fileSha256);
      assert.equal(publicationReceipts.application.publication, applicationPublication);
      assert.equal(publicationReceipts.shawl.publication, shawlPublication);
      return { probe: () => ({ platformPhase: 'final', resourceFingerprint: platformResourceFingerprint, resourceDescriptor: { botUnitSha256: 'f'.repeat(64) }, service: 'stopped', activation: 'enabled', tree: 'empty' }) };
    },
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
