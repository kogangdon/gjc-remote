import assert from 'node:assert/strict';
import test from 'node:test';
import { createServiceLifecycle } from '../src/service-lifecycle.js';
import { getServiceCleanupEvidenceInternal } from '../src/service-store.js';
import { runServiceCli, serviceReceiptBytes } from '../src/service-cli.js';
import { EXIT_CODES, runServiceEntrypoint } from '../src/service-entrypoint.js';
import {
  buildServiceArtifactBinding,
  buildServiceCandidateProof,
  buildServiceFinalProof,
  buildServiceManifest,
  buildServiceOldProof,
  buildServicePlatformState,
  buildServiceReferenceRecord,
  buildServiceReferenceSlot,
  buildServiceResourceProof,
  buildServiceTransaction,
  buildServiceTransitionProof,
  serviceConfigurationFingerprint,
  serviceRolesFingerprint,
  validateServiceTransaction,
} from '@gjc-remote/shared/service-lifecycle-envelope';
import { canonicalJson, canonicalJsonBytes, canonicalJsonHash } from '@gjc-remote/shared/strict-json';

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

function lifecycleStoreError(code, operation, writes = 0, ambiguous = false) {
  const error = new Error(`${operation} failed`);
  Object.assign(error, { name: 'ServiceStoreError', code, operation, writes, ambiguous });
  return error;
}

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
  return `C:\\gjc-remote\\releases\\${manifest.archive.sha256}\\${manifest.entrypoints.bot.replaceAll('/', '\\')}`;
}

function windowsLocationIntent(manifest) {
  const absoluteRoot = 'C:\\gjc-remote\\releases';
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
    absolutePath: `C:\\gjc-remote\\supervisors\\shawl\\${manifest.executable.sha256}\\${manifest.executable.name}`,
    directoryIdentity,
    fileIdentity,
    fileSha256: manifest.executable.sha256,
    writes: 0,
  });
  return Object.freeze({ binding, locations: Object.freeze([location]) });
}

function recoveryTransaction(phase, operation = 'install', platform = 'linux') {
  const shawlManifestFingerprint = platform === 'win32' ? '9'.repeat(64) : null;
  const old = buildServiceOldProof({ disposition: 'absent', manifestFingerprint: null, resourceProof: null, applicationManifestFingerprint: null, shawlManifestFingerprint: null, serviceGeneration: 0, activation: 'disabled-not-startable' }, platform);
  const candidate = buildServiceCandidateProof({ disposition: 'release', applicationManifestFingerprint: 'a'.repeat(64), shawlManifestFingerprint, releaseSequence: 1, releaseTreeFingerprint: 'b'.repeat(64), compatibilityFingerprint: 'c'.repeat(64) }, platform);
  const transition = buildServiceTransitionProof({ oldFingerprint: old.oldFingerprint, candidateFingerprint: candidate.candidateFingerprint, expectedBeforeResourceFingerprint: null, expectedAfterResourceFingerprint: 'd'.repeat(64), platformResourceFingerprint: 'e'.repeat(64), platformState: buildServicePlatformState(platform, 'trial') }, platform);
  const final = buildServiceFinalProof({ disposition: 'stable', manifestFingerprint: 'f'.repeat(64), resourceProof: '1'.repeat(64), applicationManifestFingerprint: 'a'.repeat(64), shawlManifestFingerprint, serviceGeneration: 1, activation: 'enabled' }, platform);
  const prepared = buildServiceTransaction({ transactionId: 'tx-recover', transactionNonce: '2'.repeat(32), operation, component: 'bot', serviceKey: 'bot', platform, architecture: 'x64', serviceGeneration: 1, old, candidate, transition, final, phase: 'prepared', substep: 'none', previousJournalFingerprint: null });
  return phase === 'prepared' ? prepared : buildServiceTransaction({
    ...prepared,
    phase,
    substep: 'intent',
    previousJournalFingerprint: prepared.transactionFingerprint,
  });
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

for (const platformPhase of ['final', 'trial', 'final-restart-armed']) {
  test(`Linux status does not infer runtime from configuration-only phase ${platformPhase}`, async () => {
    const fixture = readOnlyFixture();
    fixture.session.readJournal = () => ({ entries: [{ phase: 'committed' }], pending: null });
    const lifecycle = createServiceLifecycle({
      platform: 'linux', architecture: 'x64', store: fixture.store,
      driver: { probe: () => ({ platformPhase }) },
    });
    const result = await runServiceCli({
      argv: ['status'], input: canonicalJsonBytes({ schemaVersion: 1, target: { component: 'bot' }, roles }),
      platform: 'linux', architecture: 'x64', lifecycle,
    });
    assert.equal(result.status, 'ok');
    assert.equal(result.receipt.service, 'unknown');
    assert.equal(result.receipt.ownership, 'foreign');
    assert.equal(result.receipt.recovery, 'manual-cleanup');
    assert.equal(result.writes, 0);
    assert.deepEqual(JSON.parse(serviceReceiptBytes(result).toString('utf8')), result);
  });
}

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
  }), (error) => error.name === 'ServiceLifecycleError' && error.cause === stoppedAtPlanner);
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
    absoluteRoot: 'C:\\gjc-remote\\supervisors\\shawl',
    absolutePath: `C:\\gjc-remote\\supervisors\\shawl\\${manifest.executable.sha256}\\${relativePath}`,
    anchorIdentityFingerprint: 'd'.repeat(64),
    missingSegments: [manifest.executable.sha256, relativePath],
    existingDirectoryIdentity: null,
    writes: 0,
  };
  return Object.freeze({ ...fields, intentFingerprint: canonicalJsonHash(fields) });
}

function windowsCandidateFixture(signedEntrypoint, store = null, acquisitionOverride = null) {
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
    store: store ?? { openMutation: () => session }, acquisition: acquisitionOverride ?? acquisition,
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
  return { calls, session, lifecycle, request, stoppedAtPlanner, acquisition };
}

test('Windows candidate launch plans the signed entrypoint digest over write-free intents', async () => {
  const fixture = windowsCandidateFixture(Object.freeze({ path: 'bot/src/bot.js', sha256: '6'.repeat(64), size: 42 }));
  await assert.rejects(fixture.lifecycle.install(fixture.request), (error) => error.name === 'ServiceLifecycleError' && error.cause === fixture.stoppedAtPlanner);
  assert.deepEqual(fixture.calls, ['plan-location:application', 'plan-location:shawl', 'plan', 'acquisition-close', 'session-close']);
  assert.equal(fixture.session.writes, 0);
});

test('first install bootstraps only after an exact absent-store result', async () => {
  const storeCalls = [];
  let fixture;
  const store = {
    openMutation() {
      storeCalls.push('open-mutation');
      throw lifecycleStoreError('SERVICE_STORE_ABSENT', 'open_service_store');
    },
    bootstrap() {
      storeCalls.push('bootstrap');
      return fixture.session;
    },
  };
  fixture = windowsCandidateFixture(
    Object.freeze({ path: 'bot/src/bot.js', sha256: '6'.repeat(64), size: 42 }),
    store,
  );
  await assert.rejects(fixture.lifecycle.install(fixture.request), (error) => error.name === 'ServiceLifecycleError' && error.cause === fixture.stoppedAtPlanner);
  assert.deepEqual(storeCalls, ['open-mutation', 'bootstrap']);
  assert.deepEqual(fixture.calls, ['plan-location:application', 'plan-location:shawl', 'plan', 'acquisition-close', 'session-close']);
  assert.equal(fixture.session.writes, 0);
});

test('immutable acquisition errors retain safe metadata and bootstrap writes without leaking diagnostics', async () => {
  class ImmutableServiceAcquisitionError extends Error {
    constructor() {
      super('private acquisition diagnostic');
      Object.defineProperties(this, {
        name: { value: 'ServiceAcquisitionError' },
        code: { value: 'SERVICE_ACCESS_DENIED', enumerable: true },
        operation: { value: 'read_service_acquisition_manifests', enumerable: true },
        writes: { value: 1, enumerable: true },
        ambiguous: { value: true, enumerable: true },
      });
    }
  }
  const acquisitionError = new ImmutableServiceAcquisitionError();
  const storeCalls = [];
  let fixture;
  const store = {
    openMutation() {
      storeCalls.push('open-mutation');
      throw lifecycleStoreError('SERVICE_STORE_ABSENT', 'open_service_store');
    },
    bootstrap() {
      storeCalls.push('bootstrap');
      fixture.session.writes = 3;
      return fixture.session;
    },
  };
  const acquisition = {
    readManifests() { throw acquisitionError; },
    reserve: () => assert.fail('must not reserve before the prepared transaction'),
    publish: () => assert.fail('must not publish before the prepared transaction'),
    close: () => fixture.calls.push('acquisition-close'),
  };
  fixture = windowsCandidateFixture(
    Object.freeze({ path: 'bot/src/bot.js', sha256: '6'.repeat(64), size: 42 }),
    store,
    acquisition,
  );

  await assert.rejects(fixture.lifecycle.install(fixture.request), (error) => {
    assert.notEqual(error, acquisitionError);
    assert.equal(error.name, 'ServiceLifecycleError');
    assert.equal(error.code, 'SERVICE_ACCESS_DENIED');
    assert.equal(error.operation, 'install');
    assert.equal(error.writes, 3);
    assert.equal(error.ambiguous, true);
    assert.deepEqual(Object.keys(error), ['name', 'code', 'operation', 'writes', 'ambiguous']);
    for (const key of ['code', 'operation', 'writes', 'ambiguous']) {
      const descriptor = Object.getOwnPropertyDescriptor(error, key);
      assert.equal(descriptor.enumerable, true);
      assert.equal(descriptor.get, undefined);
      assert.equal(descriptor.set, undefined);
    }
    assert.equal(error.cause, acquisitionError);
    assert.equal(Object.getOwnPropertyDescriptor(error, 'cause').enumerable, false);
    assert.equal(error.message, 'install failed');
    assert.doesNotMatch(error.message, /private acquisition diagnostic/);
    assert.doesNotMatch(error.stack, /private acquisition diagnostic/);
    return true;
  });

  assert.equal(acquisitionError.message, 'private acquisition diagnostic');
  assert.deepEqual(
    ['name', 'code', 'operation', 'writes', 'ambiguous'].map((key) => [
      key, acquisitionError[key], Object.getOwnPropertyDescriptor(acquisitionError, key).writable,
    ]),
    [
      ['name', 'ServiceAcquisitionError', false],
      ['code', 'SERVICE_ACCESS_DENIED', false],
      ['operation', 'read_service_acquisition_manifests', false],
      ['writes', 1, false],
      ['ambiguous', true, false],
    ],
  );
  assert.deepEqual(storeCalls, ['open-mutation', 'bootstrap']);
  assert.deepEqual(fixture.session.readJournal().entries, []);
  assert.equal(fixture.session.writes, 3);
  assert.deepEqual(fixture.calls, ['acquisition-close', 'session-close']);
});

test('stale floor CAS refuses an absent-store install before bootstrap', async () => {
  const storeCalls = [];
  let fixture;
  const store = {
    openMutation() {
      storeCalls.push('open-mutation');
      throw lifecycleStoreError('SERVICE_STORE_ABSENT', 'open_service_store');
    },
    bootstrap() {
      storeCalls.push('bootstrap');
      return fixture.session;
    },
  };
  fixture = windowsCandidateFixture(
    Object.freeze({ path: 'bot/src/bot.js', sha256: '6'.repeat(64), size: 42 }),
    store,
  );
  fixture.request.expected.applicationSequenceFloor = 1;
  await assert.rejects(fixture.lifecycle.install(fixture.request), (error) => error.code === 'SERVICE_STALE');
  assert.deepEqual(storeCalls, ['open-mutation']);
  assert.deepEqual(fixture.calls, []);
});

test('nonzero install generation or resource proof is rejected before opening or bootstrapping', async () => {
  const storeCalls = [];
  const fixture = windowsCandidateFixture(
    Object.freeze({ path: 'bot/src/bot.js', sha256: '6'.repeat(64), size: 42 }),
    {
      openMutation() { storeCalls.push('open-mutation'); },
      bootstrap() { storeCalls.push('bootstrap'); },
    },
  );
  for (const expected of [
    { ...fixture.request.expected, serviceGeneration: 1 },
    { ...fixture.request.expected, resourceProof: '1'.repeat(64) },
  ]) {
    fixture.request.expected = expected;
    await assert.rejects(fixture.lifecycle.install(fixture.request), (error) => error.code === 'SERVICE_INVALID');
  }
  assert.deepEqual(storeCalls, []);
  assert.deepEqual(fixture.calls, []);
});

test('only exact zero-write SERVICE_STORE_ABSENT evidence can enter bootstrap', async () => {
  for (const openError of [
    lifecycleStoreError('SERVICE_STORE_ABSENT', 'open_service_root'),
    lifecycleStoreError('SERVICE_STORE_ABSENT', 'open_service_store', 1),
    lifecycleStoreError('SERVICE_STORE_ABSENT', 'open_service_store', 0, true),
    lifecycleStoreError('SERVICE_ACCESS_DENIED', 'open_service_store'),
    new Error('unclassified open failure'),
  ]) {
    const storeCalls = [];
    const fixture = windowsCandidateFixture(
      Object.freeze({ path: 'bot/src/bot.js', sha256: '6'.repeat(64), size: 42 }),
      {
        openMutation() {
          storeCalls.push('open-mutation');
          throw openError;
        },
        bootstrap() { storeCalls.push('bootstrap'); },
      },
    );
    await assert.rejects(fixture.lifecycle.install(fixture.request), (error) => error === openError);
    assert.deepEqual(storeCalls, ['open-mutation']);
    assert.deepEqual(fixture.calls, []);
  }
});

test('non-install operations propagate store absence without bootstrapping', async () => {
  const storeCalls = [];
  const fixture = windowsCandidateFixture(
    Object.freeze({ path: 'bot/src/bot.js', sha256: '6'.repeat(64), size: 42 }),
    {
      openMutation() {
        storeCalls.push('open-mutation');
        throw lifecycleStoreError('SERVICE_STORE_ABSENT', 'open_service_store');
      },
      bootstrap() { storeCalls.push('bootstrap'); },
    },
  );
  delete fixture.request.configuration;
  fixture.request.acceptServiceDisruption = true;
  fixture.request.expected = {
    serviceGeneration: 1,
    resourceProof: '1'.repeat(64),
    currentManifestFingerprint: '2'.repeat(64),
    applicationSequenceFloor: 0,
    shawlSequenceFloor: 0,
  };
  await assert.rejects(fixture.lifecycle.update(fixture.request), (error) => error.code === 'SERVICE_STORE_ABSENT');
  assert.deepEqual(storeCalls, ['open-mutation']);
  assert.deepEqual(fixture.calls, []);
});

test('bootstrap failures with writes or manual-cleanup evidence propagate without reopening', async () => {
  const bootstrapError = lifecycleStoreError('SERVICE_MANUAL_CLEANUP', 'open_service_root', 1, true);
  const storeCalls = [];
  let fixture;
  const store = {
    openMutation() {
      storeCalls.push('open-mutation');
      throw lifecycleStoreError('SERVICE_STORE_ABSENT', 'open_service_store');
    },
    bootstrap() {
      storeCalls.push('bootstrap');
      throw bootstrapError;
    },
  };
  fixture = windowsCandidateFixture(
    Object.freeze({ path: 'bot/src/bot.js', sha256: '6'.repeat(64), size: 42 }),
    store,
  );
  await assert.rejects(fixture.lifecycle.install(fixture.request), (error) => error === bootstrapError);
  assert.deepEqual(storeCalls, ['open-mutation', 'bootstrap']);
  assert.deepEqual(fixture.calls, []);
});

test('bootstrap access-denied failures propagate without reopening mutation', async () => {
  const bootstrapError = lifecycleStoreError('SERVICE_ACCESS_DENIED', 'open_service_root');
  const storeCalls = [];
  const fixture = windowsCandidateFixture(
    Object.freeze({ path: 'bot/src/bot.js', sha256: '6'.repeat(64), size: 42 }),
    {
      openMutation() {
        storeCalls.push('open-mutation');
        throw lifecycleStoreError('SERVICE_STORE_ABSENT', 'open_service_store');
      },
      bootstrap() {
        storeCalls.push('bootstrap');
        throw bootstrapError;
      },
    },
  );
  await assert.rejects(fixture.lifecycle.install(fixture.request), (error) => error === bootstrapError);
  assert.deepEqual(storeCalls, ['open-mutation', 'bootstrap']);
  assert.deepEqual(fixture.calls, []);
});

test('bootstrap root collision reopens mutation only for the exact zero-write race contract', async () => {
  const storeCalls = [];
  let fixture;
  const store = {
    openMutation() {
      storeCalls.push('open-mutation');
      if (storeCalls.length === 1) {
        throw lifecycleStoreError('SERVICE_STORE_ABSENT', 'open_service_store');
      }
      return fixture.session;
    },
    bootstrap() {
      storeCalls.push('bootstrap');
      throw lifecycleStoreError('SERVICE_ALREADY_EXISTS', 'open_service_root');
    },
  };
  fixture = windowsCandidateFixture(
    Object.freeze({ path: 'bot/src/bot.js', sha256: '6'.repeat(64), size: 42 }),
    store,
  );
  await assert.rejects(fixture.lifecycle.install(fixture.request), (error) => error.name === 'ServiceLifecycleError' && error.cause === fixture.stoppedAtPlanner);
  assert.deepEqual(storeCalls, ['open-mutation', 'bootstrap', 'open-mutation']);
  assert.deepEqual(fixture.calls, ['plan-location:application', 'plan-location:shawl', 'plan', 'acquisition-close', 'session-close']);
});

test('bootstrap SERVICE_ALREADY_EXISTS without exact zero-write root evidence is not a race', async () => {
  for (const collision of [
    lifecycleStoreError('SERVICE_ALREADY_EXISTS', 'open_service_directory'),
    lifecycleStoreError('SERVICE_ALREADY_EXISTS', 'open_service_root', 1),
    lifecycleStoreError('SERVICE_ALREADY_EXISTS', 'open_service_root', 0, true),
  ]) {
    const storeCalls = [];
    const fixture = windowsCandidateFixture(
      Object.freeze({ path: 'bot/src/bot.js', sha256: '6'.repeat(64), size: 42 }),
      {
        openMutation() {
          storeCalls.push('open-mutation');
          throw lifecycleStoreError('SERVICE_STORE_ABSENT', 'open_service_store');
        },
        bootstrap() {
          storeCalls.push('bootstrap');
          throw collision;
        },
      },
    );
    await assert.rejects(fixture.lifecycle.install(fixture.request), (error) => error === collision);
    assert.deepEqual(storeCalls, ['open-mutation', 'bootstrap']);
    assert.deepEqual(fixture.calls, []);
  }
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

test('mutation dependency gaps refuse before opening or bootstrapping the store', async () => {
  const calls = [];
  const lifecycle = createServiceLifecycle({
    platform: 'linux', architecture: 'x64',
    store: {
      openMutation: () => { calls.push('open'); throw new Error('must not open'); },
      bootstrap: () => { calls.push('bootstrap'); throw new Error('must not bootstrap'); },
    },
    driver: {},
  });
  const request = {
    schemaVersion: 1, target: { component: 'bot' }, roles,
    source: { kind: 'offline', applicationManifestPath: '/m', applicationSignaturePath: '/s', applicationArchivePath: '/a' },
    configuration: { runtimePath: '/runtime', workingDirectory: '/work', homeDirectory: '/home', logDirectory: '/log', channelsConfig: '/channels', expectedHostSetFingerprint: '0'.repeat(64), expectedHostCount: 0 },
    expected: { serviceGeneration: 0, resourceProof: null, applicationSequenceFloor: 0 },
  };
  await assert.rejects(lifecycle.install(request), (error) => error.code === 'SERVICE_INVALID');
  assert.deepEqual(calls, []);
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

function ownedMutationFixture(platform) {
  const calls = [];
  const absent = () => ({ present: false, value: null });
  const present = (value) => ({ present: true, value });
  const fixtureRoles = platform === 'win32' ? windowsRoles : roles;
  const prefix = platform === 'win32' ? 'C:' : '';
  const configuration = {
    runtimePath: `${prefix}/runtime`, workingDirectory: `${prefix}/work`,
    homeDirectory: `${prefix}/home`, logDirectory: `${prefix}/log`, channelsConfig: `${prefix}/channels`,
    expectedHostSetFingerprint: '0'.repeat(64), expectedHostCount: 0,
  };
  const application = windowsApplicationManifest({ manifestFingerprint: '8'.repeat(64) });
  const shawl = windowsShawlManifest({ manifestFingerprint: '9'.repeat(64) });
  const tuple = { serviceKey: 'bot', component: 'bot', platform, architecture: 'x64' };
  const bindings = {
    serviceGeneration: 4, applicationManifestFingerprint: application.manifestFingerprint,
    shawlManifestFingerprint: platform === 'win32' ? shawl.manifestFingerprint : null,
    configurationFingerprint: serviceConfigurationFingerprint(configuration, { component: 'bot', platform }),
    rolesFingerprint: serviceRolesFingerprint(fixtureRoles, platform),
    platformState: buildServicePlatformState(platform, 'final'),
  };
  const resource = buildServiceResourceProof({
    ...tuple, ...bindings, operation: 'update', transactionId: 'tx-owned', transactionNonce: '2'.repeat(32),
    predecessorResourceProof: '3'.repeat(64), platformResourceFingerprint: 'd'.repeat(64),
  });
  const current = buildServiceManifest({
    ...tuple, ...bindings, configuration, roles: fixtureRoles,
    predecessorManifestFingerprint: '4'.repeat(64), resourceProof: resource.resourceProof,
  });
  const old = buildServiceOldProof({
    disposition: 'stable', manifestFingerprint: '4'.repeat(64), resourceProof: '3'.repeat(64),
    applicationManifestFingerprint: '5'.repeat(64), shawlManifestFingerprint: bindings.shawlManifestFingerprint,
    serviceGeneration: 3, activation: 'enabled',
  }, platform);
  const candidate = buildServiceCandidateProof({
    disposition: 'release', applicationManifestFingerprint: application.manifestFingerprint,
    shawlManifestFingerprint: bindings.shawlManifestFingerprint, releaseSequence: 1,
    releaseTreeFingerprint: application.inventory.treeFingerprint, compatibilityFingerprint: application.compatibilityFingerprint,
  }, platform);
  const final = buildServiceFinalProof({
    disposition: 'stable', manifestFingerprint: current.manifestFingerprint, resourceProof: resource.resourceProof,
    applicationManifestFingerprint: current.applicationManifestFingerprint, shawlManifestFingerprint: current.shawlManifestFingerprint,
    serviceGeneration: current.serviceGeneration, activation: 'enabled',
  }, platform);
  const transition = buildServiceTransitionProof({
    oldFingerprint: old.oldFingerprint, candidateFingerprint: candidate.candidateFingerprint,
    expectedBeforeResourceFingerprint: '6'.repeat(64), expectedAfterResourceFingerprint: resource.platformResourceFingerprint,
    platformResourceFingerprint: 'e'.repeat(64), platformState: buildServicePlatformState(platform, 'trial'),
  }, platform);
  const entries = [buildServiceTransaction({
    ...tuple, transactionId: resource.transactionId, transactionNonce: resource.transactionNonce, operation: 'update',
    serviceGeneration: current.serviceGeneration, old, candidate, transition, final,
    phase: 'committed', substep: 'observed', previousJournalFingerprint: '7'.repeat(64),
  })];
  let manifestReceipt = present(current);
  let resourceReceipt = present(resource);
  let references = absent();
  let tombstone = absent();
  const rawResourceSha256 = 'f'.repeat(64);
  const session = {
    ...tuple, writes: 0,
    readManifest: (slot) => slot === 'current' ? manifestReceipt : absent(),
    readResourceProof: (slot) => slot === 'current' ? resourceReceipt : absent(),
    readReferences: () => references,
    readManualCleanup: absent, readStartupProof: absent, readSiblingReferences: () => [],
    readJournal: () => ({ entries, head: present(entries.at(-1)), pending: null }),
    assertFloorCas(input) {
      calls.push('floor-cas');
      if (input.applicationSequenceFloor !== 1 || (platform === 'win32' && input.shawlSequenceFloor !== 1)) {
        throw lifecycleStoreError('SERVICE_STALE', 'assert_floor_cas');
      }
      return { application: { floor: { committedSequence: 1 } }, ...(platform === 'win32' ? { shawl: { floor: { committedSequence: 1 } } } : {}) };
    },
    appendJournal(value) {
      validateServiceTransaction(value);
      assert.equal(value.previousJournalFingerprint, entries.at(-1).transactionFingerprint);
      entries.push(value);
      this.writes += 1;
      calls.push(value.phase);
      return value;
    },
    acceptProvisionalMetadata: () => assert.fail('uninstall must not publish provisional metadata'),
    publishCurrentMetadata: () => assert.fail('uninstall must not publish current metadata'),
    readRetainedDeploymentEnvelope: ({ purpose }) => ({ manifest: purpose === 'application' ? application : shawl }),
    readPublicationReceipt: ({ slot, artifactKind }) => {
      assert.equal(slot, 'current');
      return artifactKind === 'application' ? windowsApplicationPublication(application) : windowsShawlPublication(shawl);
    },
    readTombstone: () => tombstone,
    publishTombstone(value, expected) {
      assert.equal(expected, tombstone);
      tombstone = present(value);
      this.writes += 1;
      calls.push('publish-tombstone');
      return tombstone;
    },
    publishReferences(value, expected) {
      assert.equal(expected, references);
      references = present(value);
      this.writes += 1;
      calls.push('publish-references');
      return references;
    },
    removeManifest(slot, expected) {
      assert.equal(slot, 'current');
      assert.equal(expected, manifestReceipt);
      manifestReceipt = absent();
      this.writes += 1;
      calls.push('remove-manifest');
    },
    removeResourceProof(slot, expected) {
      assert.equal(slot, 'current');
      assert.equal(expected, resourceReceipt);
      resourceReceipt = absent();
      this.writes += 1;
      calls.push('remove-resource-proof');
    },
    close: () => calls.push('session-close'),
  };
  const driver = {
    writes: 0,
    probe() {
      assert.equal(entries.at(-1).phase, 'prepared');
      calls.push('probe');
      return { platformPhase: 'final', resourceFingerprint: resource.platformResourceFingerprint, resourceDescriptor: { botUnitSha256: rawResourceSha256 } };
    },
    stopAndQuiesce(input) {
      assert.equal(entries.at(-1).phase, 'transition-marker-intent');
      assert.deepEqual(input, { expectedResourceFingerprint: resource.platformResourceFingerprint });
      this.writes += 1;
      calls.push('stop');
    },
    removeResource(input) {
      assert.equal(entries.at(-1).phase, 'tombstoned');
      assert.equal(tombstone.present, true);
      assert.deepEqual(input, platform === 'linux'
        ? { expectedCurrentSha256: rawResourceSha256, siblings: [] }
        : { expectedResourceFingerprint: resource.platformResourceFingerprint });
      this.writes += 1;
      calls.push('remove-resource');
    },
  };
  const request = {
    schemaVersion: 1, target: { component: 'bot' }, roles: fixtureRoles, acceptServiceDisruption: true,
    expected: {
      serviceGeneration: current.serviceGeneration, resourceProof: current.resourceProof,
      currentManifestFingerprint: current.manifestFingerprint, applicationSequenceFloor: 1,
      ...(platform === 'win32' ? { shawlSequenceFloor: 1 } : {}),
    },
  };
  const lifecycle = createServiceLifecycle({ platform, architecture: 'x64', native: {}, store: { openMutation: () => session }, driver });
  return { lifecycle, session, driver, request, current, resource, entries, calls };
}

for (const platform of ['linux', 'win32']) {
  test(`${platform} owned uninstall commits an absent generation-zero final proof and an incremented transaction`, async () => {
    const fixture = ownedMutationFixture(platform);
    const { current, session, driver, entries, calls } = fixture;
    const receipt = await fixture.lifecycle.uninstall(fixture.request);
    assert.equal(receipt.serviceGeneration, current.serviceGeneration + 1);
    assert.equal(receipt.writes, session.writes + driver.writes);
    assert.equal(driver.writes, 2);
    const final = buildServiceFinalProof({
      disposition: 'absent', manifestFingerprint: null, resourceProof: null,
      applicationManifestFingerprint: null, shawlManifestFingerprint: null,
      serviceGeneration: 0, activation: 'disabled-not-startable',
    }, platform);
    for (const entry of entries.slice(1)) {
      assert.equal(entry.operation, 'uninstall');
      assert.equal(entry.old.serviceGeneration, current.serviceGeneration);
      assert.equal(entry.serviceGeneration, current.serviceGeneration + 1);
      assert.deepEqual(entry.final, final);
    }
    assert.equal(session.readTombstone().value.serviceGeneration, current.serviceGeneration + 1);
    assert.equal(session.readTombstone().value.resourceProof, current.resourceProof);
    assert.equal(session.readTombstone().value.currentManifestFingerprint, current.manifestFingerprint);
    assert.equal(session.readReferences().value.serviceGeneration, current.serviceGeneration + 1);
    assert.equal(session.readReferences().value.current, null);
    assert.equal(session.readReferences().value.previous, null);
    assert.equal(session.readReferences().value.provisional, null);
    assert.equal(session.readManifest('current').present, false);
    assert.equal(session.readResourceProof('current').present, false);
    assert.deepEqual(calls, [
      'floor-cas', 'prepared', 'probe', 'transition-marker-intent', 'stop', 'tombstoned',
      'publish-tombstone', 'remove-resource', 'publish-references', 'references-released',
      'remove-manifest', 'remove-resource-proof', 'committed', 'session-close',
    ]);
  });

  for (const variant of ['stale-generation', 'stale-resource', 'stale-manifest', 'stale-floor', 'foreign-roles', 'resource-roles', 'configuration', 'pending-journal']) {
    test(`${platform} uninstall refuses ${variant} before journal writes or driver mutation`, async () => {
      const fixture = ownedMutationFixture(platform);
      const { request, session, current, resource, entries } = fixture;
      let code = 'SERVICE_STALE';
      if (variant === 'stale-generation') request.expected.serviceGeneration -= 1;
      if (variant === 'stale-resource') request.expected.resourceProof = '0'.repeat(64);
      if (variant === 'stale-manifest') request.expected.currentManifestFingerprint = '0'.repeat(64);
      if (variant === 'stale-floor') request.expected.applicationSequenceFloor = 0;
      if (variant === 'foreign-roles') {
        const kind = platform === 'win32' ? 'sid' : 'uid';
        request.roles = { ...request.roles, management: { kind, value: platform === 'win32' ? 'S-1-5-21-2001' : 'uid:2001' } };
        code = 'SERVICE_SCOPE_MISMATCH';
      }
      if (variant === 'resource-roles') {
        session.readResourceProof = () => ({ present: true, value: { ...resource, rolesFingerprint: '0'.repeat(64) } });
        code = 'SERVICE_SCOPE_MISMATCH';
      }
      if (variant === 'configuration') {
        session.readManifest = () => ({ present: true, value: { ...current, configurationFingerprint: '0'.repeat(64) } });
        code = 'SERVICE_SCOPE_MISMATCH';
      }
      if (variant === 'pending-journal') {
        session.readJournal = () => ({ entries, head: { present: true, value: entries.at(-1) }, pending: {} });
        code = 'SERVICE_PENDING';
      }
      await assert.rejects(fixture.lifecycle.uninstall(request), { code });
      assert.equal(session.writes, 0);
      assert.equal(fixture.driver.writes, 0);
      assert.equal(entries.length, 1);
      assert.deepEqual(fixture.calls, ['floor-cas', 'session-close']);
    });
  }
}

for (const operation of ['install', 'update', 'rollback']) test(`${operation} binds the stable final proof to the incremented service manifest (rc14 domain regression)`, async () => {
  // Regression pin for the rc14 defect where #mutate wrote the application
  // deployment-manifest fingerprint into final.manifestFingerprint while the
  // store guard (service-store.js accept_provisional_metadata) requires the
  // service manifest self-fingerprint — every genuine install/update/rollback
  // died with SERVICE_SCOPE_MISMATCH before driver.probe.  Store unit tests
  // construct `final` in the correct domain and cannot see this coupling
  // defect, so this session doubles the guard's seven comparisons exactly;
  // the fixture keeps both fingerprint domains distinct so the wrong domain
  // cannot pass vacuously.
  const platform = 'linux';
  const calls = [];
  const entries = [];
  const absent = () => ({ present: false, value: null });
  const floor = () => ({ floor: { committedSequence: 0 } });
  const configuration = {
    runtimePath: '/runtime', workingDirectory: '/work',
    homeDirectory: '/home', logDirectory: '/log',
    channelsConfig: '/channels',
    expectedHostSetFingerprint: '0'.repeat(64), expectedHostCount: 0,
  };
  const applicationManifestFingerprint = 'a'.repeat(64);
  const owned = ownedMutationFixture(platform);
  if (operation !== 'install') entries.push(owned.entries[0]);
  let provisional;
  const session = {
    platform, architecture: 'x64', component: 'bot', serviceKey: 'bot', writes: 0,
    readManifest: operation === 'install' ? absent : owned.session.readManifest,
    readResourceProof: operation === 'install' ? absent : owned.session.readResourceProof,
    readReferences: operation === 'rollback'
      ? () => ({ present: true, value: { previous: { serviceGeneration: 3 } } })
      : absent,
    readManualCleanup: absent, readStartupProof: absent,
    readSiblingReferences: () => [],
    readJournal: () => ({
      entries,
      head: entries.length ? { present: true, value: entries.at(-1) } : absent(),
      pending: null,
    }),
    assertFloorCas: () => ({ application: floor() }),
    readRetainedDeploymentEnvelope: () => ({ manifest: acquisition.readManifests().application }),
    readPublicationReceipt: () => ({ artifactKind: 'application', manifestFingerprint: applicationManifestFingerprint }),
    assertApplicationRollback: ({ manifest, publication }) => {
      assert.equal(manifest.manifestFingerprint, applicationManifestFingerprint);
      assert.equal(publication.manifestFingerprint, applicationManifestFingerprint);
      calls.push('rollback-verified');
    },
    appendJournal(value) { entries.push(value); this.writes += 1; return value; },
    acceptProvisionalMetadata({ transaction, manifest, resource }) {
      // Mirror of the store guard comparisons (service-store.js
      // accept_provisional_metadata); drift here must fail exactly like the
      // production guard.
      if (manifest.resourceProof !== resource.resourceProof ||
          manifest.serviceGeneration !== transaction.serviceGeneration ||
          resource.serviceGeneration !== transaction.serviceGeneration ||
          manifest.manifestFingerprint !== transaction.final.manifestFingerprint ||
          resource.resourceProof !== transaction.final.resourceProof ||
          manifest.applicationManifestFingerprint !== transaction.final.applicationManifestFingerprint ||
          resource.applicationManifestFingerprint !== transaction.final.applicationManifestFingerprint) {
        throw lifecycleStoreError('SERVICE_SCOPE_MISMATCH', 'accept_provisional_metadata', this.writes);
      }
      provisional = { transaction, manifest, resource };
      return Object.freeze({ transactionFingerprint: transaction.transactionFingerprint });
    },
    publishCurrentMetadata: () => assert.fail('probe stop precedes current metadata publication'),
    publishManualCleanup(value) { this.writes += 1; return { present: true, value }; },
    close: () => calls.push('session-close'),
  };
  const acquisition = {
    readManifests: () => ({
      application: {
        manifestFingerprint: applicationManifestFingerprint, releaseSequence: 1,
        releaseTreeFingerprint: 'b'.repeat(64), compatibilityFingerprint: 'c'.repeat(64),
        archive: { sha256: 'd'.repeat(64) },
        inventory: { treeFingerprint: 'b'.repeat(64) },
        entrypoints: { bot: 'bot/src/bot.js' },
        entrypointPath: '/release/bot.js',
      },
    }),
    reserve: () => assert.fail('probe stop precedes sequence reservation'),
    publish: () => assert.fail('probe stop precedes release publication'),
    close: () => calls.push('acquisition-close'),
  };
  const probeStop = Object.assign(new Error('fixture stops after provisional metadata'), { code: 'SERVICE_PROBE_STOP_FIXTURE' });
  const lifecycle = createServiceLifecycle({
    platform, architecture: 'x64', native: {}, store: { openMutation: () => session },
    acquisition, compatibility: () => {},
    observeApplication: () => assert.fail('probe stop precedes application observation'),
    driver: { probe: () => { throw probeStop; } },
    planResource: () => ({
      trial: { resourceFingerprint: 'e'.repeat(64), resourceDescriptor: { name: 'gjc-remote-bot' } },
      final: { resourceFingerprint: 'f'.repeat(64), resourceDescriptor: { name: 'gjc-remote-bot' } },
    }),
  });
  const source = {
    kind: 'offline', applicationManifestPath: '/m',
    applicationSignaturePath: '/s', applicationArchivePath: '/a',
  };
  const expected = operation === 'install'
    ? { serviceGeneration: 0, resourceProof: null, applicationSequenceFloor: 0 }
    : {
      serviceGeneration: owned.current.serviceGeneration, resourceProof: owned.current.resourceProof,
      currentManifestFingerprint: owned.current.manifestFingerprint,
      ...(operation === 'rollback' ? { predecessorManifestFingerprint: applicationManifestFingerprint } : { applicationSequenceFloor: 0 }),
    };
  await assert.rejects(lifecycle[operation]({
    schemaVersion: 1, target: { component: 'bot' },
    roles,
    ...(operation === 'install' ? { configuration } : {}),
    ...(operation === 'rollback' ? {} : { source }),
    ...(operation === 'install' ? {} : { acceptServiceDisruption: true }),
    expected,
  }), (error) => error.code === 'SERVICE_PROBE_STOP_FIXTURE');
  assert.ok(provisional, 'provisional metadata admission must run before the probe stop');
  assert.equal(provisional.transaction.final.manifestFingerprint, provisional.manifest.manifestFingerprint);
  assert.notEqual(provisional.manifest.manifestFingerprint, applicationManifestFingerprint);
  assert.equal(provisional.transaction.final.applicationManifestFingerprint, applicationManifestFingerprint);
  assert.equal(provisional.manifest.applicationManifestFingerprint, applicationManifestFingerprint);
  const generation = expected.serviceGeneration + 1;
  assert.equal(provisional.transaction.old.serviceGeneration, expected.serviceGeneration);
  assert.equal(provisional.transaction.serviceGeneration, generation);
  assert.equal(provisional.transaction.final.disposition, 'stable');
  assert.equal(provisional.transaction.final.activation, 'enabled');
  assert.equal(provisional.transaction.final.serviceGeneration, generation);
  assert.equal(provisional.manifest.serviceGeneration, generation);
  assert.equal(provisional.resource.serviceGeneration, generation);
  assert.equal(entries.length, operation === 'install' ? 1 : 2);
  assert.equal(entries.at(-1).phase, 'prepared');
  assert.equal(session.writes, 1);
  assert.deepEqual(calls, operation === 'rollback' ? ['rollback-verified', 'session-close'] : ['acquisition-close', 'session-close']);
});

for (const variant of ['durable-phase', 'missing-phase', 'mismatched-phase', 'pending']) {
  test(`windows recovery consumer requires durable phase and actionable classification (${variant})`, async () => {
    const prepared = recoveryTransaction('prepared', 'install', 'win32');
    const head = recoveryTransaction('trial-start-intent', 'install', 'win32');
    assert.equal(head.previousJournalFingerprint, prepared.transactionFingerprint);
    const configuration = {
      runtimePath: 'C:/runtime', workingDirectory: 'C:/work', homeDirectory: 'C:/home',
      logDirectory: 'C:/log', channelsConfig: 'C:/channels',
      expectedHostSetFingerprint: '7'.repeat(64), expectedHostCount: 0,
    };
    const application = { ...windowsApplicationManifest({ manifestFingerprint: head.candidate.applicationManifestFingerprint }), configuration };
    const shawl = windowsShawlManifest({ manifestFingerprint: head.candidate.shawlManifestFingerprint });
    const publications = { application: windowsApplicationPublication(application), shawl: windowsShawlPublication(shawl) };
    const absent = () => ({ present: false, value: null });
    const calls = [];
    const markers = [];
    const session = {
      platform: 'win32', architecture: 'x64', component: 'bot', serviceKey: 'bot', writes: 0,
      readJournal: () => ({ entries: [prepared, head], head: { present: true, value: head }, pending: null }),
      readManifest: absent, readManualCleanup: absent,
      readRetainedDeploymentEnvelope: ({ purpose }) => ({ manifest: purpose === 'application' ? application : shawl }),
      readPublicationReceipt: ({ slot, artifactKind }) => {
        assert.equal(slot, 'provisional');
        return publications[artifactKind];
      },
      appendJournal: () => assert.fail('classifier admission must not replay the journal'),
      publishManualCleanup(value) {
        markers.push(value);
        this.writes += 1;
        return { present: true, value };
      },
      close: () => calls.push('close'),
    };
    const classification = {
      classification: variant === 'pending' ? 'pending' : 'manual-cleanup',
      platformPhase: 'trial', reason: 'platform-evidence-gap',
      ...(variant === 'missing-phase' ? {} : { phase: variant === 'mismatched-phase' ? 'trial-running' : head.phase }),
    };
    const lifecycle = createServiceLifecycle({
      platform: 'win32', architecture: 'x64', native: {}, store: { openRecovery: () => session },
      driver: {
        recoverTrialState: () => { calls.push('classify'); return classification; },
        probe: () => { calls.push('probe'); return { platformPhase: 'trial', resourceFingerprint: head.transition.platformResourceFingerprint }; },
        startTrial: () => assert.fail('manual or pending classifiers cannot start a trial'),
      },
    });
    await assert.rejects(lifecycle.recover({
      schemaVersion: 1, target: { component: 'bot' }, roles: windowsRoles,
      expected: { transactionId: head.transactionId, journalFingerprint: head.transactionFingerprint },
      acceptServiceDisruption: false,
    }), { code: variant === 'durable-phase' ? 'SERVICE_MANUAL_CLEANUP' : 'SERVICE_PENDING' });
    assert.deepEqual(calls, variant === 'durable-phase' ? ['classify', 'probe', 'close'] : ['classify', 'close']);
    assert.equal(session.writes, variant === 'durable-phase' ? 1 : 0);
    assert.equal(markers.length, variant === 'durable-phase' ? 1 : 0);
    if (markers.length) {
      assert.equal(markers[0].phase, head.phase);
      assert.equal(markers[0].journalFingerprint, head.transactionFingerprint);
      assert.equal(markers[0].transactionId, head.transactionId);
      assert.equal(markers[0].blockedUntilOperatorAction, true);
    }
  });
}

// In-memory Linux contract fixtures only: the real lifecycle performs recovery,
// while explicit session/driver doubles model durable writes and phase receipts.
// They do not qualify native locks, filesystem CAS, startup epochs, or systemd.
function recoverySuccessFixture(classifier, recoveryClassification = classifier === 'uninstall' ? 'continue' : classifier) {
  const { session, driver, current, resource, entries, calls } = ownedMutationFixture('linux');
  const seed = recoveryTransaction('prepared');
  const uninstall = classifier === 'uninstall';
  const operation = uninstall ? 'uninstall' : 'update';
  const generation = current.serviceGeneration + 1;
  const old = buildServiceOldProof({
    disposition: 'stable', manifestFingerprint: current.manifestFingerprint,
    resourceProof: current.resourceProof, applicationManifestFingerprint: current.applicationManifestFingerprint,
    shawlManifestFingerprint: null, serviceGeneration: current.serviceGeneration, activation: 'enabled',
  }, 'linux');
  const candidate = uninstall ? buildServiceCandidateProof({
    disposition: 'none', applicationManifestFingerprint: null, shawlManifestFingerprint: null,
    releaseSequence: 0, releaseTreeFingerprint: null, compatibilityFingerprint: null,
  }, 'linux') : seed.candidate;
  const finalResource = uninstall ? null : buildServiceResourceProof({
    ...resource, operation, serviceGeneration: generation,
    applicationManifestFingerprint: candidate.applicationManifestFingerprint,
    transactionId: seed.transactionId, transactionNonce: seed.transactionNonce,
    predecessorResourceProof: resource.resourceProof, platformResourceFingerprint: '6'.repeat(64),
  });
  const finalManifest = uninstall ? null : buildServiceManifest({
    ...current, serviceGeneration: generation,
    applicationManifestFingerprint: candidate.applicationManifestFingerprint,
    predecessorManifestFingerprint: current.manifestFingerprint, resourceProof: finalResource.resourceProof,
  });
  const final = buildServiceFinalProof(uninstall ? {
    disposition: 'absent', manifestFingerprint: null, resourceProof: null,
    applicationManifestFingerprint: null, shawlManifestFingerprint: null,
    serviceGeneration: 0, activation: 'disabled-not-startable',
  } : {
    disposition: 'stable', manifestFingerprint: finalManifest.manifestFingerprint,
    resourceProof: finalResource.resourceProof, applicationManifestFingerprint: candidate.applicationManifestFingerprint,
    shawlManifestFingerprint: null, serviceGeneration: generation, activation: 'enabled',
  }, 'linux');
  const transition = buildServiceTransitionProof({
    oldFingerprint: old.oldFingerprint, candidateFingerprint: candidate.candidateFingerprint,
    expectedBeforeResourceFingerprint: resource.platformResourceFingerprint,
    expectedAfterResourceFingerprint: finalResource?.platformResourceFingerprint ?? null,
    platformResourceFingerprint: seed.transition.platformResourceFingerprint,
    platformState: buildServicePlatformState('linux', 'trial'),
  }, 'linux');
  const prepared = buildServiceTransaction({
    ...seed, operation, serviceGeneration: generation, old, candidate, transition, final,
    previousJournalFingerprint: entries.at(-1).transactionFingerprint,
  });
  const head = buildServiceTransaction({
    ...prepared,
    phase: uninstall ? 'quiescent' : classifier === 'resume' ? 'trial-start-intent' : 'startup-observed',
    substep: classifier === 'resume' ? 'intent' : 'observed',
    previousJournalFingerprint: prepared.transactionFingerprint,
  });
  entries.push(prepared, head);
  const initialEntries = entries.slice();
  const absent = () => ({ present: false, value: null });
  const present = (value) => ({ present: true, value });
  const publication = (manifestFingerprint, inode) => {
    const directoryIdentity = {
      profile: 'service-release-directory', kind: 'linux-service-object-v1',
      device: '1', inode, mode: 0o40555, owner: 'uid:0', securitySha256: '7'.repeat(64),
    };
    return { binding: buildServiceArtifactBinding({
      artifactKind: 'application', rootKind: 'releases', artifactFingerprint: manifestFingerprint,
      manifestFingerprint, treeFingerprint: 'b'.repeat(64), directoryIdentity,
      directoryIdentityFingerprint: canonicalJsonHash(directoryIdentity),
    }, 'linux') };
  };
  const oldPublication = publication(current.applicationManifestFingerprint, '1');
  const candidatePublication = uninstall ? null : publication(candidate.applicationManifestFingerprint, '2');
  let references = present(buildServiceReferenceRecord({
    component: 'bot', serviceKey: 'bot', platform: 'linux', architecture: 'x64',
    serviceGeneration: current.serviceGeneration,
    current: buildServiceReferenceSlot({
      serviceGeneration: current.serviceGeneration, transactionId: resource.transactionId,
      transactionNonce: resource.transactionNonce, artifacts: [oldPublication.binding],
    }, { platform: 'linux', component: 'bot' }),
    previous: null, provisional: null,
  }));
  let manifestReceipt = present(current);
  let resourceReceipt = present(resource);
  session.readReferences = () => references;
  session.publishReferences = function (value, expected) {
    assert.equal(expected, references);
    references = present(value);
    this.writes += 1;
    calls.push('publish-references');
    return references;
  };
  session.readApplicationFloor = () => ({ floor: { committedSequence: 1 } });
  session.readPublicationReceipt = ({ slot, artifactKind }) => {
    assert.equal(slot, 'provisional');
    assert.equal(artifactKind, 'application');
    return candidatePublication;
  };
  session.readRetainedDeploymentEnvelope = ({ purpose, manifestFingerprint }) => {
    assert.equal(purpose, 'application');
    assert.equal(manifestFingerprint, candidate.applicationManifestFingerprint);
    return { manifest: {
      manifestFingerprint, releaseSequence: candidate.releaseSequence,
      inventory: { treeFingerprint: candidate.releaseTreeFingerprint },
      compatibilityFingerprint: candidate.compatibilityFingerprint,
      entrypointPath: '/releases/candidate/bot.js', configuration: current.configuration,
    } };
  };
  if (!uninstall) {
    session.readManifest = (slot) => slot === 'current' ? manifestReceipt : absent();
    session.readResourceProof = (slot) => slot === 'current' ? resourceReceipt : absent();
    session.publishCurrentMetadata = function (input) {
      assert.equal(entries.at(-1).phase, 'activation-observed');
      assert.equal(input.transaction, entries.at(-1));
      assert.equal(input.expectedManifest, manifestReceipt);
      assert.equal(input.expectedResource, resourceReceipt);
      assert.deepEqual(input.manifest, finalManifest);
      assert.deepEqual(input.resource, finalResource);
      manifestReceipt = present(input.manifest);
      resourceReceipt = present(input.resource);
      this.writes += 1;
      calls.push('publish-current');
    };
  }
  const appendDriverPhase = (phase, substep = 'observed') => {
    const previous = entries.at(-1);
    session.appendJournal(buildServiceTransaction({
      ...previous, phase, substep, previousJournalFingerprint: previous.transactionFingerprint,
    }));
  };
  const trial = { resourceFingerprint: transition.platformResourceFingerprint };
  const observeApplication = () => { calls.push('observe-application'); return { ready: true }; };
  driver.recoverTrialState = () => {
    calls.push('classify');
    return { classification: recoveryClassification, phase: head.phase, trial };
  };
  driver.probe = () => {
    calls.push('probe');
    return { platformPhase: 'trial', resourceFingerprint: transition.platformResourceFingerprint, resourceDescriptor: { botUnitSha256: 'f'.repeat(64) } };
  };
  if (uninstall) {
    driver.publishSuppressedResource = () => assert.fail('uninstall recovery must not publish a candidate resource');
    driver.stopAndQuiesce = function (input) {
      assert.equal(recoveryClassification, 'stop-and-continue');
      assert.equal(entries.at(-1).phase, 'quiescent');
      assert.deepEqual(input, { expectedResourceFingerprint: transition.platformResourceFingerprint });
      appendDriverPhase('stopping', 'intent');
      this.writes += 1;
      calls.push('stop');
      appendDriverPhase('quiescent');
    };
  }
  driver.startTrial = function (input) {
    assert.equal(uninstall || classifier === 'resume-activation', false);
    assert.deepEqual(input, { expectedResourceFingerprint: transition.platformResourceFingerprint });
    if (classifier === 'retrial') appendDriverPhase('trial-start-intent', 'intent');
    appendDriverPhase('trial-start-observed');
    this.writes += 1;
    calls.push('start-trial');
    return trial;
  };
  driver.runStartupGate = async ({ trial: suppliedTrial, observeApplication: observe }) => {
    assert.equal(uninstall, false);
    assert.equal(suppliedTrial, trial);
    assert.equal(observe, observeApplication);
    assert.deepEqual(await observe(), { ready: true });
    if (classifier !== 'resume-activation') appendDriverPhase('startup-observed');
    calls.push('startup-gate');
  };
  driver.armFinalRestart = function (input) {
    assert.equal(uninstall, false);
    assert.equal(entries.at(-1).phase, 'startup-observed');
    assert.deepEqual(input, {
      release: { entrypointPath: '/releases/candidate/bot.js', applicationManifestFingerprint: candidate.applicationManifestFingerprint },
      siblings: [],
    });
    this.writes += 1;
    calls.push('arm-final');
  };
  driver.enableFinal = function (input) {
    assert.equal(uninstall, false);
    assert.deepEqual(input, { siblings: [] });
    appendDriverPhase('activation-observed');
    this.writes += 1;
    calls.push('enable-final');
    return { resourceFingerprint: finalResource.platformResourceFingerprint };
  };
  const lifecycle = createServiceLifecycle({
    platform: 'linux', architecture: 'x64', native: {},
    store: { openRecovery: () => { calls.push('open-recovery'); return session; } },
    driver, observeApplication,
  });
  const request = {
    schemaVersion: 1, target: { component: 'bot' }, roles,
    expected: { transactionId: head.transactionId, journalFingerprint: head.transactionFingerprint },
    acceptServiceDisruption: true,
  };
  return { lifecycle, request, session, driver, entries, initialEntries, head, current, finalManifest, finalResource, calls };
}

async function publicRecovery(fixture, boundary) {
  const options = {
    argv: ['recover'], input: canonicalJsonBytes(fixture.request), lifecycle: fixture.lifecycle,
    platform: 'linux', architecture: 'x64',
  };
  if (boundary === 'cli') {
    const receipt = await runServiceCli(options);
    return { receipt, serialized: serviceReceiptBytes(receipt).toString('utf8') };
  }
  const chunks = [];
  const result = await runServiceEntrypoint({
    ...options, stdout: { write: (chunk) => { chunks.push(Buffer.from(chunk)); } },
  });
  return { ...result, serialized: Buffer.concat(chunks).toString('utf8') };
}

for (const classifier of ['resume', 'retrial', 'resume-activation', 'uninstall']) {
  for (const boundary of ['cli', 'entrypoint']) {
    test(`real lifecycle ${classifier} recovery exposes exact public success through ${boundary}`, async () => {
      const fixture = recoverySuccessFixture(classifier);
      const { session, driver, entries, initialEntries, head, calls } = fixture;
      const result = await publicRecovery(fixture, boundary);
      assert.equal(result.receipt.status, 'ok', canonicalJson(result.receipt));
      if (boundary === 'entrypoint') assert.equal(result.exitCode, EXIT_CODES.ok);
      assert.ok(session.writes > 0);
      assert.equal(driver.writes, classifier === 'uninstall' ? 1 : classifier === 'resume-activation' ? 2 : 3);
      const writes = session.writes + driver.writes;
      const expected = {
        status: 'ok', operation: 'recover', writes,
        receipt: { operation: 'recover', transactionId: head.transactionId, transactionFingerprint: entries.at(-1).transactionFingerprint, writes },
      };
      assert.deepEqual(result.receipt, expected);
      assert.equal(result.serialized, `${canonicalJson(expected)}\n`);
      assert.deepEqual(JSON.parse(result.serialized), expected);
      assert.deepEqual(entries.slice(0, initialEntries.length), initialEntries);
      assert.equal(entries.at(-1).phase, 'committed');
      assert.equal(entries.at(-1).substep, 'observed');
      assert.notEqual(entries.at(-1).transactionFingerprint, head.transactionFingerprint);
      for (const entry of entries.slice(initialEntries.length)) {
        assert.equal(entry.operation, head.operation);
        assert.equal(entry.serviceGeneration, head.serviceGeneration);
        assert.equal(entry.transactionId, head.transactionId);
        assert.equal(entry.transactionNonce, head.transactionNonce);
        for (const proof of ['old', 'candidate', 'transition', 'final']) assert.deepEqual(entry[proof], head[proof]);
      }
      const phases = entries.slice(initialEntries.length).map((entry) => entry.phase);
      if (classifier === 'uninstall') {
        assert.deepEqual(phases, ['tombstoned', 'resource-removed', 'references-released', 'committed']);
        assert.equal(head.final.serviceGeneration, 0);
        assert.equal(session.readTombstone().value.serviceGeneration, head.serviceGeneration);
        assert.equal(session.readTombstone().value.currentManifestFingerprint, fixture.current.manifestFingerprint);
        assert.equal(session.readTombstone().value.resourceProof, fixture.current.resourceProof);
        assert.equal(session.readManifest('current').present, false);
        assert.equal(session.readResourceProof('current').present, false);
        for (const slot of ['current', 'previous', 'provisional']) assert.equal(session.readReferences().value[slot], null);
        assert.equal(calls.includes('start-trial'), false);
        assert.equal(calls.includes('enable-final'), false);
        assert.ok(calls.indexOf('publish-tombstone') < calls.indexOf('remove-resource'));
      } else {
        assert.deepEqual(phases, [
          ...(classifier === 'retrial' ? ['trial-start-intent'] : []),
          ...(classifier === 'resume-activation' ? [] : ['trial-start-observed', 'startup-observed']),
          'activation-observed', 'committed',
        ]);
        assert.deepEqual(session.readManifest('current').value, fixture.finalManifest);
        assert.deepEqual(session.readResourceProof('current').value, fixture.finalResource);
        assert.equal(session.readReferences().value.current.serviceGeneration, head.serviceGeneration);
        assert.equal(session.readReferences().value.previous.serviceGeneration, fixture.current.serviceGeneration);
        assert.equal(calls.includes('start-trial'), classifier !== 'resume-activation');
        assert.ok(calls.indexOf('startup-gate') < calls.indexOf('arm-final'));
        assert.ok(calls.indexOf('enable-final') < calls.indexOf('publish-current'));
        assert.ok(calls.indexOf('publish-current') < calls.indexOf('committed'));
      }
      assert.equal(session.readReferences().value.serviceGeneration, head.serviceGeneration);
      assert.equal(calls.at(-1), 'session-close');
    });
  }

  for (const refusal of ['stale-transaction', 'stale-journal', 'missing-disruption']) {
    test(`real lifecycle ${classifier} recovery refuses ${refusal} before writes`, async () => {
      const fixture = recoverySuccessFixture(classifier);
      if (refusal === 'stale-transaction') fixture.request.expected.transactionId = 'tx-other';
      if (refusal === 'stale-journal') fixture.request.expected.journalFingerprint = '0'.repeat(64);
      if (refusal === 'missing-disruption') delete fixture.request.acceptServiceDisruption;
      await assert.rejects(fixture.lifecycle.recover(fixture.request), {
        code: refusal === 'missing-disruption' ? 'SERVICE_INVALID' : 'SERVICE_STALE', writes: 0,
      });
      assert.equal(fixture.session.writes, 0);
      assert.equal(fixture.driver.writes, 0);
      assert.deepEqual(fixture.entries, fixture.initialEntries);
      assert.deepEqual(fixture.calls, refusal === 'missing-disruption' ? [] : ['open-recovery', 'session-close']);
    });
  }
}

for (const boundary of ['cli', 'entrypoint']) {
  test(`real lifecycle uninstall stop-and-continue preserves stop without candidate replay through ${boundary}`, async () => {
    const fixture = recoverySuccessFixture('uninstall', 'stop-and-continue');
    const { session, driver, entries, head, calls, initialEntries } = fixture;
    const result = await publicRecovery(fixture, boundary);
    assert.equal(result.receipt.status, 'ok', canonicalJson(result.receipt));
    if (boundary === 'entrypoint') assert.equal(result.exitCode, EXIT_CODES.ok);
    assert.equal(driver.writes, 2);
    assert.ok(session.writes > 0);
    const writes = session.writes + driver.writes;
    const expected = {
      status: 'ok', operation: 'recover', writes,
      receipt: { operation: 'recover', transactionId: head.transactionId, transactionFingerprint: entries.at(-1).transactionFingerprint, writes },
    };
    assert.deepEqual(result.receipt, expected);
    assert.equal(result.serialized, `${canonicalJson(expected)}\n`);
    assert.deepEqual(entries.slice(initialEntries.length).map((entry) => entry.phase), [
      'stopping', 'quiescent', 'tombstoned', 'resource-removed', 'references-released', 'committed',
    ]);
    for (const entry of entries.slice(initialEntries.length)) {
      assert.equal(entry.operation, 'uninstall');
      assert.equal(entry.serviceGeneration, head.serviceGeneration);
      assert.equal(entry.final.serviceGeneration, 0);
    }
    assert.equal(calls.filter((call) => call === 'stop').length, 1);
    assert.ok(calls.indexOf('stop') < calls.indexOf('publish-tombstone'));
    assert.ok(calls.indexOf('publish-tombstone') < calls.indexOf('remove-resource'));
    assert.equal(calls.includes('start-trial'), false);
    assert.equal(calls.includes('arm-final'), false);
    assert.equal(calls.includes('enable-final'), false);
    assert.equal(session.readManifest('current').present, false);
    assert.equal(session.readResourceProof('current').present, false);
    for (const slot of ['current', 'previous', 'provisional']) assert.equal(session.readReferences().value[slot], null);
    assert.equal(calls.at(-1), 'session-close');
  });
}

for (const classifier of ['resume', 'uninstall']) {
  test(`real lifecycle ${classifier} recovery refuses a malformed final generation before writes`, async () => {
    const fixture = recoverySuccessFixture(classifier);
    const malformedFinalFields = {
      ...fixture.head.final,
      serviceGeneration: classifier === 'uninstall' ? fixture.head.serviceGeneration : fixture.head.serviceGeneration + 1,
    };
    delete malformedFinalFields.finalFingerprint;
    const malformedFinal = classifier === 'uninstall'
      ? { ...malformedFinalFields, finalFingerprint: canonicalJsonHash(malformedFinalFields) }
      : buildServiceFinalProof(malformedFinalFields, 'linux');
    if (classifier === 'uninstall') assert.throws(() => buildServiceFinalProof(malformedFinalFields, 'linux'));
    const malformedHeadFields = { ...fixture.head, final: malformedFinal };
    delete malformedHeadFields.transactionFingerprint;
    const malformedHead = { ...malformedHeadFields, transactionFingerprint: canonicalJsonHash(malformedHeadFields) };
    assert.throws(() => buildServiceTransaction(malformedHead));
    // Only this fault-injection case bypasses the production builder. Matching
    // fingerprints must not turn a semantically invalid journal into authority.
    fixture.entries[fixture.entries.length - 1] = malformedHead;
    fixture.request.expected.journalFingerprint = malformedHead.transactionFingerprint;
    const before = fixture.entries.slice();
    await assert.rejects(fixture.lifecycle.recover(fixture.request), { code: 'SERVICE_PENDING', writes: 0 });
    assert.equal(fixture.session.writes, 0);
    assert.equal(fixture.driver.writes, 0);
    assert.deepEqual(fixture.entries, before);
    assert.deepEqual(fixture.calls, ['open-recovery', 'classify', 'session-close']);
  });
}

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

for (const primaryFails of [false, true]) {
  test(`status preserves primary failure when close fails: ${primaryFails}`, async () => {
    const fixture = readOnlyFixture();
    const primary = new Error('primary read failure');
    const cleanup = new Error('close failure');
    let closes = 0;
    if (primaryFails) fixture.session.readManifest = () => { throw primary; };
    fixture.session.close = () => { closes += 1; throw cleanup; };
    const lifecycle = createServiceLifecycle({ platform: 'linux', architecture: 'x64', store: fixture.store });
    await assert.rejects(lifecycle.status({ schemaVersion: 1, target: { component: 'bot' }, roles }), error => primaryFails
      ? error === primary
      : error.name === 'ServiceLifecycleError' && error.code === 'SERVICE_MANUAL_CLEANUP' && error.writes === 0);
    assert.equal(closes, 1);
    assert.equal(fixture.session.writes, 0);
  });
}

for (const value of [undefined, null, false, 0, '']) {
  for (const primaryFails of [false, true]) {
    test(`status preserves exact falsy rejection ${String(value)}, primary=${primaryFails}`, async () => {
      const fixture = readOnlyFixture();
      let closes = 0;
      if (primaryFails) fixture.session.readManifest = () => { throw value; };
      fixture.session.close = () => {
        closes += 1;
        throw primaryFails ? new Error('secondary close failure') : value;
      };
      const lifecycle = createServiceLifecycle({ platform: 'linux', architecture: 'x64', store: fixture.store });
      let rejected = false;
      await lifecycle.status({ schemaVersion: 1, target: { component: 'bot' }, roles }).then(
        () => assert.fail('status must reject'),
        error => {
          rejected = true;
          if (primaryFails) assert.strictEqual(error, value);
          else assert.equal(error.code, 'SERVICE_MANUAL_CLEANUP');
        },
      );
      assert.equal(rejected, true);
      assert.equal(closes, 1);
      assert.equal(fixture.session.writes, 0);
    });
  }
}

for (const failProbe of [0, 1, 2]) {
  test(`status cleanup preserves awaited probe outcome, failing probe=${failProbe}`, async () => {
    const fixture = readOnlyFixture();
    fixture.session.readJournal = () => ({ entries: [{ phase: 'committed' }], pending: null });
    const primary = new Error('asynchronous probe failure');
    const cleanup = new Error('close failure');
    let probes = 0;
    let closes = 0;
    fixture.session.close = () => { closes += 1; throw cleanup; };
    const lifecycle = createServiceLifecycle({
      platform: 'linux', architecture: 'x64', store: fixture.store,
      driver: { probe: async () => {
        probes += 1;
        await Promise.resolve();
        if (probes === failProbe) throw primary;
        return { platformPhase: 'absent' };
      } },
    });
    await assert.rejects(
      lifecycle.status({ schemaVersion: 1, target: { component: 'bot' }, roles }),
      error => failProbe ? error === primary
        : error.name === 'ServiceLifecycleError' && error.code === 'SERVICE_MANUAL_CLEANUP' && error.writes === 0,
    );
    assert.equal(probes, failProbe || 2);
    assert.equal(closes, 1);
    assert.equal(fixture.session.writes, 0);
  });
}

for (const primary of [Object.freeze(new Error('frozen /private primary')), Object.preventExtensions(new Error('nonextensible primary'))]) {
  test(`status preserves ${Object.isFrozen(primary) ? 'frozen' : 'nonextensible'} primary and retains separate bounded cleanup evidence`, async () => {
    const fixture = readOnlyFixture();
    const descriptors = Object.getOwnPropertyDescriptors(primary);
    fixture.session.readManifest = () => { throw primary; };
    fixture.session.close = () => { throw Object.freeze(new Error('secret close path')); };
    const lifecycle = createServiceLifecycle({ platform: 'linux', architecture: 'x64', store: fixture.store });
    await assert.rejects(lifecycle.status({ schemaVersion: 1, target: { component: 'bot' }, roles }), (error) => error === primary);
    assert.deepEqual(Object.getOwnPropertyDescriptors(primary), descriptors);
    const evidence = getServiceCleanupEvidenceInternal(lifecycle);
    assert.equal(evidence.hasPrimary, true);
    assert.equal(evidence.cleanup.attemptedUnconfirmed, 1);
    assert.deepEqual(getServiceCleanupEvidenceInternal(primary), evidence);
    assert.equal(JSON.stringify(evidence).includes('secret'), false);
    assert.equal(JSON.stringify(evidence).includes('private'), false);
  });
}

test('absent status closes once without constructing a driver; cleanup writes refuse prepared success', async () => {
  for (const cleanupWrites of [0, 3]) {
    const fixture = readOnlyFixture();
    let closes = 0;
    fixture.session.close = () => { closes += 1; fixture.session.writes += cleanupWrites; };
    const lifecycle = createServiceLifecycle({ platform: 'linux', architecture: 'x64', store: fixture.store,
      createDriver: () => assert.fail('absent status must not construct a driver') });
    const pending = lifecycle.status({ schemaVersion: 1, target: { component: 'bot' }, roles });
    if (cleanupWrites) await assert.rejects(pending, (error) => error.code === 'SERVICE_MANUAL_CLEANUP' && error.writes === cleanupWrites);
    else assert.equal((await pending).ownership, 'absent');
    assert.equal(closes, 1);
  }
});

for (const existingLifecycleError of [false, true]) {
  test(`mutation final cleanup preserves pre-cleanup wrapper/cause/writes (existing=${existingLifecycleError})`, async () => {
    const fixture = windowsCandidateFixture(Object.freeze({ path: 'bot/src/bot.js', sha256: '6'.repeat(64), size: 42 }));
    const original = fixture.stoppedAtPlanner;
    const cause = Object.freeze(new Error('original cause'));
    if (existingLifecycleError) {
      Object.assign(original, { name: 'ServiceLifecycleError', code: 'SERVICE_PENDING', writes: 7, cause });
      Object.freeze(original);
    }
    fixture.acquisition.close = () => { fixture.calls.push('acquisition-close'); throw new Error('acquisition close'); };
    fixture.session.close = () => { fixture.calls.push('session-close'); fixture.session.writes += 4; throw new Error('session close'); };
    await assert.rejects(fixture.lifecycle.install(fixture.request), (error) => {
      assert.equal(error.name, 'ServiceLifecycleError');
      assert.equal(error.writes, existingLifecycleError ? 7 : 0);
      assert.equal(error.cause, existingLifecycleError ? cause : original);
      if (existingLifecycleError) assert.equal(error, original);
      return true;
    });
    assert.deepEqual(fixture.calls.slice(-2), ['acquisition-close', 'session-close']);
    assert.equal(fixture.session.writes, 4);
    const evidence = getServiceCleanupEvidenceInternal(fixture.lifecycle);
    assert.equal(evidence.hasPrimary, true);
    assert.equal(evidence.writes, 4);
    assert.equal(evidence.cleanup.attemptedUnconfirmed, 2);
  });
}

for (const existingLifecycleError of [false, true]) {
  test(`recovery final cleanup preserves its existing wrapper decision (existing=${existingLifecycleError})`, async () => {
    const fixture = recoverySuccessFixture('resume');
    const cause = Object.freeze(new Error('original recovery cause'));
    const original = new Error('recovery primary');
    if (existingLifecycleError) {
      Object.assign(original, { name: 'ServiceLifecycleError', code: 'SERVICE_PENDING', writes: 7, cause });
      Object.freeze(original);
    }
    let beforeCleanup;
    fixture.driver.startTrial = () => { beforeCleanup = fixture.session.writes + fixture.driver.writes; throw original; };
    fixture.session.close = () => { fixture.calls.push('session-close'); fixture.session.writes += 4; throw new Error('secondary close'); };
    await assert.rejects(fixture.lifecycle.recover(fixture.request), (error) => {
      assert.notEqual(beforeCleanup, undefined, 'reach the classified recovery edge');
      assert.equal(error.name, 'ServiceLifecycleError');
      assert.equal(error.code, 'SERVICE_PENDING');
      assert.equal(error.writes, existingLifecycleError ? 7 : beforeCleanup);
      assert.equal(error.cause, existingLifecycleError ? cause : undefined);
      if (existingLifecycleError) assert.equal(error, original);
      return true;
    });
    assert.equal(fixture.calls.at(-1), 'session-close');
    assert.equal(getServiceCleanupEvidenceInternal(fixture.lifecycle).cleanup.attemptedUnconfirmed, 1);
  });
}
