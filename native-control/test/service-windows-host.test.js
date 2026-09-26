import assert from 'node:assert/strict';
import test from 'node:test';
import dotenv from 'dotenv';
import {
  WindowsHostRefusal,
  createWindowsHostOperationFactory,
  deriveWindowsServiceLaunch,
} from '../src/service-windows-host.js';
import {
  buildWindowsShawlArgv,
  windowsServiceRuntimePolicyFingerprint,
} from '../src/service-windows.js';
import { serviceEffectiveConfigFingerprint } from '../src/service-bootstrap-policy.js';
import { serviceDaemonTargetFingerprint } from '@gjc-remote/shared/service-startup-observation';
import { serviceKeyForTarget, win32PhysicalSecurityIdentityFingerprint } from '@gjc-remote/shared/service-lifecycle-envelope';

const hex = (c) => c.repeat(64);
const roles = Object.freeze({
  management: { kind: 'sid', value: 'S-1-5-21-111111111-222222222-333333333-1001' },
  bot: { kind: 'sid', value: 'S-1-5-21-111111111-222222222-333333333-1002' },
  recovery: { kind: 'sid', value: 'S-1-5-21-111111111-222222222-333333333-1003' },
  daemon: { kind: 'sid', value: 'S-1-5-21-111111111-222222222-333333333-1004' },
  system: { kind: 'sid', value: 'S-1-5-18' },
});
const daemonTarget = Object.freeze({ component: 'daemon', hostId: 'host-a' });
const daemonKey = serviceKeyForTarget(daemonTarget);
const botConfiguration = {
  runtimePath: 'C:\\Program Files\\nodejs\\node.exe', workingDirectory: 'C:\\GJC\\bot',
  homeDirectory: 'C:\\ProgramData\\GJC\\bot', logDirectory: 'C:\\ProgramData\\GJC\\log\\bot',
  channelsConfig: 'C:\\ProgramData\\GJC\\channels.json', expectedHostSetFingerprint: hex('8'), expectedHostCount: 2,
};
const daemonConfiguration = {
  runtimePath: 'C:\\Program Files\\Bun\\bun.exe', workingDirectory: 'C:\\GJC\\daemon',
  homeDirectory: 'C:\\ProgramData\\GJC\\daemon', logDirectory: 'C:\\ProgramData\\GJC\\log\\daemon',
};
const GUARD = 'node_modules/@gjc-remote/native-control/src/service-bootstrap.js';

function identity(fileId) {
  return {
    profile: 'config', kind: 'win32-service-object-v1', volumeSerial: '0123456789abcdef',
    fileId, attributes: 32, owner: 'S-1-5-18', securitySha256: hex('e'),
  };
}
function physical(fileId) {
  const { profile, kind, ...rest } = identity(fileId);
  void profile; void kind;
  return win32PhysicalSecurityIdentityFingerprint({ kind: 'gjc-remote/win32-physical-security-identity/v1', ...rest });
}

function fakeNative(files) {
  const calls = [];
  let handles = 0;
  const native = {
    open_service_external_root(absolutePath, profile) {
      calls.push(['open', absolutePath, profile]);
      handles += 1;
      const present = Object.keys(files).some((key) => key.startsWith(`${absolutePath}\\`));
      return {
        handle: { id: handles, absolutePath }, profile, absolutePath,
        rootIdentity: present ? identity(`${handles}`.padStart(32, 'a')) : null,
        absence: present ? null : { kind: 'absent' }, writes: 0,
      };
    },
    read_service_external_object(handle, relative, mode, maximum) {
      calls.push(['read', `${handle.absolutePath}\\${relative}`, mode, maximum]);
      // Mirror the native argument contract: bytes reads need 1..1 MiB.
      if (mode === 'bytes' && (!Number.isSafeInteger(maximum) || maximum < 1 || maximum > 1024 * 1024)) {
        throw Object.assign(new Error('read_service_external_object failed'), { code: 'SERVICE_INVALID', reason: 'invalid-input', writes: 0 });
      }
      const file = files[`${handle.absolutePath}\\${relative}`];
      if (file === undefined) return { kind: 'absent', identity: null, absence: { kind: 'absent' }, bytes: null, entries: null, writes: 0 };
      if (Buffer.byteLength(file.text) > maximum) {
        throw Object.assign(new Error('read_service_external_object failed'), { code: 'SERVICE_OUTPUT_LIMIT', reason: 'limit', writes: 0 });
      }
      return { kind: 'file', identity: identity(file.fileId), absence: null, bytes: Buffer.from(file.text), entries: null, writes: 0 };
    },
    close_service_handle(handle) { calls.push(['close', handle.id]); handles -= 1; },
    read_file_facts_no_follow(absolutePath) {
      calls.push(['facts', absolutePath]);
      return {
        kind: 'win32-file-v1', volumeSerial: '0123456789abcdef', fileId: 'f'.repeat(32), size: 10,
        sha256: hex('b'), attributes: 32, owner: 'S-1-5-18', securitySha256: hex('e'),
      };
    },
  };
  return { native, calls, openHandles: () => handles };
}

function harness({ component = 'bot', env = 'DISCORD_TOKEN=secret\n', bunfig = '', scope } = {}) {
  const configuration = component === 'bot' ? botConfiguration : daemonConfiguration;
  const files = { [`${configuration.workingDirectory}\\.env`]: { fileId: 'c'.repeat(32), text: env } };
  if (component === 'daemon') files[`${configuration.workingDirectory}\\runtime-config\\.bunfig.toml`] = { fileId: 'd'.repeat(32), text: bunfig };
  const fake = fakeNative(files);
  const drivers = [];
  const compatibility = [];
  const calls = [];
  const dependencies = {
    createNative: ({ roles: bound }) => { assert.equal(bound, request.roles); return fake.native; },
    createDriver: (options) => {
      drivers.push(options);
      return {
        planResource: ({ phase, applicationManifestFingerprint }) => Object.freeze({
          resourceFingerprint: hex(phase === 'trial' ? '1' : '2'),
          resourceDescriptor: Object.freeze({ phase, applicationManifestFingerprint }),
        }),
      };
    },
    createCompatibilityObserver: (input) => {
      compatibility.push(input);
      return {
        assertFirstInstall: async (expected) => { calls.push(['install', expected]); return { compatible: true }; },
        assertUpdate: async (input) => { calls.push(['update', input]); return { compatible: true }; },
      };
    },
    readAuthorityScope: (native, input) => {
      assert.equal(native, fake.native);
      assert.equal(input.workingDirectory, configuration.workingDirectory);
      return scope ?? { scopeFingerprint: hex('4'), sdkProfileRoot: component === 'daemon' ? 'C:\\ProgramData\\GJC\\daemon-profile' : null };
    },
    createStartupObserver: (options) => ({ observeApplication: Object.assign(() => null, { options }) }),
    parseDotenv: (bytes) => dotenv.parse(bytes),
    clock: () => 1,
    sleep: async () => {},
  };
  const serviceKey = component === 'bot' ? 'bot' : daemonKey;
  const target = component === 'bot' ? { component } : { ...daemonTarget };
  const request = {
    schemaVersion: 1, target, roles,
    source: { kind: 'github-release', tag: 'v1.0.0' }, configuration,
    expected: { serviceGeneration: 0, resourceProof: null, applicationSequenceFloor: 0, shawlSequenceFloor: 0 },
  };
  const create = createWindowsHostOperationFactory(dependencies);
  return { create, request, fake, drivers, compatibility, calls, configuration, serviceKey };
}

function releaseFor(component) {
  const entry = component === 'bot' ? 'bot/src/bot.js' : 'daemon/src/daemon.js';
  const root = 'C:\\ProgramData\\GJC\\app\\releases\\r1';
  return {
    manifest: {
      entrypoints: { [component]: entry },
      windowsServiceBootstrap: {
        schemaVersion: 1, guardPath: GUARD,
        staticClosure: [{ relativePath: GUARD, sha256: hex('9') }],
        staticClosureFingerprint: hex('7'),
        runtimePolicies: {
          bot: { runtime: 'node', version: '26.7.0', sourceRevision: 'b4f23d3619c98bed09af93a21192f6080197a8c6' },
          daemon: { runtime: 'bun', version: '1.4.2', sourceRevision: '744846f844374847c902b5e7fd59b4342a51ef99' },
        },
        externalBunConfig: { relativePath: 'runtime-config/.bunfig.toml', sha256: hex('0'), byteLength: 0 },
      },
    },
    applicationManifestFingerprint: hex('d'),
    entrypointPath: `${root}\\${entry.replaceAll('/', '\\')}`,
    entrypointSha256: hex('c'),
    supervisorPath: `C:\\ProgramData\\GJC\\shawl\\${hex('a')}\\shawl.exe`,
    supervisorSha256: hex('a'),
  };
}

function session(serviceKey, configuration = null) {
  return {
    serviceKey,
    handoffDriverLocks: () => ({ locks: true }),
    readManifest: () => configuration === null ? { present: false, value: null } : { present: true, value: { configuration } },
  };
}

const context = (h, operation = 'install') => ({ operation, request: h.request, platform: 'win32', architecture: 'x64' });

async function refusal(promise, code, reason) {
  await assert.rejects(promise, (error) => {
    assert.ok(error instanceof WindowsHostRefusal);
    assert.equal(error.code, code);
    if (reason !== undefined) assert.equal(error.reason, reason);
    assert.equal(error.writes, 0);
    return true;
  });
}

test('install preflight captures protected authority through native read-only roots', async () => {
  const h = harness();
  const operation = h.create();
  await operation.effectiveConfigPreflight(context(h));
  assert.deepEqual(h.fake.calls.filter(([kind]) => kind === 'read').map(([, path, mode]) => [path, mode]),
    [['C:\\GJC\\bot\\.env', 'bytes']]);
  assert.deepEqual(h.fake.calls.filter(([kind]) => kind === 'facts'), [['facts', botConfiguration.runtimePath]]);
  assert.equal(h.fake.openHandles(), 0);
});

test('bot install composes one Launch-bound driver and plans trial and final resources', async () => {
  const h = harness();
  const operation = h.create();
  await operation.effectiveConfigPreflight(context(h));
  const options = operation.lifecycleOptions(context(h));
  const s = session('bot');
  const release = releaseFor('bot');
  const planned = options.planResource({ session: s, request: h.request, release });
  assert.equal(planned.trial.resourceFingerprint, hex('1'));
  assert.equal(planned.final.resourceDescriptor.phase, 'final');
  const driver = options.createWindowsDriver({ session: s, request: h.request, release, locks: { locks: true } });
  assert.equal(h.drivers.length, 1, 'planning and execution share one driver');
  assert.ok(driver);
  const { launch, shawl } = h.drivers[0];
  assert.equal(launch.bootstrapPath, `C:\\ProgramData\\GJC\\app\\releases\\r1\\${GUARD.replaceAll('/', '\\')}`);
  assert.equal(launch.effectiveConfigFingerprint, serviceEffectiveConfigFingerprint({
    component: 'bot', serviceKey: 'bot', entries: [['DISCORD_TOKEN', 'secret']],
  }));
  assert.equal(launch.configSourceIdentityFingerprint, physical('c'.repeat(32)));
  assert.equal(launch.runtimeSha256, hex('b'));
  assert.equal(launch.runtimePolicyFingerprint, windowsServiceRuntimePolicyFingerprint(launch, 'bot', 'bot'));
  assert.deepEqual(shawl, { path: release.supervisorPath, sha256: hex('a'), runtimeSha256: hex('b'), entrypointSha256: hex('c') });
  assert.ok(buildWindowsShawlArgv({ component: 'bot', serviceKey: 'bot', launch: { ...launch } }).includes('--env'));
  const observer = options.observeApplication({ trial: true });
  assert.deepEqual(observer.options.expectedState, { expectedHostSetFingerprint: hex('8'), expectedHostCount: 2 });
  await options.compatibility({ operation: 'install', request: h.request, release, session: s });
  assert.equal(h.compatibility[0].candidate, release.manifest);
  assert.equal(h.compatibility[0].channelsConfig, botConfiguration.channelsConfig);
  assert.deepEqual(h.calls, [['install', { expectedScopeFingerprint: hex('4') }]]);
});

test('daemon Launch binds runtime config identities, SDK profile and exact target fingerprint', async () => {
  const h = harness({ component: 'daemon', env: 'HOST_ID=host-a\nBOT_WS_URL=wss://bot.example/ws\nHOST_TOKEN=t\n' });
  const operation = h.create();
  await operation.effectiveConfigPreflight(context(h));
  const options = operation.lifecycleOptions(context(h));
  options.createWindowsDriver({ session: session(daemonKey), request: h.request, release: releaseFor('daemon'), locks: {} });
  const { launch } = h.drivers[0];
  assert.equal(launch.runtimeConfigRoot, 'C:\\GJC\\daemon\\runtime-config');
  assert.equal(launch.runtimeConfigIdentityFingerprint, physical('d'.repeat(32)));
  assert.match(launch.runtimeConfigRootIdentityFingerprint, /^[0-9a-f]{64}$/);
  assert.equal(launch.sdkProfilePath, 'C:\\ProgramData\\GJC\\daemon-profile');
  assert.equal(launch.channelsConfig, null);
  const observer = options.observeApplication({});
  assert.equal(observer.options.expectedState.targetFingerprint,
    serviceDaemonTargetFingerprint({ botWsUrl: 'wss://bot.example/ws', hostId: 'host-a' }));
});

test('reserved, conflicting or invalid effective config refuses write-free at preflight', async () => {
  for (const [env, reason] of [
    ['NODE_OPTIONS=--inspect\n', 'config-reserved-key'],
    ['GJC_REMOTE_LAUNCH_FINGERPRINT=x\n', 'config-reserved-key'],
    ['CHANNELS_CONFIG=C:\\other.json\n', 'inherited-env-conflict'],
  ]) {
    const h = harness({ env });
    await refusal(h.create().effectiveConfigPreflight(context(h)), 'SERVICE_INVALID', reason);
    assert.equal(h.drivers.length, 0);
    assert.equal(h.fake.openHandles(), 0);
  }
  const daemon = harness({ component: 'daemon', env: 'HOST_ID=a\n' });
  await refusal(daemon.create().effectiveConfigPreflight(context(daemon)), 'SERVICE_INVALID', 'daemon-target-invalid');
  const bunfig = harness({ component: 'daemon', env: 'HOST_ID=a\nBOT_WS_URL=ws://b/\n', bunfig: 'x' });
  await refusal(bunfig.create().effectiveConfigPreflight(context(bunfig)), 'SERVICE_INVALID', 'runtime-config-policy');
  const largeBunfig = harness({ component: 'daemon', env: 'HOST_ID=a\nBOT_WS_URL=ws://b/\n', bunfig: 'xy' });
  await refusal(largeBunfig.create().effectiveConfigPreflight(context(largeBunfig)), 'SERVICE_INVALID', 'runtime-config-policy');
  const scope = harness({ component: 'daemon', env: 'HOST_ID=a\nBOT_WS_URL=ws://b/\n', scope: { scopeFingerprint: hex('4'), sdkProfileRoot: null } });
  await refusal(scope.create().effectiveConfigPreflight(context(scope)), 'SERVICE_PENDING', 'scope-catalog');
});

test('operation binding refuses drift, missing preflight and foreign platforms', async () => {
  const h = harness();
  await refusal((async () => h.create().lifecycleOptions(context(h)))(), 'SERVICE_INVALID', 'preflight-missing');
  const drift = harness();
  const operation = drift.create();
  await operation.effectiveConfigPreflight(context(drift));
  await refusal((async () => operation.lifecycleOptions({ ...context(drift), request: { ...drift.request } }))(), 'SERVICE_INVALID', 'context-drift');
  const foreign = harness();
  await refusal(foreign.create().effectiveConfigPreflight({ ...context(foreign), platform: 'linux' }), 'SERVICE_UNSUPPORTED');
  const closed = harness();
  const closedOperation = closed.create();
  closedOperation.close();
  await refusal(closedOperation.effectiveConfigPreflight(context(closed)), 'SERVICE_INVALID', 'operation-closed');
});

test('update checks the candidate against the authenticated current release and the bound scope', async () => {
  const h = harness();
  const operation = h.create();
  await operation.effectiveConfigPreflight(context(h, 'update'));
  const options = operation.lifecycleOptions(context(h, 'update'));
  const s = session('bot', botConfiguration);
  const release = releaseFor('bot');
  const current = { manifestFingerprint: hex('9') };
  const retained = [];
  s.readRetainedDeploymentEnvelope = (input) => { retained.push(input); return { manifest: current }; };
  await refusal(options.compatibility({ operation: 'update', request: h.request, release, old: { applicationManifestFingerprint: null }, session: s }),
    'SERVICE_PENDING', 'current-release-unavailable');
  const oldProof = { applicationManifestFingerprint: hex('9') };
  await options.compatibility({ operation: 'update', request: h.request, release, old: oldProof, session: s });
  assert.deepEqual(retained, [{ purpose: 'application', manifestFingerprint: hex('9') }]);
  assert.equal(h.compatibility[0].candidate, release.manifest);
  assert.deepEqual(h.calls, [['update', { current, expectedScopeFingerprint: hex('4') }]]);
  await refusal(options.compatibility({ operation: 'update', request: h.request, release, old: { applicationManifestFingerprint: hex('7') }, session: s }),
    'SERVICE_PENDING', 'current-release-unavailable');
  await refusal(options.compatibility({ operation: 'rollback', request: h.request, release, old: oldProof, session: s }),
    'SERVICE_INVALID', 'compatibility-operation');
  await refusal((async () => options.createWindowsDriver({ session: session('other'), request: h.request, release, locks: {} }))(),
    'SERVICE_INVALID', 'service-key');
});

test('retained operations derive configuration from the current service manifest and refuse drift', async () => {
  const h = harness();
  const operation = h.create();
  const uninstallRequest = { schemaVersion: 1, target: h.request.target, roles, expected: {}, acceptServiceDisruption: true };
  const ctx = { operation: 'uninstall', request: uninstallRequest, platform: 'win32', architecture: 'x64' };
  await operation.effectiveConfigPreflight(ctx);
  const options = operation.lifecycleOptions(ctx);
  await refusal((async () => options.createWindowsDriver({ session: session('bot'), request: uninstallRequest, release: releaseFor('bot'), locks: {} }))(),
    'SERVICE_PENDING', 'configuration-unavailable');
  const s = session('bot', botConfiguration);
  options.createWindowsDriver({ session: s, request: uninstallRequest, release: releaseFor('bot'), locks: {} });
  assert.equal(h.drivers[0].configuration, botConfiguration);
  const moved = { ...releaseFor('bot'), entrypointSha256: hex('5') };
  await refusal((async () => options.createWindowsDriver({ session: s, request: uninstallRequest, release: moved, locks: {} }))(),
    'SERVICE_STALE', 'launch-drift');
});

test('recovery compatibility uses the configuration bound by the recovery driver', async () => {
  const h = harness();
  const operation = h.create();
  const recoverRequest = { schemaVersion: 1, target: h.request.target, roles, expected: {} };
  const ctx = { operation: 'recover', request: recoverRequest, platform: 'win32', architecture: 'x64' };
  const options = operation.lifecycleOptions(ctx);
  const s = session('bot');
  const release = releaseFor('bot');
  options.createWindowsDriver({ session: s, request: { ...recoverRequest, configuration: botConfiguration }, release, locks: {} });
  await options.compatibility({ operation: 'install', request: recoverRequest, release, session: s });
  assert.equal(h.compatibility[0].workingDirectory, botConfiguration.workingDirectory);
  assert.equal(typeof options.observeApplication({}), 'function');
});

test('Launch derivation refuses releases without signed bootstrap metadata or bound paths', () => {
  const h = harness();
  const authority = {
    configuration: botConfiguration, runtimeConfig: null, runtimeSha256: hex('b'), sdkProfilePath: null,
    scopeFingerprint: hex('4'), effectiveConfigFingerprint: hex('6'), configSourceIdentityFingerprint: hex('5'),
  };
  const good = releaseFor('bot');
  assert.ok(deriveWindowsServiceLaunch({ component: 'bot', serviceKey: h.serviceKey, release: good, authority }));
  const cases = [
    [{ ...good, manifest: { entrypoints: good.manifest.entrypoints } }, 'bootstrap-metadata-missing'],
    [{ ...good, entrypointPath: 'C:\\Elsewhere\\bot.js' }, 'release-binding'],
    [{ ...good, supervisorSha256: 'x' }, 'release-binding'],
    [{ ...good, manifest: { ...good.manifest, windowsServiceBootstrap: { ...good.manifest.windowsServiceBootstrap,
      runtimePolicies: { bot: { runtime: 'node', version: '26.0.0', sourceRevision: 'b'.repeat(40) } } } } }, 'runtime-policy-mismatch'],
  ];
  for (const [release, reason] of cases) {
    assert.throws(() => deriveWindowsServiceLaunch({ component: 'bot', serviceKey: 'bot', release, authority }),
      (error) => error.code === 'SERVICE_PENDING' && error.reason === reason);
  }
});
