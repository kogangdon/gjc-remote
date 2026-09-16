import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { existsSync, readFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';
import { setTimeout as delay } from 'node:timers/promises';

import { validateBuildManifest } from '../src/index.js';

const argv = process.argv.slice(2);
if (argv.length !== 3 || argv[0] !== '--ack-disposable-host' || argv[1] !== '--fixture') {
  throw new Error('usage: node native-control/test-fixtures/service-scm-disposable.mjs --ack-disposable-host --fixture <protected-fixture.json>');
}
if (process.platform !== 'win32' || process.arch !== 'x64') {
  throw new Error('the disposable SCM scenario requires win32-x64');
}

const fixturePath = argv[2];
const fixture = JSON.parse(readFileSync(fixturePath, 'utf8'));
assert.equal(fixture.ackDisposableHost, true, 'fixture must independently acknowledge a disposable host');
assert.equal(fixture.platform, 'win32-x64');
assert.equal(fixture.evidenceKind, 'real-disposable-host');
assert.match(fixture.transitionProof, /^[0-9a-f]{64}$/);
assert.equal(
  Object.hasOwn(fixture, 'accountName'),
  false,
  'the native layer derives the service account from the selected role SID',
);

const instanceKey = /^[a-z0-9](?:[a-z0-9-]{0,30}[a-z0-9])?-[0-9a-f]{64}$/;
assert.equal(
  fixture.serviceRole === 'bot'
    ? fixture.serviceName === 'GJCRemoteBot'
    : fixture.serviceRole === 'daemon' &&
      fixture.serviceName.startsWith('GJCRemoteDaemon-') &&
      instanceKey.test(fixture.serviceName.slice('GJCRemoteDaemon-'.length)),
  true,
  'fixture service name must use the exact documented Windows topology',
);

const require = createRequire(import.meta.url);
const addonPath = fileURLToPath(new URL('../build/Release/native_control.node', import.meta.url));
const manifestPath = fileURLToPath(new URL('../build/Release/native-control.manifest.json', import.meta.url));
const packagePath = fileURLToPath(new URL('../package.json', import.meta.url));
assert.equal(existsSync(addonPath), true, 'native_control.node must be built');
assert.equal(existsSync(manifestPath), true, 'native-control.manifest.json must be built');
const addonBytes = readFileSync(addonPath);
const manifest = JSON.parse(readFileSync(manifestPath, 'utf8'));
const packageJson = JSON.parse(readFileSync(packagePath, 'utf8'));
assert.equal(validateBuildManifest(manifest, packageJson, addonBytes), true, 'addon must be the exact current tuple');
const addon = require(addonPath);
const sha256 = (bytes) => createHash('sha256').update(bytes).digest('hex');

const existing = addon.open_win32_service(
  fixture.serviceName,
  fixture.serviceRole,
  fixture.roles,
  'query',
);
if (existing !== null) addon.close_win32_service(existing);
assert.equal(existing, null, 'fixture service name must be absent before mutation');

const logStem = fixture.serviceRole === 'bot'
  ? 'gjc-remote-bot'
  : `gjc-remote-daemon-${fixture.serviceName.slice('GJCRemoteDaemon-'.length)}`;
const launch = [
  fixture.supervisorPath,
  sha256(readFileSync(fixture.supervisorPath)),
  fixture.workingDirectory,
  fixture.homeDirectory,
  fixture.runtimePath,
  sha256(readFileSync(fixture.runtimePath)),
  fixture.entrypointPath,
  sha256(readFileSync(fixture.entrypointPath)),
  fixture.logDirectory,
  `${logStem}-wrapper`,
  `${logStem}-child`,
  fixture.serviceRole === 'bot' ? fixture.channelsConfig : null,
];
let handle = addon.create_win32_service_disabled(
  fixture.serviceName,
  fixture.serviceRole,
  ...launch,
  fixture.servicePassword ?? null,
  fixture.roles,
);
let deleted = false;
let retainedQuery = null;
try {
  let snapshot = addon.query_win32_service(handle);
  assert.equal(snapshot.startType, 'disabled');
  assert.equal(snapshot.runtime.state, 'stopped');
  assert.equal(snapshot.description, '');
  assert.equal(snapshot.accountMatchesRole, true);
  const binaryPath = snapshot.binaryPath;

  const marker = `gjc-remote:v1:${fixture.transitionProof}`;
  assert.match(marker, /^gjc-remote:v1:[0-9a-f]{64}$/);
  snapshot = addon.protect_win32_service(
    handle,
    snapshot.configFingerprint,
    snapshot.runtime.fingerprint,
    marker,
  );
  assert.equal(snapshot.aclMatches, true);
  assert.equal(snapshot.description, marker);
  assert.equal(snapshot.binaryPath, binaryPath);

  snapshot = addon.set_win32_service_start_type(
    handle,
    snapshot.configFingerprint,
    snapshot.runtime.fingerprint,
    'demand',
  );
  assert.equal(snapshot.startType, 'demand');
  assert.equal(snapshot.failurePolicy, 'none');
  assert.equal(snapshot.failureActionsOnNonCrashFailures, false);
  assert.equal(snapshot.description, marker);
  assert.equal(snapshot.binaryPath, binaryPath);

  snapshot = addon.set_win32_service_start_type(
    handle,
    snapshot.configFingerprint,
    snapshot.runtime.fingerprint,
    'disabled',
  );
  assert.equal(snapshot.description, marker);
  assert.equal(snapshot.binaryPath, binaryPath);
  assert.equal(snapshot.accountMatchesRole, true);
  retainedQuery = addon.open_win32_service(fixture.serviceName, fixture.serviceRole, fixture.roles, 'query');
  assert.notEqual(retainedQuery, null);
  const result = addon.delete_win32_service(
    handle,
    snapshot.configFingerprint,
    snapshot.runtime.fingerprint,
  );
  deleted = true;
  handle = null;
  assert.deepEqual(result, { deletionPending: true, writes: 1 });
  try {
    const pending = addon.open_win32_service(fixture.serviceName, fixture.serviceRole, fixture.roles, 'query');
    assert.notEqual(pending, null, 'a retained handle prevents proven service absence');
    addon.close_win32_service(pending);
  } catch (error) {
    assert.equal(error.code, 'SERVICE_PENDING');
    assert.equal(error.writes, 0);
  }
  addon.close_win32_service(retainedQuery);
  retainedQuery = null;
  const deadline = performance.now() + 5000;
  let absent = false;
  while (performance.now() < deadline) {
    try {
      const observed = addon.open_win32_service(fixture.serviceName, fixture.serviceRole, fixture.roles, 'query');
      if (observed === null) {
        absent = true;
        break;
      }
      addon.close_win32_service(observed);
    } catch (error) {
      if (error.code !== 'SERVICE_PENDING') throw error;
    }
    await delay(50);
  }
  assert.equal(absent, true, 'delete acceptance is not proof of service absence');
  process.stdout.write(`${JSON.stringify({
    evidenceKind: 'real-disposable-host',
    scope: 'native-scm-primitives-only',
    productionProvenance: 'not-verified',
    scenario: 'scm-create-protect-demand-disable-delete',
    platform: 'win32-x64',
    result: 'passed',
  })}\n`);
} finally {
  if (retainedQuery) addon.close_win32_service(retainedQuery);
  if (handle && !deleted) {
    // Failure is not authority to adopt a fresh snapshot and delete its service.
    // Preserve the resource for explicit disposable-host manual reconciliation.
    addon.close_win32_service(handle);
  }
}
