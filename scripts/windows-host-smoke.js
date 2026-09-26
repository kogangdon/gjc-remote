#!/usr/bin/env node
// Credential-free foreground smoke for the Windows service-host startup
// evidence path. It spawns the explicit fixture runtime
// (native-control/test-fixtures/windows-host-runtime.mjs) as a real child
// process, captures its stdout as the child log family, and feeds the bytes
// through the production service-startup-observation reducer with the same
// binding/expected state the host producer would bind.
//
// Evidence class: foreground-fixture. This is NOT an actual Windows service
// lifecycle: no SCM, Shawl, service account, ACL, native addon, bootstrap
// guard, Discord, bot WebSocket, SDK or provider is used, and no host state
// is written. A passing run must never be reported as install/start/reboot
// qualification.
import { spawn } from 'node:child_process';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { managedHostSetFingerprint } from '@gjc-remote/shared/mapping-envelope';
import {
  createServiceStartupObservationReducer,
  serviceDaemonTargetFingerprint,
} from '@gjc-remote/shared/service-startup-observation';
import {
  FIXTURE_BOT_HOSTS,
  FIXTURE_DAEMON_TARGET,
  fixtureContext,
} from '../native-control/test-fixtures/windows-host-runtime.mjs';

export const WINDOWS_HOST_SMOKE_EVIDENCE_CLASS = 'foreground-fixture';
const FIXTURE_PATH = fileURLToPath(new URL('../native-control/test-fixtures/windows-host-runtime.mjs', import.meta.url));
const MAX_OUTPUT_BYTES = 1024 * 1024;
const TIMEOUT_MS = 30_000;

function expectedStateFor(component) {
  if (component === 'bot') {
    const tokens = new Map(FIXTURE_BOT_HOSTS.map((hostId, index) => [hostId, `fixture-token-${index}`]));
    return { expectedHostSetFingerprint: managedHostSetFingerprint(tokens), expectedHostCount: tokens.size };
  }
  return { targetFingerprint: serviceDaemonTargetFingerprint(FIXTURE_DAEMON_TARGET) };
}

function bindingFor(component) {
  const context = fixtureContext(component, component === 'bot' ? 'bot' : `daemon-host-${'4'.repeat(64)}`);
  return {
    component: context.component,
    serviceKey: context.serviceKey,
    processEpochFingerprint: context.processEpochFingerprint,
    effectiveConfigFingerprint: context.effectiveConfigFingerprint,
    configSourceIdentityFingerprint: context.configSourceIdentityFingerprint,
  };
}

function runFixture(component, scenario, runtimePath) {
  return new Promise((resolve, reject) => {
    const child = spawn(runtimePath, [FIXTURE_PATH, component, scenario], {
      stdio: ['ignore', 'pipe', 'pipe'],
      windowsHide: true,
      // Explicit minimal environment: no inherited credentials or service
      // variables reach the fixture.
      env: { SystemRoot: process.env.SystemRoot ?? '', PATH: process.env.PATH ?? '' },
    });
    const chunks = [];
    let bytes = 0;
    let stderr = '';
    const timer = setTimeout(() => { child.kill(); reject(new Error('fixture timed out')); }, TIMEOUT_MS);
    child.stdout.on('data', (chunk) => {
      bytes += chunk.byteLength;
      if (bytes > MAX_OUTPUT_BYTES) { child.kill(); reject(new Error('fixture output limit')); return; }
      chunks.push(chunk);
    });
    child.stderr.on('data', (chunk) => { stderr = `${stderr}${chunk}`.slice(-4096); });
    child.on('error', (error) => { clearTimeout(timer); reject(error); });
    child.on('close', (code) => {
      clearTimeout(timer);
      if (code !== 0) reject(new Error(`fixture exited ${code}: ${stderr.trim()}`));
      else resolve(Buffer.concat(chunks));
    });
  });
}

/** Runs one fixture scenario and returns a sanitized, labeled receipt. */
export async function runWindowsHostSmoke({ component, scenario = 'ready', runtimePath = process.execPath } = {}) {
  const output = await runFixture(component, scenario, runtimePath);
  const reducer = createServiceStartupObservationReducer({
    binding: bindingFor(component), expectedState: expectedStateFor(component),
  });
  // A wrapper-family line proves non-event wrapper output is tolerated.
  reducer.consume('wrapper', Buffer.from('[shawl-fixture] child started\n'));
  const snapshot = reducer.consume('child', output);
  return Object.freeze({
    evidenceClass: WINDOWS_HOST_SMOKE_EVIDENCE_CLASS,
    actualServiceLifecycle: false,
    scm: 'not-used',
    credentials: 'none',
    component,
    scenario,
    sequence: snapshot?.sequence ?? 0,
    ready: snapshot?.ready === true,
    applicationStateFingerprint: snapshot?.applicationStateFingerprint ?? null,
    writes: 0,
  });
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const receipts = [];
  let exitCode = 0;
  for (const [component, scenario, expectReady] of [
    ['bot', 'ready', true], ['bot', 'partial-hosts', false], ['daemon', 'ready', true], ['daemon', 'denied', false],
  ]) {
    try {
      const receipt = await runWindowsHostSmoke({ component, scenario });
      receipts.push({ ...receipt, expectedReady: expectReady, pass: receipt.ready === expectReady });
      if (receipt.ready !== expectReady) exitCode = 1;
    } catch (error) {
      receipts.push({ evidenceClass: WINDOWS_HOST_SMOKE_EVIDENCE_CLASS, component, scenario, pass: false, error: String(error?.message ?? error) });
      exitCode = 1;
    }
  }
  process.stdout.write(`${JSON.stringify({ evidenceClass: WINDOWS_HOST_SMOKE_EVIDENCE_CLASS, actualServiceLifecycle: false, receipts }, null, 2)}\n`);
  process.exitCode = exitCode;
}
