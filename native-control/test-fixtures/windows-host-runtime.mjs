// Credential-free foreground fixture for the Windows service-host startup
// evidence path. It drives the REAL bot/daemon startup reporters with an
// explicit fixture transport (a scripted host registry / registration
// sequence) and writes their service-startup-observation events to stdout,
// which stands in for the Shawl child log family. It never loads the
// service bootstrap guard, native addon, Discord, the bot WebSocket, an SDK
// or a provider, and it never touches SCM, accounts, ACLs or configuration.
// Its output is fixture evidence only; it is not an actual service launch.
import { pathToFileURL } from 'node:url';
import { createBotServiceStartupReporter } from '../../bot/src/service-startup-reporter.js';
import { createDaemonServiceStartupReporter } from '../../daemon/src/service-startup-reporter.js';

export const WINDOWS_HOST_FIXTURE_SCENARIOS = Object.freeze(['ready', 'partial-hosts', 'denied']);

export function fixtureContext(component, serviceKey) {
  return Object.freeze({
    component,
    serviceKey,
    processEpochFingerprint: '1'.repeat(64),
    effectiveConfigFingerprint: '2'.repeat(64),
    configSourceIdentityFingerprint: '3'.repeat(64),
  });
}

export const FIXTURE_BOT_HOSTS = Object.freeze(['fixture-host-a', 'fixture-host-b']);
export const FIXTURE_DAEMON_TARGET = Object.freeze({ botWsUrl: 'ws://127.0.0.1:9/fixture', hostId: 'fixture-host-a' });

async function runBot(scenario, writable, onFailure) {
  const tokensByHostId = new Map(FIXTURE_BOT_HOSTS.map((hostId, index) => [hostId, `fixture-token-${index}`]));
  const reporter = createBotServiceStartupReporter({
    context: fixtureContext('bot', 'bot'), tokensByHostId, writable, onFailure,
  });
  let snapshot = { listener: 'closed', connectedHostIds: [] };
  reporter.attachRegistry({ getServiceStartupSnapshot: () => snapshot });
  snapshot = { listener: 'listening', connectedHostIds: [] };
  reporter.report();
  reporter.setDiscord('connected');
  const connected = scenario === 'partial-hosts' ? FIXTURE_BOT_HOSTS.slice(0, 1) : [...FIXTURE_BOT_HOSTS];
  for (let index = 1; index <= connected.length; index += 1) {
    snapshot = { listener: 'listening', connectedHostIds: connected.slice(0, index) };
    reporter.report();
  }
  await reporter.flush();
  await reporter.close();
}

async function runDaemon(scenario, writable, onFailure) {
  const reporter = createDaemonServiceStartupReporter({
    context: fixtureContext('daemon', `daemon-host-${'4'.repeat(64)}`),
    ...FIXTURE_DAEMON_TARGET, writable, onFailure,
  });
  const generation = reporter.registrationAttempted();
  if (scenario === 'denied') reporter.registrationDenied(generation);
  else reporter.registrationAccepted(generation);
  await reporter.flush();
  await reporter.close();
}

export async function runWindowsHostFixture({ component, scenario, writable }) {
  if (component !== 'bot' && component !== 'daemon') throw new TypeError('fixture component must be bot or daemon');
  if (!WINDOWS_HOST_FIXTURE_SCENARIOS.includes(scenario)) throw new TypeError('unknown fixture scenario');
  let failure = null;
  const onFailure = (error) => { failure = error; };
  if (component === 'bot') await runBot(scenario, writable, onFailure);
  else await runDaemon(scenario, writable, onFailure);
  if (failure !== null) throw failure;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const [component, scenario] = process.argv.slice(2);
  runWindowsHostFixture({ component, scenario, writable: process.stdout }).then(
    () => { process.exitCode = 0; },
    (error) => { process.stderr.write(`fixture failed: ${error?.message ?? error}\n`); process.exitCode = 1; },
  );
}
