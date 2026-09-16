import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import test from 'node:test';
import {
  buildServiceCandidateProof,
  buildServiceFinalProof,
  buildServiceOldProof,
  buildServicePlatformState,
  buildServiceTransaction,
  buildServiceTransitionProof,
} from '@gjc-remote/shared/service-lifecycle-envelope';
import {
  createLinuxServiceDriver,
  linuxDaemonTemplateFingerprint,
  linuxDaemonDropinDirectoryName,
  linuxServiceResourceFingerprint,
  linuxServiceUnitName,
  loadLinuxServiceTemplates,
  renderLinuxBotUnit,
  renderLinuxDaemonDropin,
} from '../src/service-linux.js';

// Every assertion in this file uses an in-memory fake-native facade. It never
// calls systemd, mutates /etc, invokes a real runner, or claims Linux host
// evidence.
const hash = (value) => createHash('sha256').update(Buffer.isBuffer(value) ? value : String(value)).digest('hex');
const hex = (character) => character.repeat(64);
const roles = Object.freeze({
  management: Object.freeze({ kind: 'uid', value: 'uid:1000' }),
  bot: Object.freeze({ kind: 'uid', value: 'uid:1001' }),
  recovery: Object.freeze({ kind: 'uid', value: 'uid:1002' }),
  daemon: Object.freeze({ kind: 'uid', value: 'uid:1003' }),
  system: Object.freeze({ kind: 'uid', value: 'uid:0' }),
});
const botConfiguration = Object.freeze({
  runtimePath: '/usr/bin/node',
  workingDirectory: '/srv/gjc-remote-bot',
  homeDirectory: '/var/lib/gjc-bot',
  logDirectory: '/var/log/gjc-remote-bot',
  channelsConfig: '/etc/gjc-remote/channels.json',
  expectedHostSetFingerprint: hex('8'),
  expectedHostCount: 2,
});
const daemonConfiguration = Object.freeze({
  runtimePath: '/usr/bin/bun',
  workingDirectory: '/srv/gjc-remote-daemon',
  homeDirectory: '/var/lib/gjc-daemon',
  logDirectory: '/var/log/gjc-remote-daemon',
});
const baseClock = Date.UTC(2024, 0, 1);
const bootId = 'linux:00000000-0000-0000-0000-000000000001';

function release(fingerprint = hex('a')) {
  return { entrypointPath: '/srv/releases/current/daemon.js', applicationManifestFingerprint: fingerprint };
}

function fakeTemplates() {
  // The fake-native model uses the exact checked-in bytes. Driver construction
  // owns its defensive copy; callers may mutate these buffers afterward.
  return loadLinuxServiceTemplates();
}

function managerDefaults(unitName, component, phase = 'absent', serviceKey = null) {
  const loaded = phase !== 'absent';
  const enabled = phase === 'final';
  const restart = phase === 'trial' ? 'no' : phase === 'final' || phase === 'final-restart-armed' ? 'on-failure' : '';
  const dropin = component === 'daemon' && serviceKey !== null ? `/etc/systemd/system/${linuxDaemonDropinDirectoryName(serviceKey)}/50-gjc-release.conf` : '';
  return {
    LoadState: loaded ? 'loaded' : 'not-found', UnitFileState: loaded ? enabled ? 'enabled' : 'disabled' : 'disabled',
    UID: component === 'bot' ? '1001' : '1003',
    Description: component === 'bot' ? 'gjc-remote bot' : 'gjc-remote daemon (immutable release bound by owned instance drop-in)',
    SyslogIdentifier: component === 'bot' ? 'gjc-remote-bot' : `gjc-remote-daemon-${serviceKey}`,
    ActiveState: 'inactive', SubState: 'dead', InvocationID: '', MainPID: '0',
    ExecMainStartTimestamp: '', Restart: restart, ConditionResult: 'yes', AssertResult: 'yes', Conditions: '', Asserts: '', RefuseManualStart: 'no', TriggeredBy: '',
    WantedBy: enabled ? 'multi-user.target' : '', RequiredBy: '', Before: '', Requires: '', Requisite: '', BindsTo: '', PartOf: '', Conflicts: '', Slice: 'system.slice',
    ControlGroup: `/system.slice/${unitName}`, FragmentPath: `/etc/systemd/system/${component === 'daemon' ? 'gjc-remote-daemon@.service' : unitName}`,
    Type: 'simple', User: component === 'bot' ? 'gjc-bot' : 'gjc-daemon',
    DropInPaths: component === 'daemon' && loaded ? dropin : '',
    EnvironmentFiles: component === 'bot'
      ? '{ path=/etc/gjc-remote/bot.env ; ignore_errors=no ; }'
      : `{ path=/etc/gjc-remote/daemon-${serviceKey}.env ; ignore_errors=no ; }`,
    WorkingDirectory: component === 'bot' ? botConfiguration.workingDirectory : daemonConfiguration.workingDirectory,
    Environment: component === 'bot'
      ? `CHANNELS_CONFIG=${botConfiguration.channelsConfig} HOME=${botConfiguration.homeDirectory}`
      : `HOME=${daemonConfiguration.homeDirectory}`,
    ExecStart: component === 'bot' ? '/usr/bin/node /srv/releases/current/daemon.js' : '/usr/bin/bun /srv/releases/current/daemon.js',
    RestartUSec: '10s', KillSignal: 'SIGTERM', KillMode: 'control-group', TimeoutStopUSec: '35s', UMask: '0077',
    After: 'network-online.target', Wants: 'network-online.target', StartLimitIntervalUSec: '600s', StartLimitBurst: '5',
    NeedDaemonReload: 'no',
  };
}

function snapshot(objectKind, state = 'absent', bytes = null, target = null) {
  return { objectKind, state, parentIdentity: null, containerIdentity: null, bytes, facts: null, target };
}

function identityNumber(seed) {
  return String(Number.parseInt(hash(String(seed)).slice(0, 8), 16));
}

function fakePhysicalIdentity(seed) {
  return {
    profile: 'service-control-file', kind: 'linux-service-object-v1', device: '1',
    inode: identityNumber(seed), mode: 33188, owner: 'uid:0', securitySha256: hex('e'),
  };
}

function fakeParentIdentity(seed) {
  return { kind: 'linux-parent-v1', device: '1', inode: identityNumber(seed), mode: 16832, owner: 'uid:0' };
}

function serviceResource(component, serviceKey, { unit = null, template = null, dropin = null, link = 'absent' } = {}) {
  return linuxServiceResourceFingerprint({
    kind: 'linux-service-resource/v1', component, serviceKey,
    botUnitSha256: unit === null ? null : hash(unit),
    templateSha256: template === null ? null : hash(template),
    dropinSha256: dropin === null ? null : hash(dropin),
    enablementLink: link,
  });
}

function transactionFixture({ component = 'bot', serviceKey = 'bot', configuration = botConfiguration, releaseFingerprint = hex('a'), candidateFingerprint = releaseFingerprint, trialReleaseFingerprint = releaseFingerprint, predecessor = false, phase = 'transition-marker-intent', substep = 'observed' } = {}) {
  const templates = fakeTemplates();
  const rel = release(trialReleaseFingerprint);
  const renderInput = (restart) => ({ configuration, entrypointPath: rel.entrypointPath, restart, releaseFingerprint: rel.applicationManifestFingerprint });
  const rendered = component === 'bot'
    ? { unit: renderLinuxBotUnit(templates, renderInput('no')) }
    : { dropin: renderLinuxDaemonDropin(renderInput('no')) };
  const trialResource = component === 'bot'
    ? serviceResource(component, serviceKey, { unit: rendered.unit })
    : serviceResource(component, serviceKey, { template: templates.daemonTemplate, dropin: rendered.dropin });
  const finalRendered = component === 'bot'
    ? { unit: renderLinuxBotUnit(templates, renderInput('on-failure')) }
    : { dropin: renderLinuxDaemonDropin(renderInput('on-failure')) };
  const finalResource = component === 'bot'
    ? serviceResource(component, serviceKey, { unit: finalRendered.unit, link: 'owned' })
    : serviceResource(component, serviceKey, { template: templates.daemonTemplate, dropin: finalRendered.dropin, link: 'owned' });
  const old = predecessor
    ? buildServiceOldProof({ disposition: 'stable', manifestFingerprint: hex('6'), resourceProof: hex('7'), applicationManifestFingerprint: releaseFingerprint, shawlManifestFingerprint: null, serviceGeneration: 1, activation: 'enabled' }, 'linux')
    : buildServiceOldProof({ disposition: 'absent', manifestFingerprint: null, resourceProof: null, applicationManifestFingerprint: null, shawlManifestFingerprint: null, serviceGeneration: 0, activation: 'disabled-not-startable' }, 'linux');
  const candidate = buildServiceCandidateProof({ disposition: 'release', applicationManifestFingerprint: candidateFingerprint, shawlManifestFingerprint: null, releaseSequence: predecessor ? 2 : 1, releaseTreeFingerprint: hex('b'), compatibilityFingerprint: hex('c') }, 'linux');
  const transition = buildServiceTransitionProof({ oldFingerprint: old.oldFingerprint, candidateFingerprint: candidate.candidateFingerprint, expectedBeforeResourceFingerprint: predecessor ? finalResource : null, expectedAfterResourceFingerprint: predecessor ? hex('f') : finalResource, platformResourceFingerprint: trialResource, platformState: buildServicePlatformState('linux', 'trial') }, 'linux');
  const final = buildServiceFinalProof({ disposition: 'stable', manifestFingerprint: hex('d'), resourceProof: hex('e'), applicationManifestFingerprint: candidateFingerprint, shawlManifestFingerprint: null, serviceGeneration: predecessor ? 2 : 1, activation: 'enabled' }, 'linux');
  const fields = { transactionId: `tx-${serviceKey}`, transactionNonce: '1'.repeat(32), operation: predecessor ? 'update' : 'install', component, serviceKey, platform: 'linux', architecture: 'x64', serviceGeneration: predecessor ? 2 : 1, old, candidate, transition, final };
  const prepared = buildServiceTransaction({ ...fields, phase: 'prepared', substep: 'none', previousJournalFingerprint: predecessor ? hex('0') : null });
  return buildServiceTransaction({ ...fields, phase, substep, previousJournalFingerprint: prepared.transactionFingerprint });
}

class FakeLinuxNative {
  constructor({ component = 'bot', serviceKey = 'bot', configuration = botConfiguration } = {}) {
    this.component = component;
    this.serviceKey = serviceKey;
    this.configuration = configuration;
    this.boot = bootId;
    this.objects = new Map();
    this.managers = new Map();
    this.process = null;
    this.calls = [];
    this.writes = 0;
    this.invocation = 0;
    this.identitySerial = 0;
    this.suppressStart = false;
    this.emptyJournal = false;
    this.cursor = 'fake-1';
    this.sharedTemplate = null;
    this.siblingManagers = new Map();
    this.siblingDropins = new Map();
    this.managerMutator = null;
    this.afterManagerProbe = null;
    this.managerProbeCount = 0;
    this.cgroupMutator = null;
    this.cgroupTree = null;
    this.cgroupIdentity = { device: '1', inode: '2' };
    this.cgroupPartial = false;
    this.mutateOnReload = false;
    this.facade = Object.freeze({
      open_linux_service_scope: this.open_linux_service_scope.bind(this),
      read_linux_service_object: this.read_linux_service_object.bind(this),
      publish_linux_service_object: this.publish_linux_service_object.bind(this),
      remove_linux_service_object: this.remove_linux_service_object.bind(this),
      close_service_handle: this.close_service_handle.bind(this),
      read_boot_id: this.read_boot_id.bind(this),
      read_process_facts: this.read_process_facts.bind(this),
      enumerate_process_tree: this.enumerate_process_tree.bind(this),
      read_linux_service_cgroup: this.read_linux_service_cgroup.bind(this),
      terminate_linux_service_cgroup: this.terminate_linux_service_cgroup.bind(this),
    });
  }

  key(handle) { return handle.key ?? this.serviceKey; }

  mapFor(key = this.serviceKey) {
    if (!this.objects.has(key)) this.objects.set(key, new Map());
    return this.objects.get(key);
  }

  object(handle, kind) {
    const key = this.key(handle);
    if (kind === 'daemon-template' || kind === 'enablement-directory') return this.mapFor('__shared__').get(kind) ?? null;
    return this.mapFor(key).get(kind) ?? null;
  }

  open_linux_service_scope(key, access) {
    this.calls.push(['open_linux_service_scope', key, access]);
    return { handle: { key: key ?? '__shared__', access }, parentIdentity: fakeParentIdentity(key ?? '__shared__'), writes: 0 };
  }

  read_linux_service_object(handle, objectKind) {
    this.calls.push(['read_linux_service_object', objectKind]);
    const item = this.object(handle, objectKind);
    if (item === null) {
      const missing = snapshot(objectKind);
      missing.parentIdentity = fakeParentIdentity(`${this.key(handle)}:parent`);
      return { snapshot: missing, writes: 0 };
    }
    const value = snapshot(objectKind, item.state, item.state === 'file' ? Buffer.from(item.bytes) : null, item.target ?? null);
    value.parentIdentity = fakeParentIdentity(`${this.key(handle)}:parent`);
    value.containerIdentity = fakePhysicalIdentity(`${this.key(handle)}:${objectKind}:container`);
    const identity = item.identity ?? fakePhysicalIdentity(`${this.key(handle)}:${objectKind}`);
    if (value.state === 'file') {
      value.facts = {
        kind: 'linux-file-v1', device: identity.device, inode: identity.inode,
        size: value.bytes.length, sha256: hash(value.bytes), mode: identity.mode,
        owner: identity.owner, securitySha256: identity.securitySha256,
      };
    } else if (value.state === 'symlink') {
      value.facts = { kind: 'linux-symlink-v1', device: identity.device, inode: identity.inode,
        mode: identity.mode, owner: identity.owner };
    } else {
      value.facts = identity;
    }
    return { snapshot: value, writes: 0 };
  }

  publish_linux_service_object(handle, objectKind, bytes) {
    this.calls.push(['publish_linux_service_object', objectKind]);
    const key = this.key(handle);
    const map = objectKind === 'daemon-template' || objectKind === 'enablement-directory' ? this.mapFor('__shared__') : this.mapFor(key);
    map.set(objectKind, bytes === null ? {
      state: objectKind === 'enablement-link' ? 'symlink' : 'directory',
      identity: fakePhysicalIdentity(++this.identitySerial),
    } : {
      state: 'file', bytes: Buffer.from(bytes), identity: fakePhysicalIdentity(++this.identitySerial),
    });
    if (objectKind === 'enablement-link') {
      const target = this.component === 'daemon'
        ? '/etc/systemd/system/gjc-remote-daemon@.service'
        : `/etc/systemd/system/${linuxServiceUnitName(this.component, key)}`;
      map.set(objectKind, { state: 'symlink', target, identity: map.get(objectKind).identity });
    }
    this.writes += 1;
    return { snapshot: this.read_linux_service_object(handle, objectKind).snapshot, writes: 1 };
  }

  remove_linux_service_object(handle, objectKind) {
    this.calls.push(['remove_linux_service_object', objectKind]);
    const key = this.key(handle);
    const map = objectKind === 'daemon-template' || objectKind === 'enablement-directory' ? this.mapFor('__shared__') : this.mapFor(key);
    map.delete(objectKind);
    this.writes += 1;
    return { snapshot: snapshot(objectKind, 'absent'), writes: 1 };
  }

  close_service_handle() { return null; }
  read_boot_id() { return this.boot; }
  read_process_facts(pid) {
    if (this.process === null || this.process.pid !== pid) return null;
    return { pid, parentPid: 1, startTime: this.process.startTime, executable: this.configuration.runtimePath, owner: this.component === 'bot' ? roles.bot.value : roles.daemon.value, state: 'running', depth: 0 };
  }
  enumerate_process_tree(pid) {
    if (this.process === null || this.process.pid !== pid) return { processes: [], treeFingerprint: hex('0'), processCount: 0 };
    const facts = this.read_process_facts(pid);
    return { processes: [{ ...facts }], treeFingerprint: this.process.treeFingerprint, processCount: 1 };
  }
  read_linux_service_cgroup() {
    if (this.process === null) return null;
    if (this.cgroupMutator !== null) {
      const mutate = this.cgroupMutator;
      this.cgroupMutator = null;
      mutate(this);
    }
    return { identity: { ...this.cgroupIdentity }, processes: [this.cgroupPartial ? { pid: this.process.pid } : { ...this.read_process_facts(this.process.pid) }], treeFingerprint: this.cgroupTree ?? this.process.treeFingerprint, processCount: 1 };
  }
  terminate_linux_service_cgroup() {
    const terminated = this.process === null ? 0 : 1;
    this.process = null;
    this.writes += 1;
    return { tree: 'empty', forced: true, terminated, writes: 1 };
  }

  phase() {
    const map = this.mapFor(this.serviceKey);
    const file = map.get(this.component === 'bot' ? 'bot-unit' : 'daemon-dropin');
    if (file?.state !== 'file') return 'absent';
    const text = file.bytes.toString('utf8');
    if (/^Restart=on-failure$/m.test(text)) return map.has('enablement-link') ? 'final' : 'final-restart-armed';
    return 'trial';
  }

  manager(unitName, key = this.serviceKey) {
    const phase = key === this.serviceKey ? this.phase() : (this.siblingManagers.get(key)?.phase ?? 'trial');
    const manager = managerDefaults(unitName, this.component, phase, key);
    const live = key === this.serviceKey ? this.process : null;
    if (live !== null) {
      manager.ActiveState = 'active'; manager.SubState = 'running'; manager.InvocationID = live.invocation;
      manager.MainPID = String(live.pid); manager.ExecMainStartTimestamp = 'Mon 2024-01-01 00:00:00 UTC';
    }
    return manager;
  }

  invoke(argv) {
    this.calls.push(['invoke', ...argv]);
    const [program, action, unitName] = argv;
    if (program === '/usr/bin/journalctl') {
      return this.emptyJournal
        ? { code: 0, stdout: '', stderr: '', writes: 0 }
        : { code: 0, stdout: `-- cursor: ${this.cursor}\n`, stderr: '', writes: 0 };
    }
    if (program !== '/usr/bin/systemctl') return { code: 1, stdout: '', stderr: '', writes: 0 };
    if (action === 'show') {
      const key = unitName.startsWith('gjc-remote-daemon@') ? unitName.slice('gjc-remote-daemon@'.length, -'.service'.length) : this.serviceKey;
      const manager = this.manager(unitName, key);
      if (this.managerMutator !== null) this.managerMutator(manager);
      this.managerProbeCount += 1;
      const result = { code: 0, stdout: `${Object.entries(manager).map(([key, value]) => `${key}=${value}`).join('\n')}\n`, stderr: '', writes: 0 };
      if (this.afterManagerProbe !== null) {
        const mutate = this.afterManagerProbe;
        mutate();
      }
      return result;
    }
    if (action === 'start') {
      if (this.suppressStart) return { code: 0, stdout: '', stderr: '', writes: 0 };
      this.invocation += 1;
      this.process = { pid: 4000 + this.invocation, invocation: String(this.invocation).repeat(32), startTime: `fake-start-${this.invocation}`, treeFingerprint: hex(String(this.invocation + 1)) };
      return { code: 0, stdout: '', stderr: '', writes: 0 };
    }
    if (action === 'stop') { this.process = null; return { code: 0, stdout: '', stderr: '', writes: 0 }; }
    if (action === 'daemon-reload') {
      if (this.mutateOnReload) this.boot = 'linux:00000000-0000-0000-0000-000000000002';
      return { code: 0, stdout: '', stderr: '', writes: 0 };
    }
    return { code: 1, stdout: '', stderr: '', writes: 0 };
  }
}

function sessionFixture(transaction, { references = { present: false, value: null }, pending = null } = {}) {
  const state = { entries: [transaction], proof: null, references, pending };
  return {
    component: transaction.component, serviceKey: transaction.serviceKey, platform: 'linux', architecture: 'x64',
    readJournal: () => ({ entries: [...state.entries], pending: state.pending }),
    appendJournal: (entry) => { state.entries.push(entry); },
    readStartupProof: () => state.proof === null ? { present: false, value: null } : { present: true, value: state.proof },
    publishStartupProof: (proof) => { state.proof = proof; },
    readReferences: () => state.references,
    state,
  };
}

function driverFixture(options = {}) {
  const component = options.component ?? 'bot';
  const serviceKey = options.serviceKey ?? (component === 'bot' ? 'bot' : 'daemon-host-' + '1'.repeat(64));
  const configuration = options.configuration ?? (component === 'bot' ? botConfiguration : daemonConfiguration);
  const transaction = options.transaction ?? transactionFixture({ component, serviceKey, configuration, releaseFingerprint: options.releaseFingerprint ?? hex('a') });
  const native = options.native ?? new FakeLinuxNative({ component, serviceKey, configuration });
  const session = options.sessionObject ?? sessionFixture(transaction, options.session);
  const driver = createLinuxServiceDriver({ native: native.facade, session, locks: { artifact: {}, sharedTemplate: {}, serviceKey: {} }, invoke: native.invoke.bind(native), roles, configuration, clock: () => baseClock, sleep: async () => {}, templates: options.templates ?? fakeTemplates() });
  return { driver, native, session, transaction, configuration };
}

// Baselines are admitted only from the durable prepared boundary.  Tests that
// seed a predecessor therefore perform that explicit admission before moving
// the journal head to transition-marker-intent.
function admitPreparedBaseline(fixture) {
  const current = fixture.session.state.entries[0];
  const prepared = buildServiceTransaction({
    ...current,
    phase: 'prepared',
    substep: 'none',
    previousJournalFingerprint: current.previousJournalFingerprint,
  });
  fixture.session.state.entries[0] = prepared;
  fixture.driver.probe();
  fixture.session.state.entries[0] = current;
}

test('checked-in templates and renders are byte-exact trial/final policy', () => {
  const sourceTemplates = loadLinuxServiceTemplates();
  assert.match(sourceTemplates.botUnit.toString('utf8'), /@GJC_REMOTE_PROOF_FINGERPRINT@/);
  const unknownTokenTemplates = {
    botUnit: Buffer.from(`${sourceTemplates.botUnit.toString('utf8')}\n# @GJC_REMOTE_UNKNOWN_TOKEN@\n`),
    daemonTemplate: Buffer.from(sourceTemplates.daemonTemplate),
  };
  assert.throws(() => renderLinuxBotUnit(unknownTokenTemplates, {
    configuration: botConfiguration, entrypointPath: '/srv/releases/current/bot.js', restart: 'no', releaseFingerprint: hex('a'),
  }), (error) => error.code === 'SERVICE_INVALID');
  const templates = fakeTemplates();
  assert.ok(templates.botUnit.includes(Buffer.from('@GJC_REMOTE_RESTART@')));
  assert.match(templates.daemonTemplate.toString('utf8'), /ExecStart=\/usr\/bin\/false/);
  assert.equal(linuxDaemonTemplateFingerprint(templates.daemonTemplate), hash(templates.daemonTemplate));
  const input = { configuration: botConfiguration, entrypointPath: '/srv/releases/current/bot.js', releaseFingerprint: hex('a') };
  const trial = renderLinuxBotUnit(templates, { ...input, restart: 'no' }).toString('utf8');
  const final = renderLinuxBotUnit(templates, { ...input, restart: 'on-failure' }).toString('utf8');
  assert.match(trial, /Restart=no/);
  assert.match(final, /Restart=on-failure/);
  assert.doesNotMatch(trial, /@GJC_REMOTE_/);
  assert.match(trial, new RegExp(`# gjc-remote-proof: ${hex('a')}`));
  assert.doesNotMatch(trial, /^(?:Condition[A-Za-z]*|Assert[A-Za-z]*|RefuseManualStart)=/m);
  assert.match(trial, /WorkingDirectory=\/srv\/gjc-remote-bot/);
  assert.match(trial, /Environment=HOME=\/var\/lib\/gjc-bot/);
  const dropin = renderLinuxDaemonDropin({ configuration: daemonConfiguration, entrypointPath: '/srv/releases/current/daemon.js', restart: 'no', releaseFingerprint: hex('b') }).toString('utf8');
  assert.equal(dropin, [
    '# gjc-remote proof-owned instance release pin; managed only by gjc-remote-service.',
    `# gjc-remote-release: ${hex('b')}`,
    '[Service]',
    'ExecStart=',
    'ExecStart=/usr/bin/bun /srv/releases/current/daemon.js',
    'WorkingDirectory=/srv/gjc-remote-daemon',
    'Environment=HOME=/var/lib/gjc-daemon',
    'Restart=no',
    '',
  ].join('\n'));
  assert.match(dropin, /ExecStart=\nExecStart=\/usr\/bin\/bun \/srv\/releases\/current\/daemon\.js/);
  assert.match(dropin, /Restart=no/);
  assert.doesNotMatch(dropin, /HOST_ID/);
});

test('fake-native bot lifecycle uses fixed argv and closed cumulative writes', async () => {
  const { driver, native, session, transaction } = driverFixture();
  assert.equal(driver.probe().platformPhase, 'absent');
  assert.equal(driver.writes, 0);
  driver.publishSuppressedResource({ phase: 'transition-marker-intent', release: release(), expectedCurrentSha256: null, siblings: [] });
  const suppressed = driver.probe();
  assert.equal(suppressed.platformPhase, 'trial');
  assert.equal(suppressed.manager.LoadState, 'loaded');
  assert.equal(suppressed.manager.UnitFileState, 'disabled');
  assert.equal(suppressed.manager.Restart, 'no');
  assert.equal(suppressed.manager.ConditionResult, 'yes');
  assert.equal(suppressed.manager.AssertResult, 'yes');
  assert.equal(suppressed.manager.TriggeredBy, '');
  assert.equal(suppressed.manager.WantedBy, '');
  assert.equal(suppressed.manager.RequiredBy, '');
  const writesAfterPublish = driver.writes;
  assert.ok(writesAfterPublish > 0);
  const trial = await driver.startTrial({});
  assert.match(trial.invocationId, /^[0-9a-f]{32}$/);
  assert.equal(trial.mainPid, 4001);
  assert.equal(native.calls.some((call) => call[0] === 'invoke' && call[1] === '/usr/bin/systemctl' && call[2] === 'start' && call[3] === 'gjc-remote-bot.service'), true);
  assert.equal(session.state.entries.at(-1).phase, 'trial-start-observed');
  await driver.runStartupGate({ trial, observeApplication: async () => ({ applicationEvidenceFingerprint: hex('1'), connectivityObservation: 'last-observed-connected' }) });
  assert.ok(session.state.proof);
  driver.armFinalRestart({ release: release(), siblings: [] });
  const armed = driver.probe();
  assert.equal(armed.platformPhase, 'final-restart-armed');
  assert.equal(armed.manager.Restart, 'on-failure');
  assert.equal(armed.manager.UnitFileState, 'disabled');
  driver.enableFinal();
  const committed = driver.probe();
  assert.equal(committed.platformPhase, 'final');
  assert.equal(committed.manager.UnitFileState, 'enabled');
  assert.equal(committed.manager.WantedBy, 'multi-user.target');
  assert.equal(driver.writes >= writesAfterPublish, true);
  assert.equal(native.calls.filter((call) => call[0] === 'invoke').some((call) => call.includes('sh -c')), false);
  assert.equal(session.state.entries.at(-1).phase, 'activation-observed');
  assert.equal(transaction.transition.platformState.phase, 'trial');
});

test('journal cursor is stdout-shaped and empty journals use an explicit baseline', async () => {
  const fixture = driverFixture();
  fixture.native.emptyJournal = true;
  fixture.driver.publishSuppressedResource({ phase: 'transition-marker-intent', release: release(), expectedCurrentSha256: null, siblings: [] });
  const trial = await fixture.driver.startTrial({});
  assert.equal(trial.preStartCursor, '');
  const journalInvocation = fixture.native.calls.find((call) => call[0] === 'invoke' && call[1] === '/usr/bin/journalctl');
  assert.deepEqual(journalInvocation.slice(1), ['/usr/bin/journalctl', '-u', 'gjc-remote-bot.service', '-b', '-n', '0', '--quiet', '--show-cursor']);
  await fixture.driver.runStartupGate({ trial, observeApplication: async () => ({ applicationEvidenceFingerprint: hex('1'), connectivityObservation: 'last-observed-connected' }) });
});

test('a store-shaped pending journal tail refuses Linux observation before native reads', () => {
  const fixture = driverFixture({ session: { pending: { phase: 'transition-marker-intent', substep: 'action' } } });
  const calls = fixture.native.calls.length;
  const writes = fixture.native.writes;
  assert.throws(() => fixture.driver.probe(),
    (error) => error.code === 'SERVICE_PENDING' && error.writes === 0);
  assert.equal(fixture.native.calls.length, calls);
  assert.equal(fixture.native.writes, writes);
});

test('zero-write refusal and fixed-argv start without a new invocation stay closed', async () => {
  const fixture = driverFixture();
  const before = fixture.driver.writes;
  assert.throws(() => fixture.driver.publishSuppressedResource({ phase: 'transition-marker-intent', release: { ...release(), applicationManifestFingerprint: 'not-hex' }, expectedCurrentSha256: null, siblings: [] }), (error) => error.code === 'SERVICE_INVALID' && error.writes === before);
  fixture.native.suppressStart = true;
  fixture.driver.publishSuppressedResource({ phase: 'transition-marker-intent', release: release(), expectedCurrentSha256: null, siblings: [] });
  await assert.rejects(fixture.driver.startTrial({}), (error) => error.code === 'SERVICE_TRIAL_NOT_OBSERVED' && error.reason === 'invocation-not-observed');
});

test('same-content recreated unit identity refuses before native mutation', () => {
  const fixture = driverFixture();
  fixture.driver.publishSuppressedResource({ phase: 'transition-marker-intent', release: release(), expectedCurrentSha256: null, siblings: [] });
  const item = fixture.native.mapFor('bot').get('bot-unit');
  item.identity = fakePhysicalIdentity('recreated-unit');
  const writes = fixture.native.writes;
  assert.throws(
    () => fixture.driver.publishSuppressedResource({ phase: 'transition-marker-intent', release: release(), expectedCurrentSha256: null, siblings: [] }),
    (error) => error.code === 'SERVICE_MANUAL_CLEANUP' && error.reason === 'recreated-resource' && error.writes === writes,
  );
  assert.equal(fixture.native.writes, writes);
});

test('same-content recreation refuses before trial start', async () => {
  const fixture = driverFixture();
  fixture.driver.publishSuppressedResource({ phase: 'transition-marker-intent', release: release(), expectedCurrentSha256: null, siblings: [] });
  fixture.native.mapFor('bot').get('bot-unit').identity = fakePhysicalIdentity('recreated-before-start');
  const writes = fixture.native.writes;
  await assert.rejects(fixture.driver.startTrial({}),
    (error) => error.code === 'SERVICE_MANUAL_CLEANUP' && error.reason === 'recreated-resource' && error.writes === writes);
  assert.equal(fixture.native.writes, writes);
});

test('same-content recreation refuses before supervisor stop', async () => {
  const fixture = driverFixture();
  fixture.driver.publishSuppressedResource({ phase: 'transition-marker-intent', release: release(), expectedCurrentSha256: null, siblings: [] });
  await fixture.driver.startTrial({});
  fixture.native.mapFor('bot').get('bot-unit').identity = fakePhysicalIdentity('recreated-before-stop');
  const writes = fixture.native.writes;
  await assert.rejects(fixture.driver.stopAndQuiesce(),
    (error) => error.code === 'SERVICE_MANUAL_CLEANUP' && error.reason === 'recreated-resource' && error.writes === writes);
  assert.equal(fixture.native.writes, writes);
});

test('same-content recreation refuses before final enablement', async () => {
  const fixture = driverFixture();
  fixture.driver.publishSuppressedResource({ phase: 'transition-marker-intent', release: release(), expectedCurrentSha256: null, siblings: [] });
  const trial = await fixture.driver.startTrial({});
  await fixture.driver.runStartupGate({ trial, observeApplication: async () => ({ applicationEvidenceFingerprint: hex('1'), connectivityObservation: 'last-observed-connected' }) });
  fixture.driver.armFinalRestart({ release: release(), siblings: [] });
  fixture.native.mapFor('bot').get('bot-unit').identity = fakePhysicalIdentity('recreated-before-enable');
  const writes = fixture.native.writes;
  assert.throws(() => fixture.driver.enableFinal(),
    (error) => error.code === 'SERVICE_MANUAL_CLEANUP' && error.reason === 'recreated-resource' && error.writes === writes);
  assert.equal(fixture.native.writes, writes);
});

test('recreated primary caught by the fresh in-scope enable snapshot', async () => {
  const fixture = driverFixture();
  fixture.driver.publishSuppressedResource({ phase: 'transition-marker-intent', release: release(), expectedCurrentSha256: null, siblings: [] });
  const trial = await fixture.driver.startTrial({});
  await fixture.driver.runStartupGate({ trial,
    observeApplication: async () => ({ applicationEvidenceFingerprint: hex('1'), connectivityObservation: 'last-observed-connected' }) });
  fixture.driver.armFinalRestart({ release: release(), siblings: [] });
  // The pre-probe has already read the old identity; mutate before its
  // manager read so only the fresh in-scope snapshot can reject the replay.
  fixture.native.afterManagerProbe = () => {
    fixture.native.mapFor('bot').get('bot-unit').identity = fakePhysicalIdentity('recreated-in-enable-snapshot');
    fixture.native.afterManagerProbe = null;
  };
  const writes = fixture.native.writes;
  assert.throws(() => fixture.driver.enableFinal(),
    (error) => error.code === 'SERVICE_MANUAL_CLEANUP' && error.reason === 'recreated-resource' && error.writes === writes);
  assert.equal(fixture.native.writes, writes);
});

test('same-content adoption without a current-session identity receipt refuses', () => {
  const fixture = driverFixture();
  const bytes = renderLinuxBotUnit(fakeTemplates(), {
    configuration: botConfiguration,
    entrypointPath: '/srv/releases/current/daemon.js',
    restart: 'no',
    releaseFingerprint: hex('a'),
  });
  fixture.native.mapFor('bot').set('bot-unit', {
    state: 'file', bytes, identity: fakePhysicalIdentity('preexisting'),
  });
  const writes = fixture.native.writes;
  assert.throws(
    () => fixture.driver.publishSuppressedResource({ phase: 'transition-marker-intent', release: release(), expectedCurrentSha256: null, siblings: [] }),
    (error) => error.code === 'SERVICE_MANUAL_CLEANUP' && error.reason === 'recreated-resource' && error.writes === writes,
  );
  assert.equal(fixture.native.writes, writes);
});

test('journal phase regression is rejected before resource mutation', () => {
  const fixture = driverFixture();
  fixture.driver.publishSuppressedResource({ phase: 'transition-marker-intent', release: release(), expectedCurrentSha256: null, siblings: [] });
  fixture.driver.publishSuppressedResource({ phase: 'resource-published', release: release(), expectedCurrentSha256: null, siblings: [] });
  const writes = fixture.native.writes;
  assert.throws(
    () => fixture.driver.publishSuppressedResource({ phase: 'transition-marker-intent', release: release(), expectedCurrentSha256: null, siblings: [] }),
    (error) => error.code === 'SERVICE_PENDING' && error.writes === writes,
  );
  assert.equal(fixture.native.writes, writes);
});

test('same-content recreated shared template refuses before native mutation', () => {
  const fixture = driverFixture({ component: 'daemon', serviceKey: `daemon-host-${'2'.repeat(64)}` });
  fixture.driver.publishSuppressedResource({ phase: 'transition-marker-intent', release: release(), expectedCurrentSha256: null, siblings: [] });
  const item = fixture.native.mapFor('__shared__').get('daemon-template');
  item.identity = fakePhysicalIdentity('recreated-template');
  const writes = fixture.native.writes;
  assert.throws(
    () => fixture.driver.publishSuppressedResource({ phase: 'transition-marker-intent', release: release(), expectedCurrentSha256: null, siblings: [] }),
    (error) => error.code === 'SERVICE_MANUAL_CLEANUP' && error.reason === 'recreated-resource' && error.writes === writes,
  );
  assert.equal(fixture.native.writes, writes);
});

test('same-content recreated enablement link refuses before native mutation', () => {
  const fixture = driverFixture();
  fixture.driver.publishSuppressedResource({ phase: 'transition-marker-intent', release: release(), expectedCurrentSha256: null, siblings: [] });
  fixture.native.mapFor('bot').set('enablement-link', {
    state: 'symlink',
    target: '/etc/systemd/system/gjc-remote-bot.service',
    identity: fakePhysicalIdentity('recreated-link'),
  });
  const writes = fixture.native.writes;
  assert.throws(
    () => fixture.driver.publishSuppressedResource({ phase: 'resource-published', release: release(), expectedCurrentSha256: null, siblings: [] }),
    (error) => error.code === 'SERVICE_MANUAL_CLEANUP' && error.reason === 'recreated-resource' && error.writes === writes,
  );
  assert.equal(fixture.native.writes, writes);
});

test('same-content recreated daemon drop-in and directory refuse before native mutation', () => {
  const fixture = driverFixture({ component: 'daemon', serviceKey: `daemon-host-${'3'.repeat(64)}` });
  fixture.driver.publishSuppressedResource({ phase: 'transition-marker-intent', release: release(), expectedCurrentSha256: null, siblings: [] });
  const map = fixture.native.mapFor(fixture.native.serviceKey);
  map.get('daemon-dropin').identity = fakePhysicalIdentity('recreated-dropin');
  const writesAfterDropin = fixture.native.writes;
  assert.throws(
    () => fixture.driver.publishSuppressedResource({ phase: 'resource-published', release: release(), expectedCurrentSha256: null, siblings: [] }),
    (error) => error.code === 'SERVICE_MANUAL_CLEANUP' && error.reason === 'recreated-resource' && error.writes === writesAfterDropin,
  );
  assert.equal(fixture.native.writes, writesAfterDropin);

  // Restore the drop-in receipt by starting a fresh fixture, then recreate
  // only the parent directory to cover the directory identity boundary.
  const second = driverFixture({ component: 'daemon', serviceKey: `daemon-host-${'4'.repeat(64)}` });
  second.driver.publishSuppressedResource({ phase: 'transition-marker-intent', release: release(), expectedCurrentSha256: null, siblings: [] });
  const shared = second.native.mapFor(second.native.serviceKey);
  shared.get('daemon-dropin-directory').identity = fakePhysicalIdentity('recreated-directory');
  const writesAfterDirectory = second.native.writes;
  assert.throws(
    () => second.driver.publishSuppressedResource({ phase: 'resource-published', release: release(), expectedCurrentSha256: null, siblings: [] }),
    (error) => error.code === 'SERVICE_MANUAL_CLEANUP' && error.reason === 'recreated-resource' && error.writes === writesAfterDirectory,
  );
  assert.equal(second.native.writes, writesAfterDirectory);
});

test('recreated unit and drop-in refuse removal before native mutation', async () => {
  const bot = driverFixture();
  bot.driver.publishSuppressedResource({ phase: 'transition-marker-intent', release: release(), expectedCurrentSha256: null, siblings: [] });
  await bot.driver.stopAndQuiesce();
  const botUnit = bot.native.mapFor('bot').get('bot-unit');
  botUnit.identity = fakePhysicalIdentity('recreated-unit-removal');
  const botWrites = bot.native.writes;
  assert.throws(
    () => bot.driver.removeResource({ expectedCurrentSha256: hash(botUnit.bytes), siblings: [] }),
    (error) => error.code === 'SERVICE_MANUAL_CLEANUP' && error.reason === 'recreated-resource' && error.writes === botWrites,
  );
  assert.equal(bot.native.writes, botWrites);

  const daemon = driverFixture({ component: 'daemon', serviceKey: `daemon-host-${'5'.repeat(64)}` });
  daemon.driver.publishSuppressedResource({ phase: 'transition-marker-intent', release: release(), expectedCurrentSha256: null, siblings: [] });
  await daemon.driver.stopAndQuiesce();
  const dropin = daemon.native.mapFor(daemon.native.serviceKey).get('daemon-dropin');
  dropin.identity = fakePhysicalIdentity('recreated-dropin-removal');
  const daemonWrites = daemon.native.writes;
  assert.throws(
    () => daemon.driver.removeResource({ expectedCurrentSha256: hash(dropin.bytes), siblings: [] }),
    (error) => error.code === 'SERVICE_MANUAL_CLEANUP' && error.reason === 'recreated-resource' && error.writes === daemonWrites,
  );
  assert.equal(daemon.native.writes, daemonWrites);
});

test('stopping action replay reconciles quiescence without a second systemctl stop', async () => {
  const native = new FakeLinuxNative();
  const transaction = transactionFixture();
  const baseSession = sessionFixture(transaction);
  let crash = true;
  const session = {
    ...baseSession,
    appendJournal(entry) {
      if (crash && entry.phase === 'stopping' && entry.substep === 'observed') {
        crash = false;
        throw new Error('simulated crash after stop');
      }
      baseSession.appendJournal(entry);
    },
  };
  const fixture = driverFixture({ native, transaction, sessionObject: session });
  fixture.driver.publishSuppressedResource({ phase: 'transition-marker-intent', release: release(), expectedCurrentSha256: null, siblings: [] });
  await fixture.driver.startTrial({});
  await assert.rejects(fixture.driver.stopAndQuiesce(), /simulated crash after stop/);
  const stopCalls = () => native.calls.filter((call) => call[0] === 'invoke' && call[2] === 'stop').length;
  assert.equal(stopCalls(), 1);
  await fixture.driver.stopAndQuiesce();
  assert.equal(stopCalls(), 1);
});

test('removal action replay preserves the exact absent primary tombstone', async () => {
  const native = new FakeLinuxNative();
  const transaction = transactionFixture();
  const baseSession = sessionFixture(transaction);
  let crash = true;
  const session = {
    ...baseSession,
    appendJournal(entry) {
      if (crash && entry.phase === 'resource-removed' && entry.substep === 'observed' &&
          baseSession.state.entries.at(-1)?.substep === 'action') {
        crash = false;
        throw new Error('simulated crash after primary removal');
      }
      baseSession.appendJournal(entry);
    },
  };
  const fixture = driverFixture({ native, transaction, sessionObject: session });
  fixture.driver.publishSuppressedResource({ phase: 'transition-marker-intent', release: release(), expectedCurrentSha256: null, siblings: [] });
  await fixture.driver.stopAndQuiesce();
  const expectedCurrentSha256 = hash(native.mapFor('bot').get('bot-unit').bytes);
  await assert.rejects(
    Promise.resolve().then(() => fixture.driver.removeResource({ expectedCurrentSha256, siblings: [] })),
    /simulated crash after primary removal/,
  );
  assert.equal(native.mapFor('bot').has('bot-unit'), false);
  const fresh = driverFixture({ native, transaction, sessionObject: session });
  assert.throws(
    () => fresh.driver.removeResource({ expectedCurrentSha256, siblings: [] }),
    (error) => error.code === 'SERVICE_MANUAL_CLEANUP' && error.reason === 'recreated-resource' && error.writes === 0,
  );
  const recovered = fixture.driver.removeResource({ expectedCurrentSha256, siblings: [] });
  assert.equal(recovered.platformPhase, 'absent');
});

for (const [label, removalCount] of [['drop-in', 1], ['drop-in directory', 2]]) {
  test(`${label} removal replay keeps unrelated daemon receipts`, async () => {
    const serviceKey = `daemon-host-${'b'.repeat(63)}${label === 'drop-in' ? '1' : '2'}`;
    const native = new FakeLinuxNative({ component: 'daemon', serviceKey, configuration: daemonConfiguration });
    const transaction = transactionFixture({ component: 'daemon', serviceKey, configuration: daemonConfiguration });
    const baseSession = sessionFixture(transaction);
    let crash = true;
    const session = {
      ...baseSession,
      appendJournal(entry) {
        const removals = native.calls.filter((call) => call[0] === 'remove_linux_service_object').length;
        if (crash && entry.phase === 'resource-removed' && entry.substep === 'observed' &&
            baseSession.state.entries.at(-1)?.substep === 'action' && removals === removalCount) {
          crash = false;
          throw new Error(`simulated crash after ${label} removal`);
        }
        baseSession.appendJournal(entry);
      },
    };
    const fixture = driverFixture({ component: 'daemon', serviceKey, native, transaction, sessionObject: session });
    fixture.driver.publishSuppressedResource({ phase: 'transition-marker-intent', release: release(), expectedCurrentSha256: null, siblings: [] });
    await fixture.driver.stopAndQuiesce();
    const map = native.mapFor(serviceKey);
    const expectedCurrentSha256 = hash(map.get('daemon-dropin').bytes);
    await assert.rejects(
      Promise.resolve().then(() => fixture.driver.removeResource({ expectedCurrentSha256, siblings: [] })),
      new RegExp(`simulated crash after ${label} removal`),
    );
    const replayed = fixture.driver.removeResource({ expectedCurrentSha256, siblings: [] });
    assert.equal(replayed.platformPhase, 'absent');
  });
}

test('link-removal replay keeps the old primary CAS state until replacement', () => {
  const oldRelease = hex('9');
  const transaction = transactionFixture({
    releaseFingerprint: oldRelease,
    trialReleaseFingerprint: oldRelease,
    candidateFingerprint: hex('a'),
    predecessor: true,
  });
  const native = new FakeLinuxNative();
  const baseSession = sessionFixture(transaction);
  let crash = true;
  const session = {
    ...baseSession,
    appendJournal(entry) {
      if (crash && entry.phase === 'transition-marker-intent' && entry.substep === 'observed' &&
          baseSession.state.entries.at(-1)?.substep === 'action') {
        crash = false;
        throw new Error('simulated crash after link removal');
      }
      baseSession.appendJournal(entry);
    },
  };
  const fixture = driverFixture({ native, transaction, sessionObject: session });
  const oldUnit = renderLinuxBotUnit(fakeTemplates(), {
    configuration: botConfiguration,
    entrypointPath: release(oldRelease).entrypointPath,
    restart: 'on-failure',
    releaseFingerprint: oldRelease,
  });
  native.mapFor('bot').set('bot-unit', {
    state: 'file', bytes: oldUnit, identity: fakePhysicalIdentity('link-replay-unit'),
  });
  native.mapFor('bot').set('enablement-link', {
    state: 'symlink', target: '/etc/systemd/system/gjc-remote-bot.service',
    identity: fakePhysicalIdentity('link-replay-link'),
  });
  admitPreparedBaseline(fixture);
  assert.throws(
    () => fixture.driver.publishSuppressedResource({
      phase: 'transition-marker-intent', release: release(oldRelease),
      expectedCurrentSha256: hash(oldUnit), siblings: [],
    }),
    /simulated crash after link removal/,
  );
  assert.equal(native.mapFor('bot').has('enablement-link'), false);
  const replayed = fixture.driver.publishSuppressedResource({
    phase: 'transition-marker-intent', release: release(oldRelease),
    expectedCurrentSha256: hash(oldUnit), siblings: [],
  });
  assert.equal(replayed.platformPhase, 'trial');
});

test('replacement action replay promotes the observed post-identity before reload', async () => {
  const native = new FakeLinuxNative();
  const transaction = transactionFixture();
  const baseSession = sessionFixture(transaction);
  let crash = true;
  const session = {
    ...baseSession,
    appendJournal(entry) {
      if (crash && entry.phase === 'activation-observed' && entry.substep === 'observed') {
        crash = false;
        throw new Error('simulated crash after replacement');
      }
      baseSession.appendJournal(entry);
    },
  };
  const fixture = driverFixture({ native, transaction, sessionObject: session });
  fixture.driver.publishSuppressedResource({ phase: 'transition-marker-intent', release: release(), expectedCurrentSha256: null, siblings: [] });
  const trial = await fixture.driver.startTrial({});
  await fixture.driver.runStartupGate({
    trial,
    observeApplication: async () => ({ applicationEvidenceFingerprint: hex('1'), connectivityObservation: 'last-observed-connected' }),
  });
  await assert.rejects(
    Promise.resolve().then(() => fixture.driver.armFinalRestart({ release: release(), siblings: [] })),
    /simulated crash after replacement/,
  );
  const publishes = () => native.calls.filter((call) => call[0] === 'publish_linux_service_object').length;
  const beforeReplay = publishes();
  fixture.driver.armFinalRestart({ release: release(), siblings: [] });
  assert.equal(publishes(), beforeReplay);
});

test('reload-arm replay accepts the exact final-restart-armed post-state', async () => {
  const native = new FakeLinuxNative();
  const transaction = transactionFixture();
  const baseSession = sessionFixture(transaction);
  let crash = true;
  const session = {
    ...baseSession,
    appendJournal(entry) {
      if (crash && entry.phase === 'activation-observed' && entry.substep === 'observed' &&
          baseSession.state.entries.at(-1)?.substep === 'action' &&
          native.calls.at(-2)?.[0] === 'invoke' && native.calls.at(-2)?.[2] === 'daemon-reload') {
        crash = false;
        throw new Error('simulated crash after final restart reload');
      }
      baseSession.appendJournal(entry);
    },
  };
  const fixture = driverFixture({ native, transaction, sessionObject: session });
  fixture.driver.publishSuppressedResource({ phase: 'transition-marker-intent', release: release(), expectedCurrentSha256: null, siblings: [] });
  const trial = await fixture.driver.startTrial({});
  await fixture.driver.runStartupGate({
    trial,
    observeApplication: async () => ({ applicationEvidenceFingerprint: hex('1'), connectivityObservation: 'last-observed-connected' }),
});
  await assert.rejects(
    Promise.resolve().then(() => fixture.driver.armFinalRestart({ release: release(), siblings: [] })),
    /simulated crash after final restart reload/,
  );
  assert.equal(native.mapFor('bot').get('bot-unit').bytes.includes(Buffer.from('Restart=on-failure')), true);
  const replayed = fixture.driver.armFinalRestart({ release: release(), siblings: [] });
  assert.equal(replayed.platformPhase, 'final-restart-armed');
});

test('daemon template action replay resumes without a duplicate publish', async () => {
  const serviceKey = `daemon-host-${'9'.repeat(64)}`;
  const native = new FakeLinuxNative({ component: 'daemon', serviceKey, configuration: daemonConfiguration });
  const transaction = transactionFixture({ component: 'daemon', serviceKey, configuration: daemonConfiguration });
  const baseSession = sessionFixture(transaction);
  let crash = true;
  const session = {
    ...baseSession,
    appendJournal(entry) {
      if (crash && entry.phase === 'transition-marker-intent' && entry.substep === 'observed') {
        crash = false;
        throw new Error('simulated daemon crash after template publish');
      }
      baseSession.appendJournal(entry);
    },
  };
  const fixture = driverFixture({ component: 'daemon', serviceKey, native, transaction, sessionObject: session });
  await assert.rejects(
    Promise.resolve().then(() => fixture.driver.publishSuppressedResource({
      phase: 'transition-marker-intent', release: release(), expectedCurrentSha256: null, siblings: [],
    })),
    /simulated daemon crash after template publish/,
  );
  const publishesBeforeReplay = native.calls.filter((call) => call[0] === 'publish_linux_service_object').length;
  fixture.driver.publishSuppressedResource({
    phase: 'transition-marker-intent', release: release(), expectedCurrentSha256: null, siblings: [],
  });
  assert.equal(
    native.calls.filter((call) => call[0] === 'publish_linux_service_object').length,
    publishesBeforeReplay + 2,
  );
});

test('daemon drop-in directory replay permits only the exact pre-drop-in gap', () => {
  const serviceKey = `daemon-host-${'a'.repeat(64)}`;
  const native = new FakeLinuxNative({ component: 'daemon', serviceKey, configuration: daemonConfiguration });
  const transaction = transactionFixture({ component: 'daemon', serviceKey, configuration: daemonConfiguration });
  const baseSession = sessionFixture(transaction);
  let crash = true;
  const session = {
    ...baseSession,
    appendJournal(entry) {
      const publishes = native.calls.filter((call) => call[0] === 'publish_linux_service_object');
      if (crash && entry.phase === 'transition-marker-intent' && entry.substep === 'observed' &&
          baseSession.state.entries.at(-1)?.substep === 'action' && publishes.length === 2) {
        crash = false;
        throw new Error('simulated crash after drop-in directory publish');
      }
      baseSession.appendJournal(entry);
    },
  };
  const fixture = driverFixture({ component: 'daemon', serviceKey, native, transaction, sessionObject: session });
  assert.throws(
    () => fixture.driver.publishSuppressedResource({
      phase: 'transition-marker-intent', release: release(), expectedCurrentSha256: null, siblings: [],
    }),
    /simulated crash after drop-in directory publish/,
  );
  assert.equal(native.mapFor(serviceKey).has('daemon-dropin'), false);
  const replayed = fixture.driver.publishSuppressedResource({
    phase: 'transition-marker-intent', release: release(), expectedCurrentSha256: null, siblings: [],
  });
  assert.equal(replayed.platformPhase, 'trial');
});


test('controller loss and reboot classify without claiming controller death stopped a tree', async () => {
  const fixture = driverFixture();
  fixture.driver.publishSuppressedResource({ phase: 'transition-marker-intent', release: release(), expectedCurrentSha256: null, siblings: [] });
  const trial = await fixture.driver.startTrial({});
  assert.deepEqual(fixture.driver.recoverTrialState(), { classification: 'stop-and-retrial', phase: 'trial-start-observed' });
  await fixture.driver.runStartupGate({ trial, observeApplication: async () => ({ applicationEvidenceFingerprint: hex('1'), connectivityObservation: 'last-observed-connected' }) });
  assert.equal(fixture.driver.recoverTrialState().classification, 'resume-activation');
  fixture.native.boot = 'linux:00000000-0000-0000-0000-000000000002';
  assert.equal(fixture.driver.recoverTrialState().classification, 'resuppress-and-retrial');
});

test('pre-suppression recovery refuses predecessor resource without live identity receipts', () => {
  const oldRelease = hex('9');
  const transaction = transactionFixture({
    releaseFingerprint: oldRelease,
    trialReleaseFingerprint: oldRelease,
    candidateFingerprint: hex('a'),
    predecessor: true,
  });
  const fixture = driverFixture({ transaction });
  const rendered = renderLinuxBotUnit(fakeTemplates(), {
    configuration: botConfiguration,
    entrypointPath: '/srv/releases/current/daemon.js',
    restart: 'on-failure',
    releaseFingerprint: oldRelease,
  });
  const map = fixture.native.mapFor('bot');
  map.set('bot-unit', { state: 'file', bytes: rendered, identity: fakePhysicalIdentity('old-final') });
  map.set('enablement-link', {
    state: 'symlink',
    target: '/etc/systemd/system/gjc-remote-bot.service',
    identity: fakePhysicalIdentity('old-link'),
  });
  assert.deepEqual(fixture.driver.recoverTrialState(), {
    classification: 'manual-cleanup',
    phase: 'transition-marker-intent',
    reason: 'recreated-resource',
  });
  map.get('bot-unit').bytes = renderLinuxBotUnit(fakeTemplates(), {
    configuration: botConfiguration,
    entrypointPath: '/srv/releases/current/daemon.js',
    restart: 'on-failure',
    releaseFingerprint: hex('c'),
  });
  assert.deepEqual(fixture.driver.recoverTrialState(), {
    classification: 'manual-cleanup',
    phase: 'transition-marker-intent',
    reason: 'recreated-resource',
  });
});

test('daemon template fingerprint and active shared-template references refuse mutation', () => {
  const foreignFingerprint = hex('f');
  const fixture = driverFixture({
    component: 'daemon',
    serviceKey: `daemon-host-${'1'.repeat(64)}`,
    session: {
      references: {
        present: true,
        value: { current: { artifacts: [{ artifactKind: 'shared-template', artifactFingerprint: foreignFingerprint }] }, previous: null, provisional: null },
      },
    },
  });
  const templates = fakeTemplates();
  assert.equal(linuxDaemonTemplateFingerprint(templates.daemonTemplate), hash(templates.daemonTemplate));
  assert.throws(() => fixture.driver.publishSuppressedResource({ phase: 'transition-marker-intent', release: release(), expectedCurrentSha256: null, siblings: [] }), (error) => error.code === 'SERVICE_REFERENCED' && error.reason === 'template-referenced' && error.writes === 0);
  assert.equal(fixture.native.writes, 0);
});

test('resource fingerprints keep sibling snapshots independent of runtime epochs', () => {
  const first = linuxServiceResourceFingerprint({ kind: 'linux-service-resource/v1', component: 'daemon', serviceKey: `daemon-a-${'a'.repeat(64)}`, botUnitSha256: null, templateSha256: hex('1'), dropinSha256: hex('2'), enablementLink: 'absent' });
  const second = linuxServiceResourceFingerprint({ kind: 'linux-service-resource/v1', component: 'daemon', serviceKey: `daemon-b-${'b'.repeat(64)}`, botUnitSha256: null, templateSha256: hex('1'), dropinSha256: hex('2'), enablementLink: 'absent' });
  assert.notEqual(first, second);
  assert.equal(first, linuxServiceResourceFingerprint({ kind: 'linux-service-resource/v1', component: 'daemon', serviceKey: `daemon-a-${'a'.repeat(64)}`, botUnitSha256: null, templateSha256: hex('1'), dropinSha256: hex('2'), enablementLink: 'absent' }));
  assert.notEqual(first, linuxServiceResourceFingerprint({ kind: 'linux-service-resource/v1', component: 'daemon', serviceKey: `daemon-a-${'a'.repeat(64)}`, botUnitSha256: null, templateSha256: hex('1'), dropinSha256: hex('2'), enablementLink: 'owned' }));
});

test('predecessor restoration trial requires an explicit old-resource fingerprint', async () => {
  const oldRelease = hex('9');
  const candidateRelease = hex('a');
  const transaction = transactionFixture({ releaseFingerprint: oldRelease, trialReleaseFingerprint: oldRelease, candidateFingerprint: candidateRelease, predecessor: true });
  assert.equal(transaction.old.applicationManifestFingerprint, oldRelease);
  const fixture = driverFixture({ transaction });
  const oldUnit = renderLinuxBotUnit(fakeTemplates(), {
    configuration: botConfiguration,
    entrypointPath: release(oldRelease).entrypointPath,
    restart: 'on-failure',
    releaseFingerprint: oldRelease,
  });
  assert.match(oldUnit.toString('utf8'), new RegExp(`# gjc-remote-release: ${oldRelease}`));
  fixture.native.mapFor('bot').set('bot-unit', {
    state: 'file', bytes: oldUnit, identity: fakePhysicalIdentity('predecessor-unit'),
  });
  fixture.native.mapFor('bot').set('enablement-link', {
    state: 'symlink', target: '/etc/systemd/system/gjc-remote-bot.service',
    identity: fakePhysicalIdentity('old-link'),
  });
  admitPreparedBaseline(fixture);
  assert.equal(fixture.driver.probe().resourceFingerprint, transaction.transition.expectedBeforeResourceFingerprint);
  fixture.driver.publishSuppressedResource({
    phase: 'transition-marker-intent', release: release(oldRelease),
    expectedCurrentSha256: hash(oldUnit), siblings: [],
  });
  await assert.rejects(fixture.driver.startTrial({}), (error) => error.code === 'SERVICE_INVALID');
  // The old release is a legal predecessor only when its exact T resource is pinned.
  const trial = await fixture.driver.startTrial({ expectedResourceFingerprint: transaction.transition.platformResourceFingerprint });
  assert.equal(trial.releaseFingerprint, oldRelease);
});

test('persisted predecessor startup proof resolves against transaction old release after driver recovery', async () => {
  const oldRelease = hex('9');
  const candidateRelease = hex('a');
  const transaction = transactionFixture({ releaseFingerprint: oldRelease, trialReleaseFingerprint: oldRelease, candidateFingerprint: candidateRelease, predecessor: true });
  const first = driverFixture({ transaction });
  const oldUnit = renderLinuxBotUnit(fakeTemplates(), {
    configuration: botConfiguration,
    entrypointPath: release(oldRelease).entrypointPath,
    restart: 'on-failure',
    releaseFingerprint: oldRelease,
  });
  first.native.mapFor('bot').set('bot-unit', {
    state: 'file', bytes: oldUnit, identity: fakePhysicalIdentity('predecessor-unit-recovery'),
  });
  first.native.mapFor('bot').set('enablement-link', {
    state: 'symlink', target: '/etc/systemd/system/gjc-remote-bot.service',
    identity: fakePhysicalIdentity('predecessor-link-recovery'),
  });
  admitPreparedBaseline(first);
  assert.equal(first.driver.probe().resourceFingerprint, transaction.transition.expectedBeforeResourceFingerprint);
  first.driver.publishSuppressedResource({
    phase: 'transition-marker-intent', release: release(oldRelease),
    expectedCurrentSha256: hash(oldUnit), siblings: [],
  });
  const trial = await first.driver.startTrial({ expectedResourceFingerprint: transaction.transition.platformResourceFingerprint });
  await first.driver.runStartupGate({ trial, observeApplication: async () => ({ applicationEvidenceFingerprint: hex('1'), connectivityObservation: 'last-observed-connected' }) });
  const recovered = driverFixture({ transaction, native: first.native, sessionObject: first.session });
  assert.throws(
    () => recovered.driver.armFinalRestart({ release: release(oldRelease), siblings: [] }),
    (error) => error.code === 'SERVICE_MANUAL_CLEANUP' && error.reason === 'recreated-resource',
  );
});

test('final startup observation refuses a boot epoch change after application evidence', async () => {
  const fixture = driverFixture();
  fixture.driver.publishSuppressedResource({ phase: 'transition-marker-intent', release: release(), expectedCurrentSha256: null, siblings: [] });
  const trial = await fixture.driver.startTrial({});
  await assert.rejects(
    fixture.driver.runStartupGate({
      trial,
      observeApplication: async () => {
        fixture.native.boot = 'linux:00000000-0000-0000-0000-000000000002';
        return { applicationEvidenceFingerprint: hex('1'), connectivityObservation: 'last-observed-connected' };
      },
    }),
    (error) => error.code === 'SERVICE_TRIAL_NOT_OBSERVED' && error.reason === 'boot-mismatch',
  );
});

test('final activation observation refuses epoch drift after daemon reload', async () => {
  const fixture = driverFixture();
  fixture.driver.publishSuppressedResource({ phase: 'transition-marker-intent', release: release(), expectedCurrentSha256: null, siblings: [] });
  const trial = await fixture.driver.startTrial({});
  await fixture.driver.runStartupGate({ trial, observeApplication: async () => ({ applicationEvidenceFingerprint: hex('1'), connectivityObservation: 'last-observed-connected' }) });
  fixture.native.mutateOnReload = true;
  assert.throws(
    () => fixture.driver.armFinalRestart({ release: release(), siblings: [] }),
    (error) => error.code === 'SERVICE_STALE' && error.reason === 'boot-mismatch',
  );
});

test('final activation rechecks invocation after the manager probe', async () => {
  const fixture = driverFixture();
  fixture.driver.publishSuppressedResource({ phase: 'transition-marker-intent', release: release(), expectedCurrentSha256: null, siblings: [] });
  const trial = await fixture.driver.startTrial({});
  await fixture.driver.runStartupGate({ trial, observeApplication: async () => ({ applicationEvidenceFingerprint: hex('1'), connectivityObservation: 'last-observed-connected' }) });
  const finalProbe = fixture.native.managerProbeCount + 2;
  fixture.native.afterManagerProbe = () => {
    if (fixture.native.managerProbeCount === finalProbe) {
      fixture.native.process.invocation = 'f'.repeat(32);
      fixture.native.afterManagerProbe = null;
    }
  };
  assert.throws(
    () => fixture.driver.armFinalRestart({ release: release(), siblings: [] }),
    (error) => error.code === 'SERVICE_STALE' && error.reason === 'epoch-lost',
  );
  assert.equal(sessionHasActivationObserved(fixture.session), true);
});

for (const [label, mutate] of [
  ['InvocationID', (native) => { native.process.invocation = 'f'.repeat(32); }],
  ['boot', (native) => { native.boot = 'linux:00000000-0000-0000-0000-000000000002'; }],
  ['cgroup tree', (native) => { native.cgroupTree = hex('d'); }],
  ['journal cursor', (native) => { native.cursor = 'fake-2'; }],
]) {
  test(`startup final policy probe rechecks mutated ${label} before publishing`, async () => {
    const fixture = driverFixture();
    fixture.driver.publishSuppressedResource({ phase: 'transition-marker-intent', release: release(), expectedCurrentSha256: null, siblings: [] });
    const trial = await fixture.driver.startTrial({});
    const finalPolicyProbe = fixture.native.managerProbeCount + 3;
    fixture.native.afterManagerProbe = () => {
      if (fixture.native.managerProbeCount === finalPolicyProbe) {
        mutate(fixture.native);
        fixture.native.afterManagerProbe = null;
      }
    };
    await assert.rejects(
      fixture.driver.runStartupGate({ trial, observeApplication: async () => ({ applicationEvidenceFingerprint: hex('1'), connectivityObservation: 'last-observed-connected' }) }),
      (error) => error.code === 'SERVICE_TRIAL_NOT_OBSERVED' && ['epoch-lost', 'boot-mismatch'].includes(error.reason),
    );
    assert.equal(fixture.session.state.entries.some((entry) => entry.phase === 'startup-observed'), false);
  });
}

for (const [label, mutate] of [
  ['InvocationID', (native) => { native.process.invocation = 'f'.repeat(32); }],
  ['boot', (native) => { native.boot = 'linux:00000000-0000-0000-0000-000000000002'; }],
  ['cgroup tree', (native) => { native.cgroupTree = hex('d'); }],
  ['journal cursor', (native) => { native.cursor = 'fake-2'; }],
]) {
  test(`activation final policy probe rechecks mutated ${label} before publishing`, async () => {
    const fixture = driverFixture();
    fixture.driver.publishSuppressedResource({ phase: 'transition-marker-intent', release: release(), expectedCurrentSha256: null, siblings: [] });
    const trial = await fixture.driver.startTrial({});
    await fixture.driver.runStartupGate({ trial, observeApplication: async () => ({ applicationEvidenceFingerprint: hex('1'), connectivityObservation: 'last-observed-connected' }) });
    const finalPolicyProbe = fixture.native.managerProbeCount + (label === 'journal cursor' ? 6 : 5);
    fixture.native.afterManagerProbe = () => {
      if (fixture.native.managerProbeCount === finalPolicyProbe) {
        mutate(fixture.native);
        fixture.native.afterManagerProbe = null;
      }
    };
    assert.throws(
      () => fixture.driver.armFinalRestart({ release: release(), siblings: [] }),
      (error) => error.code === 'SERVICE_STALE' && ['epoch-lost', 'boot-mismatch'].includes(error.reason),
    );
    assert.equal(sessionHasActivationObserved(fixture.session), true);
  });
}

function sessionHasActivationObserved(session) {
  return session.state.entries.some((entry) => entry.phase === 'activation-observed' && entry.substep === 'observed');
}

test('missing and unknown manager properties fail closed', () => {
  const missing = driverFixture();
  missing.native.managerMutator = (manager) => { delete manager.NeedDaemonReload; };
  assert.throws(() => missing.driver.probe(), (error) => error.code === 'SERVICE_IO_FAILED');
  const unknown = driverFixture();
  unknown.native.managerMutator = (manager) => { manager.ConditionResult = 'unknown'; };
  assert.equal(unknown.driver.probe().platformPhase, null);
});

test('missing effective policy properties fail closed before start', () => {
  const fixture = driverFixture();
  fixture.driver.publishSuppressedResource({ phase: 'transition-marker-intent', release: release(), expectedCurrentSha256: null, siblings: [] });
  fixture.native.managerMutator = (manager) => { delete manager.WorkingDirectory; };
  assert.throws(() => fixture.driver.probe(), (error) => error.code === 'SERVICE_IO_FAILED');
});

test('normalized manager policy accepts systemd ExecStart form but refuses partial cgroup facts', async () => {
  const fixture = driverFixture();
  fixture.driver.publishSuppressedResource({ phase: 'transition-marker-intent', release: release(), expectedCurrentSha256: null, siblings: [] });
  fixture.native.managerMutator = (manager) => {
    manager.ExecStart = '{ path=/usr/bin/node ; argv[]=/usr/bin/node /srv/releases/current/daemon.js ; ignore_errors=no ; }';
  };
  assert.equal(fixture.driver.probe().platformPhase, 'trial');
  fixture.native.managerMutator = null;
  fixture.native.cgroupPartial = true;
  await assert.rejects(fixture.driver.startTrial({}), (error) => error.code === 'SERVICE_TRIAL_NOT_OBSERVED');
});

test('EnvironmentFiles requires the systemd a(sb) shape and non-optional files', () => {
  const fixture = driverFixture();
  fixture.driver.publishSuppressedResource({ phase: 'transition-marker-intent', release: release(), expectedCurrentSha256: null, siblings: [] });
  fixture.native.managerMutator = (manager) => {
    manager.EnvironmentFiles = '{ path=/etc/gjc-remote/bot.env ; ignore_errors=yes ; }';
  };
  assert.equal(fixture.driver.probe().platformPhase, null);
});

test('activation refuses cgroup tree drift at the final observation boundary', async () => {
  const fixture = driverFixture();
  fixture.driver.publishSuppressedResource({ phase: 'transition-marker-intent', release: release(), expectedCurrentSha256: null, siblings: [] });
  const trial = await fixture.driver.startTrial({});
  await fixture.driver.runStartupGate({ trial, observeApplication: async () => ({ applicationEvidenceFingerprint: hex('1'), connectivityObservation: 'last-observed-connected' }) });
  fixture.native.cgroupMutator = (native) => { native.cgroupTree = hex('d'); };
  assert.throws(() => fixture.driver.armFinalRestart({ release: release(), siblings: [] }),
    (error) => error.code === 'SERVICE_STALE' && error.reason === 'epoch-lost');
  assert.equal(sessionHasActivationObserved(fixture.session), false);
});

test('activation refuses a startup receipt from another transaction', async () => {
  const fixture = driverFixture();
  fixture.driver.publishSuppressedResource({ phase: 'transition-marker-intent', release: release(), expectedCurrentSha256: null, siblings: [] });
  const trial = await fixture.driver.startTrial({});
  await fixture.driver.runStartupGate({ trial, observeApplication: async () => ({ applicationEvidenceFingerprint: hex('1'), connectivityObservation: 'last-observed-connected' }) });
  fixture.session.state.proof = { ...fixture.session.state.proof, transactionId: 'tx-foreign' };
  assert.throws(() => fixture.driver.armFinalRestart({ release: release(), siblings: [] }),
    (error) => error.code === 'SERVICE_STALE' && error.reason === 'startup-receipt-invalidated');
});

test('recovery refuses a resource fingerprint outside transaction T', async () => {
  const fixture = driverFixture();
  fixture.driver.publishSuppressedResource({ phase: 'transition-marker-intent', release: release(), expectedCurrentSha256: null, siblings: [] });
  await fixture.driver.startTrial({});
  const map = fixture.native.mapFor(fixture.native.serviceKey);
  map.get('bot-unit').bytes = renderLinuxBotUnit(fakeTemplates(), {
    configuration: botConfiguration,
    entrypointPath: '/srv/releases/current/daemon.js',
    restart: 'no',
    releaseFingerprint: hex('c'),
  });
  assert.deepEqual(fixture.driver.recoverTrialState(), {
    classification: 'manual-cleanup',
    phase: 'trial-start-observed',
    reason: 'resource-drift',
  });
});

test('driver pins template bytes against caller mutation', () => {
  const templates = fakeTemplates();
  const original = Buffer.from(templates.daemonTemplate);
  const fixture = driverFixture({ component: 'daemon', serviceKey: `daemon-host-${'1'.repeat(64)}`, templates });
  templates.daemonTemplate.fill(0);
  assert.equal(linuxDaemonTemplateFingerprint(original), linuxDaemonTemplateFingerprint(fixture.driver.probe().objects.template?.bytes ?? original));
  fixture.driver.publishSuppressedResource({ phase: 'transition-marker-intent', release: release(), expectedCurrentSha256: null, siblings: [] });
  assert.equal(fixture.native.objects.get('__shared__').get('daemon-template').bytes.equals(original), true);
});

test('unit path values containing spaces are explicitly refused', () => {
  assert.throws(() => renderLinuxBotUnit(fakeTemplates(), {
    configuration: { ...botConfiguration, workingDirectory: '/srv/gjc remote-bot' },
    entrypointPath: '/srv/releases/current/bot.js', restart: 'no', releaseFingerprint: hex('a'),
  }), (error) => error.code === 'SERVICE_INVALID');
});

test('shared template removal requires the pending G004 opaque store receipt', () => {
  const fixture = driverFixture({ component: 'daemon', serviceKey: `daemon-host-${'1'.repeat(64)}` });
  assert.throws(() => fixture.driver.removeSharedTemplate({
    evidence: { kind: 'linux-shared-template-zero-references/v1', templateFingerprint: hash(fixture.native.sharedTemplate ?? fakeTemplates().daemonTemplate) },
  }), (error) => error.code === 'SERVICE_PENDING' && error.reason === 'template-referenced');
});

test('each publish mutation has an independent action edge', () => {
  const fixture = driverFixture();
  fixture.driver.publishSuppressedResource({
    phase: 'transition-marker-intent', release: release(),
    expectedCurrentSha256: null, siblings: [],
  });
  const edges = fixture.session.state.entries
    .filter((entry) => entry.phase === 'transition-marker-intent')
    .map((entry) => entry.substep);
  assert.deepEqual(edges, ['observed', 'intent', 'action', 'observed', 'intent', 'action', 'observed']);
  assert.deepEqual(
    fixture.native.calls.filter((call) => call[0] === 'publish_linux_service_object' ||
      (call[0] === 'invoke' && call[2] === 'daemon-reload'))
      .map((call) => call[0] === 'invoke' ? 'daemon-reload' : call[1]),
    ['bot-unit', 'daemon-reload'],
  );
});

test('a fresh controller refuses an action head without live action and identity receipts', () => {
  const native = new FakeLinuxNative();
  const transaction = transactionFixture();
  const session = sessionFixture(transaction);
  let failObserved = true;
  const faultySession = {
    ...session,
    appendJournal(entry) {
      if (failObserved && entry.phase === 'transition-marker-intent' && entry.substep === 'observed' &&
          session.state.entries.length > 2) {
        failObserved = false;
        throw new Error('simulated crash after native call');
      }
      session.appendJournal(entry);
    },
  };
  const first = driverFixture({ native, transaction, sessionObject: faultySession });
  assert.throws(() => first.driver.publishSuppressedResource({
    phase: 'transition-marker-intent', release: release(),
    expectedCurrentSha256: null, siblings: [],
  }), /simulated crash/);
  const publishesBeforeRecovery = native.calls.filter((call) => call[0] === 'publish_linux_service_object').length;
  native.mapFor('bot').get('bot-unit').identity = fakePhysicalIdentity('recreated-after-crash');
  const recovered = driverFixture({ native, transaction, sessionObject: faultySession });
  assert.throws(() => recovered.driver.publishSuppressedResource({
    phase: 'transition-marker-intent', release: release(),
    expectedCurrentSha256: null, siblings: [],
  }), (error) => error.code === 'SERVICE_MANUAL_CLEANUP' &&
    error.reason === 'recreated-resource' && error.writes === 0);
  assert.equal(
    native.calls.filter((call) => call[0] === 'publish_linux_service_object').length,
    publishesBeforeRecovery,
  );
});

test('cgroup identity replacement invalidates the startup epoch before application evidence', async () => {
  const fixture = driverFixture();
  fixture.driver.publishSuppressedResource({ phase: 'transition-marker-intent', release: release(), expectedCurrentSha256: null, siblings: [] });
  const trial = await fixture.driver.startTrial({});
  fixture.native.cgroupMutator = (native) => { native.cgroupIdentity = { device: 'foreign-device', inode: 'foreign-inode' }; };
  await assert.rejects(
    fixture.driver.runStartupGate({
      trial,
      observeApplication: async () => ({ applicationEvidenceFingerprint: hex('1'), connectivityObservation: 'last-observed-connected' }),
    }),
    (error) => error.code === 'SERVICE_TRIAL_NOT_OBSERVED' && error.reason === 'epoch-lost',
  );
});

test('fresh recovery rejects platform evidence after a journal cursor drift', async () => {
  const first = driverFixture();
  first.driver.publishSuppressedResource({ phase: 'transition-marker-intent', release: release(), expectedCurrentSha256: null, siblings: [] });
  const trial = await first.driver.startTrial({});
  await first.driver.runStartupGate({
    trial,
    observeApplication: async () => ({ applicationEvidenceFingerprint: hex('1'), connectivityObservation: 'last-observed-connected' }),
  });
  first.native.cursor = 'fake-2';
  const recovered = driverFixture({ native: first.native, transaction: first.transaction, sessionObject: first.session });
  assert.deepEqual(recovered.driver.recoverTrialState(), {
    classification: 'manual-cleanup',
    phase: 'startup-observed',
    reason: 'recreated-resource',
  });
});

test('fresh-controller probe does not mint receipts for subsequent recovery', async () => {
  const first = driverFixture();
  first.driver.publishSuppressedResource({ phase: 'transition-marker-intent', release: release(), expectedCurrentSha256: null, siblings: [] });
  await first.driver.startTrial({});
  const recovered = driverFixture({ native: first.native, transaction: first.transaction, sessionObject: first.session });
  recovered.driver.probe();
  const calls = recovered.native.calls.length;
  assert.deepEqual(recovered.driver.recoverTrialState(), {
    classification: 'manual-cleanup',
    phase: 'trial-start-observed',
    reason: 'recreated-resource',
  });
  assert.equal(recovered.native.calls.length, calls);
});

test('caller expected resource cannot override transaction T', async () => {
  const fixture = driverFixture();
  fixture.driver.publishSuppressedResource({
    phase: 'transition-marker-intent', release: release(),
    expectedCurrentSha256: null, siblings: [],
  });
  const writes = fixture.native.writes;
  await assert.rejects(
    fixture.driver.stopAndQuiesce({ expectedResourceFingerprint: hex('f') }),
    (error) => error.code === 'SERVICE_MANUAL_CLEANUP' && error.reason === 'resource-drift',
  );
  assert.equal(fixture.native.writes, writes);
});

test('malformed Linux physical identity is rejected before mutation', () => {
  const fixture = driverFixture();
  fixture.driver.publishSuppressedResource({
    phase: 'transition-marker-intent', release: release(),
    expectedCurrentSha256: null, siblings: [],
  });
  fixture.native.mapFor('bot').get('bot-unit').identity.device = '01';
  const writes = fixture.native.writes;
  assert.throws(
    () => fixture.driver.probe(),
    (error) => error.code === 'SERVICE_INVALID' && error.writes === writes,
  );
});
