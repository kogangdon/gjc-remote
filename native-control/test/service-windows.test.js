import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import test from 'node:test';
import {
  WINDOWS_DRIVER_LIMITS,
  WINDOWS_SERVICE_ERROR_CODES,
  buildWindowsShawlArgv,
  createWindowsServiceDriver,
  serializeWindowsCommandLine,
  windowsServiceLaunchFingerprint,
  windowsServiceName,
  windowsServiceRuntimePolicyFingerprint,
  windowsServiceResourceFingerprint,
} from '../src/service-windows.js';
import {
  buildServiceCandidateProof,
  buildServiceCursorSet,
  buildServiceFamilyCursor,
  buildServiceFileCursor,
  buildServiceFinalProof,
  buildServiceOldProof,
  buildServicePlatformState,
  buildServiceTransaction,
  buildServiceTransitionProof,
  validateServiceTrialBoundarySuccessor,
} from '@gjc-remote/shared/service-lifecycle-envelope';
import { createServiceStartupObserver } from '../src/service-startup-observer.js';

const hash = (value) => createHash('sha256').update(String(value)).digest('hex');
const hex = (c) => c.repeat(64);
const roles = Object.freeze({
  management: Object.freeze({ kind: 'sid', value: 'S-1-5-21-111111111-222222222-333333333-1001' }),
  bot: Object.freeze({ kind: 'sid', value: 'S-1-5-21-111111111-222222222-333333333-1002' }),
  recovery: Object.freeze({ kind: 'sid', value: 'S-1-5-21-111111111-222222222-333333333-1003' }),
  daemon: Object.freeze({ kind: 'sid', value: 'S-1-5-21-111111111-222222222-333333333-1004' }),
  system: Object.freeze({ kind: 'sid', value: 'S-1-5-18' }),
});
const botConfiguration = Object.freeze({
  runtimePath: 'C:\\Program Files\\nodejs\\node.exe', workingDirectory: 'C:\\GJC\\bot',
  homeDirectory: 'C:\\ProgramData\\GJC\\bot', logDirectory: 'C:\\ProgramData\\GJC\\log\\bot',
  channelsConfig: 'C:\\ProgramData\\GJC\\channels.json', expectedHostSetFingerprint: hex('8'), expectedHostCount: 2,
});
const daemonConfiguration = Object.freeze({
  runtimePath: 'C:\\Program Files\\Bun\\bun.exe', workingDirectory: 'C:\\GJC\\daemon',
  homeDirectory: 'C:\\ProgramData\\GJC\\daemon', logDirectory: 'C:\\ProgramData\\GJC\\log\\daemon',
});
const shawl = Object.freeze({
  path: 'C:\\ProgramData\\GJC\\shawl\\aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\\shawl.exe',
  sha256: hex('a'), runtimeSha256: hex('b'), entrypointSha256: hex('c'),
});
const release = (applicationManifestFingerprint = hex('d'), entrypointPath = 'C:\\ProgramData\\GJC\\releases\\current\\bot.js') => ({ entrypointPath, applicationManifestFingerprint });
const daemonKey = `daemon-host-${'1'.repeat(64)}`;
const policyFinal = 'restart-3x-10s';

function launchFor(component = 'bot', serviceKey = 'bot', configuration = component === 'bot' ? botConfiguration : daemonConfiguration, entrypointPath = component === 'bot' ? release().entrypointPath : 'C:\\ProgramData\\GJC\\releases\\current\\daemon.js') {
  const daemon = component === 'daemon';
  const runtimeConfigRoot = daemon ? `${configuration.workingDirectory}\\runtime-config` : null;
  const launch = {
    supervisorPath: shawl.path,
    supervisorSha256: shawl.sha256,
    workingDirectory: configuration.workingDirectory,
    homeDirectory: configuration.homeDirectory,
    runtimePath: configuration.runtimePath,
    runtimeSha256: shawl.runtimeSha256,
    runtimeVersion: daemon ? '1.4.2' : '26.7.0',
    runtimeSourceRevision: daemon ? '744846f844374847c902b5e7fd59b4342a51ef99' : 'b4f23d3619c98bed09af93a21192f6080197a8c6',
    entrypointPath,
    entrypointSha256: shawl.entrypointSha256,
    bootstrapPath: 'C:\\ProgramData\\GJC\\service-bootstrap.js',
    bootstrapSha256: hex('9'),
    bootstrapClosureFingerprint: hex('7'),
    runtimeConfigRoot,
    runtimeConfigRootIdentityFingerprint: daemon ? hex('2') : null,
    runtimeConfigPath: daemon ? `${runtimeConfigRoot}\\.bunfig.toml` : null,
    runtimeConfigSha256: daemon ? 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855' : null,
    runtimeConfigIdentityFingerprint: daemon ? hex('3') : null,
    sdkProfilePath: daemon ? 'C:\\ProgramData\\GJC\\daemon-profile' : null,
    scopeFingerprint: hex('4'),
    logDirectory: configuration.logDirectory,
    logAs: component === 'bot' ? 'gjc-remote-bot-wrapper' : `gjc-remote-daemon-${serviceKey}-wrapper`,
    logCmdAs: component === 'bot' ? 'gjc-remote-bot-child' : `gjc-remote-daemon-${serviceKey}-child`,
    channelsConfig: component === 'bot' ? configuration.channelsConfig : null,
    effectiveConfigFingerprint: hex('6'),
    configSourceIdentityFingerprint: hex('5'),
  };
  return Object.freeze({ ...launch, runtimePolicyFingerprint: windowsServiceRuntimePolicyFingerprint(launch, component, serviceKey) });
}

function serviceResourceDescriptor(component, serviceKey, launch, applicationManifestFingerprint, phase = 'trial', configuration = component === 'bot' ? botConfiguration : daemonConfiguration) {
  const name = windowsServiceName(component, serviceKey);
  const actions = phase === 'final' ? [
    { type: 'restart', delayMs: 10000 }, { type: 'restart', delayMs: 10000 },
    { type: 'restart', delayMs: 10000 }, { type: 'none', delayMs: 0 },
  ] : [];
  return {
    name, component, serviceKey, serviceRole: component,
    serviceType: 0x10, startType: phase === 'trial' ? 'demand' : 'auto',
    errorControl: 1, tagId: 0,
    binaryPath: serializeWindowsCommandLine(buildWindowsShawlArgv({ component, serviceKey, launch })),
    loadOrderGroup: '', dependencies: [], accountName: roles[component].value,
    displayName: name, description: `gjc-remote:v1:${applicationManifestFingerprint}`,
    delayedAutoStart: false, failureResetPeriod: phase === 'final' ? 600 : 0,
    failureRebootMessage: '', failureCommand: '',
    failureActionsOnNonCrashFailures: false, failureActions: actions,
    failurePolicy: phase === 'final' ? policyFinal : 'none',
    serviceSidType: 1, requiredPrivileges: [], triggerCount: 0,
    preshutdownTimeout: 0, securitySha256: hash('acl'), aclMatches: true,
    accountMatchesRole: true,
    configFingerprint: hash(`${configuration.workingDirectory}|${configuration.homeDirectory}|${configuration.logDirectory}|${configuration.channelsConfig ?? null}`),
    runtimeFingerprint: null,
  };
}

function copy(value) {
  return value === null ? null : { ...value, runtime: { ...value.runtime }, failureActions: [...value.failureActions], dependencies: [...value.dependencies] };
}

class FakeWindowsNative {
  constructor({ component = 'bot', serviceKey = 'bot', configuration = botConfiguration, existing = null, stopPending = false, stopPendingPolls = 0, stopAckWrites = 1, mutateOnMutateOpen = false } = {}) {
    this.component = component; this.serviceKey = serviceKey; this.configuration = configuration; this.roles = roles;
    this.stopPendingMode = stopPending; this.stopPendingPolls = stopPendingPolls; this.stopPendingActive = false; this.stopAckWrites = stopAckWrites;
    this.mutateOnMutateOpen = mutateOnMutateOpen;
    this.boot = 'win32:1'; this.service = existing === null ? null : this.normalize(existing); this.process = null; this.nextPid = 5000;
    // Native log observer model: append-only wrapper/child logs, a boot tick
    // clock, and cursor sets built through the shared envelope.
    this.tick = 10_000; this.logs = { wrapper: Buffer.alloc(0), child: Buffer.alloc(0) }; this.cursors = new Map();
    this.readyMode = 'ready'; this.pageBytes = Number.POSITIVE_INFINITY; this.observerSeq = 0;
    this.calls = []; this.writes = 0; this.faults = new Map(); this.facade = Object.freeze(Object.fromEntries([
      'open_win32_service', 'close_win32_service', 'query_win32_service', 'plan_win32_service_resource', 'create_win32_service_disabled',
      'protect_win32_service', 'set_win32_service_marker', 'configure_win32_service_launch',
      'set_win32_service_start_type', 'set_win32_service_failure_actions', 'set_win32_service_failure_actions_flag',
      'start_win32_service', 'stop_win32_service', 'delete_win32_service', 'terminate_win32_service_tree',
      'read_boot_id', 'read_process_facts', 'enumerate_process_tree', 'read_file_facts_no_follow',
      'read_win32_boot_clock', 'open_win32_service_log_observer', 'read_win32_service_log_observer', 'close_service_handle',
    ].map((name) => {
      if (name === 'open_win32_service') return [name, (serviceName, serviceRole, access) => this.open_win32_service(serviceName, serviceRole, this.roles, access)];
      if (name === 'plan_win32_service_resource') return [name, (serviceName, serviceRole, launch, applicationManifestFingerprint, phase) => this.plan_win32_service_resource(serviceName, serviceRole, launch, applicationManifestFingerprint, phase, this.roles)];
      if (name === 'create_win32_service_disabled') return [name, (serviceName, serviceRole, launch, servicePassword) => this.create_win32_service_disabled(serviceName, serviceRole, launch, servicePassword, this.roles)];
      return [name, this[name].bind(this)];
    })));
  }

  normalize(value) {
    const normalized = { serviceType: 0x10, errorControl: 1, tagId: 0, loadOrderGroup: '', dependencies: [], accountName: value.serviceRole, displayName: value.name, delayedAutoStart: false, failureResetPeriod: 0, failureRebootMessage: '', failureCommand: '', failureActionsOnNonCrashFailures: false, serviceSidType: 1, requiredPrivileges: [], triggerCount: 0, preshutdownTimeout: 0, securitySha256: hash('acl'), aclMatches: true, accountMatchesRole: true, ...value, runtime: { controlsAccepted: 0, win32ExitCode: 0, serviceExitCode: 0, checkpoint: 0, waitHint: 0, serviceFlags: 0, ...value.runtime } };
    delete normalized.runtimeFingerprint;
    return normalized;
  }

  fault(name, error = { code: 'SERVICE_IO_FAILED', writes: 0 }) { this.faults.set(name, error); }
  call(name, args) {
    this.calls.push([name, ...args]);
    const fault = this.faults.get(name);
    if (fault) { this.faults.delete(name); const error = new Error(`${name} fault`); Object.assign(error, fault); throw error; }
  }
  result(writes = 0, value = undefined) { this.writes += writes; return value === undefined ? { writes } : { ...value, writes }; }
  snapshot() {
    if (this.service === null) return null;
    const service = copy(this.service);
    // Native snapshots carry only SNAPSHOT_KEYS; descriptor-only identity
    // fields are never reported by query_win32_service.
    delete service.component;
    delete service.serviceKey;
    delete service.runtimeFingerprint;
    delete service.runtime.startTime;
    if (this.process !== null) {
      if (this.stopPendingMode && this.stopPendingActive && this.stopPendingPolls > 0) {
        this.stopPendingPolls -= 1;
        if (this.stopPendingPolls === 0) { this.process = null; service.runtime = { ...service.runtime, state: 'stopped', processId: 0, startTime: '', fingerprint: hash('runtime') }; }
        else service.runtime = { ...service.runtime, state: 'stop-pending', processId: this.process.pid, startTime: this.process.startTime, fingerprint: service.runtime.fingerprint };
      } else service.runtime = { ...service.runtime, state: 'running', processId: this.process.pid, startTime: this.process.startTime, fingerprint: service.runtime.fingerprint };
    } else if (service.runtime.processId > 0) {
      // The SCM snapshot reports the wrapper as stopped after controller loss;
      // retain no stale PID that would make the driver demand process facts.
      service.runtime = { ...service.runtime, state: 'stopped', processId: 0, startTime: '', fingerprint: hash('runtime') };
    }
    delete service.runtime.startTime;
    return service;
  }
  open_win32_service(name, serviceRole, nativeRoles, access) {
    this.call('open_win32_service', [name, serviceRole, nativeRoles, access]);
    if (this.service !== null && this.service.serviceRole !== this.component) {
      const error = new Error('foreign owner'); Object.assign(error, { code: 'SERVICE_ACCESS_DENIED', writes: 0, ambiguous: true }); throw error;
    }
    if (access === 'mutate' && this.mutateOnMutateOpen && this.service !== null) {
      this.mutateOnMutateOpen = false;
      this.service.configFingerprint = hash('mutation-between-probes');
    }
    return this.service === null ? null : { name, access };
  }
  close_win32_service(handle) { this.call('close_win32_service', [handle]); return this.result(0); }
  query_win32_service(handle) { this.call('query_win32_service', [handle]); return this.snapshot(); }
  plan_win32_service_resource(name, serviceRole, launch, applicationManifestFingerprint, phase, nativeRoles) {
    this.call('plan_win32_service_resource', [...arguments]);
    const descriptor = serviceResourceDescriptor(this.component, this.serviceKey, launch, applicationManifestFingerprint, phase, this.configuration);
    return { descriptor, configFingerprint: descriptor.configFingerprint, writes: 0 };
  }
  create_win32_service_disabled(name, serviceRole, launch, servicePassword, nativeRoles) {
    this.call('create_win32_service_disabled', [...arguments]);
    this.service = { ...serviceResourceDescriptor(this.component, this.serviceKey, launch, hex('0'), 'trial', this.configuration), startType: 'disabled', description: '', runtime: { state: 'stopped', controlsAccepted: 0, win32ExitCode: 0, serviceExitCode: 0, checkpoint: 0, waitHint: 0, processId: 0, serviceFlags: 0, fingerprint: hash('runtime') } };
    return this.result(1, { handle: { name } });
  }
  protect_win32_service(handle, config, runtime, description) { this.call('protect_win32_service', [handle, config, runtime, description]); this.service.description = description; return this.result(1); }
  set_win32_service_marker(handle, config, runtime, description) { this.call('set_win32_service_marker', [handle, config, runtime, description]); this.service.description = description; return this.result(1); }
  configure_win32_service_launch(handle, config, runtime, launch) {
    this.call('configure_win32_service_launch', [...arguments].slice(1)); this.service.binaryPath = serializeWindowsCommandLine(buildWindowsShawlArgv({ component: this.component, serviceKey: this.serviceKey, launch })); this.service.configFingerprint = hash(`${this.configuration.workingDirectory}|${this.configuration.homeDirectory}|${this.configuration.logDirectory}|${this.configuration.channelsConfig ?? null}`); this.service.runtimeFingerprint = null; return this.result(1);
  }
  set_win32_service_start_type(handle, config, runtime, type) { this.call('set_win32_service_start_type', [handle, config, runtime, type]); this.service.startType = type; return this.result(1); }
  set_win32_service_failure_actions(handle, config, runtime, policy) { this.call('set_win32_service_failure_actions', [handle, config, runtime, policy]); this.service.failurePolicy = policy; this.service.failureResetPeriod = policy === 'none' ? 0 : 600; this.service.failureActions = policy === 'none' ? [] : [{ type: 'restart', delayMs: 10000 }, { type: 'restart', delayMs: 10000 }, { type: 'restart', delayMs: 10000 }, { type: 'none', delayMs: 0 }]; return this.result(1); }
  set_win32_service_failure_actions_flag(handle, config, runtime, enabled) { this.call('set_win32_service_failure_actions_flag', [handle, config, runtime, enabled]); this.service.failureActionsOnNonCrashFailures = enabled; return this.result(1); }
  start_win32_service(handle, config, runtime) {
    this.call('start_win32_service', [handle, config, runtime]); this.nextPid += 1;
    const pid = this.nextPid;
    this.process = { pid, startTime: `start-${pid}`, fingerprint: hash(`epoch-${pid}`), treeFingerprint: hash(`tree-${pid}`), wrapperEpoch: hash(`wrapper-epoch-${pid}`), childEpoch: hash(`child-epoch-${pid}`), logTree: hash(`log-tree-${pid}`) };
    this.service.runtime = { ...this.service.runtime, state: 'running', processId: pid, startTime: this.process.startTime, fingerprint: hash('runtime') };
    this.appendLog('wrapper', `shawl: started ${pid}\n`);
    if (this.readyMode !== 'none') this.appendLog('child', `${JSON.stringify(this.readyEvent(this.readyMode === 'foreign' ? hex('0') : this.process.childEpoch))}\n`);
    return this.result(1);
  }
  appendLog(family, text) { this.logs[family] = Buffer.concat([this.logs[family], Buffer.from(text, 'utf8')]); }
  readyEvent(processEpochFingerprint) {
    const state = this.component === 'bot'
      ? { listener: 'listening', discord: 'connected', expectedHostSetFingerprint: hex('8'), expectedHostCount: 2, connectedHostSetFingerprint: hex('8'), connectedHostCount: 2 }
      : { targetFingerprint: hex('9'), connectionGeneration: 1, attemptedGeneration: 1, acceptedGeneration: 1, registration: 'accepted' };
    return { schemaVersion: 1, kind: 'service-startup-observation', component: this.component, serviceKey: this.serviceKey, processEpochFingerprint, sequence: 1, effectiveConfigFingerprint: hex('6'), configSourceIdentityFingerprint: hex('5'), state };
  }
  bootFingerprint() { return hash(`boot-${this.boot}`); }
  clock() { return { schemaVersion: 1, bootFingerprint: this.bootFingerprint(), tickMs: this.tick, writes: 0 }; }
  epochFields() {
    return this.process === null
      ? { wrapperEpochFingerprint: null, childEpochFingerprint: null, treeFingerprint: null }
      : { wrapperEpochFingerprint: this.process.wrapperEpoch, childEpochFingerprint: this.process.childEpoch, treeFingerprint: this.process.logTree };
  }
  logCursor(consumed) {
    const base = this.component === 'bot' ? 'gjc-remote-bot' : `gjc-remote-daemon-${this.serviceKey}`;
    const family = (name) => {
      const bytes = this.logs[name]; const offset = consumed[name]; const present = bytes.length > 0;
      const prefix = bytes.subarray(0, offset); const partial = offset - (prefix.lastIndexOf(0x0a) + 1);
      return buildServiceFamilyCursor({
        family: name, baseName: `${base}-${name}`, directoryIdentityFingerprint: hash(`dir-${name}`),
        files: present ? [buildServiceFileCursor({ identityFingerprint: hash(`file-${name}`), logicalStartOffset: 0, observedLength: offset, prefixSha256: createHash('sha256').update(prefix).digest('hex') })] : [],
        nextLogicalOffset: offset, partialLineBytes: present ? partial : 0, absenceFingerprint: present ? null : hash(`absent-${name}`),
      });
    };
    const cursor = buildServiceCursorSet({ bootFingerprint: this.bootFingerprint(), serviceKey: this.serviceKey, configFingerprint: hex('6'), families: [family('wrapper'), family('child')] });
    this.cursors.set(cursor.cursorFingerprint, { ...consumed });
    return cursor;
  }
  read_win32_boot_clock() { this.call('read_win32_boot_clock', []); this.tick += 1; return this.clock(); }
  open_win32_service_log_observer(serviceHandle, launch, resumeCursor) {
    this.call('open_win32_service_log_observer', [serviceHandle, launch, resumeCursor]); this.tick += 1;
    let consumed;
    if (resumeCursor === null) consumed = { wrapper: this.logs.wrapper.length, child: this.logs.child.length };
    else {
      consumed = this.cursors.get(resumeCursor.cursorFingerprint);
      if (!consumed || resumeCursor.bootFingerprint !== this.bootFingerprint()) { const error = new Error('cursor CAS'); Object.assign(error, { code: 'SERVICE_STALE', writes: 0 }); throw error; }
    }
    const cursor = resumeCursor ?? this.logCursor(consumed);
    this.observerSeq += 1;
    const handle = { observer: this.observerSeq, consumed: { ...consumed }, cursor, epoch: this.process?.childEpoch ?? null, closed: false };
    return { handle, clock: this.clock(), cursor, ...this.epochFields(), writes: 0 };
  }
  read_win32_service_log_observer(handle, expectedCursorFingerprint, maxBytes) {
    this.call('read_win32_service_log_observer', [handle, expectedCursorFingerprint, maxBytes]);
    const stale = () => { const error = new Error('observer stale'); Object.assign(error, { code: 'SERVICE_STALE', writes: 0 }); throw error; };
    if (handle.closed || expectedCursorFingerprint !== handle.cursor.cursorFingerprint) stale();
    if (handle.epoch !== null && (this.process?.childEpoch ?? null) !== handle.epoch) stale();
    this.tick += 250;
    const beforeCursor = handle.cursor; const chunks = []; let budget = Math.min(maxBytes, this.pageBytes);
    for (const family of ['wrapper', 'child']) {
      const bytes = this.logs[family]; const start = handle.consumed[family]; const take = Math.min(bytes.length - start, budget);
      if (take > 0) { chunks.push({ family, fileIdentityFingerprint: hash(`file-${family}`), logicalOffset: start, bytes: Buffer.from(bytes.subarray(start, start + take)) }); handle.consumed[family] += take; budget -= take; }
    }
    handle.cursor = this.logCursor(handle.consumed);
    const eof = handle.consumed.wrapper === this.logs.wrapper.length && handle.consumed.child === this.logs.child.length;
    return { clock: this.clock(), beforeCursor, afterCursor: handle.cursor, ...this.epochFields(), chunks, eof, continuity: 'complete', writes: 0 };
  }
  close_service_handle(handle) { this.call('close_service_handle', [handle]); handle.closed = true; return this.result(0); }
  stop_win32_service(handle, config, runtime) {
    this.call('stop_win32_service', [handle, config, runtime]);
    if (this.stopPendingMode) { this.stopPendingActive = true; this.service.runtime = { ...this.service.runtime, state: 'stop-pending' }; return this.result(this.stopAckWrites, { tree: 'survivor', forced: false, terminated: 0 }); }
    if (!this.retainTree) { this.process = null; this.service.runtime = { ...this.service.runtime, state: 'stopped', processId: 0, startTime: '', fingerprint: hash('runtime') }; }
    return this.result(1, { tree: this.retainTree ? 'survivor' : 'empty', forced: false, terminated: this.retainTree ? 0 : 1 });
  }
  delete_win32_service(handle, config, runtime) { this.call('delete_win32_service', [handle, config, runtime]); if (!this.retainAfterDelete) this.service = null; this.process = null; return this.result(1, { deletionPending: this.retainAfterDelete === true }); }
  terminate_win32_service_tree(handle, config, pid, startTime, executable, owner, treeFingerprint) { this.call('terminate_win32_service_tree', [handle, config, pid, startTime, executable, owner, treeFingerprint]); this.process = null; this.service.runtime = { ...this.service.runtime, state: 'stopped', processId: 0, startTime: '', fingerprint: hash('runtime') }; return this.result(1, { tree: 'empty', forced: true, terminated: 1 }); }
  read_boot_id() { this.call('read_boot_id', []); return this.boot; }
  read_process_facts(pid) { this.call('read_process_facts', [pid]); if (!this.process || this.process.pid !== pid) return null; return { pid, startTime: this.process.startTime, executable: shawl.path, owner: roles[this.component].value, state: 'running' }; }
  enumerate_process_tree(pid, startTime, executable, owner) {
    this.call('enumerate_process_tree', [pid, startTime, executable, owner]);
    if (!this.process || pid !== this.process.pid) return { processes: [], processCount: 0, treeFingerprint: hash('empty') };
    if (this.badTree) return { processes: [], processCount: 1, treeFingerprint: this.process.treeFingerprint };
    return { processes: [{ pid, startTime, executable, owner }], processCount: 1, treeFingerprint: this.process.treeFingerprint };
  }
  read_file_facts_no_follow(path) { this.call('read_file_facts_no_follow', [path]); return { path, size: 0, sha256: hash(path) }; }
}

function sessionFixture(transaction, references = { present: false, value: null }) {
  const state = { entries: [transaction], proof: null, boundary: null };
  return {
    platform: 'win32', architecture: 'x64', component: transaction.component, serviceKey: transaction.serviceKey,
    readJournal: () => ({ entries: [...state.entries], pending: state.pending ?? null }), appendJournal: (entry) => { state.entries.push(entry); },
    readStartupProof: () => state.proof === null ? { present: false, value: null } : { present: true, value: state.proof },
    publishStartupProof: (proof) => { state.proof = proof; }, readReferences: () => references,
    readTrialBoundary: () => state.boundary === null ? { present: false, value: null } : { present: true, value: state.boundary },
    publishTrialBoundary: (boundary, prior) => {
      // Mirror the store CAS: the caller's prior receipt must be the current
      // head, and a revision must be a validated successor.
      if ((prior?.present ? prior.value.boundaryFingerprint : null) !== (state.boundary?.boundaryFingerprint ?? null)) { const error = new Error('boundary CAS'); error.code = 'SERVICE_STALE'; throw error; }
      if (state.boundary !== null) validateServiceTrialBoundarySuccessor(state.boundary, boundary);
      state.boundary = boundary;
    },
    state,
  };
}

const expectedStateFor = (component) => component === 'bot' ? { expectedHostSetFingerprint: hex('8'), expectedHostCount: 2 } : { targetFingerprint: hex('9') };
// Production shape: the entrypoint injects a factory that binds the canonical
// startup observer to the driver's protected trial observation.
const observeWith = (component = 'bot') => (trialObservation) => createServiceStartupObserver({ trialObservation, expectedState: expectedStateFor(component) }).observeApplication;

function transactionFixture({ component = 'bot', serviceKey = 'bot', applicationManifestFingerprint = hex('d'), expectedAfterResourceFingerprint = undefined } = {}) {
  const old = buildServiceOldProof({ disposition: 'absent', manifestFingerprint: null, resourceProof: null, applicationManifestFingerprint: null, shawlManifestFingerprint: null, serviceGeneration: 0, activation: 'disabled-not-startable' }, 'win32');
  const candidate = buildServiceCandidateProof({ disposition: 'release', applicationManifestFingerprint, shawlManifestFingerprint: shawl.sha256, releaseSequence: 1, releaseTreeFingerprint: hex('e'), compatibilityFingerprint: hex('f') }, 'win32');
  const configuration = component === 'bot' ? botConfiguration : daemonConfiguration;
  const launch = launchFor(component, serviceKey, configuration,
    component === 'bot' ? release(applicationManifestFingerprint).entrypointPath : `C:\\ProgramData\\GJC\\releases\\current\\daemon.js`);
  const resource = windowsServiceResourceFingerprint(serviceResourceDescriptor(
    component, serviceKey, launch, applicationManifestFingerprint, 'trial', configuration));
  const transition = buildServiceTransitionProof({ oldFingerprint: old.oldFingerprint, candidateFingerprint: candidate.candidateFingerprint, expectedBeforeResourceFingerprint: null, expectedAfterResourceFingerprint: expectedAfterResourceFingerprint === undefined ? resource : expectedAfterResourceFingerprint, platformResourceFingerprint: resource, platformState: buildServicePlatformState('win32', 'trial') }, 'win32');
  const final = buildServiceFinalProof({ disposition: 'stable', manifestFingerprint: hex('1'), resourceProof: resource, applicationManifestFingerprint, shawlManifestFingerprint: shawl.sha256, serviceGeneration: 1, activation: 'enabled' }, 'win32');
  const fields = { transactionId: `tx-${serviceKey.slice(0, 8)}`, transactionNonce: '1'.repeat(32), operation: 'install', component, serviceKey, platform: 'win32', architecture: 'x64', serviceGeneration: 1, old, candidate, transition, final };
  const prepared = buildServiceTransaction({ ...fields, phase: 'prepared', substep: 'none', previousJournalFingerprint: null });
  return buildServiceTransaction({ ...fields, phase: 'transition-marker-intent', substep: 'observed', previousJournalFingerprint: prepared.transactionFingerprint });
}

function detachedUninstallTransaction(resourceFingerprint) {
  const old = buildServiceOldProof({ disposition: 'stable', manifestFingerprint: hex('1'), resourceProof: resourceFingerprint, applicationManifestFingerprint: hex('d'), shawlManifestFingerprint: shawl.sha256, serviceGeneration: 1, activation: 'enabled' }, 'win32');
  const candidate = buildServiceCandidateProof({ disposition: 'none', applicationManifestFingerprint: null, shawlManifestFingerprint: null, releaseSequence: 0, releaseTreeFingerprint: null, compatibilityFingerprint: null }, 'win32');
  const transition = buildServiceTransitionProof({ oldFingerprint: old.oldFingerprint, candidateFingerprint: candidate.candidateFingerprint, expectedBeforeResourceFingerprint: resourceFingerprint, expectedAfterResourceFingerprint: null, platformResourceFingerprint: resourceFingerprint, platformState: buildServicePlatformState('win32', 'trial') }, 'win32');
  const final = buildServiceFinalProof({ disposition: 'absent', manifestFingerprint: null, resourceProof: null, applicationManifestFingerprint: null, shawlManifestFingerprint: null, serviceGeneration: 0, activation: 'disabled-not-startable' }, 'win32');
  const fields = { transactionId: 'tx-detached', transactionNonce: '2'.repeat(32), operation: 'uninstall', component: 'bot', serviceKey: 'bot', platform: 'win32', architecture: 'x64', serviceGeneration: 2, old, candidate, transition, final };
  const prepared = buildServiceTransaction({ ...fields, phase: 'prepared', substep: 'none', previousJournalFingerprint: hex('0') });
  return buildServiceTransaction({ ...fields, phase: 'trial-start-observed', substep: 'observed', previousJournalFingerprint: prepared.transactionFingerprint });
}

function fixture(options = {}) {
  const component = options.component ?? 'bot'; const serviceKey = options.serviceKey ?? (component === 'bot' ? 'bot' : daemonKey);
  const configuration = options.configuration ?? (component === 'bot' ? botConfiguration : daemonConfiguration);
  const transaction = options.transaction ?? transactionFixture({ component, serviceKey, applicationManifestFingerprint: options.applicationManifestFingerprint });
  const native = new FakeWindowsNative({ component, serviceKey, configuration, existing: options.existing ?? null, stopPending: options.stopPending ?? false, stopPendingPolls: options.stopPendingPolls ?? 0, stopAckWrites: options.stopAckWrites ?? 1, mutateOnMutateOpen: options.mutateOnMutateOpen ?? false });
  const session = sessionFixture(transaction, options.references);
  let now = 1_000_000;
  const launch = launchFor(component, serviceKey, configuration, options.entrypointPath ?? (component === 'bot' ? release().entrypointPath : 'C:\\ProgramData\\GJC\\releases\\current\\daemon.js'));
  const driver = createWindowsServiceDriver({ native: native.facade, session, locks: { artifact: { token: 'artifact' }, sharedTemplate: { token: 'shared' }, serviceKey: { token: 'service' } }, roles, configuration, launch, shawl, servicePassword: options.servicePassword, servicePasswordRequired: options.servicePasswordRequired, clock: () => now, sleep: async (ms) => { now += ms; } });
  return { driver, native, session, transaction, advance: (ms) => { now += ms; } };
}

function freshDriver(f, { component = f.session.component, serviceKey = f.session.serviceKey, configuration = component === 'bot' ? botConfiguration : daemonConfiguration, applicationManifestFingerprint = hex('d'), entrypointPath = 'C:\\ProgramData\\GJC\\releases\\current\\bot.js' } = {}) {
  const launch = launchFor(component, serviceKey, configuration, entrypointPath);
  return createWindowsServiceDriver({ native: f.native.facade, session: f.session, locks: { artifact: { token: 'artifact' }, sharedTemplate: { token: 'shared' }, serviceKey: { token: 'service' } }, roles, configuration, launch, shawl, clock: () => 1_000_000, sleep: async () => {} });
}

// All tests below use only the injected fake facade. No SCM, services, files, or native platform state are touched.
test('projected Windows facade uses public arities and injects roles exactly once', () => {
  const f = fixture();
  assert.equal(f.native.facade.open_win32_service.length, 3);
  assert.equal(f.native.facade.plan_win32_service_resource.length, 5);
  assert.equal(f.native.facade.create_win32_service_disabled.length, 4);
  f.driver.publishSuppressedResource({ phase: 'transition-marker-intent', release: release(), expectedCurrentSha256: null });
  const open = f.native.calls.find(([name]) => name === 'open_win32_service');
  const plan = f.native.calls.find(([name]) => name === 'plan_win32_service_resource');
  const create = f.native.calls.find(([name]) => name === 'create_win32_service_disabled');
  assert.equal(open.length - 1, 4);
  assert.equal(plan.length - 1, 6);
  assert.equal(create.length - 1, 5);
  assert.equal(open[1], 'GJCRemoteBot');
  assert.equal(open[2], 'bot');
  assert.deepEqual(open[3], roles);
  assert.equal(open[4], 'query');
  assert.equal(plan[1], 'GJCRemoteBot');
  assert.equal(plan[2], 'bot');
  assert.equal(plan[5], 'trial');
  assert.deepEqual(plan[6], roles);
  assert.equal(create[1], 'GJCRemoteBot');
  assert.equal(create[2], 'bot');
  assert.deepEqual(create.at(-1), roles);
});

test('Windows service names and exact Shawl argv cover bot and daemon policy', () => {
  assert.equal(windowsServiceName('bot', 'bot'), 'GJCRemoteBot');
  assert.equal(windowsServiceName('daemon', daemonKey), `GJCRemoteDaemon-${daemonKey}`);
  const botLaunch = launchFor('bot', 'bot', botConfiguration);
  const bot = buildWindowsShawlArgv({ component: 'bot', serviceKey: 'bot', launch: botLaunch });
  const botEnvironment = [
    ['HOME', botLaunch.homeDirectory], ['USERPROFILE', botLaunch.homeDirectory],
    ['NODE_OPTIONS', ''], ['NODE_PATH', ''], ['CHANNELS_CONFIG', botLaunch.channelsConfig],
    ['GJC_REMOTE_SERVICE_COMPONENT', 'bot'], ['GJC_REMOTE_SERVICE_KEY', 'bot'],
    ['GJC_REMOTE_SUPERVISOR_SHA256', botLaunch.supervisorSha256],
    ['GJC_REMOTE_RUNTIME_VERSION', botLaunch.runtimeVersion],
    ['GJC_REMOTE_RUNTIME_SOURCE_REVISION', botLaunch.runtimeSourceRevision],
    ['GJC_REMOTE_RUNTIME_SHA256', botLaunch.runtimeSha256],
    ['GJC_REMOTE_ENTRYPOINT_SHA256', botLaunch.entrypointSha256],
    ['GJC_REMOTE_BOOTSTRAP_PATH', botLaunch.bootstrapPath],
    ['GJC_REMOTE_BOOTSTRAP_SHA256', botLaunch.bootstrapSha256],
    ['GJC_REMOTE_BOOTSTRAP_CLOSURE_FINGERPRINT', botLaunch.bootstrapClosureFingerprint],
    ['GJC_REMOTE_RUNTIME_CONFIG_ROOT_IDENTITY_FINGERPRINT', ''],
    ['GJC_REMOTE_RUNTIME_CONFIG_PATH', ''], ['GJC_REMOTE_RUNTIME_CONFIG_SHA256', ''],
    ['GJC_REMOTE_RUNTIME_CONFIG_IDENTITY_FINGERPRINT', ''], ['GJC_REMOTE_SDK_PROFILE_PATH', ''],
    ['GJC_REMOTE_SCOPE_FINGERPRINT', botLaunch.scopeFingerprint],
    ['GJC_REMOTE_EFFECTIVE_CONFIG_FINGERPRINT', botLaunch.effectiveConfigFingerprint],
    ['GJC_REMOTE_CONFIG_SOURCE_IDENTITY_FINGERPRINT', botLaunch.configSourceIdentityFingerprint],
    ['GJC_REMOTE_LAUNCH_FINGERPRINT', windowsServiceLaunchFingerprint(botLaunch, 'bot', 'bot')],
    ['GJC_REMOTE_RUNTIME_POLICY_FINGERPRINT', botLaunch.runtimePolicyFingerprint],
  ];
  assert.deepEqual(bot, [
    shawl.path, 'run', '--name', 'GJCRemoteBot', '--cwd', botLaunch.workingDirectory,
    ...botEnvironment.flatMap(([key, value]) => ['--env', `${key}=${value}`]),
    '--kill-process-tree', '--restart-if-not', '0', '--restart-delay', '10000',
    '--stop-timeout', '30000', '--log-dir', botLaunch.logDirectory,
    '--log-as', botLaunch.logAs, '--log-cmd-as', botLaunch.logCmdAs,
    '--log-rotate', 'bytes=1048576', '--log-retain', '2', '--',
    botLaunch.runtimePath, botLaunch.entrypointPath,
  ]);
  const daemonLaunch = launchFor('daemon', daemonKey, daemonConfiguration,
    'C:\\ProgramData\\GJC\\releases\\current\\daemon.js');
  const daemon = buildWindowsShawlArgv({ component: 'daemon', serviceKey: daemonKey, launch: daemonLaunch });
  assert.deepEqual(daemon.slice(0, 6), [shawl.path, 'run', '--name', `GJCRemoteDaemon-${daemonKey}`, '--cwd', daemonLaunch.workingDirectory]);
  assert.deepEqual(daemon.slice(-5), [daemonConfiguration.runtimePath, '--config', daemonLaunch.runtimeConfigPath, '--no-env-file', daemonLaunch.entrypointPath]);
  assert.ok(daemon.includes(`GJC_CODING_AGENT_DIR=${daemonLaunch.sdkProfilePath}`));
  assert.ok(daemon.includes(`BUN_INSPECT_PRELOAD=${daemonLaunch.bootstrapPath}`));
  assert.ok(daemon.includes(`XDG_CONFIG_HOME=${daemonLaunch.runtimeConfigRoot}`));
  assert.equal(daemon.filter((argument) => argument === '--env').length, 4 + 6 + 20);
});

test('resource identity excludes runtime fingerprints and nested SCM runtime facts', () => {
  const descriptor = { name: 'GJCRemoteBot', component: 'bot', runtimeFingerprint: hex('1'), runtime: { state: 'running', processId: 42, fingerprint: hex('2') } };
  const changed = { ...descriptor, runtimeFingerprint: hex('3'), runtime: { state: 'stopped', processId: 0, fingerprint: hex('4') } };
  assert.equal(windowsServiceResourceFingerprint(descriptor), windowsServiceResourceFingerprint(changed));
});

test('disabled first-create is protected, marked, demand-startable, and has empty failure actions', () => {
  const f = fixture();
  const result = f.driver.publishSuppressedResource({ phase: 'transition-marker-intent', release: release(), expectedCurrentSha256: null });

  assert.equal(result.platformPhase, 'trial');
  assert.equal(f.native.service.startType, 'demand');
  assert.equal(f.native.service.failurePolicy, 'none');
  assert.match(f.native.service.description, /^gjc-remote:v1:[0-9a-f]{64}$/);
  assert.deepEqual(f.native.service.failureActions, []);
  assert.deepEqual(f.native.service.dependencies, []);
  assert.ok(f.driver.writes >= 5);
  const mutations = f.native.calls.filter(([name]) => ['create_win32_service_disabled', 'protect_win32_service', 'set_win32_service_start_type', 'set_win32_service_failure_actions', 'set_win32_service_failure_actions_flag'].includes(name)).map(([name]) => name);
  assert.deepEqual(mutations, ['create_win32_service_disabled', 'protect_win32_service', 'set_win32_service_start_type', 'set_win32_service_failure_actions', 'set_win32_service_failure_actions_flag']);
});

test('same-name foreign or unmarked resources are never adopted', () => {
  const existing = { name: 'GJCRemoteBot', serviceRole: roles.management.value, startType: 'auto', failureActions: [], failurePolicy: 'none', dependencies: [], binaryPath: 'C:/foreign.exe', description: 'foreign service', configFingerprint: hex('1'), runtimeFingerprint: hex('2'), runtime: { state: 'stopped', processId: 0, startTime: '', fingerprint: hex('3') } };
  const f = fixture({ existing });
  assert.throws(() => f.driver.publishSuppressedResource({ phase: 'transition-marker-intent', release: release(), expectedCurrentSha256: null }), (e) => e.code === 'SERVICE_ACCESS_DENIED');
  const foreign = { ...existing, serviceRole: 'bot' }; const g = fixture({ existing: foreign });
  assert.throws(() => g.driver.publishSuppressedResource({ phase: 'transition-marker-intent', release: release(), expectedCurrentSha256: null }), (e) => e.code === 'SERVICE_MANUAL_CLEANUP' && e.reason === 'foreign-resource' && e.writes === 0);
  const unmarked = { ...existing, serviceRole: 'bot', description: '' }; const j = fixture({ existing: unmarked });
  assert.throws(() => j.driver.publishSuppressedResource({ phase: 'transition-marker-intent', release: release(), expectedCurrentSha256: null }), (e) => e.code === 'SERVICE_MANUAL_CLEANUP' && e.reason === 'unmarked-resource');
  const ownedByOther = { ...existing, description: `gjc-remote:v1:${hex('4')}` };
  const h = fixture({ existing: ownedByOther });
  assert.throws(() => h.driver.publishSuppressedResource({ phase: 'transition-marker-intent', release: release(), expectedCurrentSha256: null }), (e) => e.code === 'SERVICE_ACCESS_DENIED');
});

test('trial start requires a fresh wrapper PID, start time, and running state', async () => {
  const f = fixture(); f.driver.publishSuppressedResource({ phase: 'transition-marker-intent', release: release(), expectedCurrentSha256: null });
  const beforePid = f.native.service.runtime.processId;
  const trial = await f.driver.startTrial({});
  assert.ok(trial.wrapper.pid > beforePid); assert.equal(trial.process.facts.startTime, `start-${trial.wrapper.pid}`); assert.equal(f.native.service.runtime.state, 'running');
  assert.equal(f.native.calls.filter(([name]) => name === 'start_win32_service').length, 1);
  const g = fixture(); g.driver.publishSuppressedResource({ phase: 'transition-marker-intent', release: release(), expectedCurrentSha256: null }); g.native.fault('start_win32_service', { code: 'SERVICE_IO_FAILED', writes: 0 });
  await assert.rejects(g.driver.startTrial({}), (e) => e.code === 'SERVICE_IO_FAILED');
});

test('startup gate reduces native observer pages and refuses foreign epochs, epoch changes, and timeouts', async () => {
  const publish = (x) => x.driver.publishSuppressedResource({ phase: 'transition-marker-intent', release: release(), expectedCurrentSha256: null });
  const f = fixture(); publish(f); const trial = await f.driver.startTrial({});
  const boundary = f.session.state.boundary;
  assert.equal(boundary.phase, 'observed'); assert.equal(boundary.revision, 2); assert.equal(boundary.boundaryFingerprint, trial.boundaryFingerprint);
  assert.equal(boundary.initialCursor.families[1].files.length, 0); assert.equal(boundary.wrapperEpochFingerprint, f.native.process.wrapperEpoch);
  const names = f.native.calls.map(([name]) => name);
  // The boundary cursor is captured before StartService; the budget begins there.
  assert.ok(names.indexOf('open_win32_service_log_observer') < names.indexOf('start_win32_service'));
  f.native.pageBytes = 16;
  const proof = await f.driver.runStartupGate({ trial, observeApplication: observeWith() });
  assert.equal(proof.clockKind, 'windows-boot-tick'); assert.equal(proof.boundaryFingerprint, boundary.boundaryFingerprint);
  assert.equal(proof.deadlineTickMs, boundary.deadlineTickMs); assert.equal(proof.bootFingerprint, boundary.bootFingerprint);
  assert.ok(f.native.calls.filter(([name]) => name === 'read_win32_service_log_observer').length > 2);
  assert.ok(f.native.calls.every(([name, ...args]) => name !== 'read_win32_service_log_observer' || args[2] === WINDOWS_DRIVER_LIMITS.logReadBytes));

  const g = fixture(); g.native.readyMode = 'foreign'; publish(g); const gt = await g.driver.startTrial({});
  await assert.rejects(g.driver.runStartupGate({ trial: gt, observeApplication: observeWith() }), (e) => e.code === 'SERVICE_STARTUP_TIMEOUT' && e.reason === 'log-epoch-invalid');
  assert.equal(g.session.state.proof, null); assert.equal(g.native.calls.at(-1)[0], 'close_service_handle');

  const h = fixture(); publish(h); const ht = await h.driver.startTrial({}); h.native.process.childEpoch = hex('0');
  await assert.rejects(h.driver.runStartupGate({ trial: ht, observeApplication: observeWith() }), (e) => e.code === 'SERVICE_STARTUP_TIMEOUT' && e.reason === 'process-epoch-changed');

  const t = fixture(); t.native.readyMode = 'none'; publish(t); const tt = await t.driver.startTrial({});
  await assert.rejects(t.driver.runStartupGate({ trial: tt, observeApplication: observeWith() }), (e) => e.code === 'SERVICE_STARTUP_TIMEOUT' && e.reason === 'startup-receipt-invalidated');
  assert.ok(t.native.tick >= t.session.state.boundary.deadlineTickMs);

  const n = fixture(); publish(n); const nt = await n.driver.startTrial({});
  await assert.rejects(n.driver.runStartupGate({ trial: nt, observeApplication: () => null }), (e) => e.code === 'SERVICE_INVALID');
});

test('fault injection preserves closed error codes and cumulative native writes', () => {
  const f = fixture(); f.native.fault('create_win32_service_disabled', { code: 'SERVICE_IO_FAILED', writes: 3, ambiguous: true });
  assert.throws(() => f.driver.publishSuppressedResource({ phase: 'transition-marker-intent', release: release(), expectedCurrentSha256: null }), (e) => e.code === 'SERVICE_IO_FAILED' && e.writes === 3 && e.ambiguous === true);
  const before = f.driver.writes; assert.equal(before, 3);
  assert.throws(() => f.driver.publishSuppressedResource({ phase: 'bad', release: release(), expectedCurrentSha256: null }), (e) => e.code === 'SERVICE_INVALID' && e.writes === before);
});

test('controller loss, reboot, and changed process epochs classify as retrial', async () => {
  const f = fixture(); f.driver.publishSuppressedResource({ phase: 'transition-marker-intent', release: release(), expectedCurrentSha256: null }); const trial = await f.driver.startTrial({});
  f.native.process = null; assert.equal(f.driver.recoverTrialState().recovery, 'retrial'); assert.equal(f.driver.recoverTrialState().reason, 'controller-loss');
  const g = fixture(); g.driver.publishSuppressedResource({ phase: 'transition-marker-intent', release: release(), expectedCurrentSha256: null }); const gt = await g.driver.startTrial({});
  await g.driver.runStartupGate({ trial: gt, observeApplication: observeWith() }); g.native.boot = 'win32:2'; assert.equal(g.driver.recoverTrialState().reason, 'reboot');
});

test('final activation rechecks the native observer before AUTO and failure actions', async () => {
  const publish = (x) => x.driver.publishSuppressedResource({ phase: 'transition-marker-intent', release: release(), expectedCurrentSha256: null });
  const f = fixture(); publish(f); const trial = await f.driver.startTrial({});
  await f.driver.runStartupGate({ trial, observeApplication: observeWith() });
  f.native.appendLog('child', 'bot: steady\n');
  f.driver.armFinalRestart(); assert.equal(f.native.service.startType, 'auto');
  f.driver.enableFinal(); assert.notEqual(f.native.service.failurePolicy, 'none');

  const g = fixture(); publish(g); const gt = await g.driver.startTrial({});
  await g.driver.runStartupGate({ trial: gt, observeApplication: observeWith() });
  assert.throws(() => freshDriver(g).armFinalRestart(), (e) => e.code === 'SERVICE_PENDING' && e.reason === 'log-cursor-invalid');
  assert.equal(g.native.service.startType, 'demand');

  const h = fixture(); publish(h); const ht = await h.driver.startTrial({});
  await h.driver.runStartupGate({ trial: ht, observeApplication: observeWith() });
  h.native.process.childEpoch = hex('0');
  assert.throws(() => h.driver.armFinalRestart(), (e) => e.code === 'SERVICE_STARTUP_TIMEOUT' && e.reason === 'startup-receipt-invalidated');
  assert.equal(h.native.service.startType, 'demand'); assert.equal(h.native.service.failurePolicy, 'none');
  assert.throws(() => h.driver.armFinalRestart(), (e) => e.code === 'SERVICE_PENDING' && e.reason === 'log-cursor-invalid');
});

test('job flag alone cannot replace native process-tree proof; force termination requires exact evidence', async () => {
  const f = fixture(); f.driver.publishSuppressedResource({ phase: 'transition-marker-intent', release: release(), expectedCurrentSha256: null }); await f.driver.startTrial({});
  // Simulate a Shawl Job flag that failed to quiesce the native tree. The SCM
  // stop call succeeds but leaves residual evidence for explicit enumeration.
  const expected = f.driver.probe().resourceFingerprint;
  f.native.retainTree = true;
  f.native.badTree = true;
  await assert.rejects(f.driver.stopAndQuiesce({ deadlineMs: 1, expectedResourceFingerprint: expected }), (e) => e.code === 'SERVICE_TREE_SURVIVOR' || e.reason === 'tree-overflow' || e.reason === 'tree-survivor');
});

test('stop, predecessor-safe removal, and exact closed errors preserve cumulative writes', async () => {
  const f = fixture(); f.driver.publishSuppressedResource({ phase: 'transition-marker-intent', release: release(), expectedCurrentSha256: null }); await f.driver.startTrial({});
  const stopped = await f.driver.stopAndQuiesce({ deadlineMs: 1, expectedResourceFingerprint: f.driver.probe().resourceFingerprint }); assert.equal(stopped.quiescent, true); const fingerprint = f.driver.probe().resourceFingerprint;
  assert.throws(() => f.driver.removeResource({ expectedResourceFingerprint: hex('0') }), (e) => e.code === 'SERVICE_MANUAL_CLEANUP' && e.reason === 'resource-drift');
  assert.deepEqual(f.driver.removeResource({ expectedResourceFingerprint: fingerprint }), { serviceName: 'GJCRemoteBot', removed: true }); assert.equal(f.driver.probe().platformPhase, 'absent');
  // An absent name without a tombstone receipt is deletion-pending, not proof
  // that this transaction's resource was removed.
  const g = fixture(); const before = g.driver.writes;
  assert.throws(() => g.driver.removeResource({ expectedResourceFingerprint: hex('a') }), (e) => e.code === 'SERVICE_PENDING');
  assert.equal(g.driver.writes, before);
  assert.ok(WINDOWS_SERVICE_ERROR_CODES.includes('SERVICE_AMBIGUOUS'));
});

test('deletionPending never reports removal while SCM name remains', async () => {
  const f = fixture(); f.driver.publishSuppressedResource({ phase: 'transition-marker-intent', release: release(), expectedCurrentSha256: null }); await f.driver.startTrial({});
  await f.driver.stopAndQuiesce({ deadlineMs: 1, expectedResourceFingerprint: f.driver.probe().resourceFingerprint });
  const fingerprint = f.driver.probe().resourceFingerprint;
  f.native.retainAfterDelete = true;
  assert.throws(() => f.driver.removeResource({ expectedResourceFingerprint: fingerprint }), (e) => e.code === 'SERVICE_PENDING' && e.reason === 'deletion-pending');
  assert.notEqual(f.driver.probe().platformPhase, 'absent');
});

test('PID-zero stop refuses without a service-scoped post-stop tree receipt', async () => {
  const f = fixture(); f.driver.publishSuppressedResource({ phase: 'transition-marker-intent', release: release(), expectedCurrentSha256: null });
  const before = f.native.calls.length;
  await assert.rejects(f.driver.stopAndQuiesce({ deadlineMs: 1, expectedResourceFingerprint: f.driver.probe().resourceFingerprint }), (e) => e.code === 'SERVICE_PENDING' && e.reason === 'ambiguous-process-tree');
  assert.equal(f.native.calls.slice(before).some(([name]) => name === 'stop_win32_service' || name === 'terminate_win32_service_tree'), false);
});

test('detached process tree with absent SCM name never reports quiescent', async () => {
  const f = fixture();
  f.driver.publishSuppressedResource({ phase: 'transition-marker-intent', release: release(), expectedCurrentSha256: null });
  await f.driver.startTrial({});
  f.session.state.entries = [detachedUninstallTransaction(f.transaction.transition.platformResourceFingerprint)];
  // The wrapper remains alive while its SCM registration disappears. There is
  // no service-scoped receipt that could prove this detached tree stopped.
  f.native.service = null;
  await assert.rejects(
    f.driver.stopAndQuiesce({ deadlineMs: 1 }),
    (error) => (error.code === 'SERVICE_PENDING' || error.code === 'SERVICE_MANUAL_CLEANUP') && error.reason === 'ambiguous-process-tree',
  );
});

test('Windows command serializer matches native quote/backslash rules', () => {
  assert.equal(serializeWindowsCommandLine(['C:/Program Files/GJC\\', 'plain', 'a\\"b']), '"C:/Program Files/GJC\\\\" "plain" "a\\\\\\"b"');
});

test('password-required accounts refuse null and pass bounded non-persisted password', () => {
  assert.throws(() => fixture({ servicePasswordRequired: true }), (error) => error.code === 'SERVICE_INVALID' && error.reason === 'service-password-required');
  const f = fixture({ servicePasswordRequired: true, servicePassword: 'secret' });
  f.driver.publishSuppressedResource({ phase: 'transition-marker-intent', release: release(), expectedCurrentSha256: null });
  const create = f.native.calls.find(([name]) => name === 'create_win32_service_disabled');
  assert.equal(create[4], 'secret');
  assert.deepEqual(create[5], roles);
  assert.throws(() => fixture({ servicePassword: '\0' }), (error) => error.code === 'SERVICE_INVALID');
});

test('publish CAS rejects a current-resource expectation on absent or stale transactions', () => {
  const f = fixture();
  assert.throws(() => f.driver.publishSuppressedResource({ phase: 'transition-marker-intent', release: release(), expectedCurrentSha256: hex('1') }), (error) => error.code === 'SERVICE_MANUAL_CLEANUP' && error.reason === 'recreated-resource');
  const stale = fixture({ transaction: transactionFixture({ applicationManifestFingerprint: hex('e') }) });
  assert.throws(() => stale.driver.publishSuppressedResource({ phase: 'transition-marker-intent', release: release(), expectedCurrentSha256: null }), (error) => error.code === 'SERVICE_STALE');
});

test('pending journal is refused before any SCM mutation', () => {
  const f = fixture();
  f.session.state.pending = { phase: 'transition-marker-intent', substep: 'action' };
  assert.throws(() => f.driver.publishSuppressedResource({ phase: 'transition-marker-intent', release: release(), expectedCurrentSha256: null }), (error) => error.code === 'SERVICE_PENDING');
  assert.equal(f.native.calls.filter(([name]) => name.endsWith('_win32_service')).length, 0);
});

test('store-shaped pending tail completes its exact entry before native action', () => {
  const f = fixture();
  const committed = f.session.state.entries.at(-1);
  const pending = buildServiceTransaction({ ...committed, phase: 'transition-marker-intent', substep: 'action', previousJournalFingerprint: committed.transactionFingerprint });
  let head = committed;
  let pendingTail = pending;
  f.session.state.entries.push(pending);
  f.session.readJournal = () => ({ head: { present: true, value: head }, entries: [...f.session.state.entries], pending: pendingTail });
  f.session.appendJournal = (entry) => {
    assert.deepEqual(entry, pendingTail ?? entry);
    if (pendingTail !== null) { pendingTail = null; head = entry; return; }
    f.session.state.entries.push(entry); head = entry;
  };
  const beforeNative = f.native.calls.length;
  f.driver.publishSuppressedResource({ phase: 'transition-marker-intent', release: release(), expectedCurrentSha256: null });
  assert.ok(f.native.calls.slice(beforeNative).some(([name]) => name === 'create_win32_service_disabled'));
  assert.equal(pendingTail, null);
});

test('unmarked same-name create replay refuses without adoption or native mutation', () => {
  const existing = { name: 'GJCRemoteBot', serviceRole: 'bot', description: '', startType: 'disabled', binaryPath: 'C:/foreign.exe', configFingerprint: hex('1'), failurePolicy: 'none', failureActions: [], runtime: { state: 'stopped', processId: 0, startTime: '', fingerprint: hex('3') } };
  const f = fixture({ existing });
  const committed = f.session.state.entries.at(-1);
  f.session.state.entries[0] = buildServiceTransaction({ ...committed, phase: 'transition-marker-intent', substep: 'action', previousJournalFingerprint: committed.transactionFingerprint });
  const before = f.native.calls.length;
  assert.throws(() => f.driver.publishSuppressedResource({ phase: 'transition-marker-intent', release: release(), expectedCurrentSha256: null }), (error) => error.code === 'SERVICE_MANUAL_CLEANUP' && error.reason === 'unmarked-resource' && error.writes === 0);
  assert.deepEqual(f.native.calls.slice(before).filter(([name]) => name.includes('_win32_service') && !name.startsWith('open_') && !name.startsWith('query_') && !name.startsWith('close_') && !name.startsWith('plan_')), []);
});

test('trial-start action replay calls StartService when the wrapper epoch is absent', async () => {
  const f = fixture();
  f.driver.publishSuppressedResource({ phase: 'transition-marker-intent', release: release(), expectedCurrentSha256: null });
  const committed = f.session.state.entries.at(-1);
  f.session.state.entries.push(buildServiceTransaction({ ...committed, phase: 'trial-start-intent', substep: 'action', previousJournalFingerprint: committed.transactionFingerprint }));
  await f.driver.startTrial({});
  assert.equal(f.native.calls.filter(([name]) => name === 'start_win32_service').length, 1);
});

test('transition action replay reconciles an already-applied protected resource', () => {
  const f = fixture();
  f.driver.publishSuppressedResource({ phase: 'transition-marker-intent', release: release(), expectedCurrentSha256: null });
  const committed = f.session.state.entries.at(-1);
  f.session.state.entries.push(buildServiceTransaction({ ...committed, phase: 'transition-marker-intent', substep: 'action', previousJournalFingerprint: committed.transactionFingerprint }));
  const before = f.native.calls.length;
  const result = f.driver.publishSuppressedResource({ phase: 'transition-marker-intent', release: release(), expectedCurrentSha256: null });
  assert.equal(result.platformPhase, 'trial');
  assert.deepEqual(f.native.calls.slice(before).filter(([name]) => ['protect_win32_service', 'configure_win32_service_launch', 'set_win32_service_marker', 'set_win32_service_start_type', 'set_win32_service_failure_actions', 'set_win32_service_failure_actions_flag'].includes(name)), []);
});

test('transition replay refuses a mutation between probe and mutate handle without setters', () => {
  const f = fixture({ mutateOnMutateOpen: true });
  f.driver.publishSuppressedResource({ phase: 'transition-marker-intent', release: release(), expectedCurrentSha256: null });
  const committed = f.session.state.entries.at(-1);
  f.session.state.entries.push(buildServiceTransaction({ ...committed, phase: 'transition-marker-intent', substep: 'observed', previousJournalFingerprint: committed.transactionFingerprint }));
  const before = f.native.calls.length;
  assert.throws(() => f.driver.publishSuppressedResource({ phase: 'transition-marker-intent', release: release(), expectedCurrentSha256: null }), (error) => error.code === 'SERVICE_MANUAL_CLEANUP' && error.reason === 'resource-drift');
  assert.deepEqual(f.native.calls.slice(before).filter(([name]) => ['protect_win32_service', 'configure_win32_service_launch', 'set_win32_service_marker', 'set_win32_service_start_type', 'set_win32_service_failure_actions', 'set_win32_service_failure_actions_flag'].includes(name)), []);
});

test('runtime changes do not false-drift static CAS across start and stop', async () => {
  const f = fixture();
  f.driver.publishSuppressedResource({ phase: 'transition-marker-intent', release: release(), expectedCurrentSha256: null });
  const identity = f.driver.probe().resourceFingerprint;
  f.native.service.runtime = { ...f.native.service.runtime, state: 'stopped', processId: 0, fingerprint: hex('1'), checkpoint: 7, waitHint: 250 };
  assert.equal(f.driver.probe().resourceFingerprint, identity);
  const trial = await f.driver.startTrial({ expectedResourceFingerprint: identity });
  f.native.service.runtime = { ...f.native.service.runtime, fingerprint: hex('2'), controlsAccepted: 1, checkpoint: 9 };
  assert.equal(f.driver.probe().resourceFingerprint, identity);
  const stopped = await f.driver.stopAndQuiesce({ deadlineMs: 1000, expectedResourceFingerprint: identity });
  assert.equal(stopped.quiescent, true);
  assert.equal(f.driver.probe().resourceFingerprint, identity);
  assert.equal(trial.resourceFingerprint, identity);
});

test('runtime changes do not false-drift trial action replay', async () => {
  const f = fixture();
  f.driver.publishSuppressedResource({ phase: 'transition-marker-intent', release: release(), expectedCurrentSha256: null });
  const identity = f.driver.probe().resourceFingerprint;
  f.native.service.runtime = { ...f.native.service.runtime, fingerprint: hex('5'), checkpoint: 11 };
  const committed = f.session.state.entries.at(-1);
  f.session.state.entries.push(buildServiceTransaction({ ...committed, phase: 'trial-start-intent', substep: 'action', previousJournalFingerprint: committed.transactionFingerprint }));
  const trial = await f.driver.startTrial({ expectedResourceFingerprint: identity });
  assert.equal(trial.resourceFingerprint, identity);
  assert.equal(f.driver.probe().resourceFingerprint, identity);
});

test('STOP_PENDING is polled before the first tree-empty receipt', async () => {
  const f = fixture({ stopPending: true, stopPendingPolls: 3 });
  f.driver.publishSuppressedResource({ phase: 'transition-marker-intent', release: release(), expectedCurrentSha256: null });
  await f.driver.startTrial({});
  const before = f.native.calls.length;
  const result = await f.driver.stopAndQuiesce({ deadlineMs: 1000, expectedResourceFingerprint: f.driver.probe().resourceFingerprint });
  assert.equal(result.quiescent, true);
  const calls = f.native.calls.slice(before).map(([name]) => name);
  const stopIndex = calls.indexOf('stop_win32_service');
  const treeIndices = calls.flatMap((name, index) => name === 'enumerate_process_tree' && index > stopIndex ? [index] : []);
  assert.ok(stopIndex >= 0);
  assert.ok(treeIndices.every((index) => index > stopIndex));
});

test('STOP_PENDING writes:0 acknowledgement and action-head replay never issue a second stop', async () => {
  const f = fixture({ stopPending: true, stopPendingPolls: 3, stopAckWrites: 0 });
  f.driver.publishSuppressedResource({ phase: 'transition-marker-intent', release: release(), expectedCurrentSha256: null });
  await f.driver.startTrial({});
  const result = await f.driver.stopAndQuiesce({ deadlineMs: 1000, expectedResourceFingerprint: f.driver.probe().resourceFingerprint });
  assert.equal(result.quiescent, true);
  assert.equal(f.native.calls.filter(([name]) => name === 'stop_win32_service').length, 1);

  const g = fixture({ stopPending: true, stopPendingPolls: 3 });
  g.driver.publishSuppressedResource({ phase: 'transition-marker-intent', release: release(), expectedCurrentSha256: null });
  await g.driver.startTrial({});
  const committed = g.session.state.entries.at(-1);
  g.session.state.entries.push(buildServiceTransaction({ ...committed, phase: 'stopping', substep: 'intent', previousJournalFingerprint: committed.transactionFingerprint }));
  const stoppingIntent = g.session.state.entries.at(-1);
  g.session.state.entries.push(buildServiceTransaction({ ...stoppingIntent, phase: 'stopping', substep: 'action', previousJournalFingerprint: stoppingIntent.transactionFingerprint }));
  g.native.stopPendingActive = true;
  g.native.service.runtime = { ...g.native.service.runtime, state: 'stop-pending' };
  const beforeCalls = g.native.calls.filter(([name]) => name === 'stop_win32_service').length;
  await g.driver.stopAndQuiesce({ deadlineMs: 1000, expectedResourceFingerprint: g.driver.probe().resourceFingerprint });
  assert.equal(g.native.calls.filter(([name]) => name === 'stop_win32_service').length, beforeCalls);
  assert.equal(g.session.state.entries.filter((entry) => entry.phase === 'stopping').length, 2);
});

test('fresh-controller trial recovery advertises callable continuation for action, observed, and starting heads', async () => {
  for (const head of ['action', 'observed', 'starting']) {
    const f = fixture();
    f.driver.publishSuppressedResource({ phase: 'transition-marker-intent', release: release(), expectedCurrentSha256: null });
    await f.driver.startTrial({});
    const base = f.session.state.entries.findLast((entry) => entry.phase === 'resource-published');
    const phase = head === 'action' ? 'trial-start-intent' : head === 'observed' ? 'trial-start-observed' : 'starting';
    const substep = head === 'action' ? 'action' : head === 'observed' ? 'observed' : 'intent';
    f.session.state.entries.push(buildServiceTransaction({ ...base, phase, substep, previousJournalFingerprint: base.transactionFingerprint }));
    const fresh = freshDriver(f);
    const recovery = fresh.recoverTrialState();

    assert.equal(recovery.recovery, 'resume');
    assert.ok(recovery.trial);
    await fresh.runStartupGate({ trial: recovery.trial, observeApplication: observeWith() });
  }
});

test('recovery derives the declared marker/path pair when constructor release is undeclared', async () => {
  const f = fixture();
  f.driver.publishSuppressedResource({ phase: 'transition-marker-intent', release: release(), expectedCurrentSha256: null });
  await f.driver.startTrial({});
  const fresh = freshDriver(f, { applicationManifestFingerprint: hex('e'), entrypointPath: 'C:\\ProgramData\\GJC\\releases\\newer\\bot.js' });
  const recovery = fresh.recoverTrialState();
  assert.equal(recovery.recovery, 'resume');
  assert.equal(recovery.trial.releaseBinding.applicationManifestFingerprint, hex('d'));
  assert.equal(recovery.trial.releaseBinding.entrypointPath, release().entrypointPath);
});

test('recovery binds the old entrypoint when old and candidate entrypoints differ', () => {
  const candidatePath = 'C:\\ProgramData\\GJC\\releases\\current\\bot.js';
  const oldPath = 'C:\\ProgramData\\GJC\\releases\\old\\bot.js';
  const f = fixture({ entrypointPath: candidatePath });
  f.driver.publishSuppressedResource({ phase: 'transition-marker-intent', release: release(hex('d')), expectedCurrentSha256: null });
  const asDescriptor = (snapshot) => ({ name: snapshot.name, component: 'bot', serviceKey: 'bot', serviceRole: snapshot.serviceRole, serviceType: snapshot.serviceType, startType: snapshot.startType, errorControl: snapshot.errorControl, tagId: snapshot.tagId, binaryPath: snapshot.binaryPath, loadOrderGroup: snapshot.loadOrderGroup, dependencies: snapshot.dependencies, accountName: snapshot.accountName, displayName: snapshot.displayName, description: snapshot.description, delayedAutoStart: snapshot.delayedAutoStart, failureResetPeriod: snapshot.failureResetPeriod, failureRebootMessage: snapshot.failureRebootMessage, failureCommand: snapshot.failureCommand, failureActionsOnNonCrashFailures: snapshot.failureActionsOnNonCrashFailures, failureActions: snapshot.failureActions, failurePolicy: snapshot.failurePolicy, serviceSidType: snapshot.serviceSidType, requiredPrivileges: snapshot.requiredPrivileges, triggerCount: snapshot.triggerCount, preshutdownTimeout: snapshot.preshutdownTimeout, securitySha256: snapshot.securitySha256, aclMatches: snapshot.aclMatches, accountMatchesRole: snapshot.accountMatchesRole, configFingerprint: snapshot.configFingerprint, runtimeFingerprint: null });
  const candidateLaunch = launchFor('bot', 'bot', botConfiguration, candidatePath);
  const oldLaunch = launchFor('bot', 'bot', botConfiguration, oldPath);
  const candidateSnapshot = { ...f.native.service, binaryPath: serializeWindowsCommandLine(buildWindowsShawlArgv({ component: 'bot', serviceKey: 'bot', launch: candidateLaunch })) };
  const candidateResource = windowsServiceResourceFingerprint(asDescriptor(candidateSnapshot));
  const oldSnapshot = { ...candidateSnapshot, binaryPath: serializeWindowsCommandLine(buildWindowsShawlArgv({ component: 'bot', serviceKey: 'bot', launch: oldLaunch })), description: `gjc-remote:v1:${hex('a')}`, startType: 'demand', failurePolicy: 'none', failureResetPeriod: 0, failureActions: [] };
  const oldResource = windowsServiceResourceFingerprint(asDescriptor(oldSnapshot));
  const old = buildServiceOldProof({ disposition: 'stable', manifestFingerprint: hex('1'), resourceProof: oldResource, applicationManifestFingerprint: hex('a'), shawlManifestFingerprint: shawl.sha256, serviceGeneration: 1, activation: 'enabled' }, 'win32');
  const candidate = buildServiceCandidateProof({ disposition: 'release', applicationManifestFingerprint: hex('d'), shawlManifestFingerprint: shawl.sha256, releaseSequence: 2, releaseTreeFingerprint: hex('e'), compatibilityFingerprint: hex('f') }, 'win32');
  const transition = buildServiceTransitionProof({ oldFingerprint: old.oldFingerprint, candidateFingerprint: candidate.candidateFingerprint, expectedBeforeResourceFingerprint: oldResource, expectedAfterResourceFingerprint: candidateResource, platformResourceFingerprint: candidateResource, platformState: buildServicePlatformState('win32', 'trial') }, 'win32');
  const final = buildServiceFinalProof({ disposition: 'stable', manifestFingerprint: hex('2'), resourceProof: candidateResource, applicationManifestFingerprint: hex('d'), shawlManifestFingerprint: shawl.sha256, serviceGeneration: 2, activation: 'enabled' }, 'win32');
  const fields = { transactionId: 'tx-update', transactionNonce: '3'.repeat(32), operation: 'update', component: 'bot', serviceKey: 'bot', platform: 'win32', architecture: 'x64', serviceGeneration: 2, old, candidate, transition, final };
  const prepared = buildServiceTransaction({ ...fields, phase: 'prepared', substep: 'none', previousJournalFingerprint: hex('0') });
  f.session.state.entries = [buildServiceTransaction({ ...fields, phase: 'transition-marker-intent', substep: 'observed', previousJournalFingerprint: prepared.transactionFingerprint })];
  f.native.service = oldSnapshot;
  f.native.process = { pid: 5001, startTime: 'start-5001', fingerprint: hash('epoch-5001'), treeFingerprint: hash('tree-5001') };
  f.native.service.runtime = { ...f.native.service.runtime, state: 'running', processId: 5001, startTime: 'start-5001', fingerprint: hash('runtime') };
  const recovery = freshDriver(f, { applicationManifestFingerprint: hex('d'), entrypointPath: candidatePath }).recoverTrialState();
  assert.equal(recovery.recovery, 'resume');
  assert.equal(recovery.releaseBinding.entrypointPath, oldPath);
  assert.equal(recovery.releaseBinding.applicationManifestFingerprint, hex('a'));
});

test('deletion retry validates tombstoned action and accepts delayed absence without DeleteService replay', async () => {
  const f = fixture();
  f.driver.publishSuppressedResource({ phase: 'transition-marker-intent', release: release(), expectedCurrentSha256: null });
  await f.driver.startTrial({});
  await f.driver.stopAndQuiesce({ deadlineMs: 1, expectedResourceFingerprint: f.driver.probe().resourceFingerprint });
  const fingerprint = f.driver.probe().resourceFingerprint;
  f.native.retainAfterDelete = true;
  assert.throws(() => f.driver.removeResource({ expectedResourceFingerprint: fingerprint }), (e) => e.code === 'SERVICE_PENDING' && e.reason === 'deletion-pending');
  const deletes = f.native.calls.filter(([name]) => name === 'delete_win32_service').length;
  f.native.service = null;
  const fresh = freshDriver(f);
  assert.deepEqual(fresh.removeResource({ expectedResourceFingerprint: fingerprint }), { serviceName: 'GJCRemoteBot', removed: true });
  assert.equal(f.native.calls.filter(([name]) => name === 'delete_win32_service').length, deletes);
  assert.equal(f.session.state.entries.at(-1).phase, 'tombstoned');
  assert.equal(f.session.state.entries.at(-1).substep, 'observed');
});