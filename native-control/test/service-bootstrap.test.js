import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { dirname, join } from 'node:path';
import test from 'node:test';
import { fileURLToPath, pathToFileURL } from 'node:url';
import {
  SERVICE_BOOTSTRAP_CONTEXT_KEYS,
  SERVICE_BOOTSTRAP_EMPTY_FILE_SHA256,
  SERVICE_BOOTSTRAP_RUNTIMES,
  SERVICE_EFFECTIVE_CONFIG_DOMAIN,
  evaluateServiceBootstrap,
  runServiceBootstrap,
  serviceEffectiveConfigFingerprint,
  validateServiceDotenvEntries,
} from '../src/service-bootstrap-policy.js';
import { windowsServiceName } from '../src/service-windows.js';

const packageRoot = dirname(dirname(fileURLToPath(import.meta.url)));
const guardPath = join(packageRoot, 'src', 'service-bootstrap.js');
const require = createRequire(import.meta.url);
const dotenv = require('dotenv');
const h = (label) => createHash('sha256').update(label).digest('hex');
const BOOTSTRAP = 'C:\\GJC\\release\\native-control\\src\\service-bootstrap.js';
const DAEMON_KEY = `default-${h('daemon-key')}`;
const CONFIG_BYTES = 'A=1\nB=two\n';

function fixture(component) {
  const entries = [['A', '1'], ['B', 'two']];
  const serviceKey = component === 'bot' ? 'bot' : DAEMON_KEY;
  const runtime = SERVICE_BOOTSTRAP_RUNTIMES[component];
  const env = {
    HOME: 'C:\\GJC\\home', USERPROFILE: 'C:\\GJC\\home', NODE_OPTIONS: '', NODE_PATH: '',
    GJC_REMOTE_SERVICE_COMPONENT: component, GJC_REMOTE_SERVICE_KEY: serviceKey,
    GJC_REMOTE_SUPERVISOR_SHA256: h('supervisor'), GJC_REMOTE_RUNTIME_VERSION: runtime.version,
    GJC_REMOTE_RUNTIME_SOURCE_REVISION: runtime.sourceRevision, GJC_REMOTE_RUNTIME_SHA256: h('runtime'),
    GJC_REMOTE_ENTRYPOINT_SHA256: h('entrypoint'), GJC_REMOTE_BOOTSTRAP_PATH: BOOTSTRAP,
    GJC_REMOTE_BOOTSTRAP_SHA256: h('bootstrap'), GJC_REMOTE_BOOTSTRAP_CLOSURE_FINGERPRINT: h('closure'),
    GJC_REMOTE_RUNTIME_CONFIG_ROOT_IDENTITY_FINGERPRINT: '', GJC_REMOTE_RUNTIME_CONFIG_PATH: '',
    GJC_REMOTE_RUNTIME_CONFIG_SHA256: '', GJC_REMOTE_RUNTIME_CONFIG_IDENTITY_FINGERPRINT: '',
    GJC_REMOTE_SDK_PROFILE_PATH: '', GJC_REMOTE_SCOPE_FINGERPRINT: h('scope'),
    GJC_REMOTE_EFFECTIVE_CONFIG_FINGERPRINT: serviceEffectiveConfigFingerprint({ component, serviceKey, entries }),
    GJC_REMOTE_CONFIG_SOURCE_IDENTITY_FINGERPRINT: h('source'),
    GJC_REMOTE_LAUNCH_FINGERPRINT: h('launch'), GJC_REMOTE_RUNTIME_POLICY_FINGERPRINT: h('policy'),
  };
  let runtimeConfig = null;
  if (component === 'bot') {
    env.CHANNELS_CONFIG = 'C:\\GJC\\config\\channels.json';
  } else {
    Object.assign(env, {
      BUN_OPTIONS: '', BUN_INSPECT_PRELOAD: BOOTSTRAP, XDG_CONFIG_HOME: 'C:\\GJC\\work\\runtime-config',
      BUN_INSPECT: '', BUN_INSPECT_CONNECT_TO: '', GJC_CODING_AGENT_DIR: 'C:\\GJC\\home\\.gjc\\agent',
      GJC_REMOTE_RUNTIME_CONFIG_ROOT_IDENTITY_FINGERPRINT: h('root'),
      GJC_REMOTE_RUNTIME_CONFIG_PATH: 'C:\\GJC\\work\\runtime-config\\.bunfig.toml',
      GJC_REMOTE_RUNTIME_CONFIG_SHA256: SERVICE_BOOTSTRAP_EMPTY_FILE_SHA256,
      GJC_REMOTE_RUNTIME_CONFIG_IDENTITY_FINGERPRINT: h('file'),
      GJC_REMOTE_SDK_PROFILE_PATH: 'C:\\GJC\\home\\.gjc\\agent',
    });
    runtimeConfig = {
      rootIdentityFingerprint: h('root'), fileIdentityFingerprint: h('file'),
      fileSha256: SERVICE_BOOTSTRAP_EMPTY_FILE_SHA256, byteLength: 0,
    };
  }
  const execPath = component === 'bot' ? 'C:\\GJC\\node\\node.exe' : 'C:\\GJC\\bun\\bun.exe';
  return {
    env,
    runtime: {
      platform: 'win32', execPath,
      argv: [execPath, `C:\\GJC\\release\\${component}\\src\\${component}.js`], execArgv: [],
      versions: component === 'bot' ? { node: runtime.version } : { node: '24.3.0', bun: runtime.version },
      bunRevision: component === 'bot' ? undefined : runtime.sourceRevision,
    },
    bootstrapPath: BOOTSTRAP,
    selfConfig: {
      schemaVersion: 1, sourceIdentityFingerprint: h('source'), bytes: Buffer.from(CONFIG_BYTES),
      runtimeConfig, writes: 0,
    },
    epoch: { processEpochFingerprint: h('epoch'), writes: 0 },
    parseDotenv: (bytes) => dotenv.parse(bytes),
  };
}

function refusal(reason) {
  return (error) => error?.code === 'SERVICE_BOOTSTRAP_REFUSED' && error.reason === reason && error.writes === 0;
}

function orchestrate(input, overrides = {}) {
  return runServiceBootstrap({
    ...input,
    createNative: () => ({
      readSelfServiceConfig: () => input.selfConfig,
      observeSelfProcessEpoch: () => input.epoch,
      ...overrides,
    }),
  });
}

function nativeFailure(operation, extra = {}) {
  return Object.assign(new Error('secret-token-value C:\\private\\config.env'), {
    code: 'SERVICE_ACCESS_DENIED', operation, writes: 0, ambiguous: false, ...extra,
  });
}

test('orchestration returns valid policy results without installing configuration and clears bytes', () => {
  for (const component of ['bot', 'daemon']) {
    const input = fixture(component);
    const before = { ...input.env };
    input.selfConfig.bytes.fill = () => { throw new Error('must use intrinsic fill'); };
    const result = orchestrate(input);
    assert.equal(result.context.component, component);
    assert.deepEqual(result.entries, [['A', '1'], ['B', 'two']]);
    assert.deepEqual(input.env, before);
    assert.equal(input.selfConfig.bytes.every((byte) => byte === 0), true);
  }
});

test('missing or unverified production loader failures have one safe outward boundary', () => {
  for (const error of [undefined, nativeFailure('create_service_bootstrap_native', {
    code: 'ERR_NATIVE_CONTROL_REFUSED', reason: 'production-native-addon-unverified',
  })]) {
    assert.throws(() => runServiceBootstrap({
      ...fixture('bot'),
      createNative: () => { throw error; },
    }), (refused) => {
      assert.equal(refused.code, 'SERVICE_BOOTSTRAP_REFUSED');
      assert.equal(refused.reason, 'native-load-failed');
      assert.equal(refused.writes, error === undefined ? null : 0);
      assert.equal(refused.diagnostics.code, error === undefined ? null : 'ERR_NATIVE_CONTROL_REFUSED');
      assert.equal(Object.hasOwn(refused, 'cause'), false);
      return true;
    });
  }
  assert.throws(() => runServiceBootstrap({ ...fixture('bot'), createNative: undefined }), (error) =>
    error.code === 'SERVICE_BOOTSTRAP_REFUSED' && error.reason === 'native-load-failed' && error.writes === null);
});

test('signed-load-equivalent self-config access denial is refused before epoch, policy or application work', () => {
  const input = fixture('bot');
  const before = { ...input.env };
  let epochCalls = 0;
  let parseCalls = 0;
  let applicationRan = false;
  input.parseDotenv = () => { parseCalls++; return {}; };
  assert.throws(() => {
    orchestrate(input, {
      readSelfServiceConfig: () => { throw nativeFailure('read_self_service_config'); },
      observeSelfProcessEpoch: () => { epochCalls++; return input.epoch; },
    });
    applicationRan = true;
  }, (error) => {
    assert.equal(error.code, 'SERVICE_BOOTSTRAP_REFUSED');
    assert.equal(error.reason, 'self-config-observation-failed');
    assert.deepEqual(error.diagnostics, {
      stage: 'self-config-observation', code: 'SERVICE_ACCESS_DENIED',
      operation: 'read_self_service_config', writes: 0, ambiguous: false,
    });
    assert.equal(Object.isFrozen(error.diagnostics), true);
    assert.doesNotMatch(`${error.message}\n${error.stack}\n${JSON.stringify(error)}`, /secret-token-value|private|config.env/);
    return true;
  });
  assert.equal(epochCalls, 0);
  assert.equal(parseCalls, 0);
  assert.equal(applicationRan, false);
  assert.deepEqual(input.env, before);
});

test('epoch failures clear config bytes, preserve write uncertainty and do not apply configuration', () => {
  for (const writes of [0, 2, undefined, -1, Infinity, Number.MAX_SAFE_INTEGER + 1]) {
    const input = fixture('daemon');
    const before = { ...input.env };
    assert.throws(() => orchestrate(input, {
      observeSelfProcessEpoch: () => {
        throw nativeFailure('observe_self_process_epoch', { writes, ambiguous: true });
      },
    }), (error) => {
      assert.equal(error.code, 'SERVICE_BOOTSTRAP_REFUSED');
      assert.equal(error.reason, 'process-epoch-observation-failed');
      assert.equal(error.writes, writes === 0 || writes === 2 ? writes : null);
      assert.equal(error.ambiguous, true);
      return true;
    });
    assert.equal(input.selfConfig.bytes.every((byte) => byte === 0), true);
    assert.deepEqual(input.env, before);
  }
});

test('policy mismatch retains its reason and clears bytes without installing configuration', () => {
  for (const writes of [0, 3, undefined]) {
    const input = fixture('daemon');
    input.env.GJC_REMOTE_RUNTIME_VERSION = 'wrong';
    input.selfConfig.writes = writes;
    const before = { ...input.env };
    assert.throws(() => orchestrate(input), (error) => {
      assert.equal(error.code, 'SERVICE_BOOTSTRAP_REFUSED');
      assert.equal(error.reason, 'runtime-policy-mismatch');
      assert.equal(error.writes, writes === undefined ? null : writes);
      assert.equal(Object.hasOwn(error, 'diagnostics'), writes !== 0);
      return true;
    });
    assert.equal(input.selfConfig.bytes.every((byte) => byte === 0), true);
    assert.deepEqual(input.env, before);
  }
});

test('opaque throws and malicious descriptors cannot leak data or execute diagnostic getters', () => {
  let getterCalls = 0;
  const malicious = Object.create({ code: 'SERVICE_ACCESS_DENIED', writes: 0 });
  for (const key of ['code', 'operation', 'writes', 'ambiguous', 'message', 'stack', 'cause']) {
    Object.defineProperty(malicious, key, { get() { getterCalls++; throw new Error('secret-token-value'); } });
  }
  const proxy = new Proxy({}, { getOwnPropertyDescriptor() { throw new Error('secret-token-value'); } });
  const huge = 'secret-token-value'.repeat(10_000);
  for (const thrown of [null, undefined, huge, 42, Symbol('secret-token-value'), malicious, proxy,
    Object.create({ code: 'SERVICE_ACCESS_DENIED', operation: 'observe_self_process_epoch', writes: 0, ambiguous: false }),
    { code: huge, operation: huge, writes: huge, ambiguous: huge, cause: malicious }]) {
    const input = fixture('bot');
    assert.throws(() => orchestrate(input, {
      observeSelfProcessEpoch: () => { throw thrown; },
    }), (error) => {
      assert.equal(error.code, 'SERVICE_BOOTSTRAP_REFUSED');
      assert.deepEqual(error.diagnostics, {
        stage: 'process-epoch-observation', code: null, operation: null, writes: null, ambiguous: null,
      });
      assert.equal(Object.hasOwn(error, 'cause'), false);
      assert.ok(JSON.stringify(error).length < 512);
      assert.doesNotMatch(`${error.message}\n${error.stack}\n${JSON.stringify(error)}`, /secret-token-value/);
      return true;
    });
    assert.equal(input.selfConfig.bytes.every((byte) => byte === 0), true);
  }
  assert.equal(getterCalls, 0);
});

test('config byte capture does not execute accessors on malformed observation records', () => {
  const input = fixture('bot');
  let getterCalls = 0;
  Object.defineProperty(input.selfConfig, 'bytes', {
    get() { getterCalls++; throw new Error('secret-token-value'); },
  });
  assert.throws(() => orchestrate(input), (error) =>
    error.code === 'SERVICE_BOOTSTRAP_REFUSED' && error.reason === 'config-source-drift' && error.writes === null);
  assert.equal(getterCalls, 0);
});

test('invalid DataView receipts are cleared without masking policy or epoch refusals', () => {
  for (const epochFails of [false, true]) {
    const input = fixture('bot');
    const storage = input.selfConfig.bytes;
    input.selfConfig.bytes = new DataView(storage.buffer, storage.byteOffset, storage.byteLength);
    const overrides = epochFails ? {
      observeSelfProcessEpoch: () => { throw nativeFailure('observe_self_process_epoch', { code: 'SERVICE_INVALID' }); },
    } : {};
    assert.throws(() => orchestrate(input, overrides), (error) => {
      assert.equal(error.code, 'SERVICE_BOOTSTRAP_REFUSED');
      assert.equal(error.reason, epochFails ? 'process-epoch-observation-failed' : 'config-source-drift');
      if (epochFails) assert.equal(error.diagnostics.code, 'SERVICE_INVALID');
      return true;
    });
    assert.equal(storage.every((byte) => byte === 0), true);
  }
});

test('unexpected policy evaluation exceptions are normalized after byte cleanup', () => {
  const input = fixture('bot');
  Object.defineProperty(input.runtime, 'platform', { get() { throw new Error('secret-token-value'); } });
  assert.throws(() => orchestrate(input), (error) => {
    assert.equal(error.code, 'SERVICE_BOOTSTRAP_REFUSED');
    assert.equal(error.reason, 'policy-evaluation-failed');
    assert.equal(error.writes, null);
    assert.doesNotMatch(error.message, /secret-token-value/);
    return true;
  });
  assert.equal(input.selfConfig.bytes.every((byte) => byte === 0), true);
});

test('error write and ambiguity claims require an own stage-matched operation and known code', () => {
  let getterCalls = 0;
  const accessor = nativeFailure('observe_self_process_epoch');
  Object.defineProperty(accessor, 'operation', { get() { getterCalls++; return 'observe_self_process_epoch'; } });
  const codeAccessor = nativeFailure('observe_self_process_epoch');
  Object.defineProperty(codeAccessor, 'code', { get() { getterCalls++; return 'SERVICE_ACCESS_DENIED'; } });
  const inherited = Object.assign(Object.create({ operation: 'observe_self_process_epoch' }), {
    code: 'SERVICE_ACCESS_DENIED', writes: 0, ambiguous: false,
  });
  for (const error of [
    nativeFailure('read_self_service_config'),
    nativeFailure(undefined), nativeFailure(42),
    nativeFailure('observe_self_process_epoch', { code: undefined }),
    nativeFailure('observe_self_process_epoch', { code: 'secret-token-value' }),
    nativeFailure('observe_self_process_epoch', { code: 'ERR_NATIVE_CONTROL_REFUSED' }),
    accessor, codeAccessor, inherited,
    Object.assign(Object.create({ code: 'SERVICE_ACCESS_DENIED' }), {
      operation: 'observe_self_process_epoch', writes: 0, ambiguous: false,
    }),
  ]) {
    const input = fixture('bot');
    assert.throws(() => orchestrate(input, {
      observeSelfProcessEpoch: () => { throw error; },
    }), (refused) => {
      assert.equal(refused.code, 'SERVICE_BOOTSTRAP_REFUSED');
      assert.equal(refused.writes, null);
      assert.equal(refused.ambiguous, null);
      assert.doesNotMatch(JSON.stringify(refused), /secret-token-value/);
      return true;
    });
    assert.equal(input.selfConfig.bytes.every((byte) => byte === 0), true);
  }
  assert.equal(getterCalls, 0);
  assert.throws(() => runServiceBootstrap({ createNative: () => {
    throw nativeFailure('create_service_bootstrap_native');
  } }), (error) => error.code === 'SERVICE_BOOTSTRAP_REFUSED' && error.writes === null && error.ambiguous === null);
});

test('malformed successful receipts cannot establish zero writes before later refusals', () => {
  for (const mutate of [
    (i) => { i.selfConfig.schemaVersion = 2; },
    (i) => { i.selfConfig.sourceIdentityFingerprint = 'invalid'; },
    (i) => { i.selfConfig.extra = true; },
    (i) => { i.selfConfig = Object.assign(Object.create({ writes: 0 }), i.selfConfig); delete i.selfConfig.writes; },
    (i) => { Object.defineProperty(i.selfConfig, 'writes', { get() { throw new Error('secret-token-value'); } }); },
  ]) {
    const input = fixture('bot');
    const bytes = input.selfConfig.bytes;
    mutate(input);
    assert.throws(() => orchestrate(input, {
      observeSelfProcessEpoch: () => { throw nativeFailure('observe_self_process_epoch'); },
    }), (error) => error.code === 'SERVICE_BOOTSTRAP_REFUSED' && error.writes === null);
    assert.equal(bytes.every((byte) => byte === 0), true);
  }
  const input = fixture('bot');
  input.epoch.processEpochFingerprint = 'invalid';
  assert.throws(() => orchestrate(input), (error) =>
    error.code === 'SERVICE_BOOTSTRAP_REFUSED' && error.reason === 'epoch-invalid' && error.writes === null);
});

for (const component of ['bot', 'daemon']) {
  test(`${component} guard inputs yield one frozen nonsecret context and verified entries`, () => {
    const input = fixture(component);
    const { context, entries } = evaluateServiceBootstrap(input);
    assert.deepEqual(Reflect.ownKeys(context), [...SERVICE_BOOTSTRAP_CONTEXT_KEYS]);
    assert.equal(Object.isFrozen(context), true);
    assert.equal(context.component, component);
    assert.equal(context.serviceKey, input.env.GJC_REMOTE_SERVICE_KEY);
    assert.equal(context.processEpochFingerprint, h('epoch'));
    assert.equal(context.effectiveConfigFingerprint, input.env.GJC_REMOTE_EFFECTIVE_CONFIG_FINGERPRINT);
    assert.equal(context.configSourceIdentityFingerprint, h('source'));
    assert.deepEqual(entries, [['A', '1'], ['B', 'two']]);
    assert.equal(Object.isFrozen(entries), true);
    assert.equal(JSON.stringify(context).includes('two'), false);
  });
}

test('guard service-key policy agrees with the Windows service naming validator', () => {
  for (const key of [DAEMON_KEY, 'a-' + h('x'), 'Default-' + h('x'), 'default-' + h('x').slice(1), '-x-' + h('x')]) {
    let windowsValid = true;
    try { windowsServiceName('daemon', key); } catch { windowsValid = false; }
    const input = fixture('daemon');
    input.env.GJC_REMOTE_SERVICE_KEY = key;
    input.env.GJC_REMOTE_EFFECTIVE_CONFIG_FINGERPRINT = serviceEffectiveConfigFingerprint({
      component: 'daemon', serviceKey: key, entries: [['A', '1'], ['B', 'two']],
    });
    let guardValid = true;
    try { evaluateServiceBootstrap(input); } catch { guardValid = false; }
    assert.equal(guardValid, windowsValid, key);
  }
});

test('guard refuses every launch, runtime, config, epoch and environment drift', () => {
  const cases = [
    ['daemon', (i) => { i.runtime.platform = 'linux'; }, 'unsupported-platform'],
    ['daemon', (i) => { i.env.GJC_REMOTE_SERVICE_COMPONENT = 'other'; }, 'component-invalid'],
    ['bot', (i) => { i.env.GJC_REMOTE_SERVICE_KEY = 'daemon'; }, 'service-key-invalid'],
    ['daemon', (i) => { i.env.NODE_OPTIONS = '--require x'; }, 'environment-policy'],
    ['bot', (i) => { delete i.env.NODE_PATH; }, 'environment-missing'],
    ['daemon', (i) => { i.env.USERPROFILE = 'C:\\Other'; }, 'home-policy'],
    ['daemon', (i) => { i.env.GJC_REMOTE_LAUNCH_FINGERPRINT = '@runtime-policy-fingerprint'; }, 'environment-policy'],
    ['daemon', (i) => { i.env.GJC_REMOTE_RUNTIME_POLICY_FINGERPRINT = '@runtime-policy-fingerprint'; }, 'environment-policy'],
    ['daemon', (i) => { i.bootstrapPath = 'C:\\GJC\\release\\node_modules\\@gjc-remote\\native-control\\src\\service-bootstrap.js'; }, 'bootstrap-path-mismatch'],
    ['daemon', (i) => { i.env.BUN_INSPECT_PRELOAD = ''; }, 'bootstrap-path-mismatch'],
    ['daemon', (i) => { i.env.BUN_INSPECT = 'ws://127.0.0.1:9229'; }, 'inspector-policy'],
    ['daemon', (i) => { i.env.BUN_INSPECT_CONNECT_TO = 'ws://x'; }, 'inspector-policy'],
    ['daemon', (i) => { i.env.BUN_OPTIONS = '--preload x'; }, 'inspector-policy'],
    ['daemon', (i) => { i.env.XDG_CONFIG_HOME = 'C:\\GJC\\other'; }, 'runtime-config-policy'],
    ['daemon', (i) => { i.env.GJC_REMOTE_RUNTIME_CONFIG_SHA256 = h('nonempty'); }, 'runtime-config-policy'],
    ['daemon', (i) => { i.env.GJC_CODING_AGENT_DIR = 'C:\\GJC\\elsewhere'; }, 'sdk-profile-policy'],
    ['daemon', (i) => { i.env.PI_CODING_AGENT_DIR = 'C:\\GJC\\elsewhere'; }, 'sdk-profile-policy'],
    ['bot', (i) => { i.env.GJC_REMOTE_SDK_PROFILE_PATH = 'C:\\GJC\\home\\.gjc\\agent'; }, 'environment-policy'],
    ['bot', (i) => { i.env.CHANNELS_CONFIG = 'channels.json'; }, 'environment-policy'],
    ['daemon', (i) => { i.env.GJC_REMOTE_RUNTIME_VERSION = '1.4.1'; }, 'runtime-policy-mismatch'],
    ['daemon', (i) => { i.runtime.versions.bun = '1.4.1'; }, 'runtime-mismatch'],
    ['daemon', (i) => { i.runtime.bunRevision = h('other').slice(0, 40); }, 'runtime-mismatch'],
    ['bot', (i) => { i.runtime.versions.node = '26.6.0'; }, 'runtime-mismatch'],
    ['bot', (i) => { i.runtime.versions.bun = '1.4.2'; }, 'runtime-mismatch'],
    ['bot', (i) => { i.runtime.execPath = 'C:\\GJC\\node\\bun.exe'; }, 'runtime-mismatch'],
    ['bot', (i) => { i.runtime.execArgv = ['--inspect']; }, 'argv-policy'],
    ['bot', (i) => { i.runtime.argv.push('--extra'); }, 'argv-policy'],
    ['daemon', (i) => { i.runtime.argv[1] = 'C:\\GJC\\release\\bot\\src\\bot.js'; }, 'argv-policy'],
    ['daemon', (i) => { i.runtime.execArgv = ['--preload', 'x']; }, 'argv-policy'],
    ['daemon', (i) => { i.runtime.execArgv = ['--config', 'C:\\GJC\\other.toml', '--no-env-file']; }, 'argv-policy'],
    ['daemon', (i) => { i.selfConfig.sourceIdentityFingerprint = h('other'); }, 'config-source-drift'],
    ['daemon', (i) => { i.selfConfig.writes = 1; }, 'config-source-drift'],
    ['daemon', (i) => { i.selfConfig.bytes = CONFIG_BYTES; }, 'config-source-drift'],
    ['daemon', (i) => { i.selfConfig.extra = 1; }, 'config-source-drift'],
    ['bot', (i) => { i.selfConfig.runtimeConfig = fixture('daemon').selfConfig.runtimeConfig; }, 'runtime-config-drift'],
    ['daemon', (i) => { i.selfConfig.runtimeConfig = null; }, 'runtime-config-drift'],
    ['daemon', (i) => { i.selfConfig.runtimeConfig.byteLength = 1; }, 'runtime-config-drift'],
    ['daemon', (i) => { i.selfConfig.runtimeConfig.fileIdentityFingerprint = h('swapped'); }, 'runtime-config-drift'],
    ['daemon', (i) => { i.epoch = { processEpochFingerprint: 'x', writes: 0 }; }, 'epoch-invalid'],
    ['daemon', (i) => { i.epoch = { processEpochFingerprint: h('epoch'), writes: 1 }; }, 'epoch-invalid'],
    ['daemon', (i) => { i.parseDotenv = () => { throw new Error('boom'); }; }, 'config-invalid'],
    ['daemon', (i) => { i.selfConfig.bytes = Buffer.from('A=1\nB=changed\n'); }, 'effective-config-drift'],
    ['daemon', (i) => { i.selfConfig.bytes = Buffer.from('A=1\nB=two\nGJC_REMOTE_SERVICE_KEY=x\n'); }, 'config-reserved-key'],
    ['daemon', (i) => { i.env.A = 'inherited'; }, 'inherited-env-conflict'],
  ];
  for (const [component, mutate, reason] of cases) {
    const input = fixture(component);
    mutate(input);
    assert.throws(() => evaluateServiceBootstrap(input), refusal(reason), reason);
  }
});

test('refusals carry no path, secret or config value in their message', () => {
  const input = fixture('daemon');
  input.selfConfig.bytes = Buffer.from('A=1\nB=secret-token-value\n');
  assert.throws(() => evaluateServiceBootstrap(input), (error) =>
    !/secret-token-value|[A-Za-z]:\\/.test(error.message) && error.reason === 'effective-config-drift');
});

test('daemon Bun execArgv accepts only the exact fixed config and no-env-file flags', () => {
  const config = 'C:\\GJC\\work\\runtime-config\\.bunfig.toml';
  for (const execArgv of [[], ['--config', config, '--no-env-file'], [`--config=${config}`, '--no-env-file']]) {
    const input = fixture('daemon');
    input.runtime.execArgv = execArgv;
    assert.doesNotThrow(() => evaluateServiceBootstrap(input));
  }
  for (const execArgv of [['--no-env-file'], ['--config', config], ['--no-env-file', '--config', config],
    ['--config', config, '--no-env-file', '--hot']]) {
    const input = fixture('daemon');
    input.runtime.execArgv = execArgv;
    assert.throws(() => evaluateServiceBootstrap(input), refusal('argv-policy'));
  }
});

test('dotenv policy refuses reserved selectors and inherited conflicts, accepting equal inherited values', () => {
  for (const key of ['GJC_REMOTE_X', 'NODE_OPTIONS', 'bun_options', 'HOME', 'UserProfile', 'XDG_CONFIG_HOME',
    'GJC_CODING_AGENT_DIR', 'PI_CODING_AGENT_DIR']) {
    assert.throws(() => validateServiceDotenvEntries({ [key]: 'x' }, {}), refusal('config-reserved-key'), key);
  }
  assert.throws(() => validateServiceDotenvEntries({ A: 'x' }, { A: 'y' }), refusal('inherited-env-conflict'));
  assert.throws(() => validateServiceDotenvEntries({ 'A-B': 'x' }, {}), refusal('config-invalid'));
  assert.deepEqual(validateServiceDotenvEntries({ B: '2', A: 'x' }, { A: 'x' }), [['A', 'x'], ['B', '2']]);
});

test('effective config fingerprint is domain-separated, order-strict and component-bound', () => {
  const entries = [['A', '1'], ['B', 'two']];
  const fingerprint = serviceEffectiveConfigFingerprint({ component: 'bot', serviceKey: 'bot', entries });
  const expected = createHash('sha256').update(`${SERVICE_EFFECTIVE_CONFIG_DOMAIN}\n${JSON.stringify({
    component: 'bot', entries, serviceKey: 'bot',
  })}`).digest('hex');
  assert.equal(fingerprint, expected);
  assert.notEqual(fingerprint, serviceEffectiveConfigFingerprint({ component: 'bot', serviceKey: 'bot', entries: [['A', '1']] }));
  assert.throws(() => serviceEffectiveConfigFingerprint({ component: 'bot', serviceKey: 'bot', entries: [...entries].reverse() }), TypeError);
  assert.throws(() => serviceEffectiveConfigFingerprint({ component: 'x', serviceKey: 'bot', entries }), TypeError);
});

test('outside a service launch the guard does no work and its context is consumable exactly once', async () => {
  assert.equal(process.env.GJC_REMOTE_SERVICE_COMPONENT, undefined);
  const module = await import(pathToFileURL(guardPath).href);
  assert.equal(module.consumeServiceBootstrapContext(), null);
  assert.throws(() => module.consumeServiceBootstrapContext(), refusal('context-already-consumed'));
  assert.deepEqual(Object.keys(module).sort(), ['consumeServiceBootstrapContext']);
});

test('a service launch refusal stops the entrypoint before any application code runs', () => {
  const env = {
    ...process.env,
    ...fixture('daemon').env,
    NODE_OPTIONS: '',
    NODE_PATH: '',
    BUN_INSPECT_PRELOAD: guardPath,
    GJC_REMOTE_BOOTSTRAP_PATH: guardPath,
  };
  const result = spawnSync(process.execPath, ['--input-type=module', '-e',
    `await import(${JSON.stringify(pathToFileURL(guardPath).href)}); console.log('APPLICATION-RAN');`], {
    env, encoding: 'utf8', timeout: 60_000,
  });
  assert.equal(result.error, undefined);
  assert.equal(result.signal, null);
  assert.equal(result.status, 1);
  assert.equal(result.stdout.includes('APPLICATION-RAN'), false);
  assert.match(result.stderr, /SERVICE_BOOTSTRAP_REFUSED/);
});

test('package exports the canonical guard path and pins the dotenv parser dependency', () => {
  const packageJson = JSON.parse(readFileSync(join(packageRoot, 'package.json'), 'utf8'));
  assert.equal(packageJson.exports['./service-bootstrap'], './src/service-bootstrap.js');
  assert.equal(packageJson.dependencies.dotenv, '16.6.1');
  assert.equal(require('dotenv/package.json').version, '16.6.1');
  assert.equal(fileURLToPath(import.meta.resolve('@gjc-remote/native-control/service-bootstrap')).toLowerCase(),
    guardPath.toLowerCase());
});
