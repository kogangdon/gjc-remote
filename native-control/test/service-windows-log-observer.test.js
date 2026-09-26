import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { existsSync, readFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';
import test from 'node:test';

import {
  SERVICE_LIFECYCLE_LIMITS,
  serviceCursorSetFingerprint,
  validateServiceCursorSet,
} from '@gjc-remote/shared/service-lifecycle-envelope';
import { capabilities, capabilitySignatures } from '../src/capabilities.js';
import { WINDOWS_DRIVER_LIMITS } from '../src/service-windows.js';

const require = createRequire(import.meta.url);
const read = (relative) => readFileSync(fileURLToPath(new URL(relative, import.meta.url)), 'utf8');
const addonPath = fileURLToPath(new URL('../build/Release/native_control.node', import.meta.url));
const addon = read('../src/addon.cc');
const observer = read('../src/service-log-observer.inc');
const vectors = JSON.parse(read('../test-fixtures/shawl-v1.9.0-log-vectors.json'));
const sha256 = (text) => createHash('sha256').update(text).digest('hex');
const hash = (label) => sha256(label);

function constant(name) {
  const match = observer.match(new RegExp(`constexpr [a-z0-9_]+ ${name} = ([^;]+);`));
  assert.ok(match, name);
  return Function(`return (${match[1].replace(/ULL/g, '')});`)();
}

function functionBody(name) {
  const start = observer.indexOf(`${name}(`);
  assert.notEqual(start, -1, name);
  const open = observer.indexOf('{', start);
  let depth = 0;
  for (let index = open; index < observer.length; index += 1) {
    if (observer[index] === '{') depth += 1;
    if (observer[index] === '}' && --depth === 0) return observer.slice(open, index + 1);
  }
  throw new Error(`unterminated ${name}`);
}

// Byte-for-byte port of LogObserverFamilyCanonical/LogObserverCursorFingerprint
// in service-log-observer.inc.  The native fingerprint must equal the shared
// canonical-JSON fingerprint the JS validator recomputes.
function nativeFamilyCanonical(family) {
  const absence = family.files.length === 0 ? `"${family.absenceFingerprint}"` : 'null';
  const files = family.files.map((file) => `{"identityFingerprint":"${file.identityFingerprint}","logicalStartOffset":${file.logicalStartOffset},"observedLength":${file.observedLength},"prefixSha256":"${file.prefixSha256}"}`).join(',');
  return `{"absenceFingerprint":${absence},"baseName":"${family.baseName}","directoryIdentityFingerprint":"${family.directoryIdentityFingerprint}","family":"${family.family}","files":[${files}],"nextLogicalOffset":${family.nextLogicalOffset},"partialLineBytes":${family.partialLineBytes}}`;
}
function nativeCursorFingerprint(set) {
  return sha256(`{"bootFingerprint":"${set.bootFingerprint}","configFingerprint":"${set.configFingerprint}","families":[${set.families.map(nativeFamilyCanonical).join(',')}],"schemaVersion":1,"serviceKey":"${set.serviceKey}"}`);
}

// Port of LogObserverNameKind.
function nameKind(name, base) {
  const prefix = `${base}_r`;
  if (name.length <= prefix.length + 4 || !name.startsWith(prefix) || !name.endsWith('.log')) return 'none';
  const infix = name.slice(prefix.length, -4);
  if (infix === 'CURRENT') return 'live';
  return /^\d{4}-\d{2}-\d{2}_\d{2}-\d{2}-\d{2}(?:\.restart-\d{4})?$/.test(infix) ? 'rotated' : 'none';
}

function cursorSet(serviceKey, families) {
  const base = serviceKey === 'bot' ? 'gjc-remote-bot' : `gjc-remote-daemon-${serviceKey}`;
  const set = {
    schemaVersion: 1,
    bootFingerprint: hash('boot'),
    serviceKey,
    configFingerprint: hash('config'),
    families: ['wrapper', 'child'].map((family, index) => {
      const files = families[index];
      const end = files.length === 0 ? 0 : files.at(-1).logicalStartOffset + files.at(-1).observedLength;
      return {
        family,
        baseName: `${base}-${family}`,
        directoryIdentityFingerprint: hash('directory'),
        files,
        nextLogicalOffset: end,
        partialLineBytes: files.length === 0 ? 0 : Math.min(7, end),
        absenceFingerprint: files.length === 0 ? hash(`absent-${family}`) : null,
      };
    }),
  };
  return { ...set, cursorFingerprint: serviceCursorSetFingerprint({ ...set, cursorFingerprint: null }) };
}

test('native log observer fragment is included once and registered in JS capability order', () => {
  assert.equal(addon.split('#include "service-log-observer.inc"').length, 2);
  const include = addon.indexOf('#include "service-log-observer.inc"');
  assert.ok(include > addon.indexOf('bool ServiceSelfExecutableIdentity('));
  assert.ok(include < addon.indexOf('napi_value ObserveSelfProcessEpoch('));
  for (const name of ['open_win32_service_log_observer', 'read_win32_service_log_observer']) {
    assert.ok(capabilities.includes(name), name);
    const signature = `signature("${name}", {${capabilitySignatures[name].map((field) => `"${field}"`).join(', ')}});`;
    assert.ok(addon.includes(signature), signature);
  }
  const listed = [...addon.matchAll(/^ {4}"([a-z0-9_]+)",$/gm)].map((match) => match[1]);
  const order = (list) => ['read_service_external_object', 'open_win32_service_log_observer', 'read_win32_service_log_observer', 'read_win32_boot_clock'].map((name) => list.indexOf(name));
  const nativeOrder = order(listed);
  assert.ok(nativeOrder.every((position, index) => position >= 0 && (index === 0 || position === nativeOrder[index - 1] + 1)), 'native capability order');
  const jsOrder = order(capabilities);
  assert.ok(jsOrder.every((position, index) => index === 0 || position === jsOrder[index - 1] + 1), 'JS capability order');
  assert.match(addon, /\{"open_win32_service_log_observer", nullptr, OpenWin32ServiceLogObserver,/);
  assert.match(addon, /\{"read_win32_service_log_observer", nullptr, ReadWin32ServiceLogObserver,/);
  // close_service_handle releases observer handles before store handles.
  assert.match(addon, /napi_value CloseServiceHandle\(napi_env env, napi_callback_info info\) \{[\s\S]{0,200}CloseWin32LogObserverValue\(env, args\[0\]\)/);
});

test('native log observer is read-only and least-privilege', () => {
  for (const forbidden of [
    'WriteFile', 'MoveFile', 'DeleteFile', 'CreateDirectory', 'SetFileInformationByHandle', 'SetSecurityInfo',
    'SetNamedSecurityInfo', 'ControlService', 'StartService', 'ChangeServiceConfig', 'TerminateProcess',
    'kFileCreate', 'kFileOverwrite', 'kFileSupersede', 'kFileOpenIf', 'WRITE_DAC', 'WRITE_OWNER', 'DELETE |',
    'FILE_WRITE_DATA', 'FILE_APPEND_DATA', 'GENERIC_WRITE', 'SERVICE_ALL_ACCESS', 'SC_MANAGER_ALL_ACCESS',
  ]) assert.equal(observer.includes(forbidden), false, forbidden);
  assert.match(observer, /OpenSCManagerW\(nullptr, nullptr, SC_MANAGER_CONNECT\)/);
  assert.match(observer, /OpenServiceW\([^;]*SERVICE_QUERY_STATUS\)/);
  assert.equal([...observer.matchAll(/OpenWindowsRelative\(/g)].length, 2);
  for (const call of observer.matchAll(/OpenWindowsRelative\(directory, Wide\(\w+\.?\w*\),\s*([^,]+),\s*kFileOpen,/g)) {
    assert.match(call[1], /^FILE_READ_(?:ATTRIBUTES|DATA \| FILE_READ_ATTRIBUTES)$/);
  }
  assert.match(functionBody('HANDLE LogObserverOpenDirectory'), /OpenWindowsPathNoFollow\([\s\S]*FILE_LIST_DIRECTORY \| FILE_READ_ATTRIBUTES,[\s\S]*VerifiedObjectType::Directory\)/);
  // Every native observer result reports zero writes.
  assert.equal([...observer.matchAll(/ServiceSetUint32\(env, (?:result|clock), "writes", 0\)/g)].length, 3);
});

test('native log observer bounds match the shared cursor contract and Shawl rotation headroom', () => {
  assert.equal(constant('kLogObserverFileBytes'), SERVICE_LIFECYCLE_LIMITS.startupCursorFileBytes);
  assert.equal(constant('kLogObserverLogicalBytes'), SERVICE_LIFECYCLE_LIMITS.startupCursorLogicalBytes);
  assert.equal(constant('kLogObserverCursorBytes'), SERVICE_LIFECYCLE_LIMITS.startupCursorBytes);
  assert.equal(constant('kLogObserverPartialLineBytes'), SERVICE_LIFECYCLE_LIMITS.startupPartialLineBytes);
  assert.equal(constant('kLogObserverFilesPerFamily'), SERVICE_LIFECYCLE_LIMITS.startupCursorFilesPerFamily);
  assert.ok(WINDOWS_DRIVER_LIMITS.logReadBytes <= constant('kLogObserverPageBytes'));
  // flexi_logger rotates only after a write crosses the size criterion, so a
  // full-cap rotation would publish rotated files the cursor cannot represent.
  assert.ok(WINDOWS_DRIVER_LIMITS.logRotateBytes * 2 <= SERVICE_LIFECYCLE_LIMITS.startupCursorFileBytes);
  assert.ok(addon.includes(`"--log-rotate", "bytes=${WINDOWS_DRIVER_LIMITS.logRotateBytes}", "--log-retain",`));
  assert.ok(addon.includes(`"--log-retain",\n    "${WINDOWS_DRIVER_LIMITS.logRetain}", "--"`));
  // Retained rotated files plus the live file fit the per-family cursor.
  assert.ok(WINDOWS_DRIVER_LIMITS.logRetain + 1 <= SERVICE_LIFECYCLE_LIMITS.startupCursorFilesPerFamily);
});

test('Shawl 1.9.0 family names classify exactly and rotated names sort chronologically', () => {
  assert.equal(vectors.source.shawl, '1.9.0');
  assert.equal(vectors.source.flexiLogger, '0.29.3');
  const body = functionBody('int LogObserverNameKind');
  assert.match(body, /base \+ "_r"/);
  assert.match(body, /infix == "CURRENT"\) return 2/);
  assert.match(body, /"dddd-dd-dd_dd-dd-dd"/);
  assert.match(body, /"\.restart-"/);
  assert.match(body, /stamp \+ kRestart\.size\(\) \+ 4/);
  for (const vector of vectors.names) assert.equal(nameKind(vector.name, vectors.baseName), vector.kind, vector.name);
  assert.deepEqual([...vectors.rotatedOrder].reverse().sort(), vectors.rotatedOrder);
  assert.match(functionBody('LogObserverOutcome LogObserverScanFamily'), /return left\.name < right\.name;/);
});

test('native cursor fingerprint serialization equals the shared canonical cursor fingerprint', () => {
  const file = (label, logicalStartOffset, observedLength) => ({
    identityFingerprint: hash(`file-${label}`), logicalStartOffset, observedLength, prefixSha256: hash(`prefix-${label}`),
  });
  const cases = [
    cursorSet('bot', [[], []]),
    cursorSet('bot', [[file('w0', 0, 12)], []]),
    cursorSet('bot', [[file('w0', 0, 1_048_600), file('w1', 1_048_600, 900)], [file('c0', 40, 0)]]),
    cursorSet(`worker-${'a'.repeat(64)}`, [[file('w0', 5, 5), file('w1', 10, 0), file('w2', 10, 3)], [file('c0', 0, 16_000)]]),
  ];
  for (const set of cases) {
    validateServiceCursorSet(set);
    assert.equal(nativeCursorFingerprint(set), set.cursorFingerprint);
  }
  const canonical = functionBody('bool LogObserverFamilyCanonical');
  for (const key of ['absenceFingerprint', 'baseName', 'directoryIdentityFingerprint', 'family', 'files', 'nextLogicalOffset', 'partialLineBytes', 'identityFingerprint', 'logicalStartOffset', 'observedLength', 'prefixSha256']) {
    assert.ok(canonical.includes(`\\"${key}\\":`), key);
  }
  const fingerprint = functionBody('bool LogObserverCursorFingerprint');
  assert.match(fingerprint, /"\{\\"bootFingerprint\\":\\"" \+ observer\.boot_fingerprint \+\s*"\\",\\"configFingerprint\\":\\"" \+ observer\.config_fingerprint \+\s*"\\",\\"families\\":\[" \+ wrapper \+ "," \+ child \+\s*"\],\\"schemaVersion\\":1,\\"serviceKey\\":\\"" \+ observer\.service_key \+\s*"\\"\}"/);
});

test('native observer reuses the self-epoch formula for the child process epoch', () => {
  const self = addon.slice(addon.indexOf('napi_value ObserveSelfProcessEpoch('));
  const epoch = functionBody('bool LogObserverProcessEpoch');
  for (const fragment of ['\\"bootId\\":\\"', '\\",\\"creationTime\\":\\"', '\\",\\"executableIdentityFingerprint\\":\\"', '\\",\\"kind\\":\\"gjc-remote/windows-self-epoch/v1\\",\\"pid\\":']) {
    assert.ok(self.includes(fragment), fragment);
    assert.ok(epoch.includes(fragment), fragment);
  }
  assert.match(epoch, /ServiceSelfExecutableIdentity\(facts\.executable, &identity\)/);
  assert.match(epoch, /ServiceSelfWin32PhysicalSecurityIdentityFingerprint\(/);
});

test('native observer commits reads only after every fallible step', () => {
  const body = functionBody('napi_value ReadWin32ServiceLogObserver');
  const commit = body.indexOf('observer->cursor_fingerprint = fingerprint;');
  assert.ok(commit > 0);
  for (const fallible of ['LogObserverObserve(', 'stale-epoch', 'LogObserverCursorFingerprint(', 'napi_create_buffer_copy(']) {
    const position = body.indexOf(fallible);
    assert.ok(position > 0 && position < commit, fallible);
  }
  assert.ok(body.indexOf('expected != observer->cursor_fingerprint') < body.indexOf('LogObserverObserve('));
  assert.match(body, /max_bytes == 0 \|\|\s*max_bytes > kLogObserverPageBytes/);
});

test('built addon exposes the observer and rejects malformed tuples before observation', (context) => {
  if (!existsSync(addonPath)) {
    context.skip('native addon is not built in this source-only check');
    return;
  }
  const native = require(addonPath);
  const contract = native.native_control_contract();
  if (!contract.capabilities.includes('open_win32_service_log_observer')) {
    context.skip('built addon predates the log observer; rebuild required for runtime evidence');
    return;
  }
  for (const name of ['open_win32_service_log_observer', 'read_win32_service_log_observer']) {
    assert.deepEqual(contract.capabilitySignatures[name], capabilitySignatures[name]);
  }
  const expected = process.platform === 'win32' && process.arch === 'x64' ? 'SERVICE_INVALID' : 'SERVICE_UNSUPPORTED';
  for (const invoke of [
    () => native.open_win32_service_log_observer({}, {}, null),
    () => native.read_win32_service_log_observer({}, hash('cursor'), 1024),
  ]) {
    assert.throws(invoke, (error) => {
      assert.equal(error.code, expected);
      assert.equal(error.writes, 0);
      return true;
    });
  }
  assert.throws(() => native.open_win32_service_log_observer({}), (error) => error.code === 'SERVICE_INVALID' && error.writes === 0);
});
