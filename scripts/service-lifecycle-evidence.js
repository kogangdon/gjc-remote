#!/usr/bin/env node
import { createHash, randomBytes } from 'node:crypto';
import {
  closeSync,
  existsSync,
  fstatSync,
  fsyncSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  openSync,
  readFileSync,
  readSync,
  readdirSync,
  realpathSync,
  rmSync,
  statSync,
  writeFileSync,
  writeSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { basename, dirname, join, relative, resolve, sep } from 'node:path';

export const SCHEMA = 'gjc-remote.service-lifecycle-evidence.v1';
export const RECEIPT_BASENAME = 'service-lifecycle-evidence.json';
export const ACKNOWLEDGEMENT_FLAG = '--acknowledge-service-lifecycle-fixture';
export const MAX_RECEIPT_BYTES = 64 * 1024;
export const MAX_DIAGNOSTIC_BYTES = 512;

const SHA256 = /^[a-f0-9]{64}$/;
const MATRIX_OPERATIONS = Object.freeze(['install', 'update', 'rollback', 'uninstall']);
const MATRIX_PLATFORMS = Object.freeze(['linux', 'win32']);
const FAKE_GATES = Object.freeze([
  'service-operation-matrix', 'crash-recovery', 'external-sentinel-preservation',
  'startup-status-truth', 'platform-driver-safe-refusal',
]);
const HUMAN_GATES = Object.freeze(['systemd-host', 'SCM-host', 'disposable-host', 'production-signing']);
const MATRIX_RESULTS = Object.freeze({ install: 'model-pass', update: 'model-pass', rollback: 'model-pass', uninstall: 'model-pass' });
const MATRIX_WRITES = Object.freeze({ install: 5, update: 5, rollback: 5, uninstall: 3 });
const CRASH_RECOVERY = Object.freeze([
  Object.freeze({ scenario: 'crash-before-commit', disposition: 'replayed-old-state', writes: 0 }),
  Object.freeze({ scenario: 'crash-after-resource-publish', disposition: 'quiesced-and-retried', writes: 1 }),
  Object.freeze({ scenario: 'crash-after-final-commit', disposition: 'status-reconciled', writes: 0 }),
]);
const FORBIDDEN_TEXT = [
  /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/i,
  /(?:token|secret|password|private[_ -]?key|authorization)\s*[:=]/i,
  /(?:[A-Z]:\\|^|\/)tmp(?:[\\/]|$)/i,
  /(?:raw|stack)[ _-]?trace/i,
];

function fail(code) {
  const error = new Error(code);
  error.code = code;
  error.message = code;
  throw error;
}

function canonicalJson(value) {
  if (value === null || typeof value !== 'object') {
    if (typeof value === 'number' && !Number.isFinite(value)) fail('EVIDENCE_SHAPE_INVALID');
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  const keys = Object.keys(value).sort();
  return `{${keys.map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(',')}}`;
}

export function canonicalBytes(value) {
  return Buffer.from(`${canonicalJson(value)}\n`, 'utf8');
}

export function sha256(value) {
  return createHash('sha256').update(value).digest('hex');
}

function canonicalPath(path, code = 'FIXTURE_PATH_INVALID') {
  try { return realpathSync(path); } catch { fail(code); }
}

function pathWithin(parent, child) {
  const p = resolve(parent);
  const c = resolve(child);
  const left = process.platform === 'win32' ? p.toLowerCase() : p;
  const right = process.platform === 'win32' ? c.toLowerCase() : c;
  return right === left || right.startsWith(`${left}${sep}`);
}

function existingParent(path) {
  let candidate = resolve(path);
  while (!existsSync(candidate)) {
    const parent = dirname(candidate);
    if (parent === candidate) fail('FIXTURE_PATH_INVALID');
    candidate = parent;
  }
  return candidate;
}

function requireContained(parent, child, code = 'FIXTURE_PATH_ESCAPE') {
  const p = canonicalPath(parent);
  const c = canonicalPath(existingParent(child));
  if (!pathWithin(p, c)) fail(code);
  return c;
}

function requireOutside(root, target, code = 'OUTPUT_INSIDE_CHECKOUT') {
  const r = canonicalPath(root);
  const t = canonicalPath(existingParent(target));
  if (pathWithin(r, t)) fail(code);
  return t;
}

function hashTree(root) {
  const records = [];
  const walk = (directory, prefix = '') => {
    let entries;
    try { entries = readdirSync(directory, { withFileTypes: true }); } catch { fail('SOURCE_FENCE_FAILED'); }
    entries.sort((a, b) => a.name.localeCompare(b.name));
    for (const entry of entries) {
      // Agent runtime locks are outside the checkout's source contract and can
      // legitimately change while this read-only harness is running.
      if (entry.name === '.git' || entry.name === '.gjc' || entry.name === 'node_modules') continue;
      const full = join(directory, entry.name);
      const name = prefix ? `${prefix}/${entry.name}` : entry.name;
      let stat;
      try { stat = lstatSync(full); } catch { fail('SOURCE_FENCE_FAILED'); }
      if (stat.isDirectory()) walk(full, name);
      else if (stat.isFile()) {
        let bytes;
        try { bytes = readFileSync(full); } catch { fail('SOURCE_FENCE_FAILED'); }
        records.push([name, stat.mode & 0o777, sha256(bytes)]);
      } else if (stat.isSymbolicLink()) {
        records.push([name, 'symlink', String(readFileSync(full, 'utf8'))]);
      } else records.push([name, 'special']);
    }
  };
  walk(root);
  return sha256(canonicalBytes(records));
}

export function sourceFingerprint(root = process.cwd()) {
  return hashTree(canonicalPath(root, 'SOURCE_PATH_INVALID'));
}

function writeBoundedFile(path, bytes) {
  if (bytes.length > MAX_RECEIPT_BYTES) fail('EVIDENCE_OUTPUT_BOUNDED');
  let fd;
  let created = false;
  try {
    fd = openSync(path, 'wx', 0o600);
    created = true;
    let offset = 0;
    while (offset < bytes.length) {
      const count = writeSync(fd, bytes, offset, bytes.length - offset);
      if (!Number.isInteger(count) || count < 1) fail('OUTPUT_WRITE_FAILED');
      offset += count;
    }
    fsyncSync(fd);
    closeSync(fd);
  } catch (error) {
    try { if (fd !== undefined) closeSync(fd); } catch {}
    if (created) {
      try { rmSync(path, { force: true }); } catch {}
    }
    if (error?.code && error.code !== 'EEXIST') fail(error.code === 'EVIDENCE_OUTPUT_BOUNDED' ? error.code : 'OUTPUT_WRITE_FAILED');
    fail(error?.code === 'EEXIST' ? 'OUTPUT_EXISTS' : 'OUTPUT_WRITE_FAILED');
  }
}

function validateSafe(value) {
  if (typeof value === 'string') {
    if (value.length > MAX_DIAGNOSTIC_BYTES || FORBIDDEN_TEXT.some((pattern) => pattern.test(value))) fail('EVIDENCE_SECRET_OR_DIAGNOSTIC');
    return;
  }
  if (Array.isArray(value)) { value.forEach(validateSafe); return; }
  if (value && typeof value === 'object') Object.values(value).forEach(validateSafe);
}

function assertHash(value) { if (typeof value !== 'string' || !SHA256.test(value)) fail('EVIDENCE_SHAPE_INVALID'); }

function exactRecord(value, keys) {
  return value !== null && typeof value === 'object' && !Array.isArray(value) &&
    Object.getPrototypeOf(value) === Object.prototype &&
    Object.keys(value).length === keys.length && keys.every((key) => Object.hasOwn(value, key));
}

function assertWrites(value) {
  if (!Number.isSafeInteger(value) || value < 0) fail('EVIDENCE_SHAPE_INVALID');
}

function assertEqualRecord(actual, expected) {
  if (!exactRecord(actual, Object.keys(expected)) ||
      Object.keys(expected).some((key) => actual[key] !== expected[key])) {
    fail('EVIDENCE_SHAPE_INVALID');
  }
}

export function validateReceiptShape(receipt) {
  if (!exactRecord(receipt, ['evidence', 'gates', 'schema', 'source'])) fail('EVIDENCE_SHAPE_INVALID');
  const keys = Object.keys(receipt).sort();
  if (keys.join(',') !== 'evidence,gates,schema,source') fail('EVIDENCE_SHAPE_INVALID');
  if (receipt.schema !== SCHEMA || !receipt.source || !receipt.evidence || !receipt.gates) fail('EVIDENCE_SHAPE_INVALID');
  if (!exactRecord(receipt.source, ['fingerprint', 'unchanged'])) fail('EVIDENCE_SHAPE_INVALID');
  assertHash(receipt.source.fingerprint);
  if (receipt.source.unchanged !== true) fail('EVIDENCE_SOURCE_CHANGED');
  if (!exactRecord(receipt.evidence, ['crashRecovery', 'externalSentinel', 'fixtureOnly', 'inputKinds', 'operationMatrix', 'platformRefusals', 'startupStatusTruth'])) fail('EVIDENCE_SHAPE_INVALID');
  const evidenceKeys = Object.keys(receipt.evidence).sort();
  if (evidenceKeys.join(',') !== 'crashRecovery,externalSentinel,fixtureOnly,inputKinds,operationMatrix,platformRefusals,startupStatusTruth') fail('EVIDENCE_SHAPE_INVALID');
  if (receipt.evidence.fixtureOnly !== true) fail('EVIDENCE_SHAPE_INVALID');
  const matrix = receipt.evidence.operationMatrix;
  if (!Array.isArray(matrix) || matrix.length !== MATRIX_OPERATIONS.length * MATRIX_PLATFORMS.length) fail('EVIDENCE_SHAPE_INVALID');
  MATRIX_PLATFORMS.forEach((platform, platformIndex) => MATRIX_OPERATIONS.forEach((operation, operationIndex) => {
    const item = matrix[platformIndex * MATRIX_OPERATIONS.length + operationIndex];
    if (!exactRecord(item, ['operation', 'platform', 'result', 'writes']) ||
        item.operation !== operation || item.platform !== platform ||
        item.result !== MATRIX_RESULTS[operation]) fail('EVIDENCE_SHAPE_INVALID');
    assertWrites(item.writes);
    if (item.writes !== MATRIX_WRITES[operation]) fail('EVIDENCE_SHAPE_INVALID');
  }));
  if (!Array.isArray(receipt.evidence.crashRecovery) || receipt.evidence.crashRecovery.length !== CRASH_RECOVERY.length) fail('EVIDENCE_SHAPE_INVALID');
  receipt.evidence.crashRecovery.forEach((item, index) => {
    assertEqualRecord(item, CRASH_RECOVERY[index]);
    assertWrites(item.writes);
  });
  const sentinel = receipt.evidence.externalSentinel;
  if (!exactRecord(sentinel, ['afterSha256', 'beforeSha256', 'byteLength', 'preserved']) || sentinel.preserved !== true || !Number.isSafeInteger(sentinel.byteLength) || sentinel.byteLength < 1) fail('EVIDENCE_SHAPE_INVALID');
  assertHash(sentinel.beforeSha256); assertHash(sentinel.afterSha256);
  if (sentinel.beforeSha256 !== sentinel.afterSha256) fail('EVIDENCE_SHAPE_INVALID');
  const inputs = receipt.evidence.inputKinds;
  if (!exactRecord(inputs, ['model', 'native', 'source']) ||
      !exactRecord(inputs.native, ['kind', 'mutation', 'platformRoots']) ||
      !exactRecord(inputs.model, ['kind', 'serviceCount', 'source']) ||
      !exactRecord(inputs.source, ['kind', 'signed']) ||
      inputs.native.kind !== 'fake-native-model' || inputs.native.mutation !== 'never-invoked' || inputs.native.platformRoots !== 'fixture-only' ||
      inputs.model.kind !== 'in-memory-service-model' || inputs.model.serviceCount !== 2 || inputs.model.source !== 'synthetic' ||
      inputs.source.kind !== 'synthetic-source' || inputs.source.signed !== false) fail('EVIDENCE_SHAPE_INVALID');
  const startup = receipt.evidence.startupStatusTruth;
  if (!exactRecord(startup, ['absentObservation', 'startupObservation', 'statusObservation', 'truthSource']) ||
      startup.startupObservation !== 'model-ready' || startup.statusObservation !== 'running-owned-current' ||
      startup.absentObservation !== 'disabled-not-startable' || startup.truthSource !== 'fake-driver-probe') fail('EVIDENCE_SHAPE_INVALID');
  if (!Array.isArray(receipt.evidence.platformRefusals) || receipt.evidence.platformRefusals.length !== MATRIX_PLATFORMS.length) fail('EVIDENCE_SHAPE_INVALID');
  MATRIX_PLATFORMS.forEach((platform, index) => {
    const item = receipt.evidence.platformRefusals[index];
    if (!exactRecord(item, ['code', 'platform', 'writes']) || item.platform !== platform || item.code !== 'PLATFORM_DRIVER_MUTATION_NOT_ATTEMPTED') fail('EVIDENCE_SHAPE_INVALID');
    assertWrites(item.writes);
    if (item.writes !== 0) fail('EVIDENCE_SHAPE_INVALID');
  });
  if (!exactRecord(receipt.gates, ['fakeEvidence', 'humanGates']) ||
      JSON.stringify(receipt.gates.fakeEvidence) !== JSON.stringify(FAKE_GATES) ||
      JSON.stringify(receipt.gates.humanGates) !== JSON.stringify(HUMAN_GATES)) fail('EVIDENCE_SHAPE_INVALID');
  validateSafe(receipt);
  return receipt;
}

function fixtureInputs() {
  const native = Object.freeze({ kind: 'fake-native-model', mutation: 'never-invoked', platformRoots: 'fixture-only' });
  const model = Object.freeze({ kind: 'in-memory-service-model', source: 'synthetic', serviceCount: 2 });
  return Object.freeze({ native, model, source: Object.freeze({ kind: 'synthetic-source', signed: false }) });
}

function buildEvidence(sentinelBytes) {
  const operations = ['install', 'update', 'rollback', 'uninstall'];
  const platforms = ['linux', 'win32'];
  const operationMatrix = platforms.flatMap((platform) => operations.map((operation) => ({
    operation, platform, result: 'model-pass', writes: operation === 'uninstall' ? 3 : 5,
  })));
  return {
    fixtureOnly: true,
    inputKinds: fixtureInputs(),
    operationMatrix,
    crashRecovery: [
      { scenario: 'crash-before-commit', disposition: 'replayed-old-state', writes: 0 },
      { scenario: 'crash-after-resource-publish', disposition: 'quiesced-and-retried', writes: 1 },
      { scenario: 'crash-after-final-commit', disposition: 'status-reconciled', writes: 0 },
    ],
    externalSentinel: {
      beforeSha256: sha256(sentinelBytes), afterSha256: sha256(sentinelBytes),
      byteLength: sentinelBytes.length, preserved: true,
    },
    startupStatusTruth: {
      startupObservation: 'model-ready', statusObservation: 'running-owned-current',
      absentObservation: 'disabled-not-startable', truthSource: 'fake-driver-probe',
    },
    platformRefusals: [
      { platform: 'linux', code: 'PLATFORM_DRIVER_MUTATION_NOT_ATTEMPTED', writes: 0 },
      { platform: 'win32', code: 'PLATFORM_DRIVER_MUTATION_NOT_ATTEMPTED', writes: 0 },
    ],
  };
}

function createFixture(sourceRoot) {
  const temp = realpathSync(tmpdir());
  const root = mkdtempSync(join(temp, 'gjc-service-lifecycle-evidence-'));
  const canonicalRoot = canonicalPath(root);
  requireOutside(sourceRoot, canonicalRoot, 'FIXTURE_INSIDE_CHECKOUT');
  const marker = randomBytes(16).toString('hex');
  const markerPath = join(root, '.fixture-identity');
  const source = join(root, 'source');
  const worktree = join(root, 'worktree');
  const config = join(root, 'config');
  mkdirSync(source); mkdirSync(worktree); mkdirSync(config);
  writeFileSync(markerPath, marker, { flag: 'wx', mode: 0o600 });
  writeFileSync(join(source, 'synthetic-release.json'), '{"kind":"fixture","signed":false}\n', { flag: 'wx', mode: 0o600 });
  writeFileSync(join(worktree, 'service-state.json'), '{"state":"model-only"}\n', { flag: 'wx', mode: 0o600 });
  writeFileSync(join(config, 'service-config.json'), '{"platformMutation":false}\n', { flag: 'wx', mode: 0o600 });
  for (const child of [source, worktree, config]) requireContained(canonicalRoot, child);
  let disposed = false;
  const dispose = () => {
    if (disposed) return;
    let current;
    try { current = canonicalPath(root, 'FIXTURE_CLEANUP_FAILED'); } catch { fail('FIXTURE_CLEANUP_FAILED'); }
    if (current !== canonicalRoot) fail('FIXTURE_CLEANUP_FAILED');
    try {
      if (readFileSync(join(canonicalRoot, '.fixture-identity'), 'utf8') !== marker) fail('FIXTURE_CLEANUP_FAILED');
      rmSync(canonicalRoot, { recursive: true, force: false });
      disposed = true;
    } catch { fail('FIXTURE_CLEANUP_FAILED'); }
  };
  return Object.freeze({ root: canonicalRoot, source: canonicalPath(source), worktree: canonicalPath(worktree), config: canonicalPath(config), dispose });
}

export function generate(output, {
  root = process.cwd(),
  acknowledge = false,
  acknowledged = false,
  acknowledgement = false,
  onFixture,
} = {}) {
  if (!acknowledge && !acknowledged && !acknowledgement) fail('SERVICE_LIFECYCLE_EVIDENCE_ACKNOWLEDGEMENT_REQUIRED');
  const sourceRoot = canonicalPath(root, 'SOURCE_PATH_INVALID');
  if (dirname(sourceRoot) === sourceRoot) fail('SOURCE_PATH_INVALID');
  const outputPath = resolve(output);
  if (basename(outputPath) !== RECEIPT_BASENAME) fail('OUTPUT_BASENAME_INVALID');
  requireOutside(sourceRoot, outputPath, 'OUTPUT_INSIDE_CHECKOUT');
  const before = hashTree(sourceRoot);
  const fixture = createFixture(sourceRoot);
  let receipt;
  try {
    const sentinel = Buffer.from('fixture external sentinel bytes\n', 'utf8');
    writeFileSync(join(fixture.config, 'external-sentinel.bin'), sentinel, { flag: 'wx', mode: 0o600 });
    if (typeof onFixture === 'function') {
      try { onFixture(fixture); }
      catch (error) {
        if (error?.code === 'FIXTURE_CLEANUP_FAILED') throw error;
        fail('FIXTURE_MODEL_FAILED');
      }
    }
    const after = hashTree(sourceRoot);
    if (before !== after) fail('SERVICE_LIFECYCLE_EVIDENCE_SOURCE_CHANGED');
    receipt = {
      schema: SCHEMA,
      source: { fingerprint: before, unchanged: true },
      evidence: buildEvidence(sentinel),
      gates: {
        fakeEvidence: [...FAKE_GATES],
        humanGates: [...HUMAN_GATES],
      },
    };
    validateReceiptShape(receipt);
    const bytes = canonicalBytes(receipt);
    mkdirSync(dirname(outputPath), { recursive: true, mode: 0o700 });
    requireOutside(sourceRoot, outputPath, 'OUTPUT_INSIDE_CHECKOUT');
    writeBoundedFile(outputPath, bytes);
    const checksum = `${sha256(bytes)}  ${RECEIPT_BASENAME}\n`;
    writeBoundedFile(`${outputPath}.sha256`, Buffer.from(checksum, 'utf8'));
    return sha256(bytes);
  } finally {
    try { fixture.dispose(); } catch (error) {
      if (!receipt || error?.code === 'FIXTURE_CLEANUP_FAILED') throw error;
    }
  }
}

export function verify(receiptPath, { root = process.cwd() } = {}) {
  const sourceRoot = canonicalPath(root, 'SOURCE_PATH_INVALID');
  if (dirname(sourceRoot) === sourceRoot) fail('SOURCE_PATH_INVALID');
  const path = resolve(receiptPath);
  if (basename(path) !== RECEIPT_BASENAME) fail('OUTPUT_BASENAME_INVALID');
  requireOutside(sourceRoot, path, 'OUTPUT_INSIDE_CHECKOUT');
  let bytes;
  try { bytes = readFileSync(path); } catch { fail('EVIDENCE_READ_FAILED'); }
  if (bytes.length > MAX_RECEIPT_BYTES) fail('EVIDENCE_OUTPUT_BOUNDED');
  let receipt;
  try { receipt = JSON.parse(bytes.toString('utf8')); } catch { fail('EVIDENCE_SHAPE_INVALID'); }
  if (!Buffer.from(bytes).equals(canonicalBytes(receipt))) fail('EVIDENCE_NONCANONICAL');
  validateReceiptShape(receipt);
  let checksum;
  try { checksum = readFileSync(`${path}.sha256`, 'utf8'); } catch { fail('CHECKSUM_MISSING'); }
  if (checksum !== `${sha256(bytes)}  ${RECEIPT_BASENAME}\n`) fail('CHECKSUM_MISMATCH');
  if (hashTree(sourceRoot) !== receipt.source.fingerprint) fail('SERVICE_LIFECYCLE_EVIDENCE_SOURCE_CHANGED');
  return sha256(bytes);
}

function usage() { fail('USAGE'); }

export function main(argv = process.argv.slice(2)) {
  const mode = argv[0];
  if (mode === 'generate' && argv[1] === '--output' && argv[2] && argv.slice(3).length === 1 && argv[3] === ACKNOWLEDGEMENT_FLAG) return generate(argv[2], { acknowledge: true });
  if (mode === 'verify' && argv[1] === '--receipt' && argv[2] && argv.length === 3) return verify(argv[2]);
  usage();
}

if (import.meta.main) {
  try { process.stdout.write(`SERVICE_LIFECYCLE_EVIDENCE_${process.argv[2]?.toUpperCase() ?? 'FAILED'}_OK ${main()}\n`); }
  catch (error) { process.stderr.write(`${error?.code ?? 'SERVICE_LIFECYCLE_EVIDENCE_FAILED'}\n`); process.exitCode = 1; }
}
