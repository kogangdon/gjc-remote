import assert from 'node:assert/strict';
import { existsSync, mkdirSync, mkdtempSync, openSync, readFileSync, rmSync, symlinkSync, writeFileSync, writeSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { execFileSync } from 'node:child_process';
import test from 'node:test';
import { canonicalBytes, sha256 } from '../issue55-evidence.js';
import {
  ENVIRONMENT,
  FACETS,
  RECEIPT_BASENAME,
  RECIPE,
  SCHEMA,
  createReceipt,
  generate,
  validateReceiptShape,
  verify,
  writeReceipt,
} from '../issue55-observability-evidence.js';

const source = Object.freeze({ headCommit: 'a'.repeat(40), tree: 'b'.repeat(40) });
const packetDigest = 'c'.repeat(64);
function receipt() { return createReceipt(source, packetDigest); }
function throwsCode(fn, code) { assert.throws(fn, (error) => error?.code === code); }
function git(root, args) { return execFileSync('git', args, { cwd: root, encoding: 'utf8' }); }
function fixture() {
  const root = mkdtempSync(join(tmpdir(), 'issue55-observability-source-'));
  for (const file of ['package.json', 'bot/package.json', 'daemon/package.json', 'native-control/package.json', 'shared/package.json', 'bun.lock', '.dockerignore', 'deploy/docker/daemon/Dockerfile', 'deploy/docker/bot/Dockerfile']) {
    const destination = join(root, file); mkdirSync(dirname(destination), { recursive: true }); writeFileSync(destination, readFileSync(file));
  }
  git(root, ['init', '--quiet']); git(root, ['config', 'user.email', 'test@example.invalid']); git(root, ['config', 'user.name', 'test']); git(root, ['add', '.']); git(root, ['commit', '--quiet', '-m', 'fixture']);
  return root;
}
function withFixture(fn) { const root = fixture(); try { return fn(root); } finally { rmSync(root, { recursive: true, force: true }); } }
const testEnvironment = { architecture: 'x64', bunVersion: '1.3.14', nodeVersion: 'v26.0.0', platform: 'linux' };
function commit(root) { return git(root, ['rev-parse', 'HEAD']).trim(); }

test('workspace bin target is committed executable before Bun linking', () => {
  const entry = execFileSync(
    'git',
    ['ls-files', '--stage', '--', 'bot/src/management-entrypoint.js'],
    { encoding: 'utf8' },
  ).trim();
  assert.match(
    entry,
    /^100755 [a-f0-9]{40} 0\tbot\/src\/management-entrypoint\.js$/,
  );
});

test('issue55 observability receipt is a closed, canonical singular claim', () => {
  const actual = receipt();
  assert.deepEqual(Object.keys(actual), ['claim', 'environment', 'recipe', 'schema', 'subject']);
  assert.equal(actual.schema, SCHEMA);
  assert.deepEqual(actual.environment, ENVIRONMENT);
  assert.deepEqual(actual.claim.facets, FACETS);
  assert.deepEqual(RECIPE[0].argv, [
    'bun',
    'install',
    '--frozen-lockfile',
    '--ignore-scripts',
  ]);
  assert.deepEqual(actual.recipe.map(({ argv, timeoutMs }) => ({ argv, timeoutMs })), RECIPE);
  assert.ok(canonicalBytes(actual).toString('utf8').endsWith('\n'));
  validateReceiptShape(actual);
});

test('receipt writer uses the fixed basename, canonical checksum, exclusive files and rollback', () => {
  const directory = mkdtempSync(join(tmpdir(), 'issue55-observability-'));
  const output = join(directory, RECEIPT_BASENAME);
  try {
    const digest = writeReceipt(output, receipt());
    const bytes = readFileSync(output);
    assert.equal(digest, sha256(bytes));
    assert.equal(readFileSync(`${output}.sha256`, 'utf8'), `${digest}  ${RECEIPT_BASENAME}\n`);
    throwsCode(() => writeReceipt(output, receipt()), 'OUTPUT_WRITE_FAILED');
    for (const failOnOpen of [1, 2]) {
      const rollback = join(directory, `rollback-${failOnOpen}.json`); let opened = 0;
      throwsCode(() => writeReceipt(rollback, receipt(), {
        open: (...args) => { opened += 1; return openSync(...args); },
        write: (fd, buffer, offset, length) => {
          if (opened === failOnOpen) { writeSync(fd, buffer, offset, 1); throw new Error('partial'); }
          return writeSync(fd, buffer, offset, length);
        },
      }), 'OUTPUT_WRITE_FAILED');
      assert.equal(existsSync(rollback), false);
      assert.equal(existsSync(`${rollback}.sha256`), false);
    }
  } finally { rmSync(directory, { recursive: true, force: true }); }
});

test('shape validation rejects unknown fields, tampered registries, recipe and environment', () => {
  for (const mutate of [
    (value) => { value.extra = true; },
    (value) => { value.claim.facets.pop(); },
    (value) => { value.recipe[0].argv.push('unexpected'); },
    (value) => { value.environment.platform = 'win32'; },
    (value) => { value.subject.headCommit = 'A'.repeat(40); },
    (value) => { value.subject.sourcePacketSha256 = '0'.repeat(63); },
  ]) {
    const value = structuredClone(receipt()); mutate(value);
    throwsCode(() => validateReceiptShape(value), 'RECEIPT_SHAPE_INVALID');
  }
});

test('verifier is fail-closed before any execution for invalid path and expected commit', () => {
  throwsCode(() => verify('relative.json', { expectedCommit: 'a'.repeat(40) }), 'RECEIPT_PATH_INVALID');
  const directory = mkdtempSync(join(tmpdir(), 'issue55-observability-'));
  try {
    const output = join(directory, RECEIPT_BASENAME);
    writeReceipt(output, receipt());
    throwsCode(() => verify(output, { expectedCommit: 'not-a-commit', exec: () => { throw new Error('must not execute'); } }), 'EXPECTED_COMMIT_INVALID');
  } finally { rmSync(directory, { recursive: true, force: true }); }
});

test('fixture generation executes only the closed direct recipe in order and verifies without execution', () => withFixture((root) => {
  const directory = mkdtempSync(join(tmpdir(), 'issue55-observability-output-'));
  try {
    const output = join(directory, RECEIPT_BASENAME);
    const calls = [];
    generate(output, {
      root, expectedCommit: commit(root), environment: testEnvironment,
      execute: (file, args, options) => { calls.push({ file, args, options }); },
    });
    assert.deepEqual(calls.map(({ file, args, options }) => [file, args, options.timeout, options.stdio]), RECIPE.map(({ argv, timeoutMs }) => [argv[0], argv.slice(1), timeoutMs, 'ignore']));
    assert.doesNotThrow(() => verify(output, { root, expectedCommit: commit(root), exec: execFileSync }));
  } finally { rmSync(directory, { recursive: true, force: true }); }
}));

test('generation fails closed on toolchain, each direct command failure, and no receipt output', () => withFixture((root) => {
  for (const [index, code] of ['INSTALL_FAILED', 'BOT_OBSERVABILITY_FAILED', 'DAEMON_OBSERVABILITY_FAILED'].entries()) {
    const directory = mkdtempSync(join(tmpdir(), 'issue55-observability-output-'));
    try {
      const output = join(directory, RECEIPT_BASENAME);
      let calls = 0;
      throwsCode(() => generate(output, {
        root, expectedCommit: commit(root), environment: testEnvironment,
        execute: () => { if (calls++ === index) throw new Error('failed'); },
      }), code);
      assert.equal(existsSync(output), false);
      assert.equal(existsSync(`${output}.sha256`), false);
    } finally { rmSync(directory, { recursive: true, force: true }); }
  }
  const output = join(mkdtempSync(join(tmpdir(), 'issue55-observability-output-')), RECEIPT_BASENAME);
  throwsCode(() => generate(output, { root, expectedCommit: commit(root), environment: { ...testEnvironment, platform: 'win32' }, execute: () => { throw new Error('must not run'); } }), 'TOOLCHAIN_MISMATCH');
  assert.equal(existsSync(output), false);
}));

test('generation rejects dirty and hidden index state before and after commands, plus source drift', () => withFixture((root) => {
  const outputDirectory = mkdtempSync(join(tmpdir(), 'issue55-observability-output-'));
  try {
    const output = join(outputDirectory, RECEIPT_BASENAME);
    writeFileSync(join(root, 'untracked.txt'), 'x');
    throwsCode(() => generate(output, { root, expectedCommit: commit(root), environment: testEnvironment, execute: () => {} }), 'CHECKOUT_DIRTY');
    rmSync(join(root, 'untracked.txt'));
    git(root, ['update-index', '--assume-unchanged', 'bun.lock']);
    throwsCode(() => generate(output, { root, expectedCommit: commit(root), environment: testEnvironment, execute: () => {} }), 'CHECKOUT_INDEX_FLAGS');
    git(root, ['update-index', '--no-assume-unchanged', 'bun.lock']);
    throwsCode(() => generate(output, { root, expectedCommit: commit(root), environment: testEnvironment, execute: () => writeFileSync(join(root, 'drift.txt'), 'x') }), 'CHECKOUT_DIRTY');
    rmSync(join(root, 'drift.txt'));
    throwsCode(() => generate(output, {
      root, expectedCommit: commit(root), environment: testEnvironment,
      execute: () => { writeFileSync(join(root, 'committed-drift.txt'), 'x'); git(root, ['add', 'committed-drift.txt']); git(root, ['commit', '--quiet', '-m', 'drift']); },
    }), 'SOURCE_DRIFT');
    const flaggedDirectory = join(outputDirectory, 'flagged'); mkdirSync(flaggedDirectory);
    const flaggedOutput = join(flaggedDirectory, RECEIPT_BASENAME);
    throwsCode(() => generate(flaggedOutput, {
      root, expectedCommit: commit(root), environment: testEnvironment,
      execute: () => git(root, ['update-index', '--skip-worktree', 'bun.lock']),
    }), 'CHECKOUT_INDEX_FLAGS');
  } finally { rmSync(outputDirectory, { recursive: true, force: true }); }
}));

test('generation enforces committed package scripts and output containment including symlink parents', () => withFixture((root) => {
  const outside = mkdtempSync(join(tmpdir(), 'issue55-observability-output-'));
  try {
    const output = join(outside, RECEIPT_BASENAME);
    const bot = join(root, 'bot/package.json');
    writeFileSync(bot, readFileSync(bot, 'utf8').replace('test:observability', 'not-observability'));
    git(root, ['add', 'bot/package.json']); git(root, ['commit', '--quiet', '-m', 'bad script']);
    throwsCode(() => generate(output, { root, expectedCommit: commit(root), environment: testEnvironment, execute: () => {} }), 'PACKAGE_SCRIPT_INVALID');
    throwsCode(() => generate(join(root, RECEIPT_BASENAME), { root, expectedCommit: commit(root), environment: testEnvironment, execute: () => {} }), 'OUTPUT_INSIDE_CHECKOUT');
    const link = join(outside, 'back'); mkdirSync(join(root, 'receipts'));
    try { symlinkSync(join(root, 'receipts'), link, process.platform === 'win32' ? 'junction' : 'dir'); } catch { return; }
    throwsCode(() => generate(join(link, RECEIPT_BASENAME), { root, expectedCommit: commit(root), environment: testEnvironment, execute: () => {} }), 'OUTPUT_INSIDE_CHECKOUT');
  } finally { rmSync(outside, { recursive: true, force: true }); }
}));

test('verifier rejects checksum, noncanonical schema/subject and source packet tampering', () => withFixture((root) => {
  const directory = mkdtempSync(join(tmpdir(), 'issue55-observability-output-'));
  try {
    const output = join(directory, RECEIPT_BASENAME);
    generate(output, { root, expectedCommit: commit(root), environment: testEnvironment, execute: () => {} });
    writeFileSync(`${output}.sha256`, `${'0'.repeat(64)}  ${RECEIPT_BASENAME}\n`);
    throwsCode(() => verify(output, { root, expectedCommit: commit(root) }), 'CHECKSUM_MISMATCH');
    const bytes = readFileSync(output);
    writeFileSync(`${output}.sha256`, `${sha256(bytes)}  ${RECEIPT_BASENAME}\n`);
    writeFileSync(output, JSON.stringify(JSON.parse(bytes)));
    writeFileSync(`${output}.sha256`, `${sha256(readFileSync(output))}  ${RECEIPT_BASENAME}\n`);
    throwsCode(() => verify(output, { root, expectedCommit: commit(root) }), 'RECEIPT_NONCANONICAL');
    for (const [index, mutate] of [
      (value) => { value.schema = 'other'; },
      (value) => { value.subject.tree = '0'.repeat(40); },
      (value) => { value.subject.sourcePacketSha256 = '0'.repeat(64); },
    ].entries()) {
      const child = join(directory, `tamper-${index}`); mkdirSync(child);
      const target = join(child, RECEIPT_BASENAME);
      generate(target, { root, expectedCommit: commit(root), environment: testEnvironment, execute: () => {} });
      const value = JSON.parse(readFileSync(target, 'utf8')); mutate(value);
      const tampered = canonicalBytes(value); writeFileSync(target, tampered); writeFileSync(`${target}.sha256`, `${sha256(tampered)}  ${RECEIPT_BASENAME}\n`);
      throwsCode(() => verify(target, { root, expectedCommit: commit(root) }), index === 0 ? 'RECEIPT_SHAPE_INVALID' : index === 1 ? 'COMMIT_OR_TREE_MISMATCH' : 'SOURCE_PACKET_MISMATCH');
    }
  } finally { rmSync(directory, { recursive: true, force: true }); }
}));
