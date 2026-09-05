#!/usr/bin/env node
import { execFileSync } from 'node:child_process';
import { basename, dirname, isAbsolute, relative, resolve, sep } from 'node:path';
import { constants, existsSync, fsyncSync, lstatSync, openSync, realpathSync, readSync, closeSync, unlinkSync, writeSync } from 'node:fs';
import {
  REPOSITORY_URL,
  canonicalBytes,
  canonicalJson,
  collectSource,
  createPacket,
  readBoundedRegularUtf8,
  sha256,
} from './issue55-evidence.js';

export const SCHEMA = 'gjc-remote.issue55.observability-execution.v1';
export const RECEIPT_BASENAME = 'issue55-observability.json';
export const ENVIRONMENT = Object.freeze({ architecture: 'x64', bunVersion: '1.3.14', nodeVersion: 'v26.0.0', platform: 'linux' });
export const FACETS = Object.freeze([
  'bot-local-observability', 'daemon-owner-telemetry', 'daemon-invoke-telemetry',
  'daemon-lifecycle-telemetry', 'admitted-v3-correlation-fence',
  'redaction-and-bounded-taxonomy', 'exactly-once-terminals', 'local-only-wire-separation',
]);
export const RECIPE = Object.freeze([
  Object.freeze({ argv: ['bun', 'install', '--frozen-lockfile'], timeoutMs: 300000 }),
  Object.freeze({ argv: ['npm', 'run', 'test:observability', '--workspace', '@gjc-remote/bot'], timeoutMs: 600000 }),
  Object.freeze({ argv: ['npm', 'run', 'test:observability', '--workspace', '@gjc-remote/daemon'], timeoutMs: 900000 }),
]);
const GIT_ID = /^[a-f0-9]{40}$/;
const SHA256 = /^[a-f0-9]{64}$/;
const MAX_RECEIPT_BYTES = 16 * 1024;
const MAX_CHECKSUM_BYTES = 256;

function fail(code) { const error = new Error(code); error.code = code; throw error; }
function same(left, right) { return canonicalJson(left) === canonicalJson(right); }
function git(args, root, exec = execFileSync) {
  try { return String(exec('git', args, { cwd: root, encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] })).trim(); } catch { fail('GIT_COMMAND_FAILED'); }
}
function canonicalPath(path, code) {
  try { return realpathSync(path); } catch { fail(code); }
}
function inside(parent, child) {
  const value = relative(parent, child);
  return value === '' || (!isAbsolute(value) && value !== '..' && !value.startsWith(`..${sep}`));
}
function requireCleanIndex(root, exec) {
  if (git(['status', '--porcelain=v1', '--untracked-files=all'], root, exec)) fail('CHECKOUT_DIRTY');
  let flags;
  try { flags = String(exec('git', ['ls-files', '-v', '-z'], { cwd: root, encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] })); } catch { fail('GIT_COMMAND_FAILED'); }
  if (flags.split('\0').some((entry) => /^[a-zS] /.test(entry))) fail('CHECKOUT_INDEX_FLAGS');
}
function requireOutput(output, root) {
  if (typeof output !== 'string' || !isAbsolute(output) || basename(output) !== RECEIPT_BASENAME) fail('OUTPUT_INVALID');
  const checkout = canonicalPath(root, 'CHECKOUT_ROOT_INVALID');
  const parent = canonicalPath(dirname(output), 'OUTPUT_PARENT_INVALID');
  try { if (!lstatSync(parent).isDirectory()) fail('OUTPUT_PARENT_INVALID'); } catch (error) { if (error?.code) throw error; fail('OUTPUT_PARENT_INVALID'); }
  if (inside(checkout, resolve(output)) || inside(checkout, parent)) fail('OUTPUT_INSIDE_CHECKOUT');
  if (existsSync(output) || existsSync(`${output}.sha256`)) fail('OUTPUT_EXISTS');
  return resolve(output);
}
function sourceSnapshot(root, exec) {
  requireCleanIndex(root, exec);
  const source = collectSource({ root, exec });
  return { source, bytes: canonicalBytes(source) };
}
function packageScripts(source, root, exec) {
  // collectSource proves tree identity; read the committed package blobs through git.
  const packageAtHead = (path) => {
    try { return JSON.parse(String(exec('git', ['show', `${source.headCommit}:${path}`], { cwd: root, encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] }))); } catch { fail('PACKAGE_SCRIPT_INVALID'); }
  };
  const bot = packageAtHead('bot/package.json');
  const daemon = packageAtHead('daemon/package.json');
  if (bot?.scripts?.['test:observability'] !== 'node --test test/host-registry.test.js' || daemon?.scripts?.['test:observability'] !== 'node --test test/daemon-observability.test.js test/lifecycle.test.js') fail('PACKAGE_SCRIPT_INVALID');
}
function checkedEnvironment({ platform = process.platform, architecture = process.arch, nodeVersion = process.version, bunVersion } = {}) {
  const bun = bunVersion ?? (() => {
    try { return String(execFileSync('bun', ['--version'], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] })).trim(); } catch { fail('TOOLCHAIN_MISMATCH'); }
  })();
  if (platform !== ENVIRONMENT.platform || architecture !== ENVIRONMENT.architecture || nodeVersion !== ENVIRONMENT.nodeVersion || bun !== ENVIRONMENT.bunVersion) fail('TOOLCHAIN_MISMATCH');
  return { ...ENVIRONMENT };
}
export function createReceipt(source, sourcePacketSha256) {
  return {
    claim: { checkId: 'observability', facets: [...FACETS], reasonCode: 'focused-observability-recipe-exit-zero', status: 'verified' },
    environment: { ...ENVIRONMENT },
    recipe: RECIPE.map(({ argv, timeoutMs }) => ({ argv: [...argv], outcome: 'succeeded', reasonCode: 'direct-execution-exit-zero', timeoutMs })),
    schema: SCHEMA,
    subject: { headCommit: source.headCommit, repositoryUrl: REPOSITORY_URL, sourcePacketSha256, tree: source.tree },
  };
}
// createPacket needs the same source collection when callers inject source; this avoids reading a second checkout in validation.
function expectedReceipt(source, root, exec) {
  const packet = createPacket({ root, exec });
  if (!same(packet.source, source)) fail('SOURCE_DRIFT');
  return createReceipt(source, sha256(canonicalBytes(packet)));
}
function writeAll(fd, content, write = writeSync) { const bytes = Buffer.isBuffer(content) ? content : Buffer.from(content); for (let offset = 0; offset < bytes.length;) { const count = write(fd, bytes, offset, bytes.length - offset); if (!Number.isInteger(count) || count < 1) throw new Error('write'); offset += count; } }
export function writeReceipt(output, receipt, io = {}) {
  const { open = openSync, write = writeSync, sync = fsyncSync, close = closeSync, unlink = unlinkSync } = io;
  const bytes = canonicalBytes(receipt); const checksum = `${sha256(bytes)}  ${RECEIPT_BASENAME}\n`; const paths = [output, `${output}.sha256`]; const created = []; let fd;
  try { for (const [path, content] of [[paths[0], bytes], [paths[1], checksum]]) { fd = open(path, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL, 0o600); created.push(path); writeAll(fd, content, write); sync(fd); close(fd); fd = undefined; } } catch { try { if (fd !== undefined) close(fd); } catch {} for (const path of paths.slice().reverse()) if (created.includes(path)) try { unlink(path); } catch {} fail('OUTPUT_WRITE_FAILED'); }
  return sha256(bytes);
}
export function validateReceiptShape(receipt) {
  if (!receipt || typeof receipt !== 'object' || Array.isArray(receipt) || !same(Object.keys(receipt).sort(), ['claim', 'environment', 'recipe', 'schema', 'subject']) || receipt.schema !== SCHEMA) fail('RECEIPT_SHAPE_INVALID');
  const expected = { claim: createReceipt({ headCommit: '0'.repeat(40), tree: '0'.repeat(40) }, '0'.repeat(64)).claim, environment: ENVIRONMENT, recipe: createReceipt({ headCommit: '0'.repeat(40), tree: '0'.repeat(40) }, '0'.repeat(64)).recipe };
  if (!same(receipt.claim, expected.claim) || !same(receipt.environment, expected.environment) || !same(receipt.recipe, expected.recipe) || !receipt.subject || typeof receipt.subject !== 'object' || Array.isArray(receipt.subject) || !same(Object.keys(receipt.subject).sort(), ['headCommit', 'repositoryUrl', 'sourcePacketSha256', 'tree']) || receipt.subject.repositoryUrl !== REPOSITORY_URL || !GIT_ID.test(receipt.subject.headCommit) || !GIT_ID.test(receipt.subject.tree) || !SHA256.test(receipt.subject.sourcePacketSha256)) fail('RECEIPT_SHAPE_INVALID');
}
export function generate(output, { root = process.cwd(), expectedCommit, exec = execFileSync, execute = execFileSync, environment } = {}) {
  const checkout = resolve(root); const target = requireOutput(output, checkout); checkedEnvironment(environment); const initial = sourceSnapshot(checkout, exec); if (!GIT_ID.test(expectedCommit ?? '') || initial.source.headCommit !== expectedCommit) fail('EXPECTED_COMMIT_INVALID'); packageScripts(initial.source, checkout, exec);
  for (const [index, recipe] of RECIPE.entries()) { try { execute(recipe.argv[0], recipe.argv.slice(1), { cwd: checkout, stdio: 'ignore', timeout: recipe.timeoutMs }); } catch { fail(['INSTALL_FAILED', 'BOT_OBSERVABILITY_FAILED', 'DAEMON_OBSERVABILITY_FAILED'][index]); } const current = sourceSnapshot(checkout, exec); if (!current.bytes.equals(initial.bytes)) fail('SOURCE_DRIFT'); }
  const final = sourceSnapshot(checkout, exec); if (!final.bytes.equals(initial.bytes)) fail('SOURCE_DRIFT');
  return writeReceipt(target, expectedReceipt(initial.source, checkout, exec));
}
export function verify(receiptPath, { root = process.cwd(), expectedCommit, exec = execFileSync } = {}) {
  if (typeof receiptPath !== 'string' || !isAbsolute(receiptPath) || basename(receiptPath) !== RECEIPT_BASENAME) fail('RECEIPT_PATH_INVALID');
  const bytes = Buffer.from(readBoundedRegularUtf8(receiptPath, MAX_RECEIPT_BYTES)); const checksum = readBoundedRegularUtf8(`${receiptPath}.sha256`, MAX_CHECKSUM_BYTES);
  if (checksum !== `${sha256(bytes)}  ${RECEIPT_BASENAME}\n`) fail('CHECKSUM_MISMATCH'); let receipt; try { receipt = JSON.parse(bytes.toString('utf8')); } catch { fail('RECEIPT_JSON_INVALID'); }
  if (!canonicalBytes(receipt).equals(bytes)) fail('RECEIPT_NONCANONICAL'); validateReceiptShape(receipt);
  if (!GIT_ID.test(expectedCommit ?? '')) fail('EXPECTED_COMMIT_INVALID');
  const snapshot = sourceSnapshot(resolve(root), exec);
  packageScripts(snapshot.source, resolve(root), exec);
  if (
    snapshot.source.headCommit !== expectedCommit ||
    receipt.subject.headCommit !== expectedCommit ||
    receipt.subject.tree !== snapshot.source.tree
  ) {
    fail('COMMIT_OR_TREE_MISMATCH');
  }
  if (!same(receipt, expectedReceipt(snapshot.source, resolve(root), exec))) {
    fail('SOURCE_PACKET_MISMATCH');
  }
  return sha256(bytes);
}
function usage() { fail('USAGE'); }
export function main(argv = process.argv.slice(2)) { const [mode, pathFlag, path, commitFlag, expectedCommit, extra] = argv; if ((mode === 'generate' && pathFlag === '--output' || mode === 'verify' && pathFlag === '--receipt') && commitFlag === '--expected-commit' && expectedCommit && !extra) return mode === 'generate' ? generate(path, { expectedCommit }) : verify(path, { expectedCommit }); usage(); }
if (import.meta.main) { try { process.stdout.write(`ISSUE55_OBSERVABILITY_${process.argv[2].toUpperCase()}_OK ${main()}\n`); } catch (error) { process.stderr.write(`ISSUE55_${error?.code ?? 'FAILED'}\n`); process.exitCode = 1; } }
