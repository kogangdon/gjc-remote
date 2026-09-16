import assert from 'node:assert/strict';
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  renameSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import {
  ACKNOWLEDGEMENT_FLAG,
  MAX_RECEIPT_BYTES,
  RECEIPT_BASENAME,
  canonicalBytes,
  generate,
  sha256,
  validateReceiptShape,
  verify,
} from '../service-lifecycle-evidence.js';

function sourceFixture() {
  const root = mkdtempSync(join(tmpdir(), 'gjc-lifecycle-source-'));
  mkdirSync(join(root, 'src'));
  writeFileSync(join(root, 'src', 'input.json'), '{"fixture":true}\n');
  return root;
}
function outputFixture() {
  return mkdtempSync(join(tmpdir(), 'gjc-lifecycle-output-'));
}
function code(fn, expected) { assert.throws(fn, (error) => error?.code === expected); }
function cleanup(...paths) { for (const path of paths) rmSync(path, { recursive: true, force: true }); }

// This suite exercises only the fixture harness. It never loads a native addon
// and never invokes a platform command or service manager.
test('generation refuses without explicit fixture acknowledgement', () => {
  const source = sourceFixture();
  const outputRoot = outputFixture();
  const output = join(outputRoot, RECEIPT_BASENAME);
  try { code(() => generate(output), 'SERVICE_LIFECYCLE_EVIDENCE_ACKNOWLEDGEMENT_REQUIRED'); }
  finally { cleanup(source, outputRoot); }
});

test('generation rejects checkout output and symlink path escape', () => {
  const source = sourceFixture();
  const outputRoot = outputFixture();
  try {
    code(() => generate(join(source, RECEIPT_BASENAME), { acknowledge: true, root: source }), 'OUTPUT_INSIDE_CHECKOUT');
    const link = join(outputRoot, 'link');
    try {
      symlinkSync(source, link, process.platform === 'win32' ? 'junction' : 'dir');
      code(() => generate(join(link, RECEIPT_BASENAME), { acknowledge: true, root: source }), 'OUTPUT_INSIDE_CHECKOUT');
    } catch (error) {
      if (error?.code !== 'EPERM' && error?.code !== 'EACCES') throw error;
    }
  } finally { cleanup(source, outputRoot); }
});

test('cleanup is identity-safe when a fixture root is replaced', () => {
  const source = sourceFixture();
  const outputRoot = outputFixture();
  const output = join(outputRoot, RECEIPT_BASENAME);
  let moved;
  try {
    code(() => generate(output, {
      acknowledge: true,
      root: source,
      onFixture: (fixture) => {
        moved = `${fixture.root}-moved`;
        renameSync(fixture.root, moved);
        mkdirSync(fixture.root);
        writeFileSync(join(fixture.root, '.replacement'), 'replacement\n');
      },
    }), 'FIXTURE_CLEANUP_FAILED');
    assert.equal(readFileSync(join(source, 'src', 'input.json'), 'utf8'), '{"fixture":true}\n');
    assert.equal(readFileSync(join(moved, '.fixture-identity'), 'utf8').length, 32);
    assert.equal(existsSync(join(source, RECEIPT_BASENAME)), false);
  } finally { cleanup(source, outputRoot, moved); }
});

test('verification rejects oversized output before parsing diagnostics', () => {
  const source = sourceFixture();
  const outputRoot = outputFixture();
  const output = join(outputRoot, RECEIPT_BASENAME);
  try {
    writeFileSync(output, Buffer.alloc(MAX_RECEIPT_BYTES + 1, 0x20));
    code(() => verify(output, { root: source }), 'EVIDENCE_OUTPUT_BOUNDED');
  } finally { cleanup(source, outputRoot); }
});

test('generation fences source bytes and emits bounded canonical fixture-only evidence', () => {
  const source = sourceFixture();
  const outputRoot = outputFixture();
  const output = join(outputRoot, RECEIPT_BASENAME);
  const before = readFileSync(join(source, 'src', 'input.json'));
  try {
    code(() => generate(output, {
      acknowledge: true,
      root: source,
      onFixture: () => writeFileSync(join(source, 'src', 'input.json'), 'changed\n'),
    }), 'SERVICE_LIFECYCLE_EVIDENCE_SOURCE_CHANGED');
    writeFileSync(join(source, 'src', 'input.json'), before);
    const digest = generate(output, { acknowledge: true, root: source });
    const bytes = readFileSync(output);
    assert.equal(digest.length, 64);
    assert.ok(bytes.length < MAX_RECEIPT_BYTES);
    const receipt = JSON.parse(bytes);
    validateReceiptShape(receipt);
    assert.equal(receipt.evidence.fixtureOnly, true);
    assert.deepEqual(receipt.gates.humanGates, ['systemd-host', 'SCM-host', 'disposable-host', 'production-signing']);
    assert.doesNotMatch(bytes.toString('utf8'), /[A-Z]:\\|\/tmp\/|PRIVATE KEY|stack trace|secret:/i);
    assert.equal(verify(output, { root: source }), digest);
    assert.deepEqual(readFileSync(join(source, 'src', 'input.json')), before);
  } finally { cleanup(source, outputRoot); }
});

test('verification rejects malformed receipts and closed-matrix rewrites even with a fresh checksum', () => {
  const source = sourceFixture();
  const outputRoot = outputFixture();
  const output = join(outputRoot, RECEIPT_BASENAME);
  try {
    generate(output, { acknowledge: true, root: source });
    const receipt = JSON.parse(readFileSync(output, 'utf8'));
    for (const mutate of [
      (value) => { delete value.gates; },
      (value) => { value.evidence.operationMatrix[0].operation = 'status'; },
    ]) {
      const candidate = JSON.parse(JSON.stringify(receipt));
      mutate(candidate);
      const rewritten = canonicalBytes(candidate);
      // The verifier must reject semantic rewrites, not merely rely on the
      // sidecar checksum (which this test deliberately refreshes).
      writeFileSync(output, rewritten);
      writeFileSync(`${output}.sha256`, `${sha256(rewritten)}  ${RECEIPT_BASENAME}\n`);
      code(() => verify(output, { root: source }), 'EVIDENCE_SHAPE_INVALID');
    }
  } finally { cleanup(source, outputRoot); }
});

test('CLI acknowledgement flag remains a single explicit opt-in token', () => {
  assert.equal(ACKNOWLEDGEMENT_FLAG, '--acknowledge-service-lifecycle-fixture');
});
