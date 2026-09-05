import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import YAML from 'yaml';

const path = '.github/workflows/issue55-observability-evidence.yml';
const workflow = readFileSync(path, 'utf8').replaceAll('\r\n', '\n');
const documentation = readFileSync('docs/verification/issue55-observability-evidence.md', 'utf8');
const receiptFiles = [
  '${{ env.EVIDENCE_DIR }}/issue55-observability.json',
  '${{ env.EVIDENCE_DIR }}/issue55-observability.json.sha256',
];
const pins = {
  checkout: 'actions/checkout@fbc6f3992d24b796d5a048ff273f7fcc4a7b6c09',
  node: 'actions/setup-node@a0853c24544627f65ddf259abe73b1d18a591444',
  bun: 'oven-sh/setup-bun@0c5077e51419868618aeaa5fe8019c62421857d6',
  upload: 'actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02',
  download: 'actions/download-artifact@634f93cb2916e3fdff6788551b99b062d0335ce0',
  attest: 'actions/attest-build-provenance@977bb373ede98d70efdf65b84cb5f73e068dcc2a',
};

function assertContract(source) {
  const value = YAML.parse(source);
  assert.deepEqual(Object.keys(value), ['name', 'on', 'permissions', 'concurrency', 'jobs']);
  assert.equal(value.name, 'Issue #55 observability execution evidence');
  assert.deepEqual(value.on, { workflow_dispatch: null });
  assert.deepEqual(value.permissions, {});
  assert.deepEqual(value.concurrency, {
    group: 'issue55-observability-evidence-${{ github.sha }}',
    'cancel-in-progress': false,
  });
  assert.deepEqual(Object.keys(value.jobs), ['validate', 'generate', 'verify', 'attest']);
  assert.deepEqual(Object.keys(value.jobs.validate), ['runs-on', 'permissions', 'steps']);
  assert.deepEqual(Object.keys(value.jobs.generate), ['needs', 'runs-on', 'permissions', 'outputs', 'steps']);
  assert.deepEqual(Object.keys(value.jobs.verify), ['needs', 'runs-on', 'permissions', 'outputs', 'steps']);
  assert.deepEqual(Object.keys(value.jobs.attest), ['needs', 'runs-on', 'permissions', 'steps']);
  for (const job of Object.values(value.jobs)) assert.equal(job['runs-on'], 'ubuntu-24.04');
  assert.equal(value.jobs.generate.needs, 'validate');
  assert.equal(value.jobs.verify.needs, 'generate');
  assert.equal(value.jobs.attest.needs, 'verify');
  assert.deepEqual(value.jobs.validate.permissions, { contents: 'read' });
  assert.deepEqual(value.jobs.generate.permissions, { contents: 'read' });
  assert.deepEqual(value.jobs.verify.permissions, { actions: 'read', contents: 'read' });
  assert.deepEqual(value.jobs.attest.permissions, { actions: 'read', attestations: 'write', 'id-token': 'write' });
  assert.deepEqual(value.jobs.generate.outputs, {
    'artifact-id': '${{ steps.handoff.outputs.artifact-id }}', commit: '${{ github.sha }}',
  });
  assert.deepEqual(value.jobs.verify.outputs, {
    'artifact-id': '${{ steps.verified.outputs.artifact-id }}', commit: '${{ needs.generate.outputs.commit }}',
  });
  assert.deepEqual(value.jobs.validate.steps.map((step) => step.name), ['Verify exact current main revision']);
  assert.deepEqual(value.jobs.generate.steps.map((step) => step.name), [
    'Checkout exact source commit', 'Set up Node', 'Set up Bun',
    'Generate and verify observability receipt', 'Upload untrusted observability handoff',
    'Remove observability directory',
  ]);
  assert.deepEqual(value.jobs.verify.steps.map((step) => step.name), [
    'Checkout receipt source commit', 'Set up Node', 'Download untrusted observability handoff',
    'Reverify exact observability bytes', 'Upload verified observability handoff',
    'Remove verification directory',
  ]);
  assert.deepEqual(value.jobs.attest.steps.map((step) => step.name), [
    'Download verified observability handoff', 'Attest observability execution evidence',
    'Upload attested observability evidence',
  ]);
  assert.deepEqual(value.jobs.validate.steps.map((step) => Object.keys(step)), [['name', 'env', 'run']]);
  assert.deepEqual(value.jobs.generate.steps.map((step) => Object.keys(step)), [
    ['name', 'uses', 'with'], ['name', 'uses', 'with'], ['name', 'uses', 'with'],
    ['name', 'env', 'run'], ['name', 'id', 'uses', 'env', 'with'], ['name', 'if', 'env', 'run'],
  ]);
  assert.deepEqual(value.jobs.verify.steps.map((step) => Object.keys(step)), [
    ['name', 'uses', 'with'], ['name', 'uses', 'with'], ['name', 'uses', 'with'],
    ['name', 'env', 'run'], ['name', 'id', 'uses', 'env', 'with'], ['name', 'if', 'env', 'run'],
  ]);
  assert.deepEqual(value.jobs.attest.steps.map((step) => Object.keys(step)), [
    ['name', 'uses', 'with'], ['name', 'uses', 'env', 'with'], ['name', 'uses', 'env', 'with'],
  ]);
  assert.deepEqual(value.jobs.generate.steps[0].with, { ref: '${{ github.sha }}', 'fetch-depth': 1, 'persist-credentials': false });
  assert.deepEqual(value.jobs.verify.steps[0].with, { ref: '${{ needs.generate.outputs.commit }}', 'fetch-depth': 1, 'persist-credentials': false });
  assert.deepEqual(value.jobs.generate.steps[1].with, { 'node-version': '26.0.0', 'check-latest': false });
  assert.deepEqual(value.jobs.verify.steps[1].with, { 'node-version': '26.0.0', 'check-latest': false });
  assert.deepEqual(value.jobs.generate.steps[2].with, { 'bun-version': '1.3.14', 'no-cache': true });
  assert.deepEqual(value.jobs.generate.steps[4].with, {
    name: 'untrusted-issue55-observability-${{ github.sha }}-${{ github.run_id }}-${{ github.run_attempt }}',
    path: `${receiptFiles.join('\n')}\n`, 'retention-days': 1, overwrite: false, 'if-no-files-found': 'error',
  });
  assert.deepEqual(value.jobs.verify.steps[2].with, {
    'artifact-ids': '${{ needs.generate.outputs.artifact-id }}',
    path: '${{ runner.temp }}/issue55-observability-verify-${{ github.run_id }}-${{ github.run_attempt }}',
  });
  assert.deepEqual(value.jobs.verify.steps[4].with, {
    name: 'verified-unattested-issue55-observability-${{ needs.generate.outputs.commit }}-${{ github.run_id }}-${{ github.run_attempt }}',
    path: `${receiptFiles.join('\n')}\n`, 'retention-days': 1, overwrite: false, 'if-no-files-found': 'error',
  });
  assert.deepEqual(value.jobs.attest.steps[0].with, {
    'artifact-ids': '${{ needs.verify.outputs.artifact-id }}',
    path: '${{ runner.temp }}/issue55-observability-attest-${{ github.run_id }}-${{ github.run_attempt }}',
  });
  assert.deepEqual(value.jobs.attest.steps[1].with['subject-path'].trim().split('\n'), receiptFiles);
  assert.deepEqual(value.jobs.attest.steps[2].with, {
    name: 'issue55-observability-evidence-${{ needs.verify.outputs.commit }}-${{ github.run_id }}-${{ github.run_attempt }}',
    path: `${receiptFiles.join('\n')}\n`, overwrite: false, 'if-no-files-found': 'error',
  });
  assert.deepEqual(value.jobs.generate.steps.filter((step) => step.uses).map((step) => step.uses), [pins.checkout, pins.node, pins.bun, pins.upload]);
  assert.deepEqual(value.jobs.verify.steps.filter((step) => step.uses).map((step) => step.uses), [pins.checkout, pins.node, pins.download, pins.upload]);
  assert.deepEqual(value.jobs.attest.steps.map((step) => step.uses), [pins.download, pins.attest, pins.upload]);
  assert.equal(value.jobs.attest.steps.some((step) => step.run || step.if), false);
  for (const job of Object.values(value.jobs)) {
    for (const step of job.steps) if (step.if !== undefined) assert.equal(step.if, 'always()');
  }
  const runDigests = Object.fromEntries(Object.entries(value.jobs).flatMap(([jobName, job]) =>
    job.steps.filter((step) => step.run).map((step) => [`${jobName}:${step.name}`, createHash('sha256').update(step.run).digest('hex')])));
  assert.deepEqual(runDigests, {
    'validate:Verify exact current main revision': 'd515d7c65070826898be17a0910cfb86e0ca41fa5c23b6da4f1f477a53868d69',
    'generate:Generate and verify observability receipt': 'fc64d5c58e6284b6828c3303b9e1bb4b17afb28854c639f56a7d3ab3c76acb18',
    'generate:Remove observability directory': '0d79795385ede5c43816bab9432d3f7b7d72520b8a65d849577f112134cfe3fa',
    'verify:Reverify exact observability bytes': 'f285e3ef5111a1aa2b48672b7439bebcd9ed8f9ea9bff7640ce05bca054e5d66',
    'verify:Remove verification directory': '0d79795385ede5c43816bab9432d3f7b7d72520b8a65d849577f112134cfe3fa',
  });
  assert.match(value.jobs.generate.steps[3].run, /scripts\/issue55-observability-evidence\.js generate --output .* --expected-commit/);
  assert.match(value.jobs.generate.steps[3].run, /scripts\/issue55-observability-evidence\.js verify --receipt .* --expected-commit/);
  assert.match(value.jobs.verify.steps[3].run, /scripts\/issue55-observability-evidence\.js verify --receipt .* --expected-commit/);
  assert.doesNotMatch(source, /(secrets\.|GITHUB_ENV|GITHUB_PATH|continue-on-error|\|\| true|strategy:|matrix:|smoke|native|publish|release|provider|repository_dispatch|workflow_call)/i);
}

test('Issue #55 observability workflow has a closed parsed contract', () => {
  assertContract(workflow);
});

test('observability workflow rejects adversarial authority and fail-open mutations', () => {
  for (const mutated of [
    workflow.replace('  workflow_dispatch:', '  workflow_dispatch:\n  repository_dispatch:'),
    workflow.replace('  workflow_dispatch:', '  workflow_dispatch:\n    inputs:\n      ref:\n        required: true'),
    workflow.replace('\n  attest:\n', '\n  surprise:\n    runs-on: ubuntu-24.04\n\n  attest:\n'),
    workflow.replace('      contents: read\n    outputs:', '      contents: read\n      id-token: write\n    outputs:'),
    workflow.replace('runs-on: ubuntu-24.04', 'runs-on: ubuntu-24.04\n    strategy:\n      matrix:\n        node: [26.0.0]'),
    workflow.replace('actions/checkout@fbc6f3992d24b796d5a048ff273f7fcc4a7b6c09', 'actions/checkout@v5'),
    workflow.replace('artifact-ids: ${{ needs.generate.outputs.artifact-id }}', 'name: untrusted-issue55-observability'),
    workflow.replace('      - name: Reverify exact observability bytes', '      - name: Reverify exact observability bytes\n        if: false'),
    workflow.replace('      - name: Attest observability execution evidence', '      - run: echo bypass\n\n      - name: Attest observability execution evidence'),
    workflow.replace('--expected-commit "$SHA"', '--expected-commit "$SHA" || true'),
    workflow.replace('node scripts/issue55-observability-evidence.js verify --receipt "$EVIDENCE_DIR/issue55-observability.json" --expected-commit "$SHA"\n', ''),
  ]) assert.throws(() => assertContract(mutated));
});

test('documentation constrains external observability ledger ingestion', () => {
  for (const required of [
    'untrusted-issue55-observability-', 'verified-unattested-issue55-observability-',
    'issue55-observability-evidence-', 'exactly these two top-level regular, non-symlink files',
    'clean detached checkout', 'EXPECTED_COMMIT', 'sha256sum --check',
    'gh attestation verify issue55-observability.json', 'gh attestation verify issue55-observability.json.sha256',
    '--signer-workflow', '--signer-digest', '--source-ref refs/heads/main', '--source-digest',
    'observability=verified', '21 blockers', 'source-negative v2 packet', 'not an override, waiver, promotion, or mutation',
    'test gate', 'local-only', 'artifact expiry requires regeneration', 'No production bot',
    'not distributed exactly-once across process',
    'No provider credential', 'No native-control', 'No full candidate test suite', 'No receipt timestamp',
    '33993917213', 'e525ff16fc162ee4534dbc5646e5b8d301a6045e',
    '9977475402', '08b3defc52327c6a967b325c35406fa45071ffb41276cd1378dafb7da11988be',
    '69db59277f101fd4dc3e93dca769ec8dbd84e21cff011e475b55d774015dc518',
    'f3689f1d60bae5a3c045be77e55e6e6abf8e5497f64089931e7c7d82822398c8',
    'Runs 1 and 2 failed closed', 'Node.js 20', 'Node.js 24',
  ]) assert.match(documentation, new RegExp(required, 'i'));

  const runSection = documentation.slice(
    documentation.indexOf('## First authenticated observability run'),
  );
  for (const immutableFact of [
    '33993917213',
    'run number 3, attempt 1',
    'workflow_dispatch',
    'e525ff16fc162ee4534dbc5646e5b8d301a6045e',
    '2026-09-05T21:44:39Z',
    '2026-09-05T21:45:46Z',
    '(`validate`, `generate`, `verify`, and `attest`) successful',
    'issue55-observability-evidence-e525ff16fc162ee4534dbc5646e5b8d301a6045e-33993917213-1',
    '9977475402',
    '1,015 bytes',
    '2026-12-04T21:44:40Z',
    '08b3defc52327c6a967b325c35406fa45071ffb41276cd1378dafb7da11988be',
    '69db59277f101fd4dc3e93dca769ec8dbd84e21cff011e475b55d774015dc518',
    'f3689f1d60bae5a3c045be77e55e6e6abf8e5497f64089931e7c7d82822398c8',
    'c67d19bda37ca29cff9cbb16aef21bed8b88bc32',
    'c86c4ec0fb4d0367292e6c31e19aa417f5b31f27abd378b9fc82157e12336c4d',
  ]) {
    assert.ok(runSection.includes(immutableFact), immutableFact);
  }
});
