import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import YAML from 'yaml';

const path = '.github/workflows/issue55-source-evidence.yml';
const workflow = readFileSync(path, 'utf8').replaceAll('\r\n', '\n');
const documentation = readFileSync('docs/verification/issue55-evidence.md', 'utf8');
const files = [
  '${{ env.EVIDENCE_DIR }}/issue55-source.json',
  '${{ env.EVIDENCE_DIR }}/issue55-source.json.sha256',
];

function names(steps) {
  return steps.map((step) => step.name);
}

function paths(step, key) {
  return step.with[key].trim().split('\n');
}

function assertContract(source) {
  const value = YAML.parse(source);
  assert.deepEqual(Object.keys(value), ['name', 'on', 'permissions', 'concurrency', 'jobs']);
  assert.equal(value.name, 'Issue #55 source evidence');
  assert.deepEqual(value.on, { workflow_dispatch: null });
  assert.deepEqual(value.permissions, {});
  assert.deepEqual(value.concurrency, {
    group: 'issue55-source-evidence-${{ github.sha }}',
    'cancel-in-progress': false,
  });
  assert.deepEqual(Object.keys(value.jobs), ['validate', 'generate', 'verify', 'attest']);
  assert.deepEqual(Object.keys(value.jobs.validate), ['runs-on', 'permissions', 'steps']);
  assert.deepEqual(Object.keys(value.jobs.generate), ['needs', 'runs-on', 'permissions', 'outputs', 'steps']);
  assert.deepEqual(Object.keys(value.jobs.verify), ['needs', 'runs-on', 'permissions', 'outputs', 'steps']);
  assert.deepEqual(Object.keys(value.jobs.attest), ['needs', 'runs-on', 'permissions', 'steps']);
  assert.equal(value.jobs.validate['runs-on'], 'ubuntu-latest');
  assert.equal(value.jobs.generate.needs, 'validate');
  assert.equal(value.jobs.generate['runs-on'], 'ubuntu-latest');
  assert.equal(value.jobs.verify.needs, 'generate');
  assert.equal(value.jobs.verify['runs-on'], 'ubuntu-latest');
  assert.equal(value.jobs.attest.needs, 'verify');
  assert.equal(value.jobs.attest['runs-on'], 'ubuntu-latest');
  assert.deepEqual(value.jobs.generate.outputs, {
    'artifact-id': '${{ steps.handoff.outputs.artifact-id }}',
    commit: '${{ github.sha }}',
  });
  assert.deepEqual(value.jobs.verify.outputs, {
    'artifact-id': '${{ steps.verified.outputs.artifact-id }}',
    commit: '${{ needs.generate.outputs.commit }}',
  });
  assert.deepEqual(value.jobs.validate.permissions, { contents: 'read' });
  assert.deepEqual(value.jobs.generate.permissions, { contents: 'read' });
  assert.deepEqual(value.jobs.verify.permissions, { actions: 'read', contents: 'read' });
  assert.deepEqual(value.jobs.attest.permissions, {
    actions: 'read',
    attestations: 'write',
    'id-token': 'write',
  });
  assert.deepEqual(names(value.jobs.validate.steps), ['Verify exact current main revision']);
  assert.deepEqual(names(value.jobs.generate.steps), [
    'Checkout exact source commit',
    'Generate and verify negative source packet',
    'Upload untrusted source handoff',
    'Remove source directory',
  ]);
  assert.deepEqual(names(value.jobs.verify.steps), [
    'Checkout packet source commit',
    'Download untrusted source handoff',
    'Reverify exact source bytes',
    'Upload verified source handoff',
    'Remove verification directory',
  ]);
  assert.deepEqual(names(value.jobs.attest.steps), [
    'Download verified source handoff',
    'Attest negative source evidence',
    'Upload attested negative source evidence',
  ]);
  const exactStepKeys = {
    validate: [['name', 'env', 'run']],
    generate: [
      ['name', 'uses', 'with'],
      ['name', 'env', 'run'],
      ['name', 'id', 'uses', 'env', 'with'],
      ['name', 'if', 'env', 'run'],
    ],
    verify: [
      ['name', 'uses', 'with'],
      ['name', 'uses', 'with'],
      ['name', 'env', 'run'],
      ['name', 'id', 'uses', 'env', 'with'],
      ['name', 'if', 'env', 'run'],
    ],
    attest: [
      ['name', 'uses', 'with'],
      ['name', 'uses', 'env', 'with'],
      ['name', 'uses', 'env', 'with'],
    ],
  };
  for (const [jobName, expected] of Object.entries(exactStepKeys)) {
    assert.deepEqual(
      value.jobs[jobName].steps.map((step) => Object.keys(step)),
      expected,
    );
  }
  for (const job of Object.values(value.jobs)) {
    for (const step of job.steps) {
      if (step.if !== undefined) assert.equal(step.if, 'always()');
    }
  }

  const actions = Object.values(value.jobs).flatMap((job) =>
    job.steps.filter((step) => step.uses).map((step) => step.uses));
  assert.deepEqual(actions, [
    'actions/checkout@fbc6f3992d24b796d5a048ff273f7fcc4a7b6c09',
    'actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02',
    'actions/checkout@fbc6f3992d24b796d5a048ff273f7fcc4a7b6c09',
    'actions/download-artifact@634f93cb2916e3fdff6788551b99b062d0335ce0',
    'actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02',
    'actions/download-artifact@634f93cb2916e3fdff6788551b99b062d0335ce0',
    'actions/attest-build-provenance@977bb373ede98d70efdf65b84cb5f73e068dcc2a',
    'actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02',
  ]);
  for (const step of [value.jobs.generate.steps[0], value.jobs.verify.steps[0]]) {
    assert.equal(step.with['fetch-depth'], 1);
    assert.equal(step.with['persist-credentials'], false);
  }
  assert.deepEqual(value.jobs.generate.steps[0].with, {
    ref: '${{ github.sha }}',
    'fetch-depth': 1,
    'persist-credentials': false,
  });
  assert.deepEqual(value.jobs.generate.steps[2].with, {
    name: 'untrusted-issue55-source-${{ github.sha }}-${{ github.run_id }}-${{ github.run_attempt }}',
    path: `${files.join('\n')}\n`,
    'retention-days': 1,
    overwrite: false,
    'if-no-files-found': 'error',
  });
  assert.deepEqual(value.jobs.verify.steps[0].with, {
    ref: '${{ needs.generate.outputs.commit }}',
    'fetch-depth': 1,
    'persist-credentials': false,
  });
  assert.deepEqual(value.jobs.verify.steps[1].with, {
    'artifact-ids': '${{ needs.generate.outputs.artifact-id }}',
    path: '${{ runner.temp }}/issue55-source-verify-${{ github.run_id }}-${{ github.run_attempt }}',
  });
  assert.deepEqual(value.jobs.verify.steps[3].with, {
    name: 'verified-unattested-issue55-source-${{ needs.generate.outputs.commit }}-${{ github.run_id }}-${{ github.run_attempt }}',
    path: `${files.join('\n')}\n`,
    'retention-days': 1,
    overwrite: false,
    'if-no-files-found': 'error',
  });
  assert.equal(value.jobs.generate.steps[1].run, [
    'set -euo pipefail',
    'test "$(git rev-parse HEAD)" = "$SHA"',
    'umask 077',
    'mkdir "$EVIDENCE_DIR"',
    'npm run evidence:issue55 -- --output "$EVIDENCE_DIR/issue55-source.json"',
    'npm run evidence:issue55:verify -- --packet "$EVIDENCE_DIR/issue55-source.json"',
    '',
  ].join('\n'));
  assert.equal(value.jobs.verify.steps[2].run, [
    'set -euo pipefail',
    'test "$(git rev-parse HEAD)" = "$SHA"',
    'test "$(find "$EVIDENCE_DIR" -maxdepth 1 -type f | wc -l)" -eq 2',
    'npm run evidence:issue55:verify -- --packet "$EVIDENCE_DIR/issue55-source.json"',
    '',
  ].join('\n'));
  assert.deepEqual(paths(value.jobs.attest.steps[1], 'subject-path'), files);
  assert.deepEqual(paths(value.jobs.attest.steps[2], 'path'), files);
  assert.equal(value.jobs.attest.steps.some((step) => step.run), false);
  assert.equal(value.jobs.attest.steps.some((step) => step.if), false);
  assert.equal(value.jobs.attest.steps[0].with['artifact-ids'], '${{ needs.verify.outputs.artifact-id }}');
  assert.deepEqual(value.jobs.attest.steps[0].with, {
    'artifact-ids': '${{ needs.verify.outputs.artifact-id }}',
    path: '${{ runner.temp }}/issue55-source-attest-${{ github.run_id }}-${{ github.run_attempt }}',
  });
  assert.equal(value.jobs.attest.steps[2].with['if-no-files-found'], 'error');
  assert.equal(value.jobs.attest.steps[2].with.overwrite, false);
  const runDigests = Object.fromEntries(
    Object.entries(value.jobs).flatMap(([jobName, job]) =>
      job.steps
        .filter((step) => step.run)
        .map((step) => [
          `${jobName}:${step.name}`,
          createHash('sha256').update(step.run).digest('hex'),
        ])),
  );
  assert.deepEqual(runDigests, {
    'validate:Verify exact current main revision': 'd515d7c65070826898be17a0910cfb86e0ca41fa5c23b6da4f1f477a53868d69',
    'generate:Generate and verify negative source packet': 'd766ec730e5ce54e3215db19e2c6e536727899fa51019c00fc5ce5d6a2331e66',
    'generate:Remove source directory': '0d79795385ede5c43816bab9432d3f7b7d72520b8a65d849577f112134cfe3fa',
    'verify:Reverify exact source bytes': '7217fc354e5bbdecd9661fb621606de3d78e0138a0bcf032668ab793da1ec6c2',
    'verify:Remove verification directory': '0d79795385ede5c43816bab9432d3f7b7d72520b8a65d849577f112134cfe3fa',
  });
  assert.doesNotMatch(source, /(candidate|smoke:local|secrets\.|GITHUB_ENV|GITHUB_PATH|continue-on-error|npm publish|release create)/i);
}

test('Issue #55 source attestation workflow has a closed parsed contract', () => {
  assertContract(workflow);
});

test('source workflow contract rejects authority and fail-open mutations', () => {
  for (const mutated of [
    workflow.replace('  workflow_dispatch:', '  workflow_dispatch:\n  repository_dispatch:'),
    workflow.replace('permissions: {}', 'permissions:\n  id-token: write'),
    workflow.replace('\n  attest:\n', '\n  surprise_job:\n    runs-on: ubuntu-latest\n\n  attest:\n'),
    workflow.replace('      contents: read\n    outputs:', '      contents: read\n      id-token: write\n    outputs:'),
    workflow.replace('      - name: Attest negative source evidence', '      - run: echo bypass\n\n      - name: Attest negative source evidence'),
    workflow.replace('npm run evidence:issue55:verify -- --packet "$EVIDENCE_DIR/issue55-source.json"', 'npm run evidence:issue55:verify -- --packet "$EVIDENCE_DIR/issue55-source.json" || true'),
    workflow.replace('      - name: Reverify exact source bytes', '      - name: Reverify exact source bytes\n        if: false'),
    workflow.replace('actions/checkout@fbc6f3992d24b796d5a048ff273f7fcc4a7b6c09', 'actions/checkout@v5'),
  ]) assert.throws(() => assertContract(mutated));
});

test('documentation keeps source attestation non-promotional', () => {
  for (const required of [
    'issue55-source-evidence',
    'untrusted-issue55-source',
    'verified-unattested-issue55-source',
    'gh attestation verify',
    '--signer-workflow',
    '--signer-digest',
    '--source-ref',
    '--source-digest',
    'does not promote',
    'does not prove historical execution',
    'candidate-tests',
    'candidate-smoke',
    '33962365033',
    '1d442959ad5ea5ebaacb138e382a785dbc219ff0',
    '57b8b667921e1dcd51c84efa6535bee15632056851baa5ac00a66fe92d26b574',
    '21 blockers',
  ]) assert.match(documentation, new RegExp(required, 'i'));
});

test('real repository Docker contract pins the current Bun lock', () => {
  const lockDigest = createHash('sha256')
    .update(execFileSync('git', ['show', 'HEAD:bun.lock']))
    .digest('hex');
  const dockerfile = readFileSync(
    'deploy/docker/daemon/Dockerfile',
    'utf8',
  ).replaceAll('\r\n', '\n');
  assert.match(
    dockerfile,
    new RegExp(`^ARG LOCK_SHA256=${lockDigest}$`, 'm'),
  );
});
