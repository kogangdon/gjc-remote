import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import YAML from 'yaml';

const workflow = YAML.parse(readFileSync('.github/workflows/signed-native-verification.yml', 'utf8'));
const targets = ['linux-x64', 'linux-arm64', 'win32-x64'];
const commit = 'a'.repeat(40);
const repository = 'kogangdon/gjc-remote';
const AsyncFunction = Object.getPrototypeOf(async function () {}).constructor;
const validateScript = workflow.jobs.validate.steps[0].with.script;

async function validate({ run = {}, artifacts, env = {}, repo = repository, ref = 'refs/heads/main', sha = commit, mainSha = commit } = {}) {
  const outputs = {};
  const data = {
    repository: { full_name: repository }, head_repository: { full_name: repository },
    event: 'push', head_branch: 'main', head_sha: commit,
    status: 'completed', conclusion: 'success', path: '.github/workflows/ci.yml', ...run,
  };
  const github = {
    rest: { git: { getRef: async () => ({ data: { object: { sha: mainSha } } }) }, actions: {
      getWorkflowRun: async (request) => {
        assert.equal(request.run_id, 123);
        return { data };
      },
      listWorkflowRunArtifacts: Symbol('artifact-list'),
    } },
    paginate: async () => artifacts ?? targets.map(target => ({
      name: `native-control-unsigned-${target}`, expired: false,
      workflow_run: { head_sha: commit },
    })),
  };
  const [owner, name] = repo.split('/');
  await new AsyncFunction('github', 'context', 'core', 'process', validateScript)(
    github, { repo: { owner, repo: name }, ref, sha }, { setOutput: (key, value) => { outputs[key] = value; } },
    { env: { SOURCE_RUN_ID: '123', SOURCE_COMMIT: commit, WORKFLOW_SHA: commit, ...env } },
  );
  return outputs;
}

test('manual-only workflow is read-only and covers three native platforms with pinned runtimes', () => {
  assert.deepEqual(Object.keys(workflow.on), ['workflow_dispatch']);
  assert.deepEqual(workflow.permissions, {});
  assert.deepEqual(workflow.jobs.verify.permissions, { actions: 'read', contents: 'read' });
  assert.deepEqual(workflow.jobs.validate.permissions, { actions: 'read', contents: 'read' });
  assert.equal(workflow.jobs.verify.needs, 'validate');
  assert.equal(workflow.jobs.verify.strategy['fail-fast'], false);
  assert.deepEqual(workflow.jobs.verify.strategy.matrix.include, [
    { os: 'ubuntu-24.04', target: 'linux-x64' },
    { os: 'ubuntu-24.04-arm', target: 'linux-arm64' },
    { os: 'windows-2022', target: 'win32-x64' },
  ]);
  const steps = workflow.jobs.verify.steps;
  const action = name => steps.find(s => s.uses?.startsWith(`${name}@`));
  for (const job of Object.values(workflow.jobs)) {
    for (const step of job.steps.filter(s => s.uses)) assert.match(step.uses, /@[a-f0-9]{40}$/);
  }
  assert.equal(action('actions/setup-node').with['node-version'], '26.7.0');
  assert.equal(action('oven-sh/setup-bun').with['bun-version'], '1.4.2');
  assert.equal(action('actions/checkout').with['persist-credentials'], false);
  assert.equal(action('actions/checkout').with.ref, '${{ needs.validate.outputs.verifier-commit }}');
  const download = action('actions/download-artifact').with;
  assert.equal(download.repository, repository);
  assert.equal(download['run-id'], '${{ needs.validate.outputs.source-run-id }}');
  assert.equal(download.name, 'native-control-unsigned-${{ matrix.target }}');
  for (const runtime of ['Node', 'Bun']) {
    const step = steps.find(s => s.name === `Verify signed addon with ${runtime}`);
    assert.match(step.run, /scripts\/verify-signed-native\.mjs/);
    assert.match(step.run, /--signatures-file verification-signatures\.json/);
    assert.match(step.run, /--source-commit "\$SOURCE_COMMIT"/);
    assert.equal(step.shell, 'bash');
  }
  const upload = action('actions/upload-artifact');
  assert.equal(upload.if, 'always()');
  assert.equal(upload.with.path, 'verification-results/*.json');
});

test('trusted source produces exact run and commit outputs', async () => {
  assert.deepEqual(await validate(), { 'source-commit': commit, 'source-run-id': '123', 'verifier-commit': commit });
});

test('verifier refuses branch dispatch, stale main and mismatched workflow revision', async () => {
  await assert.rejects(validate({ ref: 'refs/heads/feature' }), /exact main/);
  await assert.rejects(validate({ sha: 'not-a-sha' }), /exact main/);
  await assert.rejects(validate({ env: { WORKFLOW_SHA: 'b'.repeat(40) } }), /exact main/);
  await assert.rejects(validate({ mainSha: 'b'.repeat(40) }), /current main/);
});

for (const [name, run] of Object.entries({
  fork: { head_repository: { full_name: 'attacker/repo' } },
  foreign: { repository: { full_name: 'attacker/repo' } },
  pr: { event: 'pull_request' },
  branch: { head_branch: 'feature' },
  commit: { head_sha: 'b'.repeat(40) },
  pending: { status: 'in_progress' },
  failed: { conclusion: 'failure' },
  wrongWorkflow: { path: '.github/workflows/release.yml' },
})) {
  test(`source validation rejects ${name}`, async () => {
    await assert.rejects(validate({ run }), /exact successful trusted main CI push/);
  });
}

test('source validation rejects dispatch from foreign repository and malformed identifiers', async () => {
  await assert.rejects(validate({ repo: 'fork/repo' }), /Untrusted repository/);
  for (const id of ['0', '-1', '1e3', '123; echo bad', '9007199254740992']) {
    await assert.rejects(validate({ env: { SOURCE_RUN_ID: id } }), /Invalid run id/);
  }
  await assert.rejects(validate({ env: { SOURCE_COMMIT: 'main' } }), /Invalid source commit/);
});

test('source validation rejects missing, stale, mismatched, duplicate and staging-only inputs', async () => {
  const good = targets.map(target => ({
    name: `native-control-unsigned-${target}`, expired: false,
    workflow_run: { head_sha: commit },
  }));
  for (const artifacts of [
    good.slice(1),
    good.map((a, i) => i === 0 ? { ...a, expired: true } : a),
    good.map((a, i) => i === 0 ? { ...a, workflow_run: { head_sha: 'b'.repeat(40) } } : a),
    [...good, good[0]],
    good.map(a => ({ ...a, name: a.name.replace('unsigned', 'staging') })),
  ]) {
    await assert.rejects(validate({ artifacts }), /promoted input/);
  }
});
