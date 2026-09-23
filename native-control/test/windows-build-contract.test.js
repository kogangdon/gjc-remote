import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import YAML from 'yaml';

const binding = JSON.parse(
  readFileSync(new URL('../binding.gyp', import.meta.url), 'utf8'),
);
const workflow = readFileSync(
  new URL('../../.github/workflows/ci.yml', import.meta.url),
  'utf8',
).replaceAll('\r\n', '\n');
const workflowContract = YAML.parse(workflow);
const nativeControlReadme = readFileSync(
  new URL('../README.md', import.meta.url),
  'utf8',
).replaceAll('\r\n', '\n');
const dockerBotReadme = readFileSync(
  new URL('../../deploy/docker/bot/README.md', import.meta.url),
  'utf8',
).replaceAll('\r\n', '\n');
const nativeTargets = ['linux-x64', 'linux-arm64', 'win32-x64'];
const nativeBuildFiles = [
  'native_control.node',
  'native-control.manifest.json',
];

function namedStep(job, name) {
  const matches = job.steps.filter((step) => step.name === name);
  assert.equal(matches.length, 1, `expected one "${name}" step`);
  return matches[0];
}

function blockScalarLines(value) {
  return value.trim().split('\n');
}

test('Windows Release build replaces inherited options with deterministic linker flags', () => {
  const target = binding.targets.find(({ target_name: name }) => (
    name === 'native_control'
  ));
  assert.ok(target);

  const settings = target.configurations.Release.msvs_settings;
  assert.deepEqual(
    settings.VCCLCompilerTool['AdditionalOptions='],
    [],
  );
  assert.deepEqual(
    settings.VCLibrarianTool['AdditionalOptions='],
    [],
  );
  assert.deepEqual(
    settings.VCLinkerTool['AdditionalOptions='],
    ['/Brepro', '/PDBALTPATH:%_PDB%'],
  );

  for (const tool of [
    settings.VCCLCompilerTool,
    settings.VCLibrarianTool,
    settings.VCLinkerTool,
  ]) {
    assert.equal(tool.AdditionalOptions, undefined);
  }
});

test('CI promotes target-preserving signing inputs only after every dependency succeeds', () => {
  const { jobs } = workflowContract;
  const suite = jobs.suite;
  const expectedSuiteLegs = [
    { os: 'ubuntu-latest', target: 'linux-x64' },
    { os: 'ubuntu-24.04-arm', target: 'linux-arm64' },
    { os: 'windows-latest', target: 'win32-x64' },
  ];
  assert.deepEqual(suite.strategy.matrix.include, expectedSuiteLegs);
  assert.deepEqual(
    suite.strategy.matrix.include.map(({ target }) => target),
    nativeTargets,
  );

  const stage = namedStep(
    suite,
    'Stage unsigned native-control build output',
  );
  assert.equal(stage.uses, 'actions/upload-artifact@v4');
  assert.equal(
    stage.with.name,
    'native-control-staging-${{ matrix.target }}',
  );
  assert.equal(stage.with['if-no-files-found'], 'error');
  assert.equal(stage.with['retention-days'], 1);
  assert.deepEqual(blockScalarLines(stage.with.path), nativeBuildFiles.map(
    (file) => `native-control/build/Release/${file}`,
  ));
  assert.equal(stage.if, undefined);
  const suiteTestIndex = suite.steps.findIndex(
    (step) => step.run === 'npm test',
  );
  const changelogGateIndex = suite.steps.findIndex(
    (step) => step.name === 'Guard changelog history',
  );
  assert.notEqual(suiteTestIndex, -1);
  assert.notEqual(changelogGateIndex, -1);
  assert.ok(suite.steps.indexOf(stage) > suiteTestIndex);
  assert.ok(suite.steps.indexOf(stage) > changelogGateIndex);

  const promotion = jobs['promote-native-control-signing-inputs'];
  const requiredDependencies = [
    'suite',
    'bot-container-contract',
    'daemon-container-contract',
  ];
  assert.deepEqual(promotion.needs, requiredDependencies);
  assert.equal(promotion.if, '${{ success() }}');
  assert.equal(promotion['runs-on'], 'ubuntu-latest');
  assert.equal(promotion.strategy['fail-fast'], false);
  assert.deepEqual(promotion.strategy.matrix.target, nativeTargets);
  assert.deepEqual(promotion.steps.map(({ name }) => name), [
    'Download staged native-control build output',
    'Publish unsigned native-control signing input',
  ]);

  const download = namedStep(
    promotion,
    'Download staged native-control build output',
  );
  assert.equal(download.uses, 'actions/download-artifact@v4');
  assert.deepEqual(download.with, {
    name: 'native-control-staging-${{ matrix.target }}',
    path: '${{ runner.temp }}/native-control-staging/${{ matrix.target }}',
  });

  const publish = namedStep(
    promotion,
    'Publish unsigned native-control signing input',
  );
  assert.equal(publish.uses, 'actions/upload-artifact@v4');
  assert.equal(
    publish.with.name,
    'native-control-unsigned-${{ matrix.target }}',
  );
  assert.equal(publish.with['if-no-files-found'], 'error');
  assert.equal(publish.with['retention-days'], 7);
  assert.deepEqual(blockScalarLines(publish.with.path), nativeBuildFiles.map(
    (file) => (
      '${{ runner.temp }}/native-control-staging/'
      + `\${{ matrix.target }}/${file}`
    ),
  ));

  const renderTarget = (template, target) => (
    template.replace('${{ matrix.target }}', target)
  );
  assert.deepEqual(
    nativeTargets.map((target) => renderTarget(stage.with.name, target)),
    nativeTargets.map((target) => `native-control-staging-${target}`),
  );
  assert.deepEqual(
    promotion.strategy.matrix.target.map(
      (target) => renderTarget(publish.with.name, target),
    ),
    nativeTargets.map((target) => `native-control-unsigned-${target}`),
  );

  const nativeArtifactUploads = Object.entries(jobs).flatMap(
    ([jobName, job]) => job.steps
      .filter((step) => (
        step.uses === 'actions/upload-artifact@v4'
        && step.with?.name?.startsWith('native-control-')
      ))
      .map((step) => ({
        jobName,
        name: step.with.name,
        retentionDays: step.with['retention-days'],
      })),
  );
  assert.deepEqual(nativeArtifactUploads, [
    {
      jobName: 'suite',
      name: 'native-control-staging-${{ matrix.target }}',
      retentionDays: 1,
    },
    {
      jobName: 'promote-native-control-signing-inputs',
      name: 'native-control-unsigned-${{ matrix.target }}',
      retentionDays: 7,
    },
  ]);

  const aggregateGate = jobs.test;
  assert.equal(aggregateGate.if, 'always()');
  assert.deepEqual(aggregateGate.needs, [
    ...requiredDependencies,
    'promote-native-control-signing-inputs',
  ]);
  const gateRun = namedStep(
    aggregateGate,
    'Require every matrix leg to succeed',
  ).run;
  for (const dependency of aggregateGate.needs) {
    assert.ok(gateRun.includes(
      `test "\${{ needs.${dependency}.result }}" = "success"`,
    ));
  }
});

test('signing instructions reject staging artifacts and require overall CI success', () => {
  const signingArtifactNames = [
    'native-control-unsigned-linux-x64',
    'native-control-unsigned-linux-arm64',
    'native-control-unsigned-win32-x64',
  ];
  for (const documentation of [nativeControlReadme, dockerBotReadme]) {
    for (const artifactName of signingArtifactNames) {
      assert.match(documentation, new RegExp(`\`${artifactName}\``));
    }
    assert.match(
      documentation,
      /staging artifacts[\s\S]{0,200}must never\s+be signed/i,
    );
    assert.match(
      documentation,
      /overall CI\s+workflow conclusion is `success`/i,
    );
  }

  for (const target of nativeTargets) {
    assert.match(
      nativeControlReadme,
      new RegExp(`\`native-control-staging-${target}\``),
    );
  }

  assert.match(
    dockerBotReadme,
    /separate Windows promotion\s+publishes `native-control-unsigned-win32-x64`/,
  );
  assert.match(
    dockerBotReadme,
    /that bundle is not compatible\s+with\s+this Linux-only Docker image/,
  );
  assert.doesNotMatch(
    dockerBotReadme,
    /native-control-unsigned-\{X64\|ARM64\}/,
  );
});
