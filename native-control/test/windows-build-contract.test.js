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
const nativeArtifactRerunWindowDays = 7;
const trustedPromotionRepository = 'kogangdon/gjc-remote';
const trustedPromotionEvent = 'push';
const trustedPromotionRef = 'refs/heads/main';

function namedStep(job, name) {
  const matches = job.steps.filter((step) => step.name === name);
  assert.equal(matches.length, 1, `expected one "${name}" step`);
  return matches[0];
}

function blockScalarLines(value) {
  return value.trim().split('\n');
}

function evaluateConjunctiveWorkflowCondition(condition, context) {
  const wrappedExpression = condition.match(/^\$\{\{\s*(.*?)\s*\}\}$/);
  assert.ok(wrappedExpression, `invalid workflow condition: ${condition}`);

  return wrappedExpression[1].split(/\s*&&\s*/).every((term) => {
    if (term === 'success()') {
      return context.dependenciesSucceeded;
    }

    const comparison = term.match(
      /^github\.(repository|event_name|ref) == '([^']+)'$/,
    );
    assert.ok(comparison, `unsupported workflow condition term: ${term}`);
    const actual = {
      repository: context.repository,
      event_name: context.eventName,
      ref: context.ref,
    }[comparison[1]];
    return actual === comparison[2];
  });
}

function aggregateGateAccepts({
  repository,
  eventName,
  ref,
  suiteResult = 'success',
  botContainerResult = 'success',
  daemonContainerResult = 'success',
  promotionResult,
}) {
  return [
    suiteResult,
    botContainerResult,
    daemonContainerResult,
  ].every((result) => result === 'success')
    && (
      (eventName === 'pull_request' && promotionResult === 'skipped')
      || (
        repository === trustedPromotionRepository
        && eventName === trustedPromotionEvent
        && ref === trustedPromotionRef
        && promotionResult === 'success'
      )
    );
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

test('CI promotes target-preserving signing inputs only for successful main pushes', () => {
  const { jobs } = workflowContract;
  const suite = jobs.suite;
  assert.deepEqual(workflowContract.on.push.branches, ['main']);
  assert.deepEqual(workflowContract.on.pull_request.branches, ['main']);
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
  assert.equal(
    stage.with['retention-days'],
    nativeArtifactRerunWindowDays,
  );
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
  assert.equal(
    promotion.if,
    "${{ success() && github.repository == 'kogangdon/gjc-remote'"
      + " && github.event_name == 'push'"
      + " && github.ref == 'refs/heads/main' }}",
  );
  for (const [
    repository,
    eventName,
    ref,
    dependenciesSucceeded,
    expected,
  ] of [
    [
      trustedPromotionRepository,
      'pull_request',
      'refs/pull/246/merge',
      true,
      false,
    ],
    [
      trustedPromotionRepository,
      trustedPromotionEvent,
      trustedPromotionRef,
      true,
      true,
    ],
    [
      'untrusted/fork',
      trustedPromotionEvent,
      trustedPromotionRef,
      true,
      false,
    ],
    [
      trustedPromotionRepository,
      trustedPromotionEvent,
      'refs/heads/release-candidate',
      true,
      false,
    ],
    [
      trustedPromotionRepository,
      trustedPromotionEvent,
      trustedPromotionRef,
      false,
      false,
    ],
  ]) {
    assert.equal(evaluateConjunctiveWorkflowCondition(promotion.if, {
      dependenciesSucceeded,
      repository,
      eventName,
      ref,
    }), expected);
  }
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
  assert.equal(
    publish.with['retention-days'],
    nativeArtifactRerunWindowDays,
  );
  assert.equal(
    stage.with['retention-days'],
    publish.with['retention-days'],
    'staging must remain available for the full signing-input rerun window',
  );
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
      retentionDays: nativeArtifactRerunWindowDays,
    },
    {
      jobName: 'promote-native-control-signing-inputs',
      name: 'native-control-unsigned-${{ matrix.target }}',
      retentionDays: nativeArtifactRerunWindowDays,
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
  for (const dependency of requiredDependencies) {
    assert.ok(gateRun.includes(
      `test "\${{ needs.${dependency}.result }}" = "success"`,
    ));
  }
  assert.ok(gateRun.includes([
    'if [[ "${{ github.event_name }}" == "pull_request" ]]; then',
    '  test "${{ needs.promote-native-control-signing-inputs.result }}" = "skipped"',
    'else',
    '  test "${{ github.repository }}" = "kogangdon/gjc-remote"',
    '  test "${{ github.event_name }}" = "push"',
    '  test "${{ github.ref }}" = "refs/heads/main"',
    '  test "${{ needs.promote-native-control-signing-inputs.result }}" = "success"',
    'fi',
  ].join('\n')));

  const pullRequestGate = {
    repository: trustedPromotionRepository,
    eventName: 'pull_request',
    ref: 'refs/pull/246/merge',
    promotionResult: 'skipped',
  };
  assert.equal(aggregateGateAccepts(pullRequestGate), true);
  for (const failedResult of [
    'suiteResult',
    'botContainerResult',
    'daemonContainerResult',
  ]) {
    assert.equal(
      aggregateGateAccepts({ ...pullRequestGate, [failedResult]: 'failure' }),
      false,
      `pull request must reject ${failedResult}=failure`,
    );
  }
  assert.equal(aggregateGateAccepts({
    ...pullRequestGate,
    promotionResult: 'success',
  }), false);

  const mainPushGate = {
    repository: trustedPromotionRepository,
    eventName: trustedPromotionEvent,
    ref: trustedPromotionRef,
    promotionResult: 'success',
  };
  assert.equal(aggregateGateAccepts(mainPushGate), true);
  assert.equal(aggregateGateAccepts({
    ...mainPushGate,
    promotionResult: 'skipped',
  }), false);
  assert.equal(aggregateGateAccepts({
    ...mainPushGate,
    repository: 'untrusted/fork',
  }), false);
  assert.equal(aggregateGateAccepts({
    ...mainPushGate,
    ref: 'refs/heads/release-candidate',
  }), false);
});

test('signing instructions require trusted main-push provenance and authorization', () => {
  const signingArtifactNames = [
    'native-control-unsigned-linux-x64',
    'native-control-unsigned-linux-arm64',
    'native-control-unsigned-win32-x64',
  ];
  for (const source of [nativeControlReadme, dockerBotReadme]) {
    const documentation = source.replace(/\s+/g, ' ');
    for (const artifactName of signingArtifactNames) {
      assert.match(documentation, new RegExp(`\`${artifactName}\``));
    }
    assert.match(
      documentation,
      /staging artifacts[\s\S]{0,200}must never\s+be signed/i,
    );
    assert.match(
      documentation,
      /overall CI\s+workflow conclusion of `success`/i,
    );
    assert.match(documentation, /trusted repository `kogangdon\/gjc-remote`/i);
    assert.match(documentation, /event is exactly `push`/i);
    assert.match(documentation, /exact source commit/i);
    assert.match(documentation, /source ref is exactly `refs\/heads\/main`/i);
    assert.match(documentation, /explicit release authorization/i);
    assert.match(
      documentation,
      /successful `pull_request` workflow[\s\S]{0,200}(?:not|neither)[\s\S]{0,100}release provenance/i,
    );
    assert.match(
      documentation,
      /supported artifact-backed rerun window is seven days/i,
    );
    assert.match(
      documentation,
      /staging artifact has expired[\s\S]{0,300}`Re-run all jobs`/i,
    );
    assert.match(
      documentation,
      /promotion-only[\s\S]{0,100}(?:is\s+not supported|unsupported)/i,
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
