import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';

const binding = JSON.parse(
  readFileSync(new URL('../binding.gyp', import.meta.url), 'utf8'),
);
const workflow = readFileSync(
  new URL('../../.github/workflows/ci.yml', import.meta.url),
  'utf8',
).replaceAll('\r\n', '\n');
const dockerBotReadme = readFileSync(
  new URL('../../deploy/docker/bot/README.md', import.meta.url),
  'utf8',
).replaceAll('\r\n', '\n');

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

test('CI uploads one explicitly named unsigned artifact for every native target', () => {
  const suiteStart = workflow.indexOf('\n  suite:');
  const suiteEnd = workflow.indexOf('\n  bot-container-contract:');
  assert.notEqual(suiteStart, -1);
  assert.notEqual(suiteEnd, -1);
  const suite = workflow.slice(suiteStart, suiteEnd);

  const legs = [...suite.matchAll(
    /^\s+- os: (\S+)\n\s+target: (\S+)$/gm,
  )].map((match) => ({
    os: match[1],
    target: match[2],
  }));
  assert.deepEqual(legs, [
    { os: 'ubuntu-latest', target: 'linux-x64' },
    { os: 'ubuntu-24.04-arm', target: 'linux-arm64' },
    { os: 'windows-latest', target: 'win32-x64' },
  ]);

  const uploadStep = suite.match(
    /\n      - name: Upload unsigned native-control signing input\n[\s\S]+?(?=\n      - |$)/,
  )?.[0];
  assert.ok(uploadStep);
  assert.match(uploadStep, /uses: actions\/upload-artifact@v4/);
  assert.match(
    uploadStep,
    /name: native-control-unsigned-\$\{\{ matrix\.target \}\}/,
  );
  assert.match(uploadStep, /if-no-files-found: error/);
  assert.match(uploadStep, /retention-days: 7/);
  assert.match(
    uploadStep,
    /native-control\/build\/Release\/native_control\.node/,
  );
  assert.match(
    uploadStep,
    /native-control\/build\/Release\/native-control\.manifest\.json/,
  );
  assert.doesNotMatch(uploadStep, /^\s+if:/m);
});

test('Docker signing instructions use exact Linux workflow artifact names', () => {
  for (const artifactName of [
    'native-control-unsigned-linux-x64',
    'native-control-unsigned-linux-arm64',
  ]) {
    assert.match(dockerBotReadme, new RegExp(`\`${artifactName}\``));
  }
  assert.match(
    dockerBotReadme,
    /separate Windows CI leg\s+uploads `native-control-unsigned-win32-x64`/,
  );
  assert.match(
    dockerBotReadme,
    /that bundle is not compatible with\s+this Linux-only Docker image/,
  );
  assert.doesNotMatch(
    dockerBotReadme,
    /native-control-unsigned-\{X64\|ARM64\}/,
  );
});
