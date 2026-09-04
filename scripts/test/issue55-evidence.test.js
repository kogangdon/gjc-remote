import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  openSync,
  readFileSync,
  rmSync,
  symlinkSync,
  writeSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import {
  CHECK_REGISTRY,
  candidateLaunchCommand,
  canonicalBytes,
  createPacket,
  readBoundedRegularUtf8,
  sha256,
  verifyCandidate,
  verifyPacket,
  verifyPacketBytes,
  writeCandidate,
  writeCanonical,
  writeSnapshot,
} from '../issue55-evidence.js';

const SDK_INTEGRITY = 'sha512-t6iHwJBOpfbZYdpCfz8RxRpx22v9eQUB4PZmMad+F7jPTFLDZRVFiPHcBe+GBKx/Yr5iVU8nsdpxQCya/z7hbg==';
const BUN_DIGEST = 'e10577f0db68676a7024391c6e5cb4b879ebd17188ab750cf10024a6d700e5c4';
const logicalLaunch = (command) => [...command];

function command(root, args) {
  return execFileSync('git', args, { cwd: root, encoding: 'utf8' });
}

function fixture() {
  const root = mkdtempSync(join(tmpdir(), 'issue55-'));
  const write = (file, text) => {
    const destination = join(root, file);
    mkdirSync(join(destination, '..'), { recursive: true });
    writeFileSync(destination, text);
  };
  write('package.json', '{"version":"0.3.1"}\n');
  write('bot/package.json', '{"version":"0.3.1"}\n');
  write('daemon/package.json', '{"version":"0.3.1","dependencies":{"@gajae-code/coding-agent":"0.12.21"}}\n');
  write('native-control/package.json', '{"version":"1.0.0","nativeControlContract":{"version":4,"revision":3,"napi":8,"platforms":["linux-x64","linux-arm64","win32-x64"]}}\n');
  write('shared/package.json', '{"version":"0.3.1"}\n');
  write('.dockerignore', 'node_modules\n.git\n');
  const lock = `{
  "lockfileVersion": 1,
  "packages": {
    "@gajae-code/coding-agent": ["@gajae-code/coding-agent@0.12.21", "", {}, "${SDK_INTEGRITY}"]
  }
}\n`;
  write('bun.lock', lock);
  write('deploy/docker/daemon/Dockerfile', `ARG BUN_IMAGE=oven/bun:1.3.14@sha256:${BUN_DIGEST}
ARG LOCK_SHA256=${sha256(lock)}
FROM \${BUN_IMAGE} AS deps
FROM \${BUN_IMAGE} AS fixture
FROM \${BUN_IMAGE} AS runtime-base
RUN echo "\${LOCK_SHA256}  bun.lock" | sha256sum --check --strict \\
    && bun -e 'const p={version:"0.12.21"}; if(p.version!=="0.12.21") process.exit(1)'
LABEL fixture="true" \\
      org.opencontainers.image.base.name="oven/bun:1.3.14@sha256:${BUN_DIGEST}" \\
      io.gjc-remote.lock.sha256="\${LOCK_SHA256}" \\
      io.gjc-remote.sdk.version="0.12.21"
`);
  write('deploy/docker/bot/Dockerfile', `ARG BUN_IMAGE=oven/bun:1.3.14@sha256:${BUN_DIGEST}
ARG NODE_IMAGE=node:26.8.1@sha256:${'1'.repeat(64)}
FROM \${BUN_IMAGE} AS deps
RUN bun install --frozen-lockfile --production --ignore-scripts --filter @gjc-remote/bot
FROM native_control_bundle AS signed-native
FROM \${NODE_IMAGE} AS runtime
ARG VERSION=0.3.1
ARG REVISION=unknown
LABEL org.opencontainers.image.title="fixture" \\
      org.opencontainers.image.version="\${VERSION}" \\
      org.opencontainers.image.revision="\${REVISION}" \\
      org.opencontainers.image.source="https://github.com/kogangdon/gjc-remote"
COPY --chmod=0444 --from=signed-native /native_control.node ./native-control/build/Release/native_control.node
COPY --chmod=0444 --from=signed-native /native-control.manifest.json ./native-control/build/Release/native-control.manifest.json
COPY --chmod=0444 --from=signed-native /native-control.manifest.json.sig ./native-control/build/Release/native-control.manifest.json.sig
RUN node native-control/scripts/verify-build.mjs --require-signature
`);
  command(root, ['init', '--quiet']);
  command(root, ['config', 'user.email', 'test@example.invalid']);
  command(root, ['config', 'user.name', 'test']);
  command(root, ['add', '.']);
  command(root, ['commit', '--quiet', '-m', 'fixture']);
  return root;
}

function withFixture(fn) {
  const root = fixture();
  try { return fn(root); } finally { rmSync(root, { recursive: true, force: true }); }
}

function changes(packet, callback) {
  const clone = JSON.parse(JSON.stringify(packet));
  callback(clone);
  return canonicalBytes(clone);
}

test('issue55 packets are deterministic, canonical, negative, and source-bound', () => withFixture((root) => {
  const first = createPacket({ root });
  const second = createPacket({ root });
  assert.deepEqual(canonicalBytes(first), canonicalBytes(second));
  assert.equal(first.promotion.releaseEligible, false);
  assert.deepEqual(first.promotion.blockingCheckIds, CHECK_REGISTRY.slice(1).map((check) => check.id));
  assert.ok(first.checks.slice(1).every((check) => check.status === 'missing'));
  assert.match(first.source.docker.bot.dockerfileSha256, /^[a-f0-9]{64}$/);
  assert.match(first.source.docker.daemon.dockerfileSha256, /^[a-f0-9]{64}$/);
  assert.match(first.source.docker.dockerignoreSha256, /^[a-f0-9]{64}$/);
  assert.doesNotMatch(canonicalBytes(first).toString(), /issue55-|test@example|[A-Z]:\\|\/tmp\//i);
}));

test('issue55 rejects bot Dockerfile contract drift', () => {
  for (const mutation of [
    (text) => text.replace('FROM ${NODE_IMAGE}', 'FROM node:latest'),
    (text) => `  arg BUN_IMAGE=invalid@sha256:${'0'.repeat(64)}\n${text}`,
    (text) => text.replace('FROM native_control_bundle AS signed-native', 'FROM unsigned AS signed-native'),
    (text) => text.replace(
      'FROM native_control_bundle AS signed-native\nFROM ${NODE_IMAGE} AS runtime',
      'FROM ${NODE_IMAGE} AS runtime\nFROM native_control_bundle AS signed-native',
    ),
    (text) => text.replace(
      'LABEL org.opencontainers.image.title="fixture"',
      'FROM ${NODE_IMAGE} AS misplaced-labels\nLABEL org.opencontainers.image.title="fixture"',
    ),
    (text) => text.replace(
      './native-control/build/Release/native_control.node',
      './native-control/build/Release/substituted.node',
    ),
    (text) => text.replace(
      'RUN node native-control/scripts/verify-build.mjs --require-signature',
      'COPY --chmod=0444 --from=signed-native /native_control.node ./native-control/build/Release/native_control.node\nRUN node native-control/scripts/verify-build.mjs --require-signature',
    ),
    (text) => text.replace('--require-signature', ''),
    (text) => text.replace(
      'RUN node native-control/scripts/verify-build.mjs --require-signature',
      'RUN true # node native-control/scripts/verify-build.mjs --require-signature',
    ),
    (text) => `${text.replace(
      'RUN node native-control/scripts/verify-build.mjs --require-signature',
      '',
    )}
FROM \${NODE_IMAGE} AS dead-verifier
RUN node native-control/scripts/verify-build.mjs --require-signature
`,
    (text) => text.replace('ARG VERSION=0.3.1', 'ARG VERSION=9.9.9'),
    (text) => text.replace('https://github.com/kogangdon/gjc-remote', 'https://invalid.example'),
  ]) {
    withFixture((root) => {
      const docker = join(root, 'deploy/docker/bot/Dockerfile');
      writeFileSync(docker, mutation(readFileSync(docker, 'utf8')));
      command(root, ['add', '.']);
      command(root, ['commit', '--quiet', '-m', 'bad-bot']);
      assert.throws(
        () => createPacket({ root }),
        { code: 'BOT_DOCKER_CONTRACT_INVALID' },
      );
    });
  }
});

test('candidate npm commands launch the JavaScript CLI without a shell', () => {
  const npmCli = process.platform === 'win32'
    ? 'C:\\node\\npm-cli.js'
    : '/node/npm-cli.js';
  const node = process.platform === 'win32'
    ? 'C:\\node\\node.exe'
    : '/node/node';
  assert.deepEqual(
    candidateLaunchCommand(['npm', 'test'], {
      npmCli,
      processPath: node,
    }),
    [node, npmCli, 'test'],
  );
  assert.deepEqual(
    candidateLaunchCommand(['bun', 'install']),
    ['bun', 'install'],
  );
  assert.throws(
    () => candidateLaunchCommand(['npm', 'test'], {
      npmCli: 'npm.cmd',
      processPath: node,
    }),
    { code: 'NPM_CLI_UNAVAILABLE' },
  );
});

test('issue55 candidate execution has fixed command order and does not promote source', () => withFixture((root) => {
  const destination = mkdtempSync(join(tmpdir(), 'issue55-candidate-'));
  try {
    const output = join(destination, 'receipt.json');
    const calls = [];
    writeCandidate(output, {
      root,
      launch: logicalLaunch,
      execute: (file, args) => { calls.push([file, ...args]); },
    });
    assert.deepEqual(calls, [
      ['bun', 'install', '--frozen-lockfile'],
      ['npm', 'run', 'build', '--workspace', '@gjc-remote/native-control'],
      ['npm', 'test'],
      ['npm', 'run', 'smoke:local'],
    ]);
    verifyCandidate(output, { root });
  } finally { rmSync(destination, { recursive: true, force: true }); }
}));

test('candidate execution stops at each failed fixed step and writes nothing', () => {
  for (let failureIndex = 0; failureIndex < 4; failureIndex += 1) {
    withFixture((root) => {
      const destination = mkdtempSync(join(tmpdir(), 'issue55-candidate-'));
      try {
        const output = join(destination, 'receipt.json');
        let calls = 0;
        assert.throws(
          () => writeCandidate(output, {
            root,
            launch: logicalLaunch,
            execute: () => {
              if (calls++ === failureIndex) throw new Error('fixed failure');
            },
          }),
          { code: [
            'CANDIDATE_INSTALL_FAILED',
            'CANDIDATE_NATIVE_BUILD_FAILED',
            'CANDIDATE_TEST_FAILED',
            'CANDIDATE_SMOKE_FAILED',
          ][failureIndex] },
        );
        assert.equal(calls, failureIndex + 1);
        assert.equal(existsSync(output), false);
        assert.equal(existsSync(`${output}.sha256`), false);
      } finally {
        rmSync(destination, { recursive: true, force: true });
      }
    });
  }
});

test('candidate execution rejects source and hidden-index drift', () =>
  withFixture((root) => {
    const destination = mkdtempSync(join(tmpdir(), 'issue55-candidate-'));
    try {
      const output = join(destination, 'receipt.json');
      let calls = 0;
      assert.throws(
        () => writeCandidate(output, {
          root,
          launch: logicalLaunch,
          execute: () => {
            calls += 1;
            writeFileSync(join(root, 'tracked.txt'), 'changed\n');
            command(root, ['add', 'tracked.txt']);
            command(root, ['commit', '--quiet', '-m', 'source-drift']);
          },
        }),
        { code: 'CANDIDATE_SOURCE_DRIFT' },
      );
      assert.equal(calls, 1);
      assert.equal(existsSync(output), false);
    } finally {
      rmSync(destination, { recursive: true, force: true });
    }
  }));

test('candidate execution rejects every hidden tracked-index state', () => {
  for (const flags of [
    ['--assume-unchanged'],
    ['--skip-worktree'],
    ['--assume-unchanged', '--skip-worktree'],
  ]) {
    withFixture((root) => {
      for (const flag of flags) {
        command(root, ['update-index', flag, 'package.json']);
      }
      const destination = mkdtempSync(join(tmpdir(), 'issue55-candidate-'));
      try {
        let executed = false;
        assert.throws(
          () => writeCandidate(join(destination, 'receipt.json'), {
            root,
            launch: logicalLaunch,
            execute: () => { executed = true; },
          }),
          { code: 'CHECKOUT_INDEX_FLAGS' },
        );
        assert.equal(executed, false);
      } finally {
        rmSync(destination, { recursive: true, force: true });
      }
    });
  }
});

test('candidate execution rechecks hidden index state after every command', () =>
  withFixture((root) => {
    const destination = mkdtempSync(join(tmpdir(), 'issue55-candidate-'));
    try {
      let calls = 0;
      assert.throws(
        () => writeCandidate(join(destination, 'receipt.json'), {
          root,
          launch: logicalLaunch,
          execute: () => {
            calls += 1;
            command(root, ['update-index', '--skip-worktree', 'package.json']);
          },
        }),
        { code: 'CHECKOUT_INDEX_FLAGS' },
      );
      assert.equal(calls, 1);
    } finally {
      rmSync(destination, { recursive: true, force: true });
    }
  }));

test('candidate receipts are deterministic and exact-shape verified', () =>
  withFixture((root) => {
    const destination = mkdtempSync(join(tmpdir(), 'issue55-candidate-'));
    try {
      const first = join(destination, 'first.json');
      const second = join(destination, 'second.json');
      writeCandidate(first, {
        root,
        launch: logicalLaunch,
        execute: () => {},
      });
      writeCandidate(second, {
        root,
        launch: logicalLaunch,
        execute: () => {},
      });
      assert.deepEqual(readFileSync(first), readFileSync(second));
      const secondChecksum = readFileSync(`${second}.sha256`, 'utf8');
      const changedNibble = secondChecksum[0] === '0' ? '1' : '0';
      writeFileSync(
        `${second}.sha256`,
        `${changedNibble}${secondChecksum.slice(1)}`,
      );
      assert.throws(
        () => verifyCandidate(second, { root }),
        { code: 'CHECKSUM_MISMATCH' },
      );
      writeFileSync(`${second}.sha256`, secondChecksum);
      const changed = JSON.parse(readFileSync(first, 'utf8'));
      changed.checks[0].status = 'missing';
      writeFileSync(first, canonicalBytes(changed));
      writeFileSync(
        `${first}.sha256`,
        `${sha256(canonicalBytes(changed))}  first.json\n`,
      );
      assert.throws(
        () => verifyCandidate(first, { root }),
        { code: 'CANDIDATE_SHAPE_INVALID' },
      );
      writeFileSync(join(root, 'tracked.txt'), 'new-source\n');
      command(root, ['add', 'tracked.txt']);
      command(root, ['commit', '--quiet', '-m', 'candidate-source-drift']);
      assert.throws(
        () => verifyCandidate(second, { root }),
        { code: 'CANDIDATE_SOURCE_MISMATCH' },
      );
    } finally {
      rmSync(destination, { recursive: true, force: true });
    }
  }));

test('candidate receipt writes remove partial receipt and checksum files', () => {
  for (const failOnOpen of [1, 2]) {
    const destination = mkdtempSync(join(tmpdir(), 'issue55-write-'));
    try {
      const output = join(destination, 'receipt.json');
      let openCount = 0;
      assert.throws(
        () => writeCanonical(
          output,
          { fixed: true },
          'OUTPUT_WRITE_FAILED',
          {
            open: (...args) => {
              openCount += 1;
              return openSync(...args);
            },
            write: (descriptor, buffer, offset, length) => {
              if (openCount === failOnOpen) {
                writeSync(descriptor, buffer, offset, 1);
                throw new Error('partial write');
              }
              return writeSync(descriptor, buffer, offset, length);
            },
          },
        ),
        { code: 'OUTPUT_WRITE_FAILED' },
      );
      assert.equal(existsSync(output), false);
      assert.equal(existsSync(`${output}.sha256`), false);
    } finally {
      rmSync(destination, { recursive: true, force: true });
    }
  }
});

test('candidate entry points reject malformed files and unsafe outputs', () =>
  withFixture((root) => {
    const destination = mkdtempSync(join(tmpdir(), 'issue55-candidate-'));
    try {
      const invalid = join(destination, 'invalid.json');
      writeFileSync(invalid, '{');
      writeFileSync(
        `${invalid}.sha256`,
        `${sha256('{')}  invalid.json\n`,
      );
      assert.throws(
        () => verifyCandidate(invalid, { root }),
        { code: 'CANDIDATE_JSON_INVALID' },
      );

      const noncanonical = join(destination, 'noncanonical.json');
      const source = createPacket({ root }).source;
      const receipt = {
        checks: [
          {
            commands: [
              ['bun', 'install', '--frozen-lockfile'],
              ['npm', 'run', 'build', '--workspace', '@gjc-remote/native-control'],
              ['npm', 'test'],
            ],
            id: 'candidate-tests',
            reasonCode: 'direct-execution-exit-zero',
            status: 'verified',
          },
          {
            commands: [['npm', 'run', 'smoke:local']],
            id: 'candidate-smoke',
            reasonCode: 'direct-execution-exit-zero',
            status: 'verified',
          },
        ],
        schema: 'gjc-remote.issue55.candidate-execution.v1',
        subject: {
          headCommit: source.headCommit,
          sourcePacketSha256: '0'.repeat(64),
          tree: source.tree,
        },
      };
      const noncanonicalBytes = JSON.stringify(receipt);
      writeFileSync(noncanonical, noncanonicalBytes);
      writeFileSync(
        `${noncanonical}.sha256`,
        `${sha256(noncanonicalBytes)}  noncanonical.json\n`,
      );
      assert.throws(
        () => verifyCandidate(noncanonical, { root }),
        { code: 'CANDIDATE_NONCANONICAL' },
      );

      const directoryReceipt = join(destination, 'directory.json');
      mkdirSync(directoryReceipt);
      assert.throws(
        () => verifyCandidate(directoryReceipt, { root }),
        { code: 'PACKET_FILE_INVALID' },
      );
      assert.throws(
        () => writeCandidate(join(root, 'candidate.json'), {
          root,
          launch: logicalLaunch,
          execute: () => {},
        }),
        { code: 'OUTPUT_INSIDE_CHECKOUT' },
      );
      const existing = join(destination, 'existing.json');
      writeFileSync(existing, 'occupied');
      assert.throws(
        () => writeCandidate(existing, {
          root,
          launch: logicalLaunch,
          execute: () => {},
        }),
        { code: 'OUTPUT_EXISTS' },
      );
    } finally {
      rmSync(destination, { recursive: true, force: true });
    }
  }));

test('issue55 snapshot creates an exclusive packet and sibling checksum', () => withFixture((root) => {
  const destination = mkdtempSync(join(tmpdir(), 'issue55-packet-'));
  try {
    const output = join(destination, 'packet.json');
    const digest = writeSnapshot(output, { root });
    assert.match(readFileSync(`${output}.sha256`, 'utf8'), new RegExp(`^${digest}  packet\\.json\\n$`));
    assert.throws(() => writeSnapshot(output, { root }), { code: 'OUTPUT_EXISTS' });
  } finally { rmSync(destination, { recursive: true, force: true }); }
}));

test('issue55 snapshot refuses generated artifacts inside the checkout', () =>
  withFixture((root) => {
    const dotted = join(root, '..packets');
    mkdirSync(dotted);
    assert.throws(
      () => writeSnapshot(join(dotted, 'packet.json'), { root }),
      { code: 'OUTPUT_INSIDE_CHECKOUT' },
    );
  }));

test('issue55 snapshot rejects an outside indirection back into the checkout', (t) =>
  withFixture((root) => {
    const outside = mkdtempSync(join(tmpdir(), 'issue55-link-'));
    try {
      const inside = join(root, 'packet-output');
      const link = join(outside, 'back-inside');
      mkdirSync(inside);
      try {
        symlinkSync(inside, link, process.platform === 'win32' ? 'junction' : 'dir');
      } catch {
        t.skip('directory link creation is unavailable');
        return;
      }
      assert.throws(
        () => writeSnapshot(join(link, 'packet.json'), { root }),
        { code: 'OUTPUT_INSIDE_CHECKOUT' },
      );
    } finally {
      rmSync(outside, { recursive: true, force: true });
    }
  }));

test('issue55 rejects dirty source checkouts', () => withFixture((root) => {
  writeFileSync(join(root, 'untracked.txt'), 'x');
  assert.throws(() => createPacket({ root }), { code: 'CHECKOUT_DIRTY' });
}));

test('issue55 derives blobs from HEAD despite hidden working-tree transforms', () =>
  withFixture((root) => {
    const expected = createPacket({ root });
    const lockPath = join(root, 'bun.lock');
    writeFileSync(
      lockPath,
      readFileSync(lockPath, 'utf8').replaceAll('\n', '\r\n'),
    );
    command(root, ['update-index', '--assume-unchanged', 'bun.lock']);
    assert.deepEqual(createPacket({ root }), expected);
  }));

test('issue55 rejects source lock drift before accepting its SDK contents', () => withFixture((root) => {
  writeFileSync(join(root, 'bun.lock'), '{"packages":{}}\n');
  assert.throws(() => createPacket({ root }), { code: 'CHECKOUT_DIRTY' });
  command(root, ['add', 'bun.lock']); command(root, ['commit', '--quiet', '-m', 'bad-lock']);
  assert.throws(() => createPacket({ root }), { code: 'DOCKER_CONTRACT_MISMATCH' });
}));

test('issue55 detects SDK declaration and Docker lock/sdk/base mismatches from clean fixtures', () => withFixture((root) => {
  const docker = join(root, 'deploy/docker/daemon/Dockerfile');
  writeFileSync(docker, readFileSync(docker, 'utf8').replace(/ARG LOCK_SHA256=[a-f0-9]{64}/, `ARG LOCK_SHA256=${'0'.repeat(64)}`));
  command(root, ['add', '.']); command(root, ['commit', '--quiet', '-m', 'bad-docker']);
  assert.throws(() => createPacket({ root }), { code: 'DOCKER_CONTRACT_MISMATCH' });
}));

test('issue55 detects SDK declaration drift from the Docker contract', () => withFixture((root) => {
  const daemon = join(root, 'daemon/package.json');
  writeFileSync(daemon, readFileSync(daemon, 'utf8').replace('0.12.21', '0.12.22'));
  command(root, ['add', '.']); command(root, ['commit', '--quiet', '-m', 'bad-sdk']);
  assert.throws(() => createPacket({ root }), { code: 'DOCKER_CONTRACT_MISMATCH' });
}));

test('issue55 validates SDK lock identity after the Docker digest agrees', () =>
  withFixture((root) => {
    const lock = '{"lockfileVersion":1,"packages":{}}\n';
    writeFileSync(join(root, 'bun.lock'), lock);
    const docker = join(root, 'deploy/docker/daemon/Dockerfile');
    writeFileSync(
      docker,
      readFileSync(docker, 'utf8').replace(
        /ARG LOCK_SHA256=[a-f0-9]{64}/,
        `ARG LOCK_SHA256=${sha256(lock)}`,
      ),
    );
    command(root, ['add', '.']);
    command(root, ['commit', '--quiet', '-m', 'bad-sdk-lock']);
    assert.throws(
      () => createPacket({ root }),
      { code: 'SDK_LOCK_INVALID' },
    );
  }));

test('issue55 rejects malformed SDK tuple structure and integrity length', () => {
  for (const mutate of [
    (line) => line.replace('"]', '", "extra"]'),
    (line) => line.replace(SDK_INTEGRITY, 'sha512-Yg=='),
  ]) {
    withFixture((root) => {
      const lockPath = join(root, 'bun.lock');
      const lock = mutate(readFileSync(lockPath, 'utf8'));
      writeFileSync(lockPath, lock);
      const docker = join(root, 'deploy/docker/daemon/Dockerfile');
      writeFileSync(
        docker,
        readFileSync(docker, 'utf8').replace(
          /ARG LOCK_SHA256=[a-f0-9]{64}/,
          `ARG LOCK_SHA256=${sha256(lock)}`,
        ),
      );
      command(root, ['add', '.']);
      command(root, ['commit', '--quiet', '-m', 'bad-sdk-tuple']);
      assert.throws(
        () => createPacket({ root }),
        { code: 'SDK_LOCK_INVALID' },
      );
    });
  }
});

test('issue55 rejects a duplicate multiline SDK property', () =>
  withFixture((root) => {
    const lockPath = join(root, 'bun.lock');
    const lock = readFileSync(lockPath, 'utf8').replace(
      '\n  }\n}\n',
      '\n    "@gajae-code/coding-agent":\n[]\n  }\n}\n',
    );
    writeFileSync(lockPath, lock);
    const docker = join(root, 'deploy/docker/daemon/Dockerfile');
    writeFileSync(
      docker,
      readFileSync(docker, 'utf8').replace(
        /ARG LOCK_SHA256=[a-f0-9]{64}/,
        `ARG LOCK_SHA256=${sha256(lock)}`,
      ),
    );
    command(root, ['add', '.']);
    command(root, ['commit', '--quiet', '-m', 'duplicate-sdk']);
    assert.throws(
      () => createPacket({ root }),
      { code: 'SDK_LOCK_NOT_UNIQUE' },
    );
  }));

test('issue55 scans the complete packages object across nested two-space closes', () =>
  withFixture((root) => {
    const lockPath = join(root, 'bun.lock');
    const lock = readFileSync(lockPath, 'utf8').replace(
      /^    "@gajae-code\/coding-agent":.*$/m,
      (line) => `${line}
    "nested": {
  },
    "@gajae-code/coding-agent":
    []`,
    );
    writeFileSync(lockPath, lock);
    const docker = join(root, 'deploy/docker/daemon/Dockerfile');
    writeFileSync(
      docker,
      readFileSync(docker, 'utf8').replace(
        /ARG LOCK_SHA256=[a-f0-9]{64}/,
        `ARG LOCK_SHA256=${sha256(lock)}`,
      ),
    );
    command(root, ['add', '.']);
    command(root, ['commit', '--quiet', '-m', 'nested-duplicate-sdk']);
    assert.throws(
      () => createPacket({ root }),
      { code: 'SDK_LOCK_NOT_UNIQUE' },
    );
  }));

test('issue55 counts escaped JSONC keys by their decoded package name', () =>
  withFixture((root) => {
    const lockPath = join(root, 'bun.lock');
    const lock = readFileSync(lockPath, 'utf8').replace(
      /^    "@gajae-code\/coding-agent":.*$/m,
      (line) => `${line}
    "\\u0040gajae-code/coding-agent": []`,
    );
    writeFileSync(lockPath, lock);
    const docker = join(root, 'deploy/docker/daemon/Dockerfile');
    writeFileSync(
      docker,
      readFileSync(docker, 'utf8').replace(
        /ARG LOCK_SHA256=[a-f0-9]{64}/,
        `ARG LOCK_SHA256=${sha256(lock)}`,
      ),
    );
    command(root, ['add', '.']);
    command(root, ['commit', '--quiet', '-m', 'escaped-duplicate-sdk']);
    assert.throws(
      () => createPacket({ root }),
      { code: 'SDK_LOCK_NOT_UNIQUE' },
    );
  }));

test('issue55 detects Docker base label tampering', () => withFixture((root) => {
  const docker = join(root, 'deploy/docker/daemon/Dockerfile');
  writeFileSync(docker, readFileSync(docker, 'utf8').replace(`sha256:${BUN_DIGEST}"`, `sha256:${'0'.repeat(64)}"`));
  command(root, ['add', '.']); command(root, ['commit', '--quiet', '-m', 'bad-base']);
  assert.throws(() => createPacket({ root }), { code: 'DOCKER_CONTRACT_INVALID' });
}));

test('issue55 rejects case-insensitive and indented Docker ARG shadows', () => {
  for (const shadow of [
    'arg BUN_IMAGE=other.invalid/bun:latest',
    '  ARG BUN_IMAGE=other.invalid/bun:latest',
  ]) {
    withFixture((root) => {
      const docker = join(root, 'deploy/docker/daemon/Dockerfile');
      writeFileSync(
        docker,
        `${shadow}\n${readFileSync(docker, 'utf8')}`,
      );
      command(root, ['add', '.']);
      command(root, ['commit', '--quiet', '-m', 'shadowed-arg']);
      assert.throws(
        () => createPacket({ root }),
        { code: 'DOCKER_CONTRACT_INVALID' },
      );
    });
  }
});

test('issue55 rejects duplicate Docker contract labels', () =>
  withFixture((root) => {
    const docker = join(root, 'deploy/docker/daemon/Dockerfile');
    writeFileSync(
      docker,
      `${readFileSync(docker, 'utf8')}LABEL io.gjc-remote.sdk.version="0.12.21"\n`,
    );
    command(root, ['add', '.']);
    command(root, ['commit', '--quiet', '-m', 'duplicate-label']);
    assert.throws(
      () => createPacket({ root }),
      { code: 'DOCKER_CONTRACT_INVALID' },
    );
  }));

test('issue55 verify rejects malformed, noncanonical, unknown, and duplicate checks', () => withFixture((root) => {
  const packet = createPacket({ root });
  assert.throws(() => verifyPacketBytes(Buffer.from('{')), { code: 'PACKET_JSON_INVALID' });
  assert.throws(() => verifyPacketBytes(Buffer.from(`${JSON.stringify(packet, null, 2)}\n`), { root }), { code: 'PACKET_NONCANONICAL' });
  assert.throws(() => verifyPacketBytes(changes(packet, (copy) => { copy.checks[1].id = 'unknown'; }), { root }), { code: 'CHECK_REGISTRY_INVALID' });
  assert.throws(() => verifyPacketBytes(changes(packet, (copy) => { copy.checks[2].id = copy.checks[1].id; }), { root }), { code: 'CHECK_REGISTRY_INVALID' });
}));

test('issue55 verify checks checksum, source drift, missing proofs, and promotion', () => withFixture((root) => {
  const destination = mkdtempSync(join(tmpdir(), 'issue55-packet-'));
  try {
    const output = join(destination, 'packet.json');
    writeSnapshot(output, { root });
    assert.throws(() => verifyPacket(output, { root, requirePromotion: true }), { code: 'PROMOTION_BLOCKED' });
    writeFileSync(`${output}.sha256`, '0'.repeat(64) + '  packet.json\n');
    assert.throws(() => verifyPacket(output, { root }), { code: 'CHECKSUM_MISMATCH' });
    writeSnapshot(join(destination, 'drift.json'), { root });
    writeFileSync(join(root, 'tracked.txt'), 'changed\n');
    command(root, ['add', 'tracked.txt']); command(root, ['commit', '--quiet', '-m', 'drift']);
    assert.throws(() => verifyPacket(join(destination, 'drift.json'), { root }), { code: 'SOURCE_MISMATCH' });
  } finally { rmSync(destination, { recursive: true, force: true }); }
}));

test('issue55 verify rejects non-files and oversized packets before parsing', () =>
  withFixture((root) => {
    const destination = mkdtempSync(join(tmpdir(), 'issue55-packet-'));
    try {
      const directoryPacket = join(destination, 'directory.json');
      mkdirSync(directoryPacket);
      assert.throws(
        () => verifyPacket(directoryPacket, { root }),
        { code: 'PACKET_FILE_INVALID' },
      );
      const packet = join(destination, 'oversized.json');
      writeFileSync(packet, 'x'.repeat(64 * 1024 + 1));
      writeFileSync(`${packet}.sha256`, '0'.repeat(64) + '  oversized.json\n');
      assert.throws(
        () => verifyPacket(packet, { root }),
        { code: 'PACKET_FILE_INVALID' },
      );
    } finally {
      rmSync(destination, { recursive: true, force: true });
    }
  }));

test('bounded packet reads reject growth on the opened descriptor', () => {
  let reads = 0;
  let closed = false;
  assert.throws(
    () => readBoundedRegularUtf8('opaque', 4, {
      lstat: () => ({
        isFile: () => true,
        isSymbolicLink: () => false,
      }),
      open: () => 7,
      fstat: () => ({ isFile: () => true, size: 4 }),
      read: (_descriptor, buffer, offset, length) => {
        if (reads++ > 0) return 0;
        buffer.fill(0x61, offset, offset + length);
        return length;
      },
      close: () => { closed = true; },
    }),
    { code: 'PACKET_FILE_INVALID' },
  );
  assert.equal(closed, true);
});
