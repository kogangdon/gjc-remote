#!/usr/bin/env node
import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import {
  closeSync,
  constants,
  existsSync,
  fstatSync,
  lstatSync,
  openSync,
  readFileSync,
  readSync,
  realpathSync,
  unlinkSync,
  writeFileSync,
} from 'node:fs';
import {
  basename,
  dirname,
  isAbsolute,
  join,
  relative,
  resolve,
  sep,
} from 'node:path';

export const SCHEMA = 'gjc-remote.issue55.source-negative.v1';
export const REPOSITORY_URL = 'https://github.com/kogangdon/gjc-remote';
const SOURCE_REASON = 'source-checkout-derived';
const MISSING_REASON = 'not-collected-by-source-snapshot';

// This closed list is deliberately not configurable: a source checkout cannot
// prove runtime, platform, supply-chain, or operational release assertions.
export const CHECK_REGISTRY = Object.freeze([
  ['source-identity', 'verified', SOURCE_REASON],
  ['candidate-tests', 'missing', MISSING_REASON],
  ['candidate-smoke', 'missing', MISSING_REASON],
  ['signed-native-linux-x64', 'missing', MISSING_REASON],
  ['signed-native-linux-arm64', 'missing', MISSING_REASON],
  ['final-image-index-platforms', 'missing', MISSING_REASON],
  ['sbom-linux-x64', 'missing', MISSING_REASON],
  ['sbom-linux-arm64', 'missing', MISSING_REASON],
  ['scan-linux-x64', 'missing', MISSING_REASON],
  ['scan-linux-arm64', 'missing', MISSING_REASON],
  ['attestations', 'missing', MISSING_REASON],
  ['four-role-volume-manifests-cleanup', 'missing', MISSING_REASON],
  ['serving-on-e2e', 'missing', MISSING_REASON],
  ['observability', 'missing', MISSING_REASON],
  ['rollback', 'missing', MISSING_REASON],
  ['provider-recovery', 'missing', MISSING_REASON],
  ['linux-x64-distinct-principals', 'missing', MISSING_REASON],
  ['linux-arm64-distinct-principals', 'missing', MISSING_REASON],
  ['windows-ntfs-distinct-principals', 'missing', MISSING_REASON],
  ['supervisor-evidence', 'missing', MISSING_REASON],
  ['sentinel-scans', 'missing', MISSING_REASON],
  ['zero-manual-cleanup', 'missing', MISSING_REASON],
].map(([id, status, reasonCode]) => Object.freeze({ id, status, reasonCode })));

const BLOCKING_IDS = Object.freeze(CHECK_REGISTRY.filter((check) => check.status === 'missing').map((check) => check.id));
const GIT_OBJECT_ID = /^[a-f0-9]{40}$/;
const SHA512 = /^sha512-[A-Za-z0-9+/]+={0,2}$/;
const VERSION = /^(0|[1-9][0-9]*)(\.(0|[1-9][0-9]*)){2}([-.][A-Za-z0-9.-]+)?$/;
const PACKET_MAX_BYTES = 64 * 1024;
const CHECKSUM_MAX_BYTES = 256;

export function sha256(value) {
  return createHash('sha256').update(value).digest('hex');
}

export function canonicalJson(value) {
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(',')}}`;
}

export function canonicalBytes(value) {
  return Buffer.from(`${canonicalJson(value)}\n`, 'utf8');
}

function fail(code) {
  const error = new Error(code);
  error.code = code;
  throw error;
}

function runGit(args, root, exec = execFileSync) {
  try {
    return String(exec('git', args, { cwd: root, encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] })).trim();
  } catch {
    fail('GIT_UNAVAILABLE');
  }
}

function runGitBytes(args, root, exec = execFileSync) {
  try {
    const result = exec('git', args, {
      cwd: root,
      encoding: null,
      stdio: ['ignore', 'pipe', 'ignore'],
    });
    return Buffer.isBuffer(result) ? result : Buffer.from(result);
  } catch {
    fail('GIT_UNAVAILABLE');
  }
}

function readUtf8(path, readFile = readFileSync) {
  try {
    return readFile(path, 'utf8');
  } catch {
    fail('SOURCE_READ_FAILED');
  }
}

export function readBoundedRegularUtf8(
  path,
  maxBytes,
  {
    lstat = lstatSync,
    open = openSync,
    fstat = fstatSync,
    read = readSync,
    close = closeSync,
  } = {},
) {
  let descriptor;
  try {
    const pathStat = lstat(path);
    if (!pathStat.isFile() || pathStat.isSymbolicLink()) {
      fail('PACKET_FILE_INVALID');
    }
    descriptor = open(
      path,
      constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0),
    );
    const stat = fstat(descriptor);
    if (!stat.isFile() || stat.size > maxBytes) fail('PACKET_FILE_INVALID');
    const buffer = Buffer.alloc(maxBytes + 1);
    let length = 0;
    while (length < buffer.length) {
      const bytesRead = read(
        descriptor,
        buffer,
        length,
        buffer.length - length,
        null,
      );
      if (bytesRead === 0) break;
      length += bytesRead;
    }
    if (length > maxBytes) fail('PACKET_FILE_INVALID');
    return buffer.subarray(0, length).toString('utf8');
  } catch (error) {
    if (error?.code === 'PACKET_FILE_INVALID') throw error;
    fail('PACKET_READ_FAILED');
  } finally {
    if (descriptor !== undefined) {
      try { close(descriptor); } catch {}
    }
  }
}

function canonicalPath(path, code) {
  try {
    return resolve(realpathSync.native?.(path) ?? realpathSync(path));
  } catch {
    fail(code);
  }
}

function parseJson(text, code) {
  try {
    return JSON.parse(text);
  } catch {
    fail(code);
  }
}

function requireVersion(value, code) {
  if (typeof value !== 'string' || !VERSION.test(value)) fail(code);
  return value;
}

function parseDockerfile(text) {
  const unique = (pattern) => {
    const matches = [...text.matchAll(pattern)];
    return matches.length === 1 ? matches[0] : null;
  };
  if (
    (text.match(/^\s*ARG\s+BUN_IMAGE\s*=/gim) ?? []).length !== 1 ||
    (text.match(/^\s*ARG\s+LOCK_SHA256\s*=/gim) ?? []).length !== 1 ||
    (text.match(/org\.opencontainers\.image\.base\.name=/g) ?? []).length !== 1 ||
    (text.match(/io\.gjc-remote\.lock\.sha256=/g) ?? []).length !== 1 ||
    (text.match(/io\.gjc-remote\.sdk\.version=/g) ?? []).length !== 1
  ) {
    fail('DOCKER_CONTRACT_INVALID');
  }
  const image = unique(/^ARG BUN_IMAGE=([^@\s]+)@sha256:([a-f0-9]{64})$/gm);
  const lock = unique(/^ARG LOCK_SHA256=([a-f0-9]{64})$/gm);
  const labels = unique(/^\s*org\.opencontainers\.image\.base\.name="([^@\s]+)@sha256:([a-f0-9]{64})"\s*\\$/gm);
  const sdk = unique(/^\s*io\.gjc-remote\.sdk\.version="([^"]+)"\s*$/gm);
  const lockLabel = unique(/io\.gjc-remote\.lock\.sha256="\$\{LOCK_SHA256\}"/g);
  const sdkAssertion = unique(/p\.version!=="([^"]+)"/g);
  if (
    !image ||
    !lock ||
    !labels ||
    !sdk ||
    !lockLabel ||
    !sdkAssertion ||
    image[1] !== labels[1] ||
    image[2] !== labels[2] ||
    sdk[1] !== sdkAssertion[1]
  ) {
    fail('DOCKER_CONTRACT_INVALID');
  }
  if (
    (text.match(/^FROM \$\{BUN_IMAGE\} AS /gm) ?? []).length !== 3 ||
    (text.match(/sha256sum --check --strict/g) ?? []).length !== 1
  ) {
    fail('DOCKER_CONTRACT_INVALID');
  }
  return { bunImage: { name: image[1], digest: image[2] }, lockSha256: lock[1], sdkVersion: requireVersion(sdk[1], 'DOCKER_CONTRACT_INVALID') };
}

function jsoncTokens(text) {
  const tokens = [];
  for (let index = 0; index < text.length;) {
    const character = text[index];
    if (/\s/.test(character)) {
      index += 1;
      continue;
    }
    if (character === '/' && text[index + 1] === '/') {
      index = text.indexOf('\n', index + 2);
      if (index < 0) break;
      continue;
    }
    if (character === '/' && text[index + 1] === '*') {
      const end = text.indexOf('*/', index + 2);
      if (end < 0) fail('SDK_LOCK_INVALID');
      index = end + 2;
      continue;
    }
    if (character === '"') {
      const start = index;
      index += 1;
      let escaped = false;
      while (index < text.length) {
        const current = text[index++];
        if (escaped) {
          escaped = false;
        } else if (current === '\\') {
          escaped = true;
        } else if (current === '"') {
          break;
        }
      }
      if (text[index - 1] !== '"') fail('SDK_LOCK_INVALID');
      let value;
      try {
        value = JSON.parse(text.slice(start, index));
      } catch {
        fail('SDK_LOCK_INVALID');
      }
      tokens.push({ type: 'string', value, start, end: index });
      continue;
    }
    if ('{}[]:,'.includes(character)) {
      tokens.push({ type: character, start: index, end: index + 1 });
      index += 1;
      continue;
    }
    const start = index;
    while (
      index < text.length &&
      !/\s/.test(text[index]) &&
      !'{}[]:,"'.includes(text[index])
    ) {
      index += 1;
    }
    if (index === start) fail('SDK_LOCK_INVALID');
    tokens.push({ type: 'atom', start, end: index });
  }
  return tokens;
}

function jsoncObjectPropertyBody(text, property) {
  const tokens = jsoncTokens(text);
  let depth = 0;
  const starts = [];
  for (let index = 0; index < tokens.length; index += 1) {
    const token = tokens[index];
    if (token.type === '{') {
      depth += 1;
      continue;
    }
    if (token.type === '}') {
      depth -= 1;
      if (depth < 0) fail('SDK_LOCK_INVALID');
      continue;
    }
    if (
      depth === 1 &&
      token.type === 'string' &&
      token.value === property &&
      tokens[index + 1]?.type === ':' &&
      tokens[index + 2]?.type === '{'
    ) {
      starts.push(index + 2);
    }
  }
  if (depth !== 0 || starts.length !== 1) fail('SDK_LOCK_INVALID');
  const openIndex = starts[0];
  let objectDepth = 0;
  for (let index = openIndex; index < tokens.length; index += 1) {
    if (tokens[index].type === '{') objectDepth += 1;
    if (tokens[index].type === '}') {
      objectDepth -= 1;
      if (objectDepth === 0) {
        return text.slice(tokens[openIndex].end, tokens[index].start);
      }
    }
  }
  fail('SDK_LOCK_INVALID');
}

function jsoncDirectArrayProperty(text, property) {
  const tokens = jsoncTokens(text);
  let objectDepth = 0;
  let arrayDepth = 0;
  const starts = [];
  for (let index = 0; index < tokens.length; index += 1) {
    const token = tokens[index];
    if (
      objectDepth === 0 &&
      arrayDepth === 0 &&
      token.type === 'string' &&
      token.value === property &&
      tokens[index + 1]?.type === ':'
    ) {
      starts.push(index + 2);
    }
    if (token.type === '{') objectDepth += 1;
    if (token.type === '}') objectDepth -= 1;
    if (token.type === '[') arrayDepth += 1;
    if (token.type === ']') arrayDepth -= 1;
    if (objectDepth < 0 || arrayDepth < 0) fail('SDK_LOCK_INVALID');
  }
  if (objectDepth !== 0 || arrayDepth !== 0 || starts.length !== 1) {
    fail(starts.length === 0 ? 'SDK_LOCK_INVALID' : 'SDK_LOCK_NOT_UNIQUE');
  }
  const openIndex = starts[0];
  if (tokens[openIndex]?.type !== '[') fail('SDK_LOCK_INVALID');
  let depth = 0;
  for (let index = openIndex; index < tokens.length; index += 1) {
    if (tokens[index].type === '[') depth += 1;
    if (tokens[index].type === ']') {
      depth -= 1;
      if (depth === 0) {
        return parseJson(
          text.slice(tokens[openIndex].start, tokens[index].end),
          'SDK_LOCK_INVALID',
        );
      }
    }
  }
  fail('SDK_LOCK_INVALID');
}

function sdkFromLock(lockText, declaredVersion) {
  const packagesText = jsoncObjectPropertyBody(lockText, 'packages');
  const entry = jsoncDirectArrayProperty(
    packagesText,
    '@gajae-code/coding-agent',
  );
  if (!Array.isArray(entry) || entry.length !== 4) fail('SDK_LOCK_INVALID');
  const resolved = entry[0];
  const integrity = entry[3];
  const resolvedVersion = typeof resolved === 'string'
    ? resolved.slice('@gajae-code/coding-agent@'.length)
    : undefined;
  let integrityBytes;
  try {
    integrityBytes = Buffer.from(integrity?.slice('sha512-'.length), 'base64');
  } catch {
    fail('SDK_LOCK_INVALID');
  }
  if (
    resolved !== `@gajae-code/coding-agent@${resolvedVersion}` ||
    resolvedVersion !== declaredVersion ||
    typeof integrity !== 'string' ||
    !SHA512.test(integrity) ||
    integrityBytes.length !== 64 ||
    integrityBytes.toString('base64') !== integrity.slice('sha512-'.length)
  ) {
    fail('SDK_LOCK_INVALID');
  }
  return { declaredVersion, integrity, resolvedVersion };
}

export function collectSource({ root = process.cwd(), exec = execFileSync } = {}) {
  const checkout = resolve(root);
  const canonicalCheckout = canonicalPath(checkout, 'CHECKOUT_ROOT_INVALID');
  const status = runGit(['status', '--porcelain=v1', '--untracked-files=all'], checkout, exec);
  if (status) fail('CHECKOUT_DIRTY');
  const headCommit = runGit(['rev-parse', 'HEAD'], checkout, exec);
  const topLevel = canonicalPath(
    runGit(['rev-parse', '--show-toplevel'], checkout, exec),
    'CHECKOUT_ROOT_INVALID',
  );
  if (topLevel !== canonicalCheckout) fail('CHECKOUT_ROOT_INVALID');
  const tree = runGit(['rev-parse', `${headCommit}^{tree}`], checkout, exec);
  if (!GIT_OBJECT_ID.test(headCommit) || !GIT_OBJECT_ID.test(tree)) {
    fail('GIT_ID_INVALID');
  }

  const blob = (path) =>
    runGitBytes(['show', `${headCommit}:${path}`], checkout, exec).toString('utf8');
  const rootPackage = parseJson(blob('package.json'), 'PACKAGE_INVALID');
  const daemonPackage = parseJson(blob('daemon/package.json'), 'PACKAGE_INVALID');
  const nativePackage = parseJson(blob('native-control/package.json'), 'PACKAGE_INVALID');
  const lockText = blob('bun.lock');
  const docker = parseDockerfile(blob('deploy/docker/daemon/Dockerfile'));
  const rootVersion = requireVersion(rootPackage?.version, 'PACKAGE_INVALID');
  const daemonVersion = requireVersion(daemonPackage?.version, 'PACKAGE_INVALID');
  const nativeVersion = requireVersion(nativePackage?.version, 'PACKAGE_INVALID');
  const declaredVersion = requireVersion(daemonPackage?.dependencies?.['@gajae-code/coding-agent'], 'SDK_DECLARATION_INVALID');
  const contract = nativePackage?.nativeControlContract;
  if (!contract || !Number.isInteger(contract.version) || !Number.isInteger(contract.revision) || !Number.isInteger(contract.napi) || !Array.isArray(contract.platforms) || contract.platforms.some((platform) => typeof platform !== 'string')) fail('NATIVE_CONTRACT_INVALID');
  const lockSha256 = sha256(lockText);
  if (docker.lockSha256 !== lockSha256 || docker.sdkVersion !== declaredVersion) fail('DOCKER_CONTRACT_MISMATCH');
  if (runGit(['status', '--porcelain=v1', '--untracked-files=all'], checkout, exec)) {
    fail('CHECKOUT_DIRTY');
  }

  return {
    docker,
    headCommit,
    lockSha256,
    nativeControlContract: { napi: contract.napi, platforms: [...contract.platforms], revision: contract.revision, version: contract.version },
    packageVersions: { daemon: daemonVersion, native: nativeVersion, root: rootVersion },
    repositoryUrl: REPOSITORY_URL,
    sdk: sdkFromLock(lockText, declaredVersion),
    tree,
  };
}

export function createPacket(options = {}) {
  const source = collectSource(options);
  return {
    checks: CHECK_REGISTRY.map((check) => ({ ...check })),
    promotion: { blockingCheckIds: [...BLOCKING_IDS], releaseEligible: false },
    schema: SCHEMA,
    source,
  };
}

function equalJson(left, right) {
  return canonicalJson(left) === canonicalJson(right);
}

export function validatePacketShape(packet) {
  if (!packet || typeof packet !== 'object' || Array.isArray(packet)) fail('PACKET_SHAPE_INVALID');
  const expected = ['checks', 'promotion', 'schema', 'source'];
  if (!equalJson(Object.keys(packet).sort(), expected)) fail('PACKET_KEYS_INVALID');
  if (packet.schema !== SCHEMA || !Array.isArray(packet.checks) || packet.checks.length !== CHECK_REGISTRY.length) fail('PACKET_SHAPE_INVALID');
  for (let index = 0; index < CHECK_REGISTRY.length; index += 1) {
    const actual = packet.checks[index];
    const required = CHECK_REGISTRY[index];
    if (!actual || typeof actual !== 'object' || Array.isArray(actual) || !equalJson(Object.keys(actual).sort(), ['id', 'reasonCode', 'status']) || actual.id !== required.id || actual.status !== required.status || actual.reasonCode !== required.reasonCode) fail('CHECK_REGISTRY_INVALID');
  }
  const promotion = packet.promotion;
  if (!promotion || typeof promotion !== 'object' || Array.isArray(promotion) || !equalJson(Object.keys(promotion).sort(), ['blockingCheckIds', 'releaseEligible']) || promotion.releaseEligible !== false || !equalJson(promotion.blockingCheckIds, BLOCKING_IDS)) fail('PROMOTION_INVALID');
}

export function verifyPacketBytes(bytes, options = {}) {
  if (!Buffer.isBuffer(bytes)) bytes = Buffer.from(bytes);
  let packet;
  try { packet = JSON.parse(bytes.toString('utf8')); } catch { fail('PACKET_JSON_INVALID'); }
  if (!canonicalBytes(packet).equals(bytes)) fail('PACKET_NONCANONICAL');
  validatePacketShape(packet);
  const expected = createPacket(options);
  if (!equalJson(packet.source, expected.source)) fail('SOURCE_MISMATCH');
  return packet;
}

function validateAbsoluteJsonPath(value, code) {
  if (typeof value !== 'string' || !isAbsolute(value) || !value.endsWith('.json')) fail(code);
  return value;
}

export function writeSnapshot(output, options = {}) {
  const target = validateAbsoluteJsonPath(output, 'OUTPUT_INVALID');
  const checkout = resolve(options.root ?? process.cwd());
  const canonicalCheckout = canonicalPath(checkout, 'CHECKOUT_ROOT_INVALID');
  const relativeTarget = relative(checkout, target);
  if (
    relativeTarget === '' ||
    (!isAbsolute(relativeTarget) &&
      relativeTarget !== '..' &&
      !relativeTarget.startsWith(`..${sep}`))
  ) {
    fail('OUTPUT_INSIDE_CHECKOUT');
  }
  const canonicalParent = canonicalPath(dirname(target), 'OUTPUT_PARENT_INVALID');
  try {
    if (!lstatSync(canonicalParent).isDirectory()) fail('OUTPUT_PARENT_INVALID');
  } catch (error) {
    if (error?.code === 'OUTPUT_PARENT_INVALID') throw error;
    fail('OUTPUT_PARENT_INVALID');
  }
  const canonicalRelative = relative(canonicalCheckout, canonicalParent);
  if (
    canonicalRelative === '' ||
    (!isAbsolute(canonicalRelative) &&
      canonicalRelative !== '..' &&
      !canonicalRelative.startsWith(`..${sep}`))
  ) {
    fail('OUTPUT_INSIDE_CHECKOUT');
  }
  if (existsSync(target) || existsSync(`${target}.sha256`)) fail('OUTPUT_EXISTS');
  const bytes = canonicalBytes(createPacket(options));
  let packetWritten = false;
  try {
    writeFileSync(target, bytes, { encoding: 'utf8', flag: 'wx', mode: 0o600 });
    packetWritten = true;
    try {
      writeFileSync(
        `${target}.sha256`,
        `${sha256(bytes)}  ${basename(target)}\n`,
        { encoding: 'utf8', flag: 'wx', mode: 0o600 },
      );
    } catch {
      try { unlinkSync(target); } catch {}
      fail('CHECKSUM_WRITE_FAILED');
    }
  } catch (error) {
    if (error?.code === 'CHECKSUM_WRITE_FAILED') throw error;
    if (packetWritten) {
      try { unlinkSync(target); } catch {}
    }
    fail('OUTPUT_WRITE_FAILED');
  }
  return sha256(bytes);
}

export function verifyPacket(packetPath, { requirePromotion = false, ...options } = {}) {
  const target = validateAbsoluteJsonPath(packetPath, 'PACKET_PATH_INVALID');
  const bytes = Buffer.from(readBoundedRegularUtf8(target, PACKET_MAX_BYTES));
  const checksum = readBoundedRegularUtf8(
    `${target}.sha256`,
    CHECKSUM_MAX_BYTES,
  );
  if (checksum !== `${sha256(bytes)}  ${basename(target)}\n`) fail('CHECKSUM_MISMATCH');
  const packet = verifyPacketBytes(bytes, options);
  if (requirePromotion && packet.promotion.blockingCheckIds.length) fail('PROMOTION_BLOCKED');
  return sha256(bytes);
}

function usage() { fail('USAGE'); }

export function main(argv = process.argv.slice(2)) {
  const [command, flag, value, extra] = argv;
  if (command === 'snapshot' && flag === '--output' && value && !extra) return writeSnapshot(value);
  if (command === 'verify' && flag === '--packet' && value && (!extra || extra === '--require-promotion')) return verifyPacket(value, { requirePromotion: extra === '--require-promotion' });
  usage();
}

if (import.meta.main) {
  try {
    const digest = main();
    process.stdout.write(`ISSUE55_${process.argv[2].toUpperCase()}_OK ${digest}\n`);
  } catch (error) {
    process.stderr.write(`ISSUE55_${error?.code ?? 'FAILED'}\n`);
    process.exitCode = 1;
  }
}
