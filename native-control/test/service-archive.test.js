import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import test from 'node:test';
import { gunzipSync, gzipSync } from 'node:zlib';
import { create as createTar, Header } from 'tar';
import {
  DEPLOYMENT_ENVELOPE_LIMITS,
  applicationDeploymentManifestFingerprint,
  buildApplicationDeploymentManifest,
  buildBundleInventory,
  buildDeploymentCompatibility,
  bundleInventoryFingerprint,
  bundleTreeFingerprint,
} from '@gjc-remote/shared/deployment-envelope';
import { canonicalJsonBytes } from '@gjc-remote/shared/strict-json';
import { consumeApplicationArchive, inspectApplicationArchive } from '../src/service-archive.js';

const INVENTORY_PATH = 'bundle-files.json';
const BLOCK = 512;
const END = Buffer.alloc(BLOCK * 2);

const digest = (bytes) => createHash('sha256').update(bytes).digest('hex');
const pad = (size) => Buffer.alloc((BLOCK - (size % BLOCK)) % BLOCK);

function chunks(bytes, pattern = [1, 2, 7, 31, 509, 1024]) {
  return {
    async *[Symbol.asyncIterator]() {
      let offset = 0;
      let index = 0;
      while (offset < bytes.length) {
        const length = Math.min(pattern[index % pattern.length], bytes.length - offset);
        yield bytes.subarray(offset, offset + length);
        offset += length;
        index += 1;
      }
    },
  };
}

function deferred() {
  let resolve;
  let reject;
  const promise = new Promise((onResolve, onReject) => {
    resolve = onResolve;
    reject = onReject;
  });
  return { promise, resolve, reject };
}

async function settlesWithin(promise, milliseconds = 2000) {
  let timer;
  try {
    return await Promise.race([
      promise,
      new Promise((_, reject) => {
        timer = setTimeout(() => reject(new Error('test operation did not settle')), milliseconds);
      }),
    ]);
  } finally {
    clearTimeout(timer);
  }
}

function portableGzip(bytes) {
  const archive = Buffer.from(gzipSync(bytes, { level: 6 }));
  archive[9] = 255;
  return archive;
}

function checksumHeader(block) {
  block.fill(0x20, 148, 156);
  let checksum = 0;
  for (const byte of block) checksum += byte;
  const encoded = checksum.toString(8).padStart(6, '0');
  block.write(encoded, 148, 6, 'ascii');
  block[154] = 0x20;
  block[155] = 0;
  return block;
}

function header(path, size, { type = 'File', mode = 0o644 } = {}) {
  const value = new Header({
    path,
    mode,
    uid: 0,
    gid: 0,
    size,
    mtime: new Date(0),
    type,
    linkpath: '',
    uname: '',
    gname: '',
    devmaj: 0,
    devmin: 0,
  });
  value.encode();
  return Buffer.from(value.block);
}

function rawEntry(path, bytes, options = {}) {
  const body = Buffer.from(bytes);
  const block = header(path, options.declaredSize ?? body.length);
  if (options.typeByte !== undefined) {
    block[156] = typeof options.typeByte === 'string' ? options.typeByte.charCodeAt(0) : options.typeByte;
    if (options.linkpath !== undefined) block.write(options.linkpath, 157, 100, 'utf8');
    checksumHeader(block);
  }
  return Buffer.concat([block, body, pad(body.length)]);
}

function paxRecord(key, value) {
  const suffix = ` ${key}=${value}\n`;
  let length = Buffer.byteLength(suffix) + 1;
  while (Buffer.byteLength(`${length}${suffix}`) !== length) length = Buffer.byteLength(`${length}${suffix}`);
  return Buffer.from(`${length}${suffix}`);
}

function paxBody(records) {
  return Buffer.concat(records.map(([key, value]) => paxRecord(key, value)));
}

function paxFile(path, bytes, {
  records = [['path', path], ['size', String(bytes.length)], ['SCHILY.nlink', '1']],
  rawPath = 'portable-path-placeholder',
  metadataType = 'ExtendedHeader',
  metadataBody = undefined,
} = {}) {
  const body = metadataBody ?? paxBody(records);
  return Buffer.concat([
    rawEntry('PaxHeader/portable-path-placeholder', body, { typeByte: metadataType === 'GlobalExtendedHeader' ? 'g' : 'x' }),
    rawEntry(rawPath, bytes),
  ]);
}

function tarBytes(entries, ending = END) {
  return Buffer.concat([...entries, ending]);
}

function defaultFiles() {
  return [
    { path: 'bot/src/bot.js', bytes: Buffer.from('bot-entry\n'), executablePolicy: 'required' },
    { path: 'daemon/src/daemon.js', bytes: Buffer.from('daemon-entry\n'), executablePolicy: 'required' },
    {
      path: 'native-control/build/Release/native-control.manifest.json',
      bytes: Buffer.from('{"contract":"fixture"}'),
      executablePolicy: 'forbidden',
    },
    { path: 'assets/empty.bin', bytes: Buffer.alloc(0), executablePolicy: 'forbidden' },
  ];
}

function inventoryFor(files, platform = 'linux') {
  return buildBundleInventory({
    payloadEntries: files.map((file) => ({
      path: file.path,
      size: file.bytes.length,
      sha256: digest(file.bytes),
      executablePolicy: file.executablePolicy,
    })),
  }, { platform });
}

function compatibility() {
  const hash = '9'.repeat(64);
  return buildDeploymentCompatibility({
    bot: {
      domains: [{ domain: 'bot-mapping-reader', readableFormats: ['mapping-v1'], writableFormats: ['mapping-v1'] }],
    },
    daemon: {
      domains: [
        { domain: 'daemon-app-session', readableFormats: ['session-v1'], writableFormats: ['session-v1'] },
        { domain: 'workspace-lifecycle', readableFormats: ['workspace-v1'], writableFormats: ['workspace-v1'] },
      ],
      sdkExternalStateContractFingerprint: hash,
    },
  });
}

function manifestFor({ archive, inventory, inventoryBytes, platform = 'linux' }) {
  const releaseVersion = '1.2.3';
  return buildApplicationDeploymentManifest({
    signingKeyId: 'archive-test',
    releaseId: `v${releaseVersion}`,
    releaseVersion,
    releaseSequence: 7,
    source: {
      repository: 'kogangdon/gjc-remote',
      tag: `v${releaseVersion}`,
      commit: 'a'.repeat(40),
      tree: 'b'.repeat(40),
      bunLockSha256: 'c'.repeat(64),
    },
    target: { platform, architecture: platform === 'linux' ? 'x64' : 'x64' },
    archive: {
      name: `gjc-remote-service-${releaseVersion}-${platform}-x64.tar.gz`,
      mediaType: 'application/gzip',
      byteLength: archive.length,
      sha256: digest(archive),
      entryCount: inventory.payloadEntryCount + 1,
    },
    inventory: {
      path: INVENTORY_PATH,
      byteLength: inventoryBytes.length,
      sha256: digest(inventoryBytes),
      payloadEntryCount: inventory.payloadEntryCount,
      unpackedPayloadBytes: inventory.unpackedPayloadBytes,
      treeFingerprint: inventory.treeFingerprint,
    },
    entrypoints: { bot: 'bot/src/bot.js', daemon: 'daemon/src/daemon.js' },
    runtimes: { node: { minimumVersion: '26.0.0' }, bun: { minimumVersion: '1.4.0' } },
    nativeControl: {
      manifestPath: 'native-control/build/Release/native-control.manifest.json',
      manifestFingerprint: 'd'.repeat(64),
      contractVersion: 5,
      contractRevision: 1,
    },
    wireCapabilities: ['gate_presentation_v1'],
    compatibility: compatibility(),
  });
}

function manualFixture({
  files = defaultFiles(),
  platform = 'linux',
  inventory = inventoryFor(files, platform),
  inventoryBytes = canonicalJsonBytes(inventory),
  entries = undefined,
  ending = END,
} = {}) {
  const physical = entries ?? [
    rawEntry(INVENTORY_PATH, inventoryBytes),
    ...files.map((file) => rawEntry(file.path, file.bytes)),
  ];
  const tar = tarBytes(physical, ending);
  const archive = portableGzip(tar);
  return { files, inventory, inventoryBytes, tar, archive, manifest: manifestFor({ archive, inventory, inventoryBytes, platform }) };
}

function fixtureWithTar(base, tar) {
  const archive = portableGzip(tar);
  return { ...base, tar, archive, manifest: manifestFor({
    archive,
    inventory: base.inventory,
    inventoryBytes: base.inventoryBytes,
    platform: base.manifest.target.platform,
  }) };
}

function fixtureWithArchive(base, archive) {
  return { ...base, archive, manifest: manifestFor({
    archive,
    inventory: base.inventory,
    inventoryBytes: base.inventoryBytes,
    platform: base.manifest.target.platform,
  }) };
}

async function inspect(fixture, archive = fixture.archive) {
  return inspectApplicationArchive({ chunks: chunks(archive), manifest: fixture.manifest });
}

async function consume(fixture, inspection, onFile, archive = fixture.archive, manifest = fixture.manifest) {
  return consumeApplicationArchive({ chunks: chunks(archive), manifest, inspection, onFile });
}

async function refuses(action, code) {
  await assert.rejects(action, (error) => {
    assert.equal(error.code, code);
    assert.equal(error.message, code);
    assert.equal(error.writes, 0);
    assert.ok(error.message.length < 128);
    return true;
  });
}

async function portableTarFixture() {
  const longPath = `assets/${'portable-segment-'.repeat(8)}한글.txt`;
  const unicodeLongPath = `assets/${'한글'.repeat(30)}.txt`;
  const files = [...defaultFiles(), {
    path: longPath,
    bytes: Buffer.from('portable PAX path\n'),
    executablePolicy: 'forbidden',
  }, {
    path: unicodeLongPath,
    bytes: Buffer.from('portable PAX ustar prefix\n'),
    executablePolicy: 'forbidden',
  }];
  const inventory = inventoryFor(files);
  const inventoryBytes = canonicalJsonBytes(inventory);
  const root = await mkdtemp(join(tmpdir(), 'gjc-service-archive-'));
  try {
    for (const file of [{ path: INVENTORY_PATH, bytes: inventoryBytes }, ...files]) {
      const destination = join(root, ...file.path.split('/'));
      await mkdir(dirname(destination), { recursive: true });
      await writeFile(destination, file.bytes);
    }
    const stream = createTar({
      cwd: root,
      gzip: { portable: true, level: 6 },
      portable: true,
      noMtime: true,
      strict: true,
    }, [INVENTORY_PATH, ...files.map((file) => file.path)]);
    const parts = [];
    for await (const part of stream) parts.push(Buffer.from(part));
    const archive = Buffer.concat(parts);
    const manifest = manifestFor({ archive, inventory, inventoryBytes });
    return { files, inventory, inventoryBytes, archive, manifest, longPath, unicodeLongPath };
  } finally {
    await rm(root, { recursive: true, force: true });
  }
}

test('tar 7.5.22 portable gzip/PAX archive inspects and streams pass two sequentially, including zero-length bytes', async () => {
  const fixture = await portableTarFixture();
  assert.deepEqual([...fixture.archive.subarray(0, 10)], [0x1f, 0x8b, 8, 0, 0, 0, 0, 0, 0, 255]);
  const tar = gunzipSync(fixture.archive);
  let prefixedPaxObserved = false;
  for (let offset = 0; offset + BLOCK <= tar.length;) {
    const block = tar.subarray(offset, offset + BLOCK);
    const decoded = new Header(block);
    if (decoded.nullBlock) break;
    if (block[156] === 0x78 &&
        block.subarray(345, 500).toString('utf8').split('\0')[0] === 'PaxHeader') {
      prefixedPaxObserved = true;
    }
    offset += BLOCK + Math.ceil(decoded.size / BLOCK) * BLOCK;
  }
  assert.equal(prefixedPaxObserved, true);

  const inspection = await inspect(fixture);
  assert.equal(Object.isFrozen(inspection), true);
  assert.equal(Object.isFrozen(inspection.files), true);
  assert.equal(inspection.archiveSha256, fixture.manifest.archive.sha256);
  assert.equal(inspection.inventoryFingerprint, fixture.inventory.inventoryFingerprint);
  assert.equal(inspection.files.length, fixture.manifest.archive.entryCount);
  assert.ok(inspection.files.some((record) => record.path === fixture.longPath));
  assert.ok(inspection.files.some((record) => record.path === fixture.unicodeLongPath));
  assert.equal(inspection.files.find((record) => record.path === 'bot/src/bot.js').executablePolicy, 'required');
  assert.equal(inspection.files.find((record) => record.path === 'assets/empty.bin').executablePolicy, 'forbidden');
  assert.throws(() => { inspection.files[0].size = 1; }, TypeError);

  const expected = new Map([[INVENTORY_PATH, fixture.inventoryBytes], ...fixture.files.map((file) => [file.path, file.bytes])]);
  const observed = [];
  let callbackActive = false;
  const result = await consume(fixture, inspection, async (record, byteChunks) => {
    assert.equal(callbackActive, false);
    callbackActive = true;
    assert.equal(Object.isFrozen(record), true);
    const parts = [];
    for await (const part of byteChunks) parts.push(Buffer.from(part));
    await Promise.resolve();
    assert.deepEqual(Buffer.concat(parts), expected.get(record.path));
    if (record.path === INVENTORY_PATH) {
      assert.deepEqual(record, {
        path: INVENTORY_PATH,
        size: fixture.manifest.inventory.byteLength,
        sha256: fixture.manifest.inventory.sha256,
        executablePolicy: 'forbidden',
      });
    }
    observed.push(record.path);
    callbackActive = false;
  });
  assert.equal(result, undefined);
  assert.deepEqual(observed, inspection.files.map((record) => record.path));
  assert.equal(expected.get('assets/empty.bin').length, 0);
});

test('inspection brand is unforgeable and bound to the exact manifest object and bytes', async () => {
  const fixture = manualFixture();
  const inspection = await inspect(fixture);
  const clonedManifest = structuredClone(fixture.manifest);
  const foreignInspection = await inspectApplicationArchive({ chunks: chunks(fixture.archive), manifest: clonedManifest });
  const drain = async (record, byteChunks) => { for await (const unused of byteChunks) void unused; };

  await refuses(consume(fixture, { ...inspection }, drain), 'SERVICE_ARCHIVE_INSPECTION_INVALID');
  await refuses(consume(fixture, inspection, drain, fixture.archive, clonedManifest), 'SERVICE_ARCHIVE_INSPECTION_INVALID');
  await refuses(consume(fixture, foreignInspection, drain), 'SERVICE_ARCHIVE_INSPECTION_INVALID');
  assert.equal(Object.isFrozen(foreignInspection), true);
});

test('pass two detects source corruption even after an exact pass-one receipt', async () => {
  const fixture = manualFixture();
  const inspection = await inspect(fixture);
  const changed = Buffer.from(fixture.archive);
  changed[8] = changed[8] === 0 ? 2 : 0;
  await refuses(
    consume(fixture, inspection, async (record, byteChunks) => { for await (const unused of byteChunks) void unused; }, changed),
    'SERVICE_ARCHIVE_HASH_INVALID',
  );
});

test('consumer errors and abandoned or partially consumed streams fail closed with bounded codes', async () => {
  const fixture = manualFixture();
  const inspection = await inspect(fixture);
  await refuses(consume(fixture, inspection, async () => { throw new Error('attacker-controlled consumer detail'); }), 'SERVICE_ARCHIVE_CONSUMER_FAILED');
  await refuses(consume(fixture, inspection, async () => {}), 'SERVICE_ARCHIVE_CONSUMER_INCOMPLETE');
  await refuses(consume(fixture, inspection, async (record, byteChunks) => {
    for await (const unused of byteChunks) { void unused; break; }
  }), 'SERVICE_ARCHIVE_CONSUMER_INCOMPLETE');
  await refuses(
    consumeApplicationArchive({ chunks: chunks(fixture.archive), manifest: fixture.manifest, inspection, onFile: null }),
    'SERVICE_ARCHIVE_INPUT_INVALID',
  );
});

test('deferred callback failure cancels a pending source after the entry was drained', async () => {
  const fixture = manualFixture();
  const inspection = await inspect(fixture);
  const sourceWait = deferred();
  const sourceWaiting = deferred();
  const callbackDrained = deferred();
  const callbackFailure = deferred();
  let sent = false;
  let returned = false;
  let pendingNext = false;
  const iterator = {
    next() {
      if (!sent) {
        sent = true;
        return Promise.resolve({ done: false, value: fixture.archive });
      }
      pendingNext = true;
      sourceWaiting.resolve();
      return sourceWait.promise.finally(() => { pendingNext = false; });
    },
    return() {
      returned = true;
      sourceWait.resolve({ done: true });
      return Promise.resolve({ done: true });
    },
  };
  const source = { [Symbol.asyncIterator]: () => iterator };
  let callbacks = 0;
  const operation = consumeApplicationArchive({
    chunks: source,
    manifest: fixture.manifest,
    inspection,
    async onFile(record, byteChunks) {
      callbacks += 1;
      for await (const unused of byteChunks) void unused;
      callbackDrained.resolve();
      await callbackFailure.promise;
    },
  });
  operation.catch(() => {});

  await settlesWithin(Promise.all([callbackDrained.promise, sourceWaiting.promise]));
  callbackFailure.reject(new Error('deferred callback detail'));
  await refuses(settlesWithin(operation), 'SERVICE_ARCHIVE_CONSUMER_FAILED');
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(callbacks, 1);
  assert.equal(returned, true);
  assert.equal(pendingNext, false);
});

test('source failure mid-entry aborts the active byte stream and settles without a dangling source wait', async () => {
  const streamedFile = Buffer.alloc(64 * 1024);
  let random = 0x9e3779b9;
  for (let index = 0; index < streamedFile.length; index += 1) {
    random ^= random << 13;
    random ^= random >>> 17;
    random ^= random << 5;
    streamedFile[index] = random & 0xff;
  }
  const streamedPath = 'assets/source-failure.bin';
  const fixture = manualFixture({
    files: [
      { path: streamedPath, bytes: streamedFile, executablePolicy: 'forbidden' },
      ...defaultFiles(),
    ],
  });
  const inspection = await inspect(fixture);
  const failSource = deferred();
  const sourceWaiting = deferred();
  const firstChunkBytes = Math.min(8 * 1024, fixture.archive.length - 9);
  let sent = false;
  let returned = false;
  let pendingNext = false;
  const iterator = {
    next() {
      if (!sent) {
        sent = true;
        return Promise.resolve({ done: false, value: fixture.archive.subarray(0, firstChunkBytes) });
      }
      pendingNext = true;
      sourceWaiting.resolve();
      return failSource.promise.then(() => {
        throw new Error('attacker-controlled source detail');
      }).finally(() => { pendingNext = false; });
    },
    return() {
      returned = true;
      failSource.resolve();
      return Promise.resolve({ done: true });
    },
  };
  const source = { [Symbol.asyncIterator]: () => iterator };
  let streamedBytes = 0;
  const operation = consumeApplicationArchive({
    chunks: source,
    manifest: fixture.manifest,
    inspection,
    async onFile(record, byteChunks) {
      for await (const bytes of byteChunks) {
        if (record.path === streamedPath) {
          streamedBytes += bytes.length;
          failSource.resolve();
          await new Promise((resolve) => setImmediate(resolve));
        }
      }
    },
  });
  operation.catch(() => {});

  await settlesWithin(sourceWaiting.promise);
  await refuses(settlesWithin(operation), 'SERVICE_ARCHIVE_INPUT_INVALID');
  await new Promise((resolve) => setImmediate(resolve));
  assert.ok(streamedBytes > 0);
  assert.ok(streamedBytes < streamedFile.length);
  assert.equal(returned, true);
  assert.equal(pendingNext, false);
});

test('manifest validation occurs before archive iteration and all chunk inputs are bytes from an async iterable', async () => {
  const fixture = manualFixture();
  let iterated = false;
  const source = { async *[Symbol.asyncIterator]() { iterated = true; yield fixture.archive; } };
  await refuses(inspectApplicationArchive({ chunks: source, manifest: {} }), 'SERVICE_ARCHIVE_MANIFEST_INVALID');
  assert.equal(iterated, false);
  await refuses(inspectApplicationArchive({ chunks: [fixture.archive], manifest: fixture.manifest }), 'SERVICE_ARCHIVE_INPUT_INVALID');
  await refuses(inspectApplicationArchive({
    chunks: { async *[Symbol.asyncIterator]() { yield 'not bytes'; } },
    manifest: fixture.manifest,
  }), 'SERVICE_ARCHIVE_INPUT_INVALID');
});

test('links, devices, FIFOs, directories, contiguous files, sparse and unknown types are all rejected', async (t) => {
  for (const typeByte of ['1', '2', '3', '4', '5', '6', '7', 'S', 's']) {
    await t.test(`type ${typeByte}`, async () => {
      const base = manualFixture();
      const entries = [rawEntry(INVENTORY_PATH, base.inventoryBytes)];
      entries.push(rawEntry(base.files[0].path, base.files[0].bytes, { typeByte, linkpath: typeByte === '1' || typeByte === '2' ? 'target' : undefined }));
      entries.push(...base.files.slice(1).map((file) => rawEntry(file.path, file.bytes)));
      const hostile = manualFixture({ files: base.files, inventory: base.inventory, inventoryBytes: base.inventoryBytes, entries });
      await refuses(inspect(hostile), 'SERVICE_ARCHIVE_HEADER_INVALID');
    });
  }
});

test('raw ustar checksum, UTF-8, octal fields, magic and reserved bytes are verified before tar normalization', async (t) => {
  const cases = [
    ['checksum', (block) => { block[0] ^= 1; }],
    ['invalid UTF-8', (block) => { block[0] = 0xff; checksumHeader(block); }],
    ['invalid octal', (block) => { block.write('00000000008 ', 124, 12, 'ascii'); checksumHeader(block); }],
    ['base-256 number', (block) => { block[124] = 0x80; checksumHeader(block); }],
    ['high-bit octal digit alias', (block) => { block[113] = 0xb1; checksumHeader(block); }],
    ['non-space numeric padding', (block) => { block[114] = 0x09; checksumHeader(block); }],
    ['non-ustar magic', (block) => { block[257] = 0; checksumHeader(block); }],
    ['reserved header bytes', (block) => { block[500] = 1; checksumHeader(block); }],
  ];
  for (const [name, mutate] of cases) {
    await t.test(name, async () => {
      const base = manualFixture();
      const first = rawEntry(base.files[0].path, base.files[0].bytes);
      mutate(first.subarray(0, BLOCK));
      const hostile = manualFixture({
        files: base.files,
        inventory: base.inventory,
        inventoryBytes: base.inventoryBytes,
        entries: [rawEntry(INVENTORY_PATH, base.inventoryBytes), first, ...base.files.slice(1).map((file) => rawEntry(file.path, file.bytes))],
      });
      await refuses(inspect(hostile), 'SERVICE_ARCHIVE_HEADER_INVALID');
    });
  }
});

test('only the documented bounded local PAX subset is accepted and cleared after exactly one file', async (t) => {
  const make = (replacement) => {
    const base = manualFixture();
    return manualFixture({
      files: base.files,
      inventory: base.inventory,
      inventoryBytes: base.inventoryBytes,
      entries: [rawEntry(INVENTORY_PATH, base.inventoryBytes), replacement(base.files[0]), ...base.files.slice(1).map((file) => rawEntry(file.path, file.bytes))],
    });
  };
  const cases = [
    ['foreign PAX ustar prefix', 'SERVICE_ARCHIVE_PAX_INVALID', (file) => Buffer.concat([
      rawEntry(`ForeignHeader/${'한글'.repeat(30)}`, paxBody([['path', file.path]]), { typeByte: 'x' }),
      rawEntry(file.path, file.bytes),
    ])],
    ['unknown uid rewrite', 'SERVICE_ARCHIVE_PAX_INVALID', (file) => paxFile(file.path, file.bytes, { records: [['path', file.path], ['uid', '0']] })],
    ['global header', 'SERVICE_ARCHIVE_HEADER_INVALID', (file) => paxFile(file.path, file.bytes, { metadataType: 'GlobalExtendedHeader' })],
    ['size rewrite', 'SERVICE_ARCHIVE_PAX_INVALID', (file) => paxFile(file.path, file.bytes, { records: [['path', file.path], ['size', String(file.bytes.length + 1)]] })],
    ['non-unit nlink', 'SERVICE_ARCHIVE_PAX_INVALID', (file) => paxFile(file.path, file.bytes, { records: [['path', file.path], ['SCHILY.nlink', '2']] })],
    ['duplicate key', 'SERVICE_ARCHIVE_PAX_INVALID', (file) => paxFile(file.path, file.bytes, { records: [['path', file.path], ['path', file.path]] })],
    ['malformed length', 'SERVICE_ARCHIVE_PAX_INVALID', (file) => paxFile(file.path, file.bytes, { metadataBody: Buffer.from(`99 path=${file.path}\n`) })],
    ['high-bit PAX length digit alias', 'SERVICE_ARCHIVE_PAX_INVALID', (file) => {
      const path = paxRecord('path', file.path);
      const size = paxRecord('size', String(file.bytes.length));
      size[0] |= 0x80;
      return paxFile(file.path, file.bytes, { metadataBody: Buffer.concat([path, size]) });
    }],
    ['high-bit PAX key alias', 'SERVICE_ARCHIVE_PAX_INVALID', (file) => {
      const body = paxBody([['path', file.path], ['SCHILY.nlink', '1']]);
      body[body.indexOf(Buffer.from('SCHILY.nlink'))] |= 0x80;
      return paxFile(file.path, file.bytes, { metadataBody: body });
    }],
    ['oversized metadata', 'SERVICE_ARCHIVE_PAX_INVALID', (file) => Buffer.concat([
      rawEntry('PaxHeader/oversized', Buffer.alloc(DEPLOYMENT_ENVELOPE_LIMITS.pathBytes + 1025), { typeByte: 'x' }),
      rawEntry(file.path, file.bytes),
    ])],
    ['consecutive metadata', 'SERVICE_ARCHIVE_PAX_INVALID', (file) => Buffer.concat([
      rawEntry('PaxHeader/one', paxBody([['path', file.path]]), { typeByte: 'x' }),
      rawEntry('PaxHeader/two', paxBody([['path', file.path]]), { typeByte: 'x' }),
      rawEntry(file.path, file.bytes),
    ])],
  ];
  for (const [name, code, replacement] of cases) {
    await t.test(name, async () => {
      await refuses(inspect(make(replacement)), code);
    });
  }
  await t.test('dangling metadata at end', async () => {
    const base = manualFixture();
    const entries = [rawEntry(INVENTORY_PATH, base.inventoryBytes), ...base.files.map((file) => rawEntry(file.path, file.bytes))];
    entries.push(rawEntry('PaxHeader/dangling', paxBody([['path', 'unused']]), { typeByte: 'x' }));
    const hostile = manualFixture({ files: base.files, inventory: base.inventory, inventoryBytes: base.inventoryBytes, entries });
    await refuses(inspect(hostile), 'SERVICE_ARCHIVE_PAX_INVALID');
  });
});

test('absolute, drive, UNC, backslash, dot, empty, mutable-state and unsafe Windows paths reject through shared path policy', async (t) => {
  const cases = [
    ['absolute', '/absolute/file'],
    ['drive', 'C:/drive/file'],
    ['UNC', '//server/share/file'],
    ['backslash', 'dir\\file'],
    ['dot', 'dir/./file'],
    ['parent', 'dir/../file'],
    ['empty segment', 'dir//file'],
    ['mutable state', '.env/secret'],
    ['reserved Windows name', 'dir/con.txt'],
    ['Windows ADS', 'dir/name:stream'],
    ['Windows trailing dot', 'dir/name.'],
    ['Windows trailing space', 'dir/name '],
    ['too many segments', `${'x/'.repeat(64)}file`],
    ['over 4096 UTF-8 bytes', `dir/${'x'.repeat(DEPLOYMENT_ENVELOPE_LIMITS.pathBytes)}`],
  ];
  for (const [name, path] of cases) {
    await t.test(name, async () => {
      const base = manualFixture({ platform: 'win32' });
      const first = base.files[0];
      const replacement = Buffer.byteLength(path) < 100
        ? rawEntry(path, first.bytes)
        : paxFile(path, first.bytes);
      const hostile = manualFixture({
        files: base.files,
        platform: 'win32',
        inventory: base.inventory,
        inventoryBytes: base.inventoryBytes,
        entries: [rawEntry(INVENTORY_PATH, base.inventoryBytes), replacement, ...base.files.slice(1).map((file) => rawEntry(file.path, file.bytes))],
      });
      await refuses(inspect(hostile), 'SERVICE_ARCHIVE_PATH_INVALID');
    });
  }
  await t.test('empty path', async () => {
    const base = manualFixture({ platform: 'win32' });
    const hostile = manualFixture({
      files: base.files,
      platform: 'win32',
      inventory: base.inventory,
      inventoryBytes: base.inventoryBytes,
      entries: [
        rawEntry(INVENTORY_PATH, base.inventoryBytes),
        rawEntry('', base.files[0].bytes),
        ...base.files.slice(1).map((file) => rawEntry(file.path, file.bytes)),
      ],
    });
    await refuses(inspect(hostile), 'SERVICE_ARCHIVE_HEADER_INVALID');
  });
});

test('case aliases and file/directory prefix collisions reject using the shared tree validator', async () => {
  for (const paths of [['Alias/file', 'alias/file'], ['tree', 'tree/file']]) {
    const base = manualFixture({ platform: 'win32' });
    const entries = [
      rawEntry(INVENTORY_PATH, base.inventoryBytes),
      rawEntry(paths[0], base.files[0].bytes),
      rawEntry(paths[1], base.files[1].bytes),
      ...base.files.slice(2).map((file) => rawEntry(file.path, file.bytes)),
    ];
    const hostile = manualFixture({ files: base.files, platform: 'win32', inventory: base.inventory, inventoryBytes: base.inventoryBytes, entries });
    await refuses(inspect(hostile), 'SERVICE_ARCHIVE_PATH_INVALID');
  }
});

test('extra, missing, duplicate and unlisted regular entries cannot disagree with inventory', async () => {
  const base = manualFixture();
  const inventoryEntry = rawEntry(INVENTORY_PATH, base.inventoryBytes);
  const regular = base.files.map((file) => rawEntry(file.path, file.bytes));
  const cases = [
    [tarBytes([inventoryEntry, ...regular, rawEntry('extra.txt', Buffer.alloc(0))]), 'SERVICE_ARCHIVE_ENTRY_INVALID'],
    [tarBytes([inventoryEntry, inventoryEntry, ...regular]), 'SERVICE_ARCHIVE_ENTRY_INVALID'],
    [tarBytes(regular), 'SERVICE_ARCHIVE_PAYLOAD_INVALID'],
    [tarBytes([inventoryEntry, ...regular.slice(0, -1)]), 'SERVICE_ARCHIVE_PAYLOAD_INVALID'],
    [tarBytes([inventoryEntry, regular[0], regular[0], ...regular.slice(2)]), 'SERVICE_ARCHIVE_ENTRY_INVALID'],
    [tarBytes([inventoryEntry, rawEntry('unlisted.txt', base.files[0].bytes), ...regular.slice(1)]), 'SERVICE_ARCHIVE_PAYLOAD_INVALID'],
  ];
  for (const [tar, code] of cases) await refuses(inspect(fixtureWithTar(base, tar)), code);
});

test('inventory canonical bytes, ordering, fingerprints, tree and payload bytes are reverified', async () => {
  const base = manualFixture();
  const prettyInventory = Buffer.from(JSON.stringify(base.inventory, null, 2));
  const pretty = manualFixture({ inventory: base.inventory, inventoryBytes: prettyInventory });
  await refuses(inspect(pretty), 'SERVICE_ARCHIVE_INVENTORY_INVALID');

  const unsortedInventory = structuredClone(base.inventory);
  unsortedInventory.payloadEntries.reverse();
  unsortedInventory.inventoryFingerprint = bundleInventoryFingerprint(unsortedInventory);
  const unsortedBytes = canonicalJsonBytes(unsortedInventory);
  const unsorted = manualFixture({ inventory: base.inventory, inventoryBytes: unsortedBytes });
  await refuses(inspect(unsorted), 'SERVICE_ARCHIVE_INVENTORY_INVALID');

  const changedBytes = Buffer.from(base.files[0].bytes);
  changedBytes[0] ^= 1;
  const entries = [
    rawEntry(INVENTORY_PATH, base.inventoryBytes),
    rawEntry(base.files[0].path, changedBytes),
    ...base.files.slice(1).map((file) => rawEntry(file.path, file.bytes)),
  ];
  const changed = manualFixture({ files: base.files, inventory: base.inventory, inventoryBytes: base.inventoryBytes, entries });
  await refuses(inspect(changed), 'SERVICE_ARCHIVE_PAYLOAD_INVALID');
});

test('gzip and tar truncation, concatenation, trailers and exact two-block termination are strict', async () => {
  const base = manualFixture();
  await refuses(inspect(base, base.archive.subarray(0, base.archive.length - 1)), 'SERVICE_ARCHIVE_SIZE_INVALID');

  const badFlags = Buffer.from(base.archive);
  badFlags[3] = 8;
  await refuses(inspect(fixtureWithArchive(base, badFlags)), 'SERVICE_ARCHIVE_GZIP_INVALID');

  const nonportableOs = Buffer.from(base.archive);
  nonportableOs[9] = 3;
  await refuses(inspect(fixtureWithArchive(base, nonportableOs)), 'SERVICE_ARCHIVE_GZIP_INVALID');

  const badTrailer = Buffer.from(base.archive);
  badTrailer[badTrailer.length - 8] ^= 1;
  await refuses(inspect(fixtureWithArchive(base, badTrailer)), 'SERVICE_ARCHIVE_GZIP_INVALID');

  const secondMember = portableGzip(tarBytes([rawEntry('other', Buffer.alloc(0))]));
  await refuses(inspect(fixtureWithArchive(base, Buffer.concat([base.archive, secondMember]))), 'SERVICE_ARCHIVE_GZIP_INVALID');
  await refuses(inspect(fixtureWithArchive(base, Buffer.concat([base.archive, Buffer.from([0])]))), 'SERVICE_ARCHIVE_GZIP_INVALID');

  const entries = [rawEntry(INVENTORY_PATH, base.inventoryBytes), ...base.files.map((file) => rawEntry(file.path, file.bytes))];
  await refuses(inspect(fixtureWithTar(base, tarBytes(entries, Buffer.alloc(0)))), 'SERVICE_ARCHIVE_TAR_INVALID');
  await refuses(inspect(fixtureWithTar(base, tarBytes(entries, Buffer.alloc(BLOCK)))), 'SERVICE_ARCHIVE_TAR_INVALID');
  await refuses(inspect(fixtureWithTar(base, tarBytes(entries, Buffer.alloc(BLOCK * 3)))), 'SERVICE_ARCHIVE_TAR_INVALID');
  await refuses(inspect(fixtureWithTar(base, Buffer.concat([tarBytes(entries), Buffer.from([1])]))), 'SERVICE_ARCHIVE_TAR_INVALID');

  const badPadding = rawEntry(base.files[0].path, base.files[0].bytes);
  badPadding[BLOCK + base.files[0].bytes.length] = 1;
  await refuses(inspect(fixtureWithTar(base, tarBytes([
    rawEntry(INVENTORY_PATH, base.inventoryBytes),
    badPadding,
    ...base.files.slice(1).map((file) => rawEntry(file.path, file.bytes)),
  ]))), 'SERVICE_ARCHIVE_TAR_INVALID');

  const truncatedBody = Buffer.concat([
    rawEntry(INVENTORY_PATH, base.inventoryBytes),
    header(base.files[0].path, base.files[0].bytes.length),
    base.files[0].bytes.subarray(0, 1),
  ]);
  await refuses(inspect(fixtureWithTar(base, truncatedBody)), 'SERVICE_ARCHIVE_TAR_INVALID');
});

test('approved model bounds are exact and exercised with small declared-size/path predicates, not huge allocations', async () => {
  assert.deepEqual({
    archiveBytes: DEPLOYMENT_ENVELOPE_LIMITS.archiveBytes,
    payloadBytes: DEPLOYMENT_ENVELOPE_LIMITS.unpackedPayloadBytes,
    inventoryBytes: DEPLOYMENT_ENVELOPE_LIMITS.inventoryBytes,
    payloadEntries: DEPLOYMENT_ENVELOPE_LIMITS.payloadEntries,
    pathBytes: DEPLOYMENT_ENVELOPE_LIMITS.pathBytes,
    pathSegments: DEPLOYMENT_ENVELOPE_LIMITS.pathSegments,
  }, {
    archiveBytes: 1024 * 1024 * 1024,
    payloadBytes: 2 * 1024 * 1024 * 1024,
    inventoryBytes: 32 * 1024 * 1024,
    payloadEntries: 100_000,
    pathBytes: 4096,
    pathSegments: 64,
  });

  const base = manualFixture();
  const declaredOversize = header(base.files[0].path, DEPLOYMENT_ENVELOPE_LIMITS.unpackedPayloadBytes + 1);
  const hostileTar = tarBytes([rawEntry(INVENTORY_PATH, base.inventoryBytes), declaredOversize, ...base.files.slice(1).map((file) => rawEntry(file.path, file.bytes))]);
  await refuses(inspect(fixtureWithTar(base, hostileTar)), 'SERVICE_ARCHIVE_PAYLOAD_INVALID');

  const manifestBounds = [
    (manifest) => { manifest.archive.byteLength = DEPLOYMENT_ENVELOPE_LIMITS.archiveBytes + 1; },
    (manifest) => { manifest.inventory.byteLength = DEPLOYMENT_ENVELOPE_LIMITS.inventoryBytes + 1; },
    (manifest) => { manifest.inventory.unpackedPayloadBytes = DEPLOYMENT_ENVELOPE_LIMITS.unpackedPayloadBytes + 1; },
    (manifest) => {
      manifest.inventory.payloadEntryCount = DEPLOYMENT_ENVELOPE_LIMITS.payloadEntries + 1;
      manifest.archive.entryCount = manifest.inventory.payloadEntryCount + 1;
    },
  ];
  for (const mutate of manifestBounds) {
    const oversizedManifest = structuredClone(base.manifest);
    mutate(oversizedManifest);
    oversizedManifest.manifestFingerprint = applicationDeploymentManifestFingerprint(oversizedManifest);
    await refuses(inspectApplicationArchive({ chunks: chunks(base.archive), manifest: oversizedManifest }), 'SERVICE_ARCHIVE_MANIFEST_INVALID');
  }
});

test('manifest/inventory count, size, hash, preimage and sort disagreement all remain fail closed', async () => {
  const base = manualFixture();
  const wrongTree = structuredClone(base.inventory);
  wrongTree.treeFingerprint = 'e'.repeat(64);
  wrongTree.inventoryFingerprint = bundleInventoryFingerprint(wrongTree);
  await refuses(inspect(manualFixture({ inventory: base.inventory, inventoryBytes: canonicalJsonBytes(wrongTree) })), 'SERVICE_ARCHIVE_INVENTORY_INVALID');

  const wrongPreimage = structuredClone(base.inventory);
  wrongPreimage.inventoryFingerprint = 'f'.repeat(64);
  await refuses(inspect(manualFixture({ inventory: base.inventory, inventoryBytes: canonicalJsonBytes(wrongPreimage) })), 'SERVICE_ARCHIVE_INVENTORY_INVALID');

  const wrongCount = structuredClone(base.inventory);
  wrongCount.payloadEntryCount += 1;
  wrongCount.inventoryFingerprint = bundleInventoryFingerprint(wrongCount);
  await refuses(inspect(manualFixture({ inventory: base.inventory, inventoryBytes: canonicalJsonBytes(wrongCount) })), 'SERVICE_ARCHIVE_INVENTORY_INVALID');

  const wrongBytes = structuredClone(base.inventory);
  wrongBytes.unpackedPayloadBytes += 1;
  wrongBytes.inventoryFingerprint = bundleInventoryFingerprint(wrongBytes);
  await refuses(inspect(manualFixture({ inventory: base.inventory, inventoryBytes: canonicalJsonBytes(wrongBytes) })), 'SERVICE_ARCHIVE_INVENTORY_INVALID');

  assert.equal(bundleTreeFingerprint(base.inventory.payloadEntries, { platform: 'linux' }), base.inventory.treeFingerprint);
});
