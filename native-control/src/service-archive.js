import { createHash } from 'node:crypto';
import { once } from 'node:events';
import { createInflateRaw } from 'node:zlib';
import { Parser } from 'tar';
import {
  APPLICATION_BUNDLE_INVENTORY_PATH,
  DEPLOYMENT_ENVELOPE_LIMITS,
  bundleTreeFingerprint,
  validateApplicationDeploymentManifest,
  validateBundleInventory,
} from '@gjc-remote/shared/deployment-envelope';
import {
  assertStrictText,
  canonicalJsonBytes,
  parseCanonicalJsonBytes,
  utf8Compare,
} from '@gjc-remote/shared/strict-json';

const MANIFEST_JSON_LIMITS = Object.freeze({ maxBytes: DEPLOYMENT_ENVELOPE_LIMITS.manifestBytes, maxDepth: 32, maxNodes: 10_000 });
const INVENTORY_JSON_LIMITS = Object.freeze({
  maxBytes: DEPLOYMENT_ENVELOPE_LIMITS.inventoryBytes,
  maxDepth: 16,
  maxNodes: DEPLOYMENT_ENVELOPE_LIMITS.payloadEntries * 6 + 32,
});
const PAX_BODY_BYTES = DEPLOYMENT_ENVELOPE_LIMITS.pathBytes + 1024;
const ZERO_HASH = '0'.repeat(64);
const GZIP_HEADER_BYTES = 10;
const GZIP_TRAILER_BYTES = 8;
const TAR_BLOCK_BYTES = 512;
const TAR_END_BYTES = TAR_BLOCK_BYTES * 2;
const INSPECTION_KIND = 'application-archive-inspection';
const INSPECTIONS = new WeakMap();
const ABORTED = Symbol('aborted');
const PAX_KEYS = Object.freeze(
  ['path', 'size', 'mtime', 'SCHILY.nlink']
    .map((name) => Object.freeze({ name, bytes: Buffer.from(name, 'ascii') })),
);

const CODES = Object.freeze({
  manifest: 'SERVICE_ARCHIVE_MANIFEST_INVALID',
  input: 'SERVICE_ARCHIVE_INPUT_INVALID',
  size: 'SERVICE_ARCHIVE_SIZE_INVALID',
  hash: 'SERVICE_ARCHIVE_HASH_INVALID',
  gzip: 'SERVICE_ARCHIVE_GZIP_INVALID',
  expansion: 'SERVICE_ARCHIVE_DECOMPRESSION_LIMIT',
  tar: 'SERVICE_ARCHIVE_TAR_INVALID',
  header: 'SERVICE_ARCHIVE_HEADER_INVALID',
  pax: 'SERVICE_ARCHIVE_PAX_INVALID',
  path: 'SERVICE_ARCHIVE_PATH_INVALID',
  entry: 'SERVICE_ARCHIVE_ENTRY_INVALID',
  inventory: 'SERVICE_ARCHIVE_INVENTORY_INVALID',
  payload: 'SERVICE_ARCHIVE_PAYLOAD_INVALID',
  inspection: 'SERVICE_ARCHIVE_INSPECTION_INVALID',
  consumer: 'SERVICE_ARCHIVE_CONSUMER_FAILED',
  incomplete: 'SERVICE_ARCHIVE_CONSUMER_INCOMPLETE',
});

class ServiceArchiveError extends Error {
  constructor(code) {
    super(code);
    this.name = 'ServiceArchiveError';
    this.code = code;
    this.writes = 0;
  }
}

function failure(code) {
  return new ServiceArchiveError(code);
}

function fail(code) {
  throw failure(code);
}

function boundedError(error, fallback) {
  return error instanceof ServiceArchiveError ? error : failure(fallback);
}

function deepFreeze(value) {
  if (value === null || typeof value !== 'object' || Object.isFrozen(value)) return value;
  for (const child of Object.values(value)) deepFreeze(child);
  return Object.freeze(value);
}

function captureManifest(manifest) {
  try {
    validateApplicationDeploymentManifest(manifest);
    const bytes = canonicalJsonBytes(manifest, MANIFEST_JSON_LIMITS);
    const snapshot = parseCanonicalJsonBytes(bytes, MANIFEST_JSON_LIMITS);
    validateApplicationDeploymentManifest(snapshot);
    return { identity: manifest, bytes, snapshot: deepFreeze(snapshot) };
  } catch {
    fail(CODES.manifest);
  }
}

function assertManifestUnchanged(captured) {
  try {
    validateApplicationDeploymentManifest(captured.identity);
    const current = canonicalJsonBytes(captured.identity, MANIFEST_JSON_LIMITS);
    if (!current.equals(captured.bytes)) fail(CODES.manifest);
  } catch (error) {
    throw boundedError(error, CODES.manifest);
  }
}

function sha256(bytes) {
  return createHash('sha256').update(bytes).digest('hex');
}

function isBytes(value) {
  return Buffer.isBuffer(value) || value instanceof Uint8Array;
}

function asBuffer(value) {
  return Buffer.isBuffer(value)
    ? value
    : Buffer.from(value.buffer, value.byteOffset, value.byteLength);
}

function asyncIteratorFor(chunks) {
  try {
    if (chunks === null || chunks === undefined || typeof chunks[Symbol.asyncIterator] !== 'function') fail(CODES.input);
    const iterator = chunks[Symbol.asyncIterator]();
    if (iterator === null || typeof iterator !== 'object' || typeof iterator.next !== 'function') fail(CODES.input);
    return iterator;
  } catch (error) {
    throw boundedError(error, CODES.input);
  }
}

const CRC_TABLE = (() => {
  const table = new Uint32Array(256);
  for (let index = 0; index < table.length; index += 1) {
    let value = index;
    for (let bit = 0; bit < 8; bit += 1) value = (value & 1) ? (0xedb88320 ^ (value >>> 1)) : (value >>> 1);
    table[index] = value >>> 0;
  }
  return table;
})();

function updateCrc32(crc, bytes) {
  let value = crc;
  for (const byte of bytes) value = CRC_TABLE[(value ^ byte) & 0xff] ^ (value >>> 8);
  return value >>> 0;
}

function writeInflater(inflater, bytes) {
  if (bytes.length === 0) return Promise.resolve();
  return new Promise((resolve, reject) => {
    const onError = (error) => {
      cleanup();
      reject(error);
    };
    const cleanup = () => inflater.off('error', onError);
    inflater.once('error', onError);
    inflater.write(bytes, (error) => {
      cleanup();
      if (error) reject(error);
      else resolve();
    });
  });
}

function endInflater(inflater) {
  return new Promise((resolve, reject) => {
    const onError = (error) => {
      cleanup();
      reject(error);
    };
    const cleanup = () => inflater.off('error', onError);
    inflater.once('error', onError);
    inflater.end(() => {
      cleanup();
      resolve();
    });
  });
}

/*
 * Accepted gzip framing is deliberately narrower than generic gunzip:
 * one RFC 1952 member, deflate, no optional fields, zero MTIME, XFL 0/2/4,
 * and portable OS=255. tar 7.5.22's portable gzip writer explicitly emits
 * OS=255 on every platform. The final eight bytes are withheld from raw
 * inflate, then CRC32 and ISIZE are checked. Concatenated members and every
 * byte before or after that one trailer are rejected.
 */
function validateGzipHeader(header) {
  const valid = header.length === GZIP_HEADER_BYTES &&
    header[0] === 0x1f && header[1] === 0x8b && header[2] === 8 && header[3] === 0 &&
    header[4] === 0 && header[5] === 0 && header[6] === 0 && header[7] === 0 &&
    (header[8] === 0 || header[8] === 2 || header[8] === 4) && header[9] === 255;
  if (!valid) fail(CODES.gzip);
}

class GzipFeeder {
  constructor(chunks, expectedArchive) {
    this.iterator = asyncIteratorFor(chunks);
    this.expectedArchive = expectedArchive;
    this.header = Buffer.alloc(GZIP_HEADER_BYTES);
    this.headerOffset = 0;
    this.tail = Buffer.alloc(0);
    this.trailing = [];
    this.trailingBytes = 0;
    this.inflateEndedEarly = false;
    this.endedInflater = false;
    this.stopped = false;
    this.cancelNext = null;
    this.compressedBytes = 0;
    this.compressedHash = createHash('sha256');
  }

  abort() {
    if (this.stopped) return;
    this.stopped = true;
    this.cancelNext?.();
    try {
      const returned = this.iterator.return?.();
      if (returned !== undefined) Promise.resolve(returned).catch(() => {});
    } catch {
      // The original bounded parser failure remains authoritative.
    }
  }

  async next() {
    let cancel;
    const aborted = new Promise((resolve) => {
      cancel = () => resolve(ABORTED);
      this.cancelNext = cancel;
    });
    try {
      return await Promise.race([
        Promise.resolve().then(() => this.iterator.next()),
        aborted,
      ]);
    } finally {
      if (this.cancelNext === cancel) this.cancelNext = null;
    }
  }

  addTrailing(bytes) {
    if (bytes.length === 0) return;
    this.trailingBytes += bytes.length;
    if (this.trailingBytes > GZIP_TRAILER_BYTES) fail(CODES.gzip);
    this.trailing.push(Buffer.from(bytes));
  }

  async finishInflater(inflater) {
    if (this.endedInflater) return;
    this.endedInflater = true;
    try {
      await endInflater(inflater);
    } catch {
      fail(CODES.gzip);
    }
  }

  async feedDeflatePiece(inflater, bytes) {
    if (bytes.length === 0) return false;
    const before = inflater.bytesWritten;
    try {
      await writeInflater(inflater, bytes);
    } catch {
      fail(CODES.gzip);
    }
    const consumed = inflater.bytesWritten - before;
    if (!Number.isSafeInteger(consumed) || consumed < 0 || consumed > bytes.length) fail(CODES.gzip);
    if (consumed === bytes.length) return false;
    this.inflateEndedEarly = true;
    this.addTrailing(bytes.subarray(consumed));
    await this.finishInflater(inflater);
    return true;
  }

  async holdTrailerAndFeed(inflater, bytes) {
    if (bytes.length === 0) return;
    if (this.inflateEndedEarly) {
      this.addTrailing(bytes);
      return;
    }

    const pieces = [];
    let nextTail;
    if (bytes.length >= GZIP_TRAILER_BYTES) {
      if (this.tail.length > 0) pieces.push(this.tail);
      const feedLength = bytes.length - GZIP_TRAILER_BYTES;
      if (feedLength > 0) pieces.push(bytes.subarray(0, feedLength));
      nextTail = Buffer.from(bytes.subarray(feedLength));
    } else {
      const feedFromTail = Math.max(0, this.tail.length + bytes.length - GZIP_TRAILER_BYTES);
      if (feedFromTail > 0) pieces.push(this.tail.subarray(0, feedFromTail));
      nextTail = Buffer.concat([this.tail.subarray(feedFromTail), bytes]);
    }

    for (let index = 0; index < pieces.length; index += 1) {
      const ended = await this.feedDeflatePiece(inflater, pieces[index]);
      if (!ended) continue;
      for (let rest = index + 1; rest < pieces.length; rest += 1) this.addTrailing(pieces[rest]);
      this.addTrailing(nextTail);
      this.tail = Buffer.alloc(0);
      return;
    }
    this.tail = nextTail;
  }

  async accept(inflater, input) {
    let bytes = input;
    if (this.headerOffset < GZIP_HEADER_BYTES) {
      const take = Math.min(bytes.length, GZIP_HEADER_BYTES - this.headerOffset);
      bytes.copy(this.header, this.headerOffset, 0, take);
      this.headerOffset += take;
      bytes = bytes.subarray(take);
      if (this.headerOffset === GZIP_HEADER_BYTES) validateGzipHeader(this.header);
    }
    if (bytes.length > 0) await this.holdTrailerAndFeed(inflater, bytes);
  }

  async run(inflater) {
    try {
      while (!this.stopped) {
        let result;
        try {
          result = await this.next();
        } catch {
          fail(CODES.input);
        }
        if (result === ABORTED) fail(CODES.input);
        if (result === null || typeof result !== 'object' ||
            (result.done !== undefined && typeof result.done !== 'boolean')) fail(CODES.input);
        if (result.done === true) break;
        if (!isBytes(result.value)) fail(CODES.input);
        const bytes = asBuffer(result.value);
        this.compressedBytes += bytes.length;
        if (!Number.isSafeInteger(this.compressedBytes) || this.compressedBytes > this.expectedArchive.byteLength) fail(CODES.size);
        this.compressedHash.update(bytes);
        await this.accept(inflater, bytes);
      }
      if (this.stopped) fail(CODES.input);
      if (this.compressedBytes !== this.expectedArchive.byteLength) fail(CODES.size);
      if (this.headerOffset !== GZIP_HEADER_BYTES) fail(CODES.gzip);
      const digest = this.compressedHash.digest('hex');
      if (digest !== this.expectedArchive.sha256) fail(CODES.hash);

      let trailer;
      if (this.inflateEndedEarly) {
        if (this.trailingBytes !== GZIP_TRAILER_BYTES) fail(CODES.gzip);
        trailer = Buffer.concat(this.trailing, GZIP_TRAILER_BYTES);
      } else {
        if (this.tail.length !== GZIP_TRAILER_BYTES) fail(CODES.gzip);
        trailer = this.tail;
        await this.finishInflater(inflater);
      }
      return { byteLength: this.compressedBytes, sha256: digest, trailer };
    } catch (error) {
      this.abort();
      if (!this.endedInflater) inflater.destroy();
      throw boundedError(error, CODES.gzip);
    }
  }
}

function decodeTarText(bytes) {
  const nul = bytes.indexOf(0);
  const content = nul === -1 ? bytes : bytes.subarray(0, nul);
  if (nul !== -1) {
    for (let index = nul; index < bytes.length; index += 1) if (bytes[index] !== 0) fail(CODES.header);
  }
  let value;
  try {
    value = new TextDecoder('utf-8', { fatal: true }).decode(content);
    assertStrictText(value, 'tar header text', bytes.length);
  } catch {
    fail(CODES.header);
  }
  return value;
}

function decodeOctal(bytes, { required = false, maximum = Number.MAX_SAFE_INTEGER } = {}) {
  let index = 0;
  while (index < bytes.length && bytes[index] === 0x20) index += 1;
  const firstDigit = index;
  let value = 0;
  while (index < bytes.length && bytes[index] >= 0x30 && bytes[index] <= 0x37) {
    value = value * 8 + bytes[index] - 0x30;
    if (!Number.isSafeInteger(value) || value > maximum) fail(CODES.header);
    index += 1;
  }
  if (index === firstDigit) {
    if (required) fail(CODES.header);
    while (index < bytes.length && bytes[index] === 0) index += 1;
    if (index !== bytes.length) fail(CODES.header);
    return undefined;
  }
  if (index < bytes.length && bytes[index] === 0x20) index += 1;
  while (index < bytes.length && bytes[index] === 0) index += 1;
  if (index !== bytes.length) fail(CODES.header);
  return value;
}

function isZeroBlock(block) {
  for (const byte of block) if (byte !== 0) return false;
  return true;
}

/*
 * Files use the POSIX ustar magic/version, valid UTF-8 NUL-padded text,
 * unsigned octal numbers (never base-256), the unsigned checksum, empty link
 * and zero device fields, and type `0` or NUL. Ownership, timestamp, and mode
 * numbers use only leading ASCII spaces, contiguous octal digits, at most one
 * trailing ASCII space, and then NULs; they are never installer policy. Body
 * padding is all zero and termination is exactly two zero blocks with no third
 * block or partial/trailing data. V7/GNU/star variants are intentionally out.
 */
function decodeRawHeader(block) {
  if (block.length !== TAR_BLOCK_BYTES) fail(CODES.header);
  if (isZeroBlock(block)) return null;

  const expectedChecksum = decodeOctal(block.subarray(148, 156), { required: true });
  let checksum = 8 * 0x20;
  for (let index = 0; index < 148; index += 1) checksum += block[index];
  for (let index = 156; index < TAR_BLOCK_BYTES; index += 1) checksum += block[index];
  if (checksum !== expectedChecksum) fail(CODES.header);

  if (!block.subarray(257, 263).equals(Buffer.from('ustar\0', 'binary')) ||
      !block.subarray(263, 265).equals(Buffer.from('00', 'ascii'))) fail(CODES.header);
  for (let index = 500; index < TAR_BLOCK_BYTES; index += 1) if (block[index] !== 0) fail(CODES.header);

  const name = decodeTarText(block.subarray(0, 100));
  const prefix = decodeTarText(block.subarray(345, 500));
  const linkpath = decodeTarText(block.subarray(157, 257));
  decodeTarText(block.subarray(265, 297));
  decodeTarText(block.subarray(297, 329));
  const mode = decodeOctal(block.subarray(100, 108), { maximum: 0o7777 });
  decodeOctal(block.subarray(108, 116), { maximum: 0o7777777 });
  decodeOctal(block.subarray(116, 124), { maximum: 0o7777777 });
  const size = decodeOctal(block.subarray(124, 136), { required: true, maximum: 0o77777777777 });
  decodeOctal(block.subarray(136, 148), { maximum: 0o77777777777 });
  const devMajor = decodeOctal(block.subarray(329, 337), { maximum: 0o7777777 });
  const devMinor = decodeOctal(block.subarray(337, 345), { maximum: 0o7777777 });
  if ((devMajor ?? 0) !== 0 || (devMinor ?? 0) !== 0 || linkpath !== '') fail(CODES.header);

  const typeByte = block[156];
  if (name.length === 0 || ![0, 0x30, 0x78].includes(typeByte)) fail(CODES.header);
  return {
    path: prefix.length === 0 ? name : `${prefix}/${name}`,
    mode,
    size,
    typeByte,
  };
}

function parsePaxDecimal(value, code = CODES.pax) {
  if (!/^(?:0|[1-9][0-9]*)$/.test(value)) fail(code);
  const number = Number(value);
  if (!Number.isSafeInteger(number) || number < 0) fail(code);
  return number;
}

function parsePaxTime(value) {
  if (!/^-?(?:0|[1-9][0-9]*)(?:\.[0-9]{1,9})?$/.test(value)) fail(CODES.pax);
  const number = Number(value);
  if (!Number.isFinite(number) || Math.abs(number) > 8_640_000_000_000) fail(CODES.pax);
}

/*
 * The only metadata form accepted is one local POSIX PAX `x` header directly
 * before one regular file. Its body is at most PAX_BODY_BYTES and contains a
 * required `path`, plus optional `size`, `mtime`, and `SCHILY.nlink` records.
 * `size` may only restate (not rewrite) the ustar size, and nlink must be 1.
 * This is exactly the field subset emitted by tar 7.5.22 for portable long
 * paths. Global PAX, GNU long-name/link, sparse, ACL, and vendor keys reject.
 */
function parsePaxBody(body) {
  const records = new Map();
  let offset = 0;
  while (offset < body.length) {
    let space = offset;
    while (space < body.length && body[space] !== 0x20) space += 1;
    if (space === offset || space >= body.length) fail(CODES.pax);
    let length = 0;
    for (let index = offset; index < space; index += 1) {
      const byte = body[index];
      if ((index === offset && (byte < 0x31 || byte > 0x39)) ||
          (index !== offset && (byte < 0x30 || byte > 0x39))) fail(CODES.pax);
      length = length * 10 + byte - 0x30;
      if (!Number.isSafeInteger(length)) fail(CODES.pax);
    }
    const end = offset + length;
    if (end > body.length || body[end - 1] !== 0x0a) fail(CODES.pax);
    const equals = body.indexOf(0x3d, space + 1);
    if (equals === -1 || equals >= end - 1) fail(CODES.pax);
    const keyBytes = body.subarray(space + 1, equals);
    const key = PAX_KEYS.find((candidate) => keyBytes.equals(candidate.bytes))?.name;
    if (key === undefined || records.has(key)) fail(CODES.pax);
    let value;
    try {
      value = new TextDecoder('utf-8', { fatal: true }).decode(body.subarray(equals + 1, end - 1));
      assertStrictText(value, 'PAX value', PAX_BODY_BYTES);
    } catch {
      fail(CODES.pax);
    }
    records.set(key, value);
    offset = end;
  }
  if (!records.has('path')) fail(CODES.pax);
  if (records.get('path').length === 0) fail(CODES.pax);
  if (records.has('size')) records.set('size', parsePaxDecimal(records.get('size')));
  if (records.has('mtime')) parsePaxTime(records.get('mtime'));
  if (records.has('SCHILY.nlink') && parsePaxDecimal(records.get('SCHILY.nlink')) !== 1) fail(CODES.pax);
  return records;
}

function validatePayloadPath(path, platform) {
  if (path === APPLICATION_BUNDLE_INVENTORY_PATH) return;
  try {
    bundleTreeFingerprint([{ path, size: 0, sha256: ZERO_HASH, executablePolicy: 'forbidden' }], { platform });
  } catch {
    fail(CODES.path);
  }
}

class RawTarScanner {
  constructor(manifest, onEntry) {
    this.manifest = manifest;
    this.onEntry = onEntry;
    this.header = Buffer.alloc(TAR_BLOCK_BYTES);
    this.headerOffset = 0;
    this.phase = 'header';
    this.contentRemaining = 0;
    this.paddingRemaining = 0;
    this.current = null;
    this.pendingPax = null;
    this.paxEntries = 0;
    this.regularEntries = 0;
    this.payloadEntries = 0;
    this.payloadBytes = 0;
    this.inventoryEntries = 0;
    this.paths = new Set();
    this.payloadPaths = [];
  }

  acceptHeader(block) {
    const header = decodeRawHeader(block);
    if (this.phase === 'second-zero') {
      if (header !== null) fail(CODES.tar);
      this.phase = 'done';
      return;
    }
    if (header === null) {
      if (this.pendingPax !== null) fail(CODES.pax);
      this.phase = 'second-zero';
      return;
    }

    if (header.typeByte === 0x78) {
      if (this.pendingPax !== null ||
          !/^PaxHeader\/[^/\\]+$/.test(header.path) || header.size > PAX_BODY_BYTES) fail(CODES.pax);
      this.paxEntries += 1;
      if (this.paxEntries > this.manifest.archive.entryCount) fail(CODES.pax);
      this.current = { kind: 'pax', size: header.size, body: Buffer.alloc(header.size), offset: 0 };
      this.startContent();
      return;
    }

    if (header.typeByte !== 0 && header.typeByte !== 0x30) fail(CODES.header);
    const rawPath = header.path;
    validatePayloadPath(rawPath, this.manifest.target.platform);
    let effectivePath = rawPath;
    let hadPax = false;
    if (this.pendingPax !== null) {
      effectivePath = this.pendingPax.get('path');
      if (this.pendingPax.has('size') && this.pendingPax.get('size') !== header.size) fail(CODES.pax);
      this.pendingPax = null;
      hadPax = true;
    }
    validatePayloadPath(effectivePath, this.manifest.target.platform);
    if (this.paths.has(effectivePath)) fail(CODES.entry);
    this.paths.add(effectivePath);

    this.regularEntries += 1;
    if (this.regularEntries > this.manifest.archive.entryCount) fail(CODES.entry);
    if (effectivePath === APPLICATION_BUNDLE_INVENTORY_PATH) {
      this.inventoryEntries += 1;
      if (this.inventoryEntries !== 1 || header.size !== this.manifest.inventory.byteLength) fail(CODES.inventory);
    } else {
      this.payloadEntries += 1;
      this.payloadBytes += header.size;
      if (!Number.isSafeInteger(this.payloadBytes) ||
          this.payloadEntries > this.manifest.inventory.payloadEntryCount ||
          this.payloadBytes > this.manifest.inventory.unpackedPayloadBytes) fail(CODES.payload);
      this.payloadPaths.push(effectivePath);
    }

    const descriptor = Object.freeze({
      path: effectivePath,
      size: header.size,
      tarType: header.typeByte === 0 ? 'OldFile' : 'File',
      pax: hadPax,
    });
    this.onEntry(descriptor);
    this.current = { kind: 'file', size: header.size };
    this.startContent();
  }

  startContent() {
    this.contentRemaining = this.current.size;
    this.paddingRemaining = (TAR_BLOCK_BYTES - (this.current.size % TAR_BLOCK_BYTES)) % TAR_BLOCK_BYTES;
    this.phase = this.contentRemaining === 0 ? 'padding' : 'content';
    if (this.phase === 'padding' && this.paddingRemaining === 0) this.finishCurrent();
  }

  finishCurrent() {
    if (this.current.kind === 'pax') this.pendingPax = parsePaxBody(this.current.body);
    this.current = null;
    this.phase = 'header';
  }

  write(input) {
    let offset = 0;
    while (offset < input.length) {
      if (this.phase === 'done') fail(CODES.tar);
      if (this.phase === 'header' || this.phase === 'second-zero') {
        const take = Math.min(input.length - offset, TAR_BLOCK_BYTES - this.headerOffset);
        input.copy(this.header, this.headerOffset, offset, offset + take);
        this.headerOffset += take;
        offset += take;
        if (this.headerOffset === TAR_BLOCK_BYTES) {
          const block = this.header;
          this.header = Buffer.alloc(TAR_BLOCK_BYTES);
          this.headerOffset = 0;
          this.acceptHeader(block);
        }
        continue;
      }
      if (this.phase === 'content') {
        const take = Math.min(input.length - offset, this.contentRemaining);
        if (this.current.kind === 'pax') {
          input.copy(this.current.body, this.current.offset, offset, offset + take);
          this.current.offset += take;
        }
        this.contentRemaining -= take;
        offset += take;
        if (this.contentRemaining === 0) {
          this.phase = 'padding';
          if (this.paddingRemaining === 0) this.finishCurrent();
        }
        continue;
      }
      if (this.phase === 'padding') {
        const take = Math.min(input.length - offset, this.paddingRemaining);
        for (let index = offset; index < offset + take; index += 1) if (input[index] !== 0) fail(CODES.tar);
        this.paddingRemaining -= take;
        offset += take;
        if (this.paddingRemaining === 0) this.finishCurrent();
      }
    }
  }

  end() {
    if (this.phase !== 'done' || this.headerOffset !== 0 || this.current !== null || this.pendingPax !== null) fail(CODES.tar);
    if (this.regularEntries !== this.manifest.archive.entryCount ||
        this.inventoryEntries !== 1 ||
        this.payloadEntries !== this.manifest.inventory.payloadEntryCount ||
        this.payloadBytes !== this.manifest.inventory.unpackedPayloadBytes) fail(CODES.payload);
    try {
      const records = this.payloadPaths
        .map((path) => ({ path, size: 0, sha256: ZERO_HASH, executablePolicy: 'forbidden' }))
        .sort((left, right) => utf8Compare(left.path, right.path));
      bundleTreeFingerprint(records, { platform: this.manifest.target.platform });
    } catch {
      fail(CODES.path);
    }
  }
}

function maximumTarBytes(manifest) {
  const data = manifest.inventory.byteLength + manifest.inventory.unpackedPayloadBytes;
  const perEntry = TAR_BLOCK_BYTES + (TAR_BLOCK_BYTES - 1) + TAR_BLOCK_BYTES + PAX_BODY_BYTES + (TAR_BLOCK_BYTES - 1);
  return data + manifest.archive.entryCount * perEntry + TAR_END_BYTES;
}

class TarPass {
  constructor({ manifest, mode, inspectionState, onFile }) {
    this.manifest = manifest;
    this.mode = mode;
    this.inspectionState = inspectionState;
    this.onFile = onFile;
    this.rawEntries = [];
    this.parserEntries = 0;
    this.parserMetadata = 0;
    this.actualFiles = [];
    this.inventoryParts = [];
    this.inventoryBytes = 0;
    this.failure = null;
    this.openEntries = new Set();
    this.handlerTail = Promise.resolve();
    this.scanner = new RawTarScanner(manifest, (entry) => this.rawEntries.push(entry));
    this.parser = new Parser({
      strict: true,
      gzip: false,
      brotli: false,
      zstd: false,
      maxMetaEntrySize: PAX_BODY_BYTES,
    });
    this.failed = new Promise((_, reject) => { this.rejectFailure = reject; });
    this.failed.catch(() => {});
    this.parserDone = once(this.parser, 'end');
    this.parserDone.catch(() => {});

    this.parser.on('meta', () => { this.parserMetadata += 1; });
    this.parser.on('ignoredEntry', () => this.setFailure(failure(CODES.header)));
    this.parser.on('warn', () => this.setFailure(failure(CODES.tar)));
    this.parser.on('error', () => this.setFailure(failure(CODES.tar), false));
    this.parser.on('entry', (entry) => this.queueEntry(entry));
  }

  setFailure(error, abortParser = true) {
    if (this.failure !== null) return;
    this.failure = boundedError(error, CODES.tar);
    this.rejectFailure(this.failure);
    if (abortParser) {
      try { this.parser.abort(this.failure); } catch { /* failure is already recorded */ }
    }
    for (const entry of this.openEntries) {
      try { entry.destroy(this.failure); } catch { /* failure is already recorded */ }
    }
  }

  queueEntry(entry) {
    entry.on('error', () => {});
    this.openEntries.add(entry);
    const close = () => this.openEntries.delete(entry);
    entry.once('end', close);
    entry.once('close', close);
    const descriptor = this.rawEntries.shift();
    const index = this.parserEntries;
    this.parserEntries += 1;
    if (descriptor === undefined) {
      this.setFailure(failure(CODES.entry));
      return;
    }
    this.handlerTail = this.handlerTail
      .then(() => {
        if (this.failure !== null) throw this.failure;
        return this.consumeEntry(entry, descriptor, index);
      })
      .catch((error) => { this.setFailure(error); });
  }

  async consumeEntry(entry, descriptor, index) {
    if (entry.type !== descriptor.tarType || entry.path !== descriptor.path || entry.size !== descriptor.size ||
        Boolean(entry.extended) !== descriptor.pax || entry.linkpath) fail(CODES.entry);

    let callbackRecord;
    if (this.mode === 'consume') {
      callbackRecord = this.inspectionState.files[index];
      if (callbackRecord === undefined || callbackRecord.path !== descriptor.path || callbackRecord.size !== descriptor.size) fail(CODES.inspection);
    }

    const hash = createHash('sha256');
    let seen = 0;
    let completed = false;
    const isInventory = descriptor.path === APPLICATION_BUNDLE_INVENTORY_PATH;
    const byteChunks = (async function* (pass) {
      try {
        for await (const value of entry) {
          if (!isBytes(value)) fail(CODES.tar);
          const bytes = asBuffer(value);
          seen += bytes.length;
          if (!Number.isSafeInteger(seen) || seen > descriptor.size) fail(CODES.entry);
          hash.update(bytes);
          if (isInventory) {
            pass.inventoryBytes += bytes.length;
            if (pass.inventoryBytes > DEPLOYMENT_ENVELOPE_LIMITS.inventoryBytes) fail(CODES.inventory);
            pass.inventoryParts.push(Buffer.from(bytes));
          }
          yield bytes;
        }
        completed = true;
      } catch (error) {
        throw boundedError(error, CODES.tar);
      }
    })(this);

    if (this.mode === 'consume') {
      try {
        await this.onFile(callbackRecord, byteChunks);
      } catch (error) {
        if (error instanceof ServiceArchiveError) throw error;
        fail(CODES.consumer);
      }
      if (!completed) fail(CODES.incomplete);
    } else {
      for await (const unused of byteChunks) void unused;
    }

    if (!completed || seen !== descriptor.size) fail(CODES.entry);
    const digest = hash.digest('hex');
    if (this.mode === 'consume' && digest !== callbackRecord.sha256) fail(CODES.payload);
    this.actualFiles.push(Object.freeze({ path: descriptor.path, size: seen, sha256: digest }));
  }

  async write(bytes) {
    if (this.failure !== null) throw this.failure;
    try {
      this.scanner.write(bytes);
    } catch (error) {
      this.setFailure(error);
      throw this.failure;
    }
    let writable;
    try {
      writable = this.parser.write(bytes);
    } catch {
      this.setFailure(failure(CODES.tar));
      throw this.failure;
    }
    if (!writable) {
      try {
        await Promise.race([once(this.parser, 'drain'), this.failed]);
      } catch (error) {
        throw this.failure ?? boundedError(error, CODES.tar);
      }
    }
    if (this.failure !== null) throw this.failure;
  }

  async end() {
    if (this.failure !== null) throw this.failure;
    try {
      this.scanner.end();
      this.parser.end();
      await Promise.race([this.parserDone, this.failed]);
      await Promise.race([this.handlerTail, this.failed]);
    } catch (error) {
      this.setFailure(boundedError(error, CODES.tar));
    }
    if (this.failure !== null) throw this.failure;
    if (this.rawEntries.length !== 0 || this.parserEntries !== this.manifest.archive.entryCount ||
        this.parserMetadata !== this.scanner.paxEntries || this.actualFiles.length !== this.parserEntries) fail(CODES.entry);
  }

  inventory() {
    if (this.inventoryBytes !== this.manifest.inventory.byteLength) fail(CODES.inventory);
    return Buffer.concat(this.inventoryParts, this.inventoryBytes);
  }
}

function parseAndValidateInventory(bytes, manifest) {
  if (bytes.length !== manifest.inventory.byteLength || sha256(bytes) !== manifest.inventory.sha256) fail(CODES.inventory);
  try {
    const inventory = parseCanonicalJsonBytes(bytes, INVENTORY_JSON_LIMITS);
    validateBundleInventory(inventory, { platform: manifest.target.platform });
    validateApplicationDeploymentManifest(manifest, inventory);
    return inventory;
  } catch (error) {
    throw boundedError(error, CODES.inventory);
  }
}

function bindVerifiedFiles(actualFiles, inventory, manifest) {
  const payload = new Map(inventory.payloadEntries.map((record) => [record.path, record]));
  const files = [];
  for (const actual of actualFiles) {
    let expected;
    if (actual.path === APPLICATION_BUNDLE_INVENTORY_PATH) {
      expected = {
        path: APPLICATION_BUNDLE_INVENTORY_PATH,
        size: manifest.inventory.byteLength,
        sha256: manifest.inventory.sha256,
        executablePolicy: 'forbidden',
      };
    } else {
      expected = payload.get(actual.path);
      if (expected === undefined) fail(CODES.payload);
      payload.delete(actual.path);
    }
    if (actual.size !== expected.size || actual.sha256 !== expected.sha256) fail(CODES.payload);
    files.push(Object.freeze({
      path: expected.path,
      size: expected.size,
      sha256: expected.sha256,
      executablePolicy: expected.executablePolicy,
    }));
  }
  if (payload.size !== 0 || files.length !== manifest.archive.entryCount) fail(CODES.payload);
  return Object.freeze(files);
}

async function executePass({ chunks, captured, mode, inspectionState, onFile }) {
  const manifest = captured.snapshot;
  const inflater = createInflateRaw();
  const feeder = new GzipFeeder(chunks, manifest.archive);
  const pass = new TarPass({ manifest, mode, inspectionState, onFile });
  const inflated = inflater[Symbol.asyncIterator]();
  const output = { crc: 0xffffffff, byteLength: 0 };
  let producerFailure = null;
  const producer = feeder.run(inflater).catch((error) => {
    producerFailure = error;
    pass.setFailure(error);
    inflater.destroy();
    throw error;
  });
  producer.catch(() => {});

  try {
    while (true) {
      const result = await Promise.race([inflated.next(), pass.failed]);
      if (result.done) break;
      const value = result.value;
      if (!isBytes(value)) fail(CODES.gzip);
      const bytes = asBuffer(value);
      output.byteLength += bytes.length;
      if (!Number.isSafeInteger(output.byteLength) || output.byteLength > maximumTarBytes(manifest)) fail(CODES.expansion);
      output.crc = updateCrc32(output.crc, bytes);
      await pass.write(bytes);
    }
    const framing = await Promise.race([producer, pass.failed]);
    const expectedCrc = framing.trailer.readUInt32LE(0);
    const expectedSize = framing.trailer.readUInt32LE(4);
    const actualCrc = (output.crc ^ 0xffffffff) >>> 0;
    if (expectedCrc !== actualCrc || expectedSize !== (output.byteLength >>> 0)) fail(CODES.gzip);
    await pass.end();
    assertManifestUnchanged(captured);
    return pass;
  } catch (error) {
    const reason = pass.failure ??
      (error instanceof ServiceArchiveError ? error : producerFailure ?? failure(CODES.gzip));
    pass.setFailure(reason);
    feeder.abort();
    inflater.destroy();
    try {
      const returned = inflated.return?.();
      if (returned !== undefined) Promise.resolve(returned).catch(() => {});
    } catch {
      // The original bounded parser failure remains authoritative.
    }
    throw reason;
  }
}

function makeInspection(captured, inventory, files) {
  const manifest = captured.snapshot;
  const inspection = Object.freeze({
    schemaVersion: 1,
    kind: INSPECTION_KIND,
    manifestFingerprint: manifest.manifestFingerprint,
    archiveByteLength: manifest.archive.byteLength,
    archiveSha256: manifest.archive.sha256,
    entryCount: manifest.archive.entryCount,
    inventoryFingerprint: inventory.inventoryFingerprint,
    treeFingerprint: inventory.treeFingerprint,
    files,
  });
  INSPECTIONS.set(inspection, Object.freeze({
    manifest: captured.identity,
    manifestBytes: captured.bytes,
    files,
    inventoryFingerprint: inventory.inventoryFingerprint,
    treeFingerprint: inventory.treeFingerprint,
  }));
  return inspection;
}

function inspectionFor(inspection, captured) {
  const state = inspection !== null && typeof inspection === 'object' ? INSPECTIONS.get(inspection) : undefined;
  if (state === undefined || state.manifest !== captured.identity || !state.manifestBytes.equals(captured.bytes)) fail(CODES.inspection);
  return state;
}

function readCallField(input, field) {
  try {
    if (input === null || typeof input !== 'object' || Array.isArray(input)) fail(CODES.input);
    return input[field];
  } catch (error) {
    throw boundedError(error, CODES.input);
  }
}

export async function inspectApplicationArchive(input = {}) {
  const manifest = readCallField(input, 'manifest');
  const captured = captureManifest(manifest);
  try {
    const chunks = readCallField(input, 'chunks');
    const pass = await executePass({ chunks, captured, mode: 'inspect' });
    const inventory = parseAndValidateInventory(pass.inventory(), captured.snapshot);
    const files = bindVerifiedFiles(pass.actualFiles, inventory, captured.snapshot);
    return makeInspection(captured, inventory, files);
  } catch (error) {
    throw boundedError(error, CODES.tar);
  }
}

export async function consumeApplicationArchive(input = {}) {
  const manifest = readCallField(input, 'manifest');
  const captured = captureManifest(manifest);
  try {
    const inspection = readCallField(input, 'inspection');
    const state = inspectionFor(inspection, captured);
    const onFile = readCallField(input, 'onFile');
    if (typeof onFile !== 'function') fail(CODES.input);
    const chunks = readCallField(input, 'chunks');
    const pass = await executePass({ chunks, captured, mode: 'consume', inspectionState: state, onFile });
    const inventory = parseAndValidateInventory(pass.inventory(), captured.snapshot);
    const files = bindVerifiedFiles(pass.actualFiles, inventory, captured.snapshot);
    if (inventory.inventoryFingerprint !== state.inventoryFingerprint || inventory.treeFingerprint !== state.treeFingerprint ||
        files.length !== state.files.length || files.some((record, index) =>
          record.path !== state.files[index].path || record.size !== state.files[index].size ||
          record.sha256 !== state.files[index].sha256 || record.executablePolicy !== state.files[index].executablePolicy)) fail(CODES.inspection);
  } catch (error) {
    throw boundedError(error, CODES.tar);
  }
}
