import assert from 'node:assert/strict';
import test from 'node:test';
import {
  STATUS_MESSAGE_TYPE,
  STATUS_PROTOCOL,
  createStatusProtocolDecoder,
  createStatusProtocolEndpoint,
  encodeStatusProtocolFrame,
} from '../src/service-status-protocol.js';

// Deterministic private wire/state tests only. These are not host, bridge,
// supervisor, command, descriptor-close, reaping, or deployment evidence.
const { CHECK, INVOKE, STOP, RESULT, DONE, ACK } = STATUS_MESSAGE_TYPE;
const NONCE = Buffer.from('00112233445566778899aabbccddeeff', 'hex');
const EMPTY = Buffer.alloc(0);
const MAX_PAYLOAD = 256 * 1024;
const MAX_CHUNK = 64 * 1024;
const MAX_U64 = (1n << 64n) - 1n;

function errorIs(reason) {
  return (error) => error.name === 'ServiceStatusProtocolError' &&
    error.code === `SERVICE_STATUS_PROTOCOL_${reason}` && error.message === error.code;
}

function wire({ type = CHECK, payload = EMPTY, nonce = NONCE, sequence = 1n,
  requestId = type === CHECK || type === INVOKE || type === RESULT ? 1n : 0n } = {}) {
  return encodeStatusProtocolFrame({ version: 1, type, flags: 0, nonce, sequence, requestId, payload });
}

// Only small wire-vector assertions collect snapshots. Production decoding is
// callback-only; the coalescing/burst tests below exercise that API directly.
function decoder(nextSequence = 1n, nonce = NONCE) {
  const reader = createStatusProtocolDecoder({ nonce, nextSequence });
  return {
    get pendingBytes() { return reader.pendingBytes; },
    get maximumPayloadAllocation() { return reader.maximumPayloadAllocation; },
    push(bytes) {
      const frames = [];
      reader.push(bytes, (frame) => { frames.push(frame); });
      return frames;
    },
    end() { reader.end(); },
  };
}

function pair() {
  return {
    requester: createStatusProtocolEndpoint({ nonce: NONCE, role: 'requester' }),
    responder: createStatusProtocolEndpoint({ nonce: NONCE, role: 'responder' }),
  };
}

function enqueue(endpoint, type, payload = EMPTY, requestId = 0n) {
  endpoint.enqueue({ type, requestId, payload });
}

function drain(source, target = null, maximumBytes = 40 + MAX_CHUNK) {
  const events = [];
  const chunks = [];
  for (let count = 0; count < 10000; count += 1) {
    const chunk = source.pull(maximumBytes);
    if (chunk === null) return { events, chunks };
    chunks.push(chunk);
    if (target !== null) events.push(...target.receive(chunk));
  }
  assert.fail('transmission did not terminate within its bounded test allowance');
}

function chunkPayload(bytes, { total = bytes.length, offset = 0, result = false, stop = null } = {}) {
  const prefix = result ? 13 + (stop?.length ?? 0) : 8;
  const payload = Buffer.alloc(prefix + bytes.length);
  payload.writeUInt32BE(total, 0);
  payload.writeUInt32BE(offset, 4);
  if (result) {
    payload[8] = stop === null ? 0 : 1;
    payload.writeUInt32BE(stop?.length ?? 0, 9);
    stop?.copy(payload, 13);
  }
  bytes.copy(payload, prefix);
  return payload;
}

function admit(requester, responder, type = INVOKE, requestId = 1n, bytes = Buffer.from('request')) {
  enqueue(requester, type, bytes, requestId);
  const { events } = drain(requester, responder);
  assert.equal(events.length, 1);
  assert.equal(events[0].type, type);
  assert.equal(events[0].requestId, requestId);
  assert.deepEqual(events[0].payload, bytes);
}

test('v1 has an exact 40-byte big-endian header and explicit native-compatible codes 1..6', () => {
  assert.deepEqual(STATUS_MESSAGE_TYPE, { CHECK: 1, INVOKE: 2, STOP: 3, RESULT: 4, DONE: 5, ACK: 6 });
  const bytes = wire({
    payload: Buffer.from('deadbeef', 'hex'),
    sequence: 0x0102030405060708n,
    requestId: 0xfedcba9876543210n,
  });
  assert.equal(bytes.toString('hex'),
    '000000040101000000112233445566778899aabbccddeeff0102030405060708fedcba9876543210deadbeef');
  const [frame] = decoder(0x0102030405060708n).push(bytes);
  assert.equal(frame.sequence, 0x0102030405060708n);
  assert.equal(frame.requestId, 0xfedcba9876543210n);
  assert.equal(frame.version, 1);
  assert.equal(frame.flags, 0);
  assert.deepEqual(frame.payload, Buffer.from('deadbeef', 'hex'));
  assert.equal(STATUS_PROTOCOL.headerBytes, bytes.length - 4);
});

test('all header/body split points, empty fragments and coalesced frames decode exactly once', () => {
  const encoded = wire({ payload: Buffer.from([7, 8, 9]) });
  for (let split = 0; split <= encoded.length; split += 1) {
    const reader = decoder();
    const frames = [...reader.push(encoded.subarray(0, split)), ...reader.push(EMPTY),
      ...reader.push(encoded.subarray(split))];
    assert.equal(frames.length, 1, `split ${split}`);
    assert.deepEqual(frames[0].payload, Buffer.from([7, 8, 9]));
    assert.equal(reader.pendingBytes, 0);
    reader.end();
  }
  const reader = decoder();
  const frames = reader.push(Buffer.concat([
    wire(), wire({ type: STOP, sequence: 2n }), wire({ type: DONE, sequence: 3n }),
  ]));
  assert.deepEqual(frames.map((frame) => frame.type), [CHECK, STOP, DONE]);
  assert.deepEqual(frames.map((frame) => frame.sequence), [1n, 2n, 3n]);
  reader.end();
});

test('payload boundary 256 KiB is exact and fragmentation retains at most one bounded body', () => {
  for (const size of [0, 1, MAX_CHUNK - 1, MAX_CHUNK, MAX_CHUNK + 1, MAX_PAYLOAD]) {
    const bytes = Buffer.alloc(size, 0x5a);
    const encoded = wire({ payload: bytes });
    const reader = decoder();
    const frames = [];
    for (let offset = 0; offset < encoded.length; offset += 17) {
      frames.push(...reader.push(encoded.subarray(offset, offset + 17)));
      assert.ok(reader.pendingBytes <= 40 + MAX_PAYLOAD);
    }
    assert.equal(frames.length, 1);
    assert.deepEqual(frames[0].payload, bytes);
    assert.equal(reader.maximumPayloadAllocation, size);
    reader.end();
  }
  assert.throws(() => wire({ payload: Buffer.alloc(MAX_PAYLOAD + 1) }), errorIs('LENGTH'));
  const reader = decoder();
  const encoded = wire({ payload: Buffer.alloc(MAX_CHUNK, 0xa5) });
  let completed = 0;
  for (let index = 0; index < encoded.length; index += 1) {
    for (const frame of reader.push(encoded.subarray(index, index + 1))) {
      completed += 1;
      assert.deepEqual(frame.payload, Buffer.alloc(MAX_CHUNK, 0xa5));
    }
  }
  assert.equal(completed, 1);
  assert.equal(reader.maximumPayloadAllocation, MAX_CHUNK);
});

test('invalid headers refuse before body allocation, including oversized and unsigned u32 lengths', () => {
  const mutations = [
    ['LENGTH', (bytes) => bytes.writeUInt32BE(MAX_PAYLOAD + 1, 0)],
    ['LENGTH', (bytes) => bytes.writeUInt32BE(0xffffffff, 0)],
    ['VERSION', (bytes) => { bytes[4] = 0; }],
    ['VERSION', (bytes) => { bytes[4] = 2; }],
    ['TYPE', (bytes) => { bytes[5] = 0; }],
    ['TYPE', (bytes) => { bytes[5] = 7; }],
    ['TYPE', (bytes) => { bytes[5] = 255; }],
    ['FLAGS', (bytes) => bytes.writeUInt16BE(1, 6)],
    ['FLAGS', (bytes) => bytes.writeUInt16BE(0x8000, 6)],
    ['NONCE', (bytes) => { bytes[8] ^= 1; }],
    ['UINT64', (bytes) => bytes.writeBigUInt64BE(0n, 24)],
    ['SEQUENCE', (bytes) => bytes.writeBigUInt64BE(2n, 24)],
    ['REQUEST_ID', (bytes) => bytes.writeBigUInt64BE(0n, 32)],
    ['REQUEST_ID', (bytes) => { bytes[5] = STOP; }],
  ];
  for (const [reason, mutate] of mutations) {
    const reader = decoder();
    const header = wire({ payload: Buffer.alloc(1024) }).subarray(0, 40);
    mutate(header);
    assert.deepEqual(reader.push(header.subarray(0, 39)), []);
    assert.equal(reader.maximumPayloadAllocation, 0);
    assert.throws(() => reader.push(Buffer.concat([header.subarray(39), Buffer.alloc(4096)])), errorIs(reason));
    assert.equal(reader.maximumPayloadAllocation, 0, reason);
    assert.throws(() => reader.push(wire()), errorIs(reason));
    assert.throws(() => reader.end(), errorIs(reason));
  }
});

test('nonce/sequence/request ids are exact uint64 BigInts, nonwrapping and replay resistant', () => {
  for (const sequence of [0n, -1n, MAX_U64 + 1n, 1, Number.MAX_SAFE_INTEGER, '1']) {
    assert.throws(() => wire({ sequence }), errorIs('UINT64'));
  }
  for (const requestId of [-1n, MAX_U64 + 1n, 1, '1']) {
    assert.throws(() => wire({ requestId }), errorIs('UINT64'));
  }
  for (const nonce of [Buffer.alloc(0), Buffer.alloc(15), Buffer.alloc(17)]) {
    assert.throws(() => wire({ nonce }), /SERVICE_STATUS_PROTOCOL_(NONCE|LENGTH)/);
  }
  const reader = decoder(MAX_U64);
  const [frame] = reader.push(wire({ sequence: MAX_U64, requestId: MAX_U64 }));
  assert.equal(frame.sequence, MAX_U64);
  assert.equal(frame.requestId, MAX_U64);
  assert.throws(() => reader.push(wire()), errorIs('SEQUENCE_EXHAUSTED'));
  const complete = decoder(MAX_U64);
  complete.push(wire({ sequence: MAX_U64 }));
  complete.end();
  for (const sequence of [1n, 3n]) {
    const replay = decoder();
    replay.push(wire());
    assert.throws(() => replay.push(wire({ sequence })), errorIs('SEQUENCE'));
  }
});

test('encoder and decoder keep independent nonce/payload snapshots; returned bytes cannot mutate evidence', () => {
  const nonce = Buffer.from(NONCE);
  const reader = decoder(1n, nonce);
  nonce.fill(0);
  const payload = Buffer.from('abcdef');
  const encoded = wire({ payload });
  payload.fill(0);
  const tail = Buffer.from(encoded.subarray(43));
  reader.push(encoded.subarray(0, 43));
  encoded.fill(0);
  const [frame] = reader.push(tail);
  assert.deepEqual(frame.payload, Buffer.from('abcdef'));
  frame.payload.fill(0);
  frame.nonce.fill(0);
  new Uint8Array(frame.payload.buffer).fill(0);
  new Uint8Array(frame.nonce.buffer).fill(0);
  assert.deepEqual(frame.payload, Buffer.from('abcdef'));
  assert.deepEqual(frame.nonce, NONCE);
  assert.ok(Object.isFrozen(frame));
  assert.throws(() => { frame.requestId = 2n; }, TypeError);
});

test('closed metadata schemas refuse accessors, inherited fields, symbols and proxies without invoking getters', () => {
  let calls = 0;
  const base = { version: 1, type: CHECK, flags: 0, nonce: NONCE, sequence: 1n, requestId: 1n, payload: EMPTY };
  const accessor = { ...base };
  Object.defineProperty(accessor, 'sequence', { enumerable: true, get() { calls += 1; return 1n; } });
  const proxy = new Proxy(base, {
    get() { calls += 1; throw new Error('raw getter'); },
    ownKeys() { calls += 1; throw new Error('raw keys'); },
    getPrototypeOf() { calls += 1; throw new Error('raw prototype'); },
  });
  for (const metadata of [accessor, proxy, { ...base, extra: 1 }, { ...base, [Symbol('extra')]: 1 },
    Object.create(base), Object.assign(Object.create(null), base)]) {
    assert.throws(() => encodeStatusProtocolFrame(metadata), errorIs('INVALID'));
  }
  const options = { nonce: NONCE, nextSequence: 1n };
  Object.defineProperty(options, 'nonce', { enumerable: true, get() { calls += 1; return NONCE; } });
  assert.throws(() => createStatusProtocolDecoder(options), errorIs('INVALID'));
  const endpointOptions = { nonce: NONCE, role: 'requester' };
  Object.defineProperty(endpointOptions, 'role', { enumerable: true, get() { calls += 1; return 'requester'; } });
  assert.throws(() => createStatusProtocolEndpoint(endpointOptions), errorIs('INVALID'));
  const { requester } = pair();
  const message = { type: CHECK, requestId: 1n, payload: EMPTY };
  Object.defineProperty(message, 'payload', { enumerable: true, get() { calls += 1; return EMPTY; } });
  assert.throws(() => requester.enqueue(message), errorIs('INVALID'));
  assert.equal(calls, 0);
});

test('byte inputs reject shared/proxied/non-byte views and do not read caller byte metadata getters', () => {
  for (const payload of ['bytes', [], new Uint16Array(1), new DataView(new ArrayBuffer(1)),
    new Proxy(Buffer.alloc(1), {}), new Uint8Array(new SharedArrayBuffer(1))]) {
    assert.throws(() => wire({ payload }), errorIs('BYTES'));
    assert.throws(() => decoder().push(payload), errorIs('BYTES'));
  }
  const payload = new Uint8Array([1, 2, 3]);
  for (const key of ['buffer', 'byteOffset', 'byteLength']) {
    Object.defineProperty(payload, key, { get() { throw new Error('must not call byte metadata getter'); } });
  }
  assert.deepEqual(decoder().push(wire({ payload }))[0].payload, Buffer.from([1, 2, 3]));
});

test('EOF is terminal: partial headers/bodies poison, complete framing alone is not endpoint settlement', () => {
  const encoded = wire({ payload: Buffer.from([1, 2]) });
  for (const length of [1, 7, 39, 40, 41]) {
    const reader = decoder();
    reader.push(encoded.subarray(0, length));
    assert.throws(() => reader.end(), errorIs('PARTIAL_EOF'));
    assert.throws(() => reader.push(encoded.subarray(length)), errorIs('PARTIAL_EOF'));
  }
  const reader = decoder();
  reader.end();
  assert.throws(() => reader.push(EMPTY), errorIs('EOF'));
  assert.throws(() => pair().requester.end(), errorIs('PREMATURE_EOF'));
  const { requester } = pair();
  requester.receive(wire({ type: STOP }));
  assert.equal(requester.state, 'STOPPING');
  assert.throws(() => requester.end(), errorIs('PREMATURE_EOF'));
});

test('large logical requests/results use <=64 KiB wire chunks with exact total/offset reassembly', () => {
  for (const size of [0, 1, MAX_CHUNK - 8, MAX_CHUNK - 7, MAX_CHUNK, MAX_CHUNK + 1, MAX_PAYLOAD]) {
    const { requester, responder } = pair();
    const payload = Buffer.alloc(size, 0x63);
    enqueue(requester, INVOKE, payload, 9007199254740993n);
    const sent = drain(requester, responder);
    assert.equal(sent.events.length, 1);
    assert.deepEqual(sent.events[0].payload, payload);
    assert.equal(sent.events[0].requestId, 9007199254740993n);
    const frames = decoder().push(Buffer.concat(sent.chunks));
    let offset = 0;
    for (const frame of frames) {
      assert.ok(frame.payload.length <= MAX_CHUNK);
      assert.equal(frame.payload.readUInt32BE(0), size);
      assert.equal(frame.payload.readUInt32BE(4), offset);
      offset += frame.payload.length - 8;
    }
    assert.equal(offset, size);
    enqueue(responder, RESULT, payload, 9007199254740993n);
    const reply = drain(responder, requester);
    assert.equal(reply.events.length, 1);
    assert.deepEqual(reply.events[0].payload, payload);
    assert.equal(reply.events[0].stop, null);
    for (const frame of decoder().push(Buffer.concat(reply.chunks))) assert.ok(frame.payload.length <= MAX_CHUNK);
    assert.equal(requester.outstandingRequestId, null);
    assert.equal(responder.outstandingRequestId, null);
  }
});

test('directional sequences and request correlation are independent, single-outstanding and monotonic', () => {
  const { requester, responder } = pair();
  admit(requester, responder, CHECK, MAX_U64);
  enqueue(responder, RESULT, EMPTY, MAX_U64);
  drain(responder, requester, 1);
  assert.throws(() => enqueue(requester, CHECK, EMPTY, 1n), errorIs('REQUEST_ORDER'));
  const busy = pair();
  enqueue(busy.requester, CHECK, EMPTY, 1n);
  assert.throws(() => enqueue(busy.requester, INVOKE, EMPTY, 2n), errorIs('REQUEST_ORDER'));
  const wrong = pair();
  admit(wrong.requester, wrong.responder);
  assert.throws(() => enqueue(wrong.responder, RESULT, EMPTY, 2n), errorIs('CORRELATION'));
  const unsolicited = pair();
  assert.throws(() => unsolicited.requester.receive(wire({ type: RESULT, payload: chunkPayload(EMPTY, { result: true }) })),
    errorIs('CORRELATION'));
  const notSent = pair();
  enqueue(notSent.requester, CHECK, EMPTY, 1n);
  assert.throws(() => notSent.requester.receive(wire({ type: RESULT, payload: chunkPayload(EMPTY, { result: true }) })),
    errorIs('CORRELATION'));
});

test('first local STOP sticks, cancels unsent requests and prevents forward work', () => {
  const { requester, responder } = pair();
  enqueue(requester, INVOKE, Buffer.from('never admitted'), 1n);
  const reason = Buffer.from('deadline');
  enqueue(requester, STOP, reason);
  reason.fill(0);
  enqueue(requester, STOP, Buffer.from('later signal'));
  const sent = drain(requester, responder);
  assert.deepEqual(sent.events.map((event) => event.type), [STOP]);
  assert.deepEqual(requester.stop, Buffer.from('deadline'));
  assert.deepEqual(responder.stop, Buffer.from('deadline'));
  assert.equal(requester.outstandingRequestId, null);
  requester.stop.fill(0);
  assert.deepEqual(requester.stop, Buffer.from('deadline'));
  assert.throws(() => enqueue(requester, CHECK, EMPTY, 2n), errorIs('REQUEST_ORDER'));
  assert.equal(requester.state, 'STOPPING');
});

test('STOP outranks unsent RESULT; even an empty stop has a present immutable result snapshot', () => {
  for (const stop of [EMPTY, Buffer.from('cancel'), Buffer.alloc(1024, 7)]) {
    const { requester, responder } = pair();
    admit(requester, responder);
    enqueue(responder, RESULT, Buffer.from('receipt'), 1n);
    enqueue(responder, STOP, stop);
    const { events, chunks } = drain(responder, requester);
    assert.deepEqual(events.map((event) => event.type), [STOP, RESULT]);
    assert.deepEqual(events[1].stop, stop);
    events[1].stop.fill(0);
    assert.deepEqual(events[1].stop, stop);
    const frames = decoder().push(Buffer.concat(chunks));
    assert.equal(frames[1].payload[8], 1);
    assert.equal(frames[1].payload.readUInt32BE(9), stop.length);
    assert.equal(requester.state, 'STOPPING');
    assert.equal(responder.state, 'STOPPING');
  }
  const { requester } = pair();
  assert.throws(() => enqueue(requester, STOP, Buffer.alloc(1025)), errorIs('STOP'));
});

test('STOP finishes a partial RESULT frame, then precedes its continuation with a sticky snapshot', () => {
  const { requester, responder } = pair();
  admit(requester, responder);
  const receipt = Buffer.alloc(MAX_PAYLOAD, 0xa3);
  enqueue(responder, RESULT, receipt, 1n);
  const prefix = responder.pull(7);
  assert.deepEqual(requester.receive(prefix), []);
  enqueue(responder, STOP, Buffer.from('signal'));
  const { events, chunks } = drain(responder, requester, 997);
  assert.deepEqual(events.map((event) => event.type), [STOP, RESULT]);
  assert.deepEqual(events[1].payload, receipt);
  assert.deepEqual(events[1].stop, Buffer.from('signal'));
  const frames = decoder().push(Buffer.concat([prefix, ...chunks]));
  assert.deepEqual(frames.slice(0, 3).map((frame) => frame.type), [RESULT, STOP, RESULT]);
  assert.equal(frames[0].payload[8], 0);
  assert.equal(frames[2].payload[8], 1);
  assert.deepEqual(frames.map((frame) => frame.sequence), frames.map((_, index) => BigInt(index + 1)));
});

test('STOP abandons an incomplete request without delivering an invocation or stranding correlation', () => {
  const { requester, responder } = pair();
  enqueue(requester, INVOKE, Buffer.alloc(MAX_PAYLOAD, 1), 1n);
  const prefix = requester.pull(41);
  assert.deepEqual(responder.receive(prefix), []);
  enqueue(requester, STOP, Buffer.from('cancel partial request'));
  const { events } = drain(requester, responder);
  assert.deepEqual(events.map((event) => event.type), [STOP]);
  const canceled = drain(responder, requester).events;
  assert.equal(canceled.length, 1);
  assert.equal(canceled[0].type, RESULT);
  assert.equal(canceled[0].canceled, true);
  assert.equal(requester.outstandingRequestId, null);
  assert.equal(responder.outstandingRequestId, null);
  enqueue(responder, DONE, Buffer.from('not invoked'));
  drain(responder, requester);
  enqueue(requester, ACK);
  drain(requester, responder);
  requester.end();
  responder.end();
});

test('received STOP cannot be cleared by a later local stop, and an active completed request still drains its result', () => {
  const { requester, responder } = pair();
  admit(requester, responder);
  enqueue(requester, STOP, Buffer.from('first'));
  drain(requester, responder);
  enqueue(responder, STOP, Buffer.from('later'));
  enqueue(responder, RESULT, Buffer.from('settled command evidence'), 1n);
  const { events } = drain(responder, requester);
  assert.deepEqual(events.map((event) => event.type), [RESULT]);
  assert.equal(events[0].canceled, false);
  assert.deepEqual(events[0].stop, Buffer.from('first'));
  assert.deepEqual(responder.stop, Buffer.from('first'));
});

test('DONE/ACK transition through STOPPING to protocol SETTLED and only then accept terminal EOF', () => {
  const { requester, responder } = pair();
  admit(requester, responder);
  enqueue(responder, RESULT, Buffer.from('result'), 1n);
  drain(responder, requester);
  enqueue(responder, DONE, Buffer.alloc(MAX_CHUNK + 1, 0x42));
  assert.equal(responder.state, 'STOPPING');
  const { events } = drain(responder, requester, 991);
  assert.deepEqual(events.map((event) => event.type), [DONE]);
  assert.equal(requester.state, 'STOPPING');
  assert.equal(responder.state, 'STOPPING');
  enqueue(requester, ACK);
  const ackStart = requester.pull(1);
  responder.receive(ackStart);
  assert.equal(requester.state, 'STOPPING');
  drain(requester, responder);
  assert.equal(requester.state, 'SETTLED');
  assert.equal(responder.state, 'SETTLED');
  requester.end();
  responder.end();
  assert.throws(() => requester.receive(EMPTY), errorIs('EOF'));
  assert.throws(() => responder.pull(1), errorIs('EOF'));
});

test('W may be the requester and send DONE; its peer ACKs without another forward grant', () => {
  const { requester, responder } = pair();
  admit(requester, responder, CHECK);
  enqueue(responder, RESULT, EMPTY, 1n);
  drain(responder, requester);
  enqueue(requester, DONE, Buffer.from('W outcome evidence'));
  const { events } = drain(requester, responder);
  assert.deepEqual(events.map((event) => event.type), [DONE]);
  assert.deepEqual(events[0].payload, Buffer.from('W outcome evidence'));
  enqueue(responder, ACK);
  drain(responder, requester);
  assert.equal(requester.state, 'SETTLED');
  assert.equal(responder.state, 'SETTLED');
  requester.end();
  responder.end();
});

test('simultaneous STOP preserves each local first stop and transmits the responder snapshot unchanged', () => {
  const { requester, responder } = pair();
  admit(requester, responder);
  enqueue(requester, STOP, Buffer.from('F stop'));
  enqueue(responder, STOP, Buffer.from('W stop'));
  drain(requester, responder);
  drain(responder, requester);
  enqueue(responder, RESULT, Buffer.from('evidence'), 1n);
  const { events } = drain(responder, requester);
  assert.deepEqual(requester.stop, Buffer.from('F stop'));
  assert.deepEqual(responder.stop, Buffer.from('W stop'));
  assert.deepEqual(events[0].stop, Buffer.from('W stop'));
  new Uint8Array(events[0].payload.buffer).fill(0);
  new Uint8Array(events[0].stop.buffer).fill(0);
  new Uint8Array(requester.stop.buffer).fill(0);
  assert.deepEqual(events[0].payload, Buffer.from('evidence'));
  assert.deepEqual(events[0].stop, Buffer.from('W stop'));
  assert.deepEqual(requester.stop, Buffer.from('F stop'));
});

test('premature DONE/ACK, duplicate requests/results/STOP, role violations and unknown messages poison endpoints', () => {
  const beforeDone = pair();
  assert.throws(() => enqueue(beforeDone.requester, ACK), errorIs('ACK_ORDER'));
  const ackBeforeDone = pair();
  assert.throws(() => ackBeforeDone.responder.receive(wire({ type: ACK })), errorIs('ACK_ORDER'));
  const outstanding = pair();
  admit(outstanding.requester, outstanding.responder);
  assert.throws(() => enqueue(outstanding.responder, DONE), errorIs('DONE_ORDER'));
  const duplicate = pair();
  admit(duplicate.requester, duplicate.responder);
  const repeated = wire({ type: INVOKE, sequence: 2n, payload: chunkPayload(EMPTY) });
  assert.throws(() => duplicate.responder.receive(repeated), errorIs('REQUEST_ORDER'));
  const result = pair();
  admit(result.requester, result.responder);
  enqueue(result.responder, RESULT, EMPTY, 1n);
  drain(result.responder, result.requester);
  assert.throws(() => result.requester.receive(wire({ type: RESULT, sequence: 2n,
    payload: chunkPayload(EMPTY, { result: true }) })), errorIs('CORRELATION'));
  const stopped = pair();
  stopped.requester.receive(wire({ type: STOP, payload: Buffer.from('one') }));
  assert.throws(() => stopped.requester.receive(wire({ type: STOP, sequence: 2n, payload: Buffer.from('two') })),
    errorIs('DUPLICATE_STOP'));
  assert.deepEqual(stopped.requester.stop, Buffer.from('one'));
  const role = pair();
  assert.throws(() => enqueue(role.responder, CHECK, EMPTY, 1n), errorIs('REQUEST_ORDER'));
  const unknown = pair();
  assert.throws(() => enqueue(unknown.requester, 7), errorIs('TYPE'));
  assert.throws(() => unknown.requester.pull(1), errorIs('TYPE'));
});

test('endpoint control payloads, terminal duplication and request replays fail closed', () => {
  const oversizedStop = pair();
  assert.throws(() => oversizedStop.requester.receive(wire({ type: STOP, payload: Buffer.alloc(1025) })),
    errorIs('STOP'));
  const badAck = pair();
  enqueue(badAck.responder, DONE);
  drain(badAck.responder, badAck.requester);
  assert.throws(() => badAck.responder.receive(wire({ type: ACK, payload: Buffer.from([1]) })), errorIs('ACK_ORDER'));
  const duplicateDone = pair();
  duplicateDone.requester.receive(wire({ type: DONE, payload: chunkPayload(EMPTY) }));
  assert.throws(() => duplicateDone.requester.receive(wire({ type: DONE, sequence: 2n, payload: chunkPayload(EMPTY) })),
    errorIs('DONE_ORDER'));
  const replay = pair();
  admit(replay.requester, replay.responder);
  enqueue(replay.responder, RESULT, EMPTY, 1n);
  drain(replay.responder, replay.requester);
  assert.throws(() => replay.responder.receive(wire({ type: INVOKE, sequence: 2n, payload: chunkPayload(EMPTY) })),
    errorIs('REQUEST_ORDER'));
  const wrongNonce = pair();
  assert.throws(() => wrongNonce.responder.receive(wire({ type: INVOKE, nonce: Buffer.alloc(16),
    payload: chunkPayload(EMPTY) })), errorIs('NONCE'));
  assert.equal(wrongNonce.responder.state, 'STOPPING');
  assert.throws(() => wrongNonce.responder.pull(1), errorIs('NONCE'));
});

test('malformed chunk totals, offsets, lengths, order and interleaving refuse without an application event', () => {
  const cases = [
    [Buffer.alloc(7), 'CHUNK'],
    [chunkPayload(EMPTY, { total: MAX_PAYLOAD + 1 }), 'CHUNK'],
    [chunkPayload(Buffer.from([1]), { total: 0 }), 'CHUNK'],
    [chunkPayload(EMPTY, { total: 1 }), 'CHUNK'],
    [chunkPayload(Buffer.from([1]), { total: 2, offset: 1 }), 'CHUNK'],
    [chunkPayload(Buffer.alloc(MAX_CHUNK)), 'CHUNK'],
  ];
  for (const [payload, reason] of cases) {
    const { responder } = pair();
    assert.throws(() => responder.receive(wire({ type: INVOKE, payload })), errorIs(reason));
    assert.equal(responder.state, 'STOPPING');
  }
  for (const second of [
    { type: INVOKE, requestId: 1n, payload: chunkPayload(Buffer.from([2]), { total: 2, offset: 0 }) },
    { type: CHECK, requestId: 1n, payload: chunkPayload(Buffer.from([2]), { total: 2, offset: 1 }) },
    { type: INVOKE, requestId: 2n, payload: chunkPayload(Buffer.from([2]), { total: 2, offset: 1 }) },
    { type: INVOKE, requestId: 1n, payload: chunkPayload(Buffer.from([2]), { total: 3, offset: 1 }) },
  ]) {
    const { responder } = pair();
    assert.deepEqual(responder.receive(wire({ type: INVOKE,
      payload: chunkPayload(Buffer.from([1]), { total: 2 }) })), []);
    assert.throws(() => responder.receive(wire({ ...second, sequence: 2n })), errorIs('CHUNK_ORDER'));
  }
});

test('RESULT snapshots reject invalid presence/length, changes, disappearance and omission after peer STOP', () => {
  const malformed = [];
  const badPresence = chunkPayload(EMPTY, { result: true });
  badPresence[8] = 2;
  malformed.push(badPresence);
  const absentWithLength = chunkPayload(EMPTY, { result: true });
  absentWithLength.writeUInt32BE(1, 9);
  malformed.push(absentWithLength);
  const missingBytes = chunkPayload(EMPTY, { result: true });
  missingBytes[8] = 1;
  missingBytes.writeUInt32BE(1025, 9);
  malformed.push(missingBytes);
  for (const payload of malformed) {
    const { requester, responder } = pair();
    admit(requester, responder);
    assert.throws(() => requester.receive(wire({ type: RESULT, payload })), errorIs('STOP_SNAPSHOT'));
  }
  for (const nextStop of [null, Buffer.from('changed')]) {
    const { requester, responder } = pair();
    admit(requester, responder);
    requester.receive(wire({ type: RESULT, payload: chunkPayload(Buffer.from([1]), {
      total: 2, result: true, stop: Buffer.from('first'),
    }) }));
    assert.throws(() => requester.receive(wire({ type: RESULT, sequence: 2n, payload: chunkPayload(Buffer.from([2]), {
      total: 2, offset: 1, result: true, stop: nextStop,
    }) })), errorIs('STOP_SNAPSHOT'));
  }
  const { requester, responder } = pair();
  admit(requester, responder);
  requester.receive(wire({ type: STOP, payload: Buffer.from('peer stop') }));
  assert.throws(() => requester.receive(wire({ type: RESULT, sequence: 2n,
    payload: chunkPayload(EMPTY, { result: true }) })), errorIs('STOP_SNAPSHOT'));
});

test('EOF with a logical partial message or pending ACK is never successful settlement', () => {
  const { responder } = pair();
  responder.receive(wire({ type: INVOKE, payload: chunkPayload(Buffer.from([1]), { total: 2 }) }));
  assert.throws(() => responder.end(), errorIs('PREMATURE_EOF'));
  const pending = pair();
  enqueue(pending.responder, DONE);
  drain(pending.responder, pending.requester);
  enqueue(pending.requester, ACK);
  assert.throws(() => pending.requester.end(), errorIs('PREMATURE_EOF'));
  const partial = pair();
  partial.requester.receive(wire({ type: STOP }).subarray(0, 39));
  assert.throws(() => partial.requester.end(), errorIs('PARTIAL_EOF'));
});

test('coalesced 256-KiB one-byte chunks consume synchronously with one completed logical event', () => {
  const frameBytes = 49; // 40-byte header + 8-byte chunk prefix + one byte.
  const coalesced = Buffer.alloc(frameBytes * MAX_PAYLOAD);
  const template = wire({ type: INVOKE, payload: chunkPayload(Buffer.from([0x5a]), { total: MAX_PAYLOAD }) });
  for (let index = 0; index < MAX_PAYLOAD; index += 1) {
    const start = index * frameBytes;
    template.copy(coalesced, start);
    coalesced.writeBigUInt64BE(BigInt(index + 1), start + 24);
    coalesced.writeUInt32BE(index, start + 44);
  }
  const reader = createStatusProtocolDecoder({ nonce: NONCE, nextSequence: 1n });
  let consumed = 0n;
  reader.push(coalesced, (frame) => {
    consumed += 1n;
    // Callback delivery precedes parsing the next frame; no output batch is
    // retained and the pending body has already been released.
    assert.equal(reader.decodedFrames, consumed);
    assert.equal(reader.pendingBytes, 0);
    assert.equal(frame.payload.length, 9);
  });
  assert.equal(consumed, BigInt(MAX_PAYLOAD));
  assert.equal(reader.maximumPayloadAllocation, 9);
  reader.end();
  const { responder } = pair();
  const events = responder.receive(coalesced);
  assert.equal(events.length, 1);
  assert.equal(responder.decodedFrames, BigInt(MAX_PAYLOAD));
  assert.deepEqual(events[0].payload, Buffer.alloc(MAX_PAYLOAD, 0x5a));
  assert.equal(responder.outstandingRequestId, 1n);
});

test('coalesced control bursts stop at the second STOP, before inspecting their malformed tail', () => {
  const burst = Buffer.alloc(40 * 4096);
  const template = wire({ type: STOP });
  for (let index = 0; index < 4096; index += 1) {
    template.copy(burst, index * 40);
    burst.writeBigUInt64BE(BigInt(index + 1), index * 40 + 24);
  }
  burst[2 * 40 + 4] = 255;
  const { requester } = pair();
  assert.throws(() => requester.receive(burst), errorIs('DUPLICATE_STOP'));
  assert.equal(requester.decodedFrames, 2n);
  assert.equal(requester.state, 'STOPPING');
  const reader = createStatusProtocolDecoder({ nonce: NONCE, nextSequence: 1n });
  let consumed = 0;
  assert.throws(() => reader.push(burst, () => {
    consumed += 1;
    if (consumed === 2) throw new Error('consumer refusal');
  }), errorIs('INVALID'));
  assert.equal(consumed, 2);
  assert.equal(reader.decodedFrames, 2n);
  assert.equal(reader.maximumPayloadAllocation, 0);
  assert.throws(() => reader.push(EMPTY, () => {}), errorIs('INVALID'));
});

test('decoder requires incremental consumption and poisons reentrancy even when the consumer catches it', () => {
  const missing = createStatusProtocolDecoder({ nonce: NONCE, nextSequence: 1n });
  assert.throws(() => missing.push(wire()), errorIs('CONSUMER'));
  const reader = createStatusProtocolDecoder({ nonce: NONCE, nextSequence: 1n });
  assert.throws(() => reader.push(wire(), () => {
    assert.throws(() => reader.push(EMPTY, () => {}), errorIs('REENTRANT'));
  }), errorIs('REENTRANT'));
  assert.equal(reader.decodedFrames, 1n);
});

test('receiver STOP drains partial headers/bodies of single- and multi-frame requests without admission', () => {
  for (const type of [CHECK, INVOKE]) {
    for (const size of [3, MAX_PAYLOAD]) {
      for (const split of [1, 7, 39, 40, 41, 47, 48, 49]) {
        const { requester, responder } = pair();
        enqueue(requester, type, Buffer.alloc(size, 0x71), 1n);
        const prefix = requester.pull(split);
        assert.equal(prefix.length, split);
        assert.deepEqual(responder.receive(prefix), []);
        enqueue(responder, STOP, Buffer.from('receiver canceled'));
        const stopped = drain(responder, requester);
        assert.deepEqual(stopped.events.map((event) => event.type), [STOP]);
        const remainder = drain(requester, responder);
        assert.deepEqual(remainder.events, []);
        const canceled = drain(responder, requester).events;
        assert.equal(canceled.length, 1);
        assert.equal(canceled[0].type, RESULT);
        assert.equal(canceled[0].canceled, true);
        assert.deepEqual(canceled[0].payload, EMPTY);
        assert.equal(requester.outstandingRequestId, null);
        assert.equal(responder.outstandingRequestId, null);
        assert.equal(responder.decodedFrames, 1n);
        assert.equal(requester.state, 'STOPPING');
        assert.equal(responder.state, 'STOPPING');
        enqueue(requester, DONE, Buffer.from('no invocation'));
        assert.deepEqual(drain(requester, responder).events.map((event) => event.type), [DONE]);
        enqueue(responder, ACK);
        drain(responder, requester);
        requester.end();
        responder.end();
      }
    }
  }
});

test('receiver STOP validates a pending continuation then discards remaining unsent request chunks', () => {
  for (const split of [1, 39, 41, 49]) {
    const { requester, responder } = pair();
    enqueue(requester, INVOKE, Buffer.alloc(MAX_PAYLOAD, 0x34), 7n);
    assert.deepEqual(responder.receive(requester.pull(40 + MAX_CHUNK)), []);
    assert.equal(responder.outstandingRequestId, 7n);
    assert.deepEqual(responder.receive(requester.pull(split)), []);
    enqueue(responder, STOP, Buffer.from('cancel continuation'));
    drain(responder, requester);
    assert.deepEqual(drain(requester, responder).events, []);
    assert.equal(responder.decodedFrames, 2n);
    assert.equal(responder.outstandingRequestId, null);
    assert.equal(requester.outstandingRequestId, null);
    // Unsent continuations were abandoned. The requester owns terminal DONE;
    // it follows the finished active frame and the canceled-result receipt.
    enqueue(requester, DONE);
    drain(requester, responder);
    enqueue(responder, ACK);
    drain(responder, requester);
    requester.end();
    responder.end();
  }
});

test('receiver STOP never permits a second request frame, wrong identity/order, or partial-frame EOF', () => {
  const cases = [
    ['NONCE', (bytes) => { bytes[8] ^= 1; }],
    ['SEQUENCE', (bytes) => bytes.writeBigUInt64BE(2n, 24)],
    ['CHUNK', (bytes) => bytes.writeUInt32BE(2, 44)],
  ];
  for (const [reason, mutate] of cases) {
    const { responder } = pair();
    const bytes = wire({ type: INVOKE, payload: chunkPayload(Buffer.from([1])) });
    mutate(bytes);
    responder.receive(bytes.subarray(0, 1));
    enqueue(responder, STOP);
    assert.throws(() => responder.receive(bytes.subarray(1)), errorIs(reason));
    assert.throws(() => responder.pull(1), errorIs(reason));
  }
  const { requester, responder } = pair();
  enqueue(requester, INVOKE, Buffer.from('one'), 1n);
  responder.receive(requester.pull(41));
  enqueue(responder, STOP);
  drain(responder, requester);
  drain(requester, responder);
  assert.throws(() => responder.receive(wire({ type: INVOKE, sequence: 2n, requestId: 2n,
    payload: chunkPayload(EMPTY) })), errorIs('REQUEST_ORDER'));
  const partial = pair();
  partial.responder.receive(wire({ type: INVOKE, payload: chunkPayload(EMPTY) }).subarray(0, 41));
  enqueue(partial.responder, STOP);
  assert.throws(() => partial.responder.end(), errorIs('PARTIAL_EOF'));
});

test('full request handoff crossing partial receipt retires correlation via explicit canceled RESULT', () => {
  for (const size of [3, MAX_PAYLOAD]) {
    const splits = size === 3 ? [0, 1, 39, 41] : [0, 1, 39, 41, 40 + MAX_CHUNK + 41];
    for (const split of splits) {
      const { requester, responder } = pair();
      enqueue(requester, INVOKE, Buffer.alloc(size, 0x2c), 9n);
      const handedOff = Buffer.concat(drain(requester).chunks);
      assert.equal(requester.outstandingRequestId, 9n);
      assert.deepEqual(responder.receive(handedOff.subarray(0, split)), []);
      enqueue(responder, STOP, Buffer.from('receiver stop crossing handoff'));
      const beforeDrain = drain(responder, requester);
      // Remaining bytes were already handed off before STOP; they are only
      // validated/discarded, never exposed as an application request.
      assert.deepEqual(responder.receive(handedOff.subarray(split)), []);
      const afterDrain = drain(responder, requester);
      const events = [...beforeDrain.events, ...afterDrain.events];
      assert.deepEqual(events.map((event) => event.type), [STOP, RESULT]);
      assert.equal(events[1].canceled, true);
      assert.equal(events[1].requestId, 9n);
      assert.deepEqual(events[1].payload, EMPTY);
      assert.deepEqual(events[1].stop, Buffer.from('receiver stop crossing handoff'));
      const frames = decoder().push(Buffer.concat([...beforeDrain.chunks, ...afterDrain.chunks]));
      assert.equal(frames[1].payload[8], 3); // Present STOP + canceled-before-admission.
      assert.equal(frames[1].payload.readUInt32BE(0), 0);
      assert.equal(frames[1].payload.readUInt32BE(4), 0);
      assert.equal(requester.outstandingRequestId, null);
      assert.equal(responder.outstandingRequestId, null);
      enqueue(requester, DONE, Buffer.from('protocol evidence only'));
      drain(requester, responder);
      enqueue(responder, ACK);
      drain(responder, requester);
      requester.end();
      responder.end();
    }
  }
});

test('canceled RESULT rejects reserved status bits, application data, missing STOP and wrong correlation', () => {
  for (const [status, data, reason] of [
    [7, EMPTY, 'STOP_SNAPSHOT'],
    [2, EMPTY, 'STOP_SNAPSHOT'],
    [3, Buffer.from([1]), 'CANCELLATION'],
  ]) {
    const { requester, responder } = pair();
    admit(requester, responder);
    enqueue(requester, STOP);
    const payload = chunkPayload(data, { result: true, stop: EMPTY });
    payload[8] = status;
    assert.throws(() => requester.receive(wire({ type: RESULT, payload })), errorIs(reason));
  }
  for (const requestId of [1n, 2n]) {
    const { requester, responder } = pair();
    admit(requester, responder);
    if (requestId === 2n) enqueue(requester, STOP);
    const payload = chunkPayload(EMPTY, { result: true, stop: EMPTY });
    payload[8] = 3;
    assert.throws(() => requester.receive(wire({ type: RESULT, requestId, payload })), errorIs('CORRELATION'));
  }
});

test('canceled continuation drain keeps exact id/type/total/offset checks and never admits a new operation', () => {
  for (const change of [
    { type: CHECK }, { requestId: 8n }, { total: MAX_PAYLOAD - 1 }, { offset: MAX_CHUNK - 9 },
  ]) {
    const { requester, responder } = pair();
    enqueue(requester, INVOKE, Buffer.alloc(MAX_PAYLOAD, 1), 7n);
    responder.receive(requester.pull(40 + MAX_CHUNK));
    enqueue(responder, STOP);
    drain(responder, requester);
    const payload = chunkPayload(Buffer.from([1]), {
      total: change.total ?? MAX_PAYLOAD, offset: change.offset ?? MAX_CHUNK - 8,
    });
    assert.throws(() => responder.receive(wire({ type: change.type ?? INVOKE,
      requestId: change.requestId ?? 7n, sequence: 2n, payload })), errorIs('CHUNK_ORDER'));
  }
});

test('simultaneous STOP during a partial request produces one canceled receipt and no command event', () => {
  const { requester, responder } = pair();
  enqueue(requester, INVOKE, Buffer.alloc(MAX_PAYLOAD, 0x61), 1n);
  responder.receive(requester.pull(41));
  enqueue(requester, STOP, Buffer.from('requester first'));
  enqueue(responder, STOP, Buffer.from('responder first'));
  assert.deepEqual(drain(requester, responder).events.map((event) => event.type), [STOP]);
  const { events } = drain(responder, requester);
  assert.deepEqual(events.map((event) => event.type), [STOP, RESULT]);
  assert.equal(events[1].canceled, true);
  assert.deepEqual(events[1].stop, Buffer.from('responder first'));
  assert.deepEqual(requester.stop, Buffer.from('requester first'));
  assert.deepEqual(responder.stop, Buffer.from('responder first'));
  assert.equal(requester.outstandingRequestId, null);
  assert.equal(responder.outstandingRequestId, null);
  enqueue(requester, DONE);
  drain(requester, responder);
  enqueue(responder, ACK);
  drain(responder, requester);
  requester.end();
  responder.end();
});

test('STOP followed by premature DONE cannot overtake a fully handed-off but delayed INVOKE', () => {
  for (const size of [3, MAX_PAYLOAD]) {
    const { requester, responder } = pair();
    enqueue(requester, INVOKE, Buffer.alloc(size, 0x45), 23n);
    const delayed = Buffer.concat(drain(requester).chunks);
    assert.ok(delayed.length > 40);
    assert.equal(requester.outstandingRequestId, 23n);
    assert.equal(responder.outstandingRequestId, null);
    enqueue(responder, STOP, Buffer.from('stop before receipt'));
    assert.throws(() => enqueue(responder, DONE), errorIs('DONE_ORDER'));
    assert.equal(responder.state, 'STOPPING');
    assert.equal(requester.state, 'OPEN');
    assert.equal(requester.outstandingRequestId, 23n);
    assert.throws(() => responder.pull(40 + MAX_CHUNK), errorIs('DONE_ORDER'));
    assert.throws(() => responder.receive(delayed), errorIs('DONE_ORDER'));
    assert.throws(() => responder.end(), errorIs('DONE_ORDER'));
    assert.throws(() => requester.end(), errorIs('PREMATURE_EOF'));
  }
});

test('delayed INVOKE must drain and canceled RESULT must finish before either peer can own DONE', () => {
  for (const size of [3, MAX_PAYLOAD]) {
    for (const doneSender of ['requester', 'responder']) {
      const { requester, responder } = pair();
      enqueue(requester, INVOKE, Buffer.alloc(size, 0x73), 29n);
      const delayed = Buffer.concat(drain(requester).chunks);
      enqueue(responder, STOP, Buffer.from('cancel delayed invocation'));
      assert.deepEqual(drain(responder, requester).events.map((event) => event.type), [STOP]);
      assert.equal(requester.outstandingRequestId, 29n);
      assert.deepEqual(responder.receive(delayed), []);
      assert.equal(responder.outstandingRequestId, 29n);
      // Handoff of the canceled RESULT is distinct from requester receipt.
      const cancellation = Buffer.concat(drain(responder).chunks);
      assert.equal(responder.outstandingRequestId, null);
      assert.equal(requester.outstandingRequestId, 29n);
      const [canceled] = requester.receive(cancellation);
      assert.equal(canceled.type, RESULT);
      assert.equal(canceled.canceled, true);
      assert.equal(canceled.requestId, 29n);
      assert.deepEqual(canceled.payload, EMPTY);
      assert.equal(requester.outstandingRequestId, null);
      assert.equal(requester.state, 'STOPPING');
      assert.equal(responder.state, 'STOPPING');
      const sender = doneSender === 'requester' ? requester : responder;
      const peer = doneSender === 'requester' ? responder : requester;
      enqueue(sender, DONE, Buffer.from('canceled protocol outcome'));
      assert.deepEqual(drain(sender, peer).events.map((event) => event.type), [DONE]);
      assert.equal(sender.state, 'STOPPING');
      assert.equal(peer.state, 'STOPPING');
      enqueue(peer, ACK);
      assert.deepEqual(drain(peer, sender).events.map((event) => event.type), [ACK]);
      assert.equal(sender.state, 'SETTLED');
      assert.equal(peer.state, 'SETTLED');
      assert.equal(sender.outstandingRequestId, null);
      assert.equal(peer.outstandingRequestId, null);
      sender.end();
      peer.end();
    }
  }
});

test('DONE while delayed cancellation RESULT is still queued fails instead of dropping correlation', () => {
  for (const doneSender of ['requester', 'responder']) {
    const { requester, responder } = pair();
    enqueue(requester, INVOKE, Buffer.from('delayed'), 31n);
    const delayed = Buffer.concat(drain(requester).chunks);
    enqueue(responder, STOP);
    drain(responder, requester);
    responder.receive(delayed);
    assert.equal(responder.outstandingRequestId, 31n);
    assert.equal(requester.outstandingRequestId, 31n);
    const sender = doneSender === 'requester' ? requester : responder;
    assert.throws(() => enqueue(sender, DONE), errorIs('DONE_ORDER'));
    assert.equal(sender.state, 'STOPPING');
    assert.throws(() => sender.pull(1), errorIs('DONE_ORDER'));
  }
});
