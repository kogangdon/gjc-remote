import { types } from 'node:util';

// Private F/W and F/H protocol only. No sockets, host qualification, waits,
// descriptor closure, command execution, clocks, or public API are provided here.
export const STATUS_PROTOCOL = Object.freeze({
  version: 1,
  headerBytes: 40,
  nonceBytes: 16,
  maximumPayloadBytes: 256 * 1024,
  maximumChunkBytes: 64 * 1024,
  maximumStopBytes: 1024,
  maximumReceiveEvents: 3,
  maximumUint64: (1n << 64n) - 1n,
});

// These numeric assignments and all offsets below are the future native H header
// contract. Network byte order throughout; uint64 values are always BigInt.
export const STATUS_MESSAGE_TYPE = Object.freeze({
  CHECK: 1,
  INVOKE: 2,
  STOP: 3,
  RESULT: 4,
  DONE: 5,
  ACK: 6,
});
const { CHECK, INVOKE, STOP, RESULT, DONE, ACK } = STATUS_MESSAGE_TYPE;
const { maximumPayloadBytes: MAX_PAYLOAD, maximumChunkBytes: MAX_CHUNK,
  maximumStopBytes: MAX_STOP, maximumUint64: MAX_U64 } = STATUS_PROTOCOL;
const EMPTY = Buffer.alloc(0);
const typedArrayPrototype = Object.getPrototypeOf(Uint8Array.prototype);
const byteLengthGetter = Object.getOwnPropertyDescriptor(typedArrayPrototype, 'byteLength').get;
const byteOffsetGetter = Object.getOwnPropertyDescriptor(typedArrayPrototype, 'byteOffset').get;
const bufferGetter = Object.getOwnPropertyDescriptor(typedArrayPrototype, 'buffer').get;

class ServiceStatusProtocolError extends Error {
  constructor(reason) {
    const code = `SERVICE_STATUS_PROTOCOL_${reason}`;
    super(code);
    Object.defineProperties(this, {
      name: { value: 'ServiceStatusProtocolError' },
      code: { value: code, enumerable: true },
    });
  }
}

function invalid(reason = 'INVALID') {
  throw new ServiceStatusProtocolError(reason);
}

// Inspect data descriptors, never caller-supplied accessors or proxy traps.
function dataValues(value, keys) {
  if (value === null || typeof value !== 'object' || types.isProxy(value) ||
      Object.getPrototypeOf(value) !== Object.prototype) invalid();
  const ownKeys = Reflect.ownKeys(value);
  if (ownKeys.length !== keys.length || keys.some((key) => !ownKeys.includes(key))) invalid();
  const descriptors = Object.getOwnPropertyDescriptors(value);
  const result = Object.create(null);
  for (const key of keys) {
    const descriptor = descriptors[key];
    if (!descriptor || !descriptor.enumerable || !Object.hasOwn(descriptor, 'value')) invalid();
    result[key] = descriptor.value;
  }
  return result;
}

function byteView(value) {
  if (types.isProxy(value) || !types.isUint8Array(value)) invalid('BYTES');
  try {
    const backing = bufferGetter.call(value);
    if (types.isSharedArrayBuffer(backing)) invalid('BYTES');
    return Buffer.from(backing, byteOffsetGetter.call(value), byteLengthGetter.call(value));
  } catch {
    invalid('BYTES');
  }
}

// Avoid the shared Buffer pool: exposing a copy's .buffer must not expose any
// other private snapshot or previously returned bytes in the same allocation.
function copyBytes(view) {
  const copy = Buffer.allocUnsafeSlow(view.length);
  view.copy(copy);
  return copy;
}

function snapshot(value, maximum = MAX_PAYLOAD) {
  const view = byteView(value);
  if (view.length > maximum) invalid('LENGTH');
  return copyBytes(view);
}

function nonceSnapshot(value) {
  const nonce = snapshot(value, 16);
  if (nonce.length !== 16) invalid('NONCE');
  return nonce;
}

function uint64(value, nonzero = false) {
  if (typeof value !== 'bigint' || value < (nonzero ? 1n : 0n) || value > MAX_U64) invalid('UINT64');
}

function checkHeader(values, expectedNonce = null, expectedSequence = null) {
  if (values.length > MAX_PAYLOAD) invalid('LENGTH');
  if (values.version !== 1) invalid('VERSION');
  if (!Number.isInteger(values.type) || values.type < CHECK || values.type > ACK) invalid('TYPE');
  if (values.flags !== 0) invalid('FLAGS');
  uint64(values.sequence, true);
  uint64(values.requestId);
  const correlated = values.type === CHECK || values.type === INVOKE || values.type === RESULT;
  if (correlated === (values.requestId === 0n)) invalid('REQUEST_ID');
  if (expectedNonce !== null && !values.nonce.equals(expectedNonce)) invalid('NONCE');
  if (expectedSequence !== null && values.sequence !== expectedSequence) invalid('SEQUENCE');
}

function frameSnapshot(values, payload) {
  const nonce = copyBytes(values.nonce);
  const bytes = copyBytes(payload);
  return Object.freeze({
    version: values.version,
    type: values.type,
    flags: values.flags,
    sequence: values.sequence,
    requestId: values.requestId,
    // Buffers cannot be frozen. Each read returns a copy of private immutable bytes.
    get nonce() { return copyBytes(nonce); },
    get payload() { return copyBytes(bytes); },
  });
}

// Header: [0..3] payload length, [4] version, [5] type, [6..7] flags (zero),
// [8..23] operation nonce, [24..31] directional sequence, [32..39] request id.
export function encodeStatusProtocolFrame(metadata) {
  if (arguments.length !== 1) invalid();
  const values = dataValues(metadata, ['version', 'type', 'flags', 'nonce', 'sequence', 'requestId', 'payload']);
  const nonce = nonceSnapshot(values.nonce);
  const view = byteView(values.payload);
  checkHeader({ ...values, nonce, length: view.length });
  const encoded = Buffer.allocUnsafeSlow(40 + view.length);
  encoded.writeUInt32BE(view.length, 0);
  encoded[4] = 1;
  encoded[5] = values.type;
  encoded.writeUInt16BE(0, 6);
  nonce.copy(encoded, 8);
  encoded.writeBigUInt64BE(values.sequence, 24);
  encoded.writeBigUInt64BE(values.requestId, 32);
  view.copy(encoded, 40);
  return encoded;
}

// nextSequence is explicit to support deterministic boundary qualification;
// new operation directions MUST start at 1n, as the endpoint below does.
// push(chunk, consume) invokes consume synchronously once per frame BEFORE
// decoding the next header. It never collects output frames. The consumer owns
// any retained snapshots; throwing stops consumption and poisons the decoder.
export function createStatusProtocolDecoder(options) {
  if (arguments.length !== 1) invalid();
  const values = dataValues(options, ['nonce', 'nextSequence']);
  const nonce = nonceSnapshot(values.nonce);
  uint64(values.nextSequence, true);
  let nextSequence = values.nextSequence;
  const header = Buffer.alloc(40);
  let headerUsed = 0;
  let metadata = null;
  let body = null;
  let bodyUsed = 0;
  let ended = false;
  let failure = null;
  let maximumPayloadAllocation = 0;
  let decodedFrames = 0n;
  let consuming = false;

  function guard() {
    if (failure !== null) throw failure;
    if (ended) invalid('EOF');
    if (consuming) invalid('REENTRANT');
  }

  function poison(error) {
    failure = error instanceof ServiceStatusProtocolError ? error : new ServiceStatusProtocolError('INVALID');
    body = null;
    metadata = null;
    headerUsed = 0;
    bodyUsed = 0;
    throw failure;
  }

  return Object.freeze({
    get pendingBytes() { return headerUsed + bodyUsed; },
    get maximumPayloadAllocation() { return maximumPayloadAllocation; },
    get decodedFrames() { return decodedFrames; },
    push(chunk, consume) {
      try {
        guard();
        if (typeof consume !== 'function') invalid('CONSUMER');
        const input = byteView(chunk);
        consuming = true;
        let offset = 0;
        while (offset < input.length) {
          if (metadata === null) {
            if (nextSequence === null) invalid('SEQUENCE_EXHAUSTED');
            const count = Math.min(40 - headerUsed, input.length - offset);
            input.copy(header, headerUsed, offset, offset + count);
            headerUsed += count;
            offset += count;
            if (headerUsed !== 40) break;
            metadata = {
              length: header.readUInt32BE(0), version: header[4], type: header[5],
              flags: header.readUInt16BE(6), nonce: header.subarray(8, 24),
              sequence: header.readBigUInt64BE(24), requestId: header.readBigUInt64BE(32),
            };
            // All header checks precede allocation or any body copy.
            checkHeader(metadata, nonce, nextSequence);
            body = Buffer.allocUnsafeSlow(metadata.length);
            maximumPayloadAllocation = Math.max(maximumPayloadAllocation, metadata.length);
          }
          const count = Math.min(body.length - bodyUsed, input.length - offset);
          input.copy(body, bodyUsed, offset, offset + count);
          bodyUsed += count;
          offset += count;
          if (bodyUsed !== body.length) break;
          const frame = frameSnapshot(metadata, body);
          nextSequence = nextSequence === MAX_U64 ? null : nextSequence + 1n;
          headerUsed = 0;
          bodyUsed = 0;
          body = null;
          metadata = null;
          decodedFrames += 1n;
          consume(frame);
          if (failure !== null) throw failure;
        }
      } catch (error) {
        return poison(error);
      } finally {
        consuming = false;
      }
    },
    end() {
      try {
        guard();
        if (headerUsed !== 0 || bodyUsed !== 0 || metadata !== null) invalid('PARTIAL_EOF');
        ended = true;
      } catch (error) {
        poison(error);
      }
    },
  });
}

function nullableBytesEqual(left, right) {
  return left === null ? right === null : right !== null && left.equals(right);
}

function eventSnapshot(type, requestId, payload, stop, canceled = false) {
  const bytes = copyBytes(payload);
  const stopped = stop === null ? null : copyBytes(stop);
  return Object.freeze({
    type,
    requestId,
    canceled,
    get payload() { return copyBytes(bytes); },
    get stop() { return stopped === null ? null : copyBytes(stopped); },
  });
}

// Endpoint payload contract (not JSON):
// CHECK / INVOKE / DONE: u32 total application bytes, u32 offset, chunk bytes.
// RESULT: same prefix, then u8 status bits, u32 stop length, stop bytes,
//         then application chunk bytes. A present, empty STOP is distinct from none.
// Status bit 0 = stop present; bit 1 = canceled before application admission;
// other bits are forbidden. Canceled RESULT must have stop present, total=0,
// offset=0 and no data. It retires correlation, NOT command success/execution,
// command exit, descriptor closure or resource cleanup. Events expose canceled.
// STOP: opaque first-stop evidence, <= 1024 bytes (also fits RESULT prefix).
// ACK: empty. STOP/DONE/ACK request id = 0; requests/results use nonzero ids.
// Each complete chunk payload is <= 64 KiB, logical messages <= 256 KiB.
// No interleaving logical messages except STOP; offsets must exactly advance.
// A single CHECK/INVOKE may be outstanding; ids strictly increase per operation.
// requester sends CHECK/INVOKE; responder sends RESULT. Either side may send
// DONE when no request remains; its peer ACKs (W can be requester and send DONE).
// Local DONE also requires no unresolved canceled-request drain. Trying it early
// is a terminal DONE_ORDER error, not a deferred send. If continuation chunks
// were abandoned, the requester sends DONE after its canceled RESULT; receiving
// that ordered DONE ends the responder's drain record, allowing ACK, not DONE.
// Both directions start sequence 1, independently. There is no retry or wrap.
//
// enqueue() accepts complete logical messages. pull() hands off at most part of
// one frame; callers MUST finish handing off those bytes before another pull.
// Once handed off, bytes cannot be recalled. A local STOP finishes the active
// frame, then precedes all not-yet-started result chunks. Snapshotting happens at
// frame start, so subsequent RESULT chunks carry the sticky stop at that point.
// First STOP *observed by this endpoint* sticks, including simultaneous STOPs.
// A responder stopping before application admission validates/discards bytes of
// that one logical request and automatically sends a canceled RESULT once its id
// is known. This also covers full sender handoff crossing partial receipt. The
// sender finishes its active frame, drops unstarted chunks, and keeps started
// correlation until RESULT. No request event/forward grant is emitted. A scalar
// drain record checks any already-handed-off continuations without reassembly;
// a complete request, peer STOP, DONE or ACK terminates it. Other ids are refused.
// A previously admitted request still needs a real, caller-supplied RESULT.
// W still needs its real synchronous post-result CHECK in future composition.
//
// SETTLED means DONE/ACK protocol handshake only, NEVER host/descriptor/reaping
// settlement. The ACK sender reaches it when the last ACK byte is handed off;
// its peer reaches it on receipt. The I/O owner must separately prove delivery,
// close and exit results. EOF requires that handshake and drained outbound data.
export function createStatusProtocolEndpoint(options) {
  if (arguments.length !== 1) invalid();
  const values = dataValues(options, ['nonce', 'role']);
  const nonce = nonceSnapshot(values.nonce);
  if (values.role !== 'requester' && values.role !== 'responder') invalid('ROLE');
  const requester = values.role === 'requester';
  const decoder = createStatusProtocolDecoder({ nonce, nextSequence: 1n });
  let state = 'OPEN';
  let failure = null;
  let ended = false;
  let stop = null;
  let stopQueued = false;
  let receivedStop = null;
  let nextSequence = 1n;
  let lastRequestId = 0n;
  let outstanding = null;
  let assembly = null;
  let requestDrain = null;
  let doneQueued = false;
  let doneReceived = false;
  let doneSent = false;
  let ackQueued = false;
  let active = null;
  const queue = [];

  function guard() {
    if (failure !== null) throw failure;
    if (ended) invalid('EOF');
    if (state === 'SETTLED') invalid('SETTLED');
  }

  function poison(error) {
    if (failure === null) {
      failure = error instanceof ServiceStatusProtocolError ? error : new ServiceStatusProtocolError('INVALID');
      if (state !== 'SETTLED') state = 'STOPPING';
      queue.length = 0;
      active = null;
      assembly = null;
      requestDrain = null;
    }
    throw failure;
  }

  function queueCancellation(requestId) {
    outstanding = { id: requestId, ready: true, resultQueued: true };
    queue.push({ type: RESULT, requestId, payload: EMPTY, offset: 0, canceled: true });
  }

  function observeStop(payload, local = false) {
    if (stop === null) stop = copyBytes(payload);
    state = 'STOPPING';
    if (local && !requester && (outstanding === null || !outstanding.ready)) {
      requestDrain = assembly === null ? {} : {
        type: assembly.type, requestId: assembly.requestId, total: assembly.total, used: assembly.used,
      };
    }
    if (assembly?.type === CHECK || assembly?.type === INVOKE) {
      const requestId = assembly.requestId;
      assembly = null;
      outstanding = null;
      queueCancellation(requestId);
    }
    if (!local && !requester) requestDrain = null;
    if (requester && outstanding !== null && !outstanding.ready && !outstanding.started) {
      outstanding = null;
    }
    // Requests not started are no longer permitted. If already started, only
    // the active frame is finished; the peer sees STOP, not a new invocation.
    for (let index = queue.length - 1; index >= 0; index -= 1) {
      if (queue[index].type === CHECK || queue[index].type === INVOKE) queue.splice(index, 1);
    }
  }

  function completeTransmission(message) {
    if ((message.type === CHECK || message.type === INVOKE) && outstanding !== null) outstanding.ready = true;
    if (message.type === DONE) doneSent = true;
    if (message.type === ACK) {
      state = 'SETTLED';
      requestDrain = null;
    }
  }

  function frameFor(message) {
    if (nextSequence === null) invalid('SEQUENCE_EXHAUSTED');
    let payload;
    let complete = true;
    if ((message.type === CHECK || message.type === INVOKE) && outstanding !== null) outstanding.started = true;
    if (message.type === STOP || message.type === ACK) {
      payload = message.payload;
    } else {
      const prefix = message.type === RESULT ? 13 + (stop?.length ?? 0) : 8;
      const count = Math.min(MAX_CHUNK - prefix, message.payload.length - message.offset);
      payload = Buffer.allocUnsafeSlow(prefix + count);
      payload.writeUInt32BE(message.payload.length, 0);
      payload.writeUInt32BE(message.offset, 4);
      if (message.type === RESULT) {
        payload[8] = (stop === null ? 0 : 1) | (message.canceled ? 2 : 0);
        payload.writeUInt32BE(stop?.length ?? 0, 9);
        stop?.copy(payload, 13);
      }
      message.payload.copy(payload, prefix, message.offset, message.offset + count);
      message.offset += count;
      complete = message.offset === message.payload.length;
    }
    const bytes = encodeStatusProtocolFrame({
      version: 1, type: message.type, flags: 0, nonce,
      sequence: nextSequence, requestId: message.requestId, payload,
    });
    nextSequence = nextSequence === MAX_U64 ? null : nextSequence + 1n;
    return { bytes, offset: 0, message, complete };
  }

  function receiveChunk(frame, payload, events) {
    if (payload.length > MAX_CHUNK || payload.length < (frame.type === RESULT ? 13 : 8)) invalid('CHUNK');
    const total = payload.readUInt32BE(0);
    const offset = payload.readUInt32BE(4);
    if (total > MAX_PAYLOAD || offset > total) invalid('CHUNK');
    let prefix = 8;
    let resultStop = null;
    let canceled = false;
    if (frame.type === RESULT) {
      const status = payload[8];
      const present = (status & 1) !== 0;
      canceled = (status & 2) !== 0;
      const length = payload.readUInt32BE(9);
      if (status > 3 || (!present && length !== 0) || (canceled && !present) || length > MAX_STOP ||
          13 + length > payload.length) invalid('STOP_SNAPSHOT');
      prefix = 13 + length;
      if (present) resultStop = copyBytes(payload.subarray(13, prefix));
      if (canceled && (total !== 0 || offset !== 0 || payload.length !== prefix)) invalid('CANCELLATION');
      if (receivedStop !== null && !nullableBytesEqual(receivedStop, resultStop)) invalid('STOP_SNAPSHOT');
    }
    const count = payload.length - prefix;
    if (count > total - offset || (count === 0 && (total !== 0 || offset !== 0))) invalid('CHUNK');
    if (requestDrain !== null && (frame.type === CHECK || frame.type === INVOKE)) {
      if (requestDrain.type === undefined) {
        if (offset !== 0 || frame.requestId <= lastRequestId) invalid('REQUEST_ORDER');
        lastRequestId = frame.requestId;
        requestDrain = { type: frame.type, requestId: frame.requestId, total, used: offset };
        queueCancellation(frame.requestId);
      } else if (frame.type !== requestDrain.type || frame.requestId !== requestDrain.requestId ||
          total !== requestDrain.total || offset !== requestDrain.used) invalid('CHUNK_ORDER');
      requestDrain.used += count;
      if (requestDrain.used === total) requestDrain = null;
      return;
    }
    if (assembly === null) {
      if (offset !== 0) invalid('CHUNK');
      if (frame.type === CHECK || frame.type === INVOKE) {
        if (requester || state !== 'OPEN' || outstanding !== null || frame.requestId <= lastRequestId) {
          invalid('REQUEST_ORDER');
        }
        outstanding = { id: frame.requestId, ready: false, resultQueued: false };
        lastRequestId = frame.requestId;
      } else if (frame.type === RESULT) {
        if (!requester || outstanding === null || (!outstanding.ready && !canceled) ||
            (canceled && stop === null) || outstanding.id !== frame.requestId) {
          invalid('CORRELATION');
        }
      } else if (frame.type === DONE) {
        if (outstanding !== null || doneReceived || doneQueued) invalid('DONE_ORDER');
        requestDrain = null;
        state = 'STOPPING';
      }
      assembly = { type: frame.type, requestId: frame.requestId, total, used: 0,
        bytes: Buffer.allocUnsafeSlow(total), stop: resultStop };
    }
    if (assembly.type !== frame.type || assembly.requestId !== frame.requestId ||
        assembly.total !== total || assembly.used !== offset) invalid('CHUNK_ORDER');
    if (frame.type === RESULT) {
      // A stop snapshot may become present between chunks, but never disappear
      // or change once present. This includes STOP arriving mid-result.
      if (assembly.stop !== null && !nullableBytesEqual(assembly.stop, resultStop)) invalid('STOP_SNAPSHOT');
      assembly.stop = resultStop;
      if (resultStop !== null) observeStop(resultStop);
    }
    payload.copy(assembly.bytes, offset, prefix);
    assembly.used += count;
    if (assembly.used !== total) return;
    if (frame.type === CHECK || frame.type === INVOKE) outstanding.ready = true;
    if (frame.type === RESULT) outstanding = null;
    if (frame.type === DONE) doneReceived = true;
    events.push(eventSnapshot(frame.type, frame.requestId, assembly.bytes, assembly.stop, canceled));
    assembly = null;
  }

  return Object.freeze({
    get state() { return state; },
    get stop() { return stop === null ? null : copyBytes(stop); },
    get outstandingRequestId() { return outstanding?.id ?? null; },
    get decodedFrames() { return decoder.decodedFrames; },
    enqueue(metadata) {
      try {
        guard();
        const message = dataValues(metadata, ['type', 'requestId', 'payload']);
        uint64(message.requestId);
        if (!Number.isInteger(message.type) || message.type < CHECK || message.type > ACK) invalid('TYPE');
        const payload = snapshot(message.payload);
        if (message.type === STOP) {
          if (message.requestId !== 0n || payload.length > MAX_STOP) invalid('STOP');
          if (stopQueued || stop !== null) return;
          observeStop(payload, true);
          stopQueued = true;
          queue.unshift({ ...message, payload, offset: 0 });
          return;
        }
        if (message.type === CHECK || message.type === INVOKE) {
          if (!requester || state !== 'OPEN' || outstanding !== null || message.requestId <= lastRequestId) {
            invalid('REQUEST_ORDER');
          }
          uint64(message.requestId, true);
          lastRequestId = message.requestId;
          outstanding = { id: message.requestId, ready: false, started: false };
        } else if (message.type === RESULT) {
          if (requester || outstanding === null || !outstanding.ready || outstanding.resultQueued ||
              outstanding.id !== message.requestId) invalid('CORRELATION');
          outstanding.resultQueued = true;
        } else if (message.type === DONE) {
          if (message.requestId !== 0n || outstanding !== null || requestDrain !== null || doneQueued || doneReceived) {
            invalid('DONE_ORDER');
          }
          doneQueued = true;
          state = 'STOPPING';
        } else if (message.type === ACK) {
          if (message.requestId !== 0n || payload.length !== 0 || !doneReceived || ackQueued) {
            invalid('ACK_ORDER');
          }
          ackQueued = true;
        }
        queue.push({ ...message, payload, offset: 0 });
      } catch (error) {
        poison(error);
      }
    },
    pull(maximumBytes) {
      try {
        if (failure !== null) throw failure;
        if (ended) invalid('EOF');
        if (!Number.isSafeInteger(maximumBytes) || maximumBytes < 1 || maximumBytes > 40 + MAX_CHUNK) invalid('LENGTH');
        if (state === 'SETTLED' && (active !== null || queue.length !== 0)) invalid('SETTLED');
        if (active === null) {
          if (queue.length === 0) return null;
          active = frameFor(queue.shift());
        }
        const end = Math.min(active.offset + maximumBytes, active.bytes.length);
        const bytes = copyBytes(active.bytes.subarray(active.offset, end));
        active.offset = end;
        if (end === active.bytes.length) {
          const { message, complete } = active;
          active = null;
          if (!complete) {
            // STOP may already be at the head. Continue after it, never before it.
            const position = queue[0]?.type === STOP ? 1 : 0;
            if ((message.type !== CHECK && message.type !== INVOKE) || state === 'OPEN') {
              queue.splice(position, 0, message);
            }
          } else {
            if (message.type === RESULT) outstanding = null;
            completeTransmission(message);
          }
        }
        return bytes;
      } catch (error) {
        return poison(error);
      }
    },
    receive(chunk) {
      try {
        guard();
        const events = [];
        decoder.push(chunk, (frame) => {
          if (state === 'SETTLED') invalid('SETTLED');
          // No user callbacks run here. Refuse before allocating another event,
          // even if a future state-machine change accidentally permits a burst.
          if (events.length === STATUS_PROTOCOL.maximumReceiveEvents) invalid('EVENT_LIMIT');
          const payload = frame.payload;
          if (frame.type === STOP) {
            if (payload.length > MAX_STOP) invalid('STOP');
            if (receivedStop !== null) invalid('DUPLICATE_STOP');
            receivedStop = copyBytes(payload);
            observeStop(payload);
            events.push(eventSnapshot(STOP, 0n, payload, stop));
          } else if (frame.type === ACK) {
            if (payload.length !== 0 || !doneSent || outstanding !== null || assembly !== null) {
              invalid('ACK_ORDER');
            }
            state = 'SETTLED';
            requestDrain = null;
            events.push(eventSnapshot(ACK, 0n, EMPTY, stop));
          } else {
            receiveChunk(frame, payload, events);
          }
        });
        return Object.freeze(events);
      } catch (error) {
        return poison(error);
      }
    },
    end() {
      try {
        if (failure !== null) throw failure;
        if (ended) invalid('EOF');
        decoder.end();
        if (state !== 'SETTLED' || assembly !== null || requestDrain !== null ||
            active !== null || queue.length !== 0 || outstanding !== null) {
          invalid('PREMATURE_EOF');
        }
        ended = true;
      } catch (error) {
        poison(error);
      }
    },
  });
}
