import assert from "node:assert/strict";
import test from "node:test";

import { webSocketPayloadByteLength } from "../src/ws-payload.js";

test("payload byte length uses UTF-8 bytes for strings", () => {
  assert.equal(webSocketPayloadByteLength("ascii"), 5);
  assert.equal(webSocketPayloadByteLength("한글"), Buffer.byteLength("한글"));
});

test("payload byte length supports Buffer, typed arrays, and ArrayBuffer", () => {
  assert.equal(webSocketPayloadByteLength(Buffer.alloc(7)), 7);
  assert.equal(webSocketPayloadByteLength(new Uint8Array(9)), 9);
  assert.equal(webSocketPayloadByteLength(new ArrayBuffer(11)), 11);
});

test("payload byte length sums fragmented ws RawData chunks", () => {
  assert.equal(
    webSocketPayloadByteLength([Buffer.alloc(3), Buffer.alloc(5), new Uint8Array(7)]),
    15
  );
});

test("payload byte length rejects unsupported values", () => {
  assert.throws(() => webSocketPayloadByteLength({ length: 1 }), /Unsupported/);
});
