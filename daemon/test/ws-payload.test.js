import assert from "node:assert/strict";
import test from "node:test";

import {
  webSocketPayloadByteLength,
  webSocketPayloadToUtf8,
} from "../src/ws-payload.js";

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

test("payload UTF-8 decoding supports every RawData shape", () => {
  const json = JSON.stringify({ message: "한글" });
  const encoded = Buffer.from(json);
  const split = encoded.indexOf(0xed) + 1;

  assert.equal(webSocketPayloadToUtf8(json), json);
  assert.equal(webSocketPayloadToUtf8(encoded), json);
  assert.equal(
    webSocketPayloadToUtf8([
      encoded.subarray(0, split),
      new Uint8Array(encoded.subarray(split)),
    ]),
    json
  );
  assert.equal(
    webSocketPayloadToUtf8(
      encoded.buffer.slice(encoded.byteOffset, encoded.byteOffset + encoded.byteLength)
    ),
    json
  );
});

test("payload helpers reject unsupported values", () => {
  assert.throws(() => webSocketPayloadByteLength({ length: 1 }), /Unsupported/);
  assert.throws(() => webSocketPayloadToUtf8({ length: 1 }), /Unsupported/);
});
