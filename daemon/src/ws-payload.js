export function webSocketPayloadByteLength(raw) {
  if (typeof raw === "string") return Buffer.byteLength(raw);
  if (Array.isArray(raw)) {
    return raw.reduce((total, chunk) => total + asBuffer(chunk).byteLength, 0);
  }
  return asBuffer(raw).byteLength;
}

export function webSocketPayloadToUtf8(raw) {
  if (typeof raw === "string") return raw;
  if (Array.isArray(raw)) return Buffer.concat(raw.map(asBuffer)).toString("utf8");
  return asBuffer(raw).toString("utf8");
}

function asBuffer(raw) {
  if (raw instanceof ArrayBuffer) return Buffer.from(raw);
  if (ArrayBuffer.isView(raw)) {
    return Buffer.from(raw.buffer, raw.byteOffset, raw.byteLength);
  }
  throw new TypeError("Unsupported WebSocket payload type");
}
