export function webSocketPayloadByteLength(raw) {
  if (typeof raw === "string") return Buffer.byteLength(raw);
  if (Array.isArray(raw)) {
    return raw.reduce((total, chunk) => total + webSocketPayloadByteLength(chunk), 0);
  }
  if (raw instanceof ArrayBuffer || ArrayBuffer.isView(raw)) return raw.byteLength;
  throw new TypeError("Unsupported WebSocket payload type");
}
