import { MAX_WS_PAYLOAD_BYTES } from "@gjc-remote/shared";

const MAX_ERROR_LENGTH = 1024;

function boundedString(value, maxLength) {
  return typeof value === "string" ? value.slice(0, maxLength) : undefined;
}

function fallbackFrame(requestId, extra, originalType) {
  const frame = {
    type: "event",
    requestId,
    event: {
      type: "event_truncated",
      code: "EVENT_PAYLOAD_TOO_LARGE",
      originalType: boundedString(originalType, 128),
    },
  };
  if (typeof extra.done === "boolean") frame.done = extra.done;
  if (typeof extra.error === "string") frame.error = extra.error.slice(0, MAX_ERROR_LENGTH);
  return frame;
}

/** Serialize a daemon event without ever exceeding the negotiated WS frame cap. */
export function serializeEventFrame(
  requestId,
  event,
  extra = {},
  maxBytes = MAX_WS_PAYLOAD_BYTES
) {
  const frame = { type: "event", requestId, event, ...extra };
  try {
    const serialized = JSON.stringify(frame);
    if (Buffer.byteLength(serialized) <= maxBytes) return serialized;
  } catch {
    // Fall through to the bounded diagnostic frame.
  }

  const fallback = JSON.stringify(
    fallbackFrame(requestId, extra, event?.type)
  );
  if (Buffer.byteLength(fallback) > maxBytes) {
    return JSON.stringify({
      type: "event",
      requestId,
      event: { type: "event_truncated", code: "EVENT_PAYLOAD_TOO_LARGE" },
    });
  }
  return fallback;
}
