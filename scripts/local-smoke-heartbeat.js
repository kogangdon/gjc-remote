import { performance } from "node:perf_hooks";
import { isPongMessage } from "../shared/protocol.js";

const DEFAULT_HEARTBEAT_TIMEOUT_MS = 30_000;
const MIN_HEARTBEAT_TIMEOUT_MS = 1_000;
const MAX_HEARTBEAT_TIMEOUT_MS = 120_000;
const HOST_POLL_INTERVAL_MS = 100;

const monotonicNow = () => performance.now();
const sleep = (delay) =>
  new Promise((resolve) => {
    setTimeout(resolve, delay);
  });

function heartbeatTimeoutError() {
  return new Error(
    "SMOKE_HEARTBEAT_TIMEOUT_MS must be a base-10 integer from 1000 to 120000",
  );
}

export function parseSmokeHeartbeatTimeout(rawValue) {
  if (rawValue === undefined) return DEFAULT_HEARTBEAT_TIMEOUT_MS;
  if (typeof rawValue !== "string" || !/^[0-9]+$/.test(rawValue)) {
    throw heartbeatTimeoutError();
  }

  const timeoutMs = Number(rawValue);
  if (
    !Number.isSafeInteger(timeoutMs) ||
    timeoutMs < MIN_HEARTBEAT_TIMEOUT_MS ||
    timeoutMs > MAX_HEARTBEAT_TIMEOUT_MS
  ) {
    throw heartbeatTimeoutError();
  }
  return timeoutMs;
}

export async function waitForHost(
  registry,
  hostId,
  timeoutMs,
  {
    now = monotonicNow,
    wait = sleep,
  } = {},
) {
  const deadline = now() + timeoutMs;
  while (true) {
    const remaining = deadline - now();
    if (remaining <= 0) {
      throw new Error(`host '${hostId}' did not connect within ${timeoutMs}ms`);
    }
    if (registry.isOnline(hostId)) return;
    await wait(Math.min(HOST_POLL_INTERVAL_MS, remaining));
  }
}

export async function waitForTelemetry(
  events,
  predicate,
  count,
  timeoutMs,
  {
    now = monotonicNow,
    wait = sleep,
  } = {},
) {
  const deadline = now() + timeoutMs;
  while (true) {
    const remaining = deadline - now();
    if (remaining <= 0) {
      throw new Error(
        `expected ${count} matching daemon telemetry events within ${timeoutMs}ms`,
      );
    }
    if (events.filter(predicate).length >= count) return;
    await wait(Math.min(10, remaining));
  }
}

export async function waitForRegisteredHeartbeatPong(
  registry,
  hostId,
  timeoutMs,
  {
    now = monotonicNow,
    setTimeoutFn = setTimeout,
    clearTimeoutFn = clearTimeout,
  } = {},
) {
  const socket = registry.connections.get(hostId);
  if (!socket) {
    throw new Error(
      `host '${hostId}' has no registered connection for the heartbeat proof`,
    );
  }

  const deadline = now() + timeoutMs;
  return new Promise((resolve, reject) => {
    let deadlineTimer;
    let settled = false;

    const deadlineError = () =>
      new Error(
        `host '${hostId}' did not return an application-level pong within ${timeoutMs}ms`,
      );
    const cleanup = () => {
      if (deadlineTimer !== undefined) clearTimeoutFn(deadlineTimer);
      socket.off("message", onMessage);
      socket.off("close", onClose);
    };
    const succeed = () => {
      if (settled) return;
      settled = true;
      cleanup();
      resolve(socket);
    };
    const fail = (error) => {
      if (settled) return;
      settled = true;
      cleanup();
      reject(error);
    };
    const onMessage = (raw, isBinary) => {
      if (isBinary) return;

      let message;
      try {
        message = JSON.parse(raw.toString());
      } catch {
        return;
      }
      if (!isPongMessage(message)) return;
      if (now() >= deadline) {
        fail(deadlineError());
        return;
      }
      if (registry.connections.get(hostId) !== socket) {
        fail(
          new Error(
            `host '${hostId}' connection changed before returning an application-level pong`,
          ),
        );
        return;
      }
      succeed();
    };
    const onClose = () => {
      if (now() >= deadline) {
        fail(deadlineError());
        return;
      }
      fail(
        new Error(
          `host '${hostId}' disconnected before returning an application-level pong`,
        ),
      );
    };
    const armDeadline = () => {
      const remaining = deadline - now();
      if (remaining <= 0) {
        fail(deadlineError());
        return;
      }
      deadlineTimer = setTimeoutFn(armDeadline, Math.max(1, Math.ceil(remaining)));
    };

    socket.on("message", onMessage);
    socket.once("close", onClose);
    if (registry.connections.get(hostId) !== socket) {
      fail(
        new Error(
          `host '${hostId}' connection changed before the heartbeat proof started`,
        ),
      );
      return;
    }
    armDeadline();
  });
}
