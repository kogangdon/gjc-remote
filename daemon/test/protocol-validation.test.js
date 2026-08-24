import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { EventEmitter, once } from "node:events";
import { fileURLToPath } from "node:url";
import test from "node:test";
import {
  CAPABILITIES,
  MAX_WS_PAYLOAD_BYTES,
  MSG_TYPES,
  PROTOCOL_VERSION,
  PROTOCOL_VERSION_V2,
  PROTOCOL_VERSION_V3,
  PROTOCOL_ERROR_CODES,
  READINESS_REMEDIATIONS,
  READINESS_ERROR_TAXONOMY,
  V0_LIMITS,
  READINESS_DEFAULT_TTL_MS,
  READINESS_DIMENSIONS,
  READINESS_MAX_TTL_MS,
  READINESS_MIN_TTL_MS,
  READINESS_STATUS_VALUES,
  WORKSPACE_ID_MAX_LENGTH,
  WORKSPACE_READINESS_CAPABILITY,
  WORKSPACE_INVENTORY_RECEIPT_CAPABILITY,
  INVENTORY_RECEIPT_TTL_MS,
  isAnswerMessage,
  isBindOkMessage,
  isBindWorkspaceMessage,
  isEventMessage,
  isGateRequestEvent,
  isInvokeMessage,
  isReadinessCapabilityGate,
  isReadinessMessage,
  isReadinessStatus,
  isReadinessTtl,
  normalizeReadinessTtl,
  isRegisterMessage,
  isRegisterOkMessage,
  isWorkspaceId,
  normalizeProtocolError,
} from "@gjc-remote/shared";
import { workspaceBindingFingerprint } from "@gjc-remote/shared/workspace-binding";
import {
  buildWorkspaceInventory,
  workspaceInventoryBytes,
} from "@gjc-remote/shared/workspace-inventory";
import { WebSocket, WebSocketServer } from "ws";
import { findWorkspaceInventory, parseWorkspaceInventory } from "../src/workspace-inventory.js";
import { invalidateBindingRequests } from "../src/binding-fence.js";
import { WorkspaceLeaseRegistry } from "../src/workspace-lease-registry.js";

const daemonEntry = fileURLToPath(new URL("../src/daemon.js", import.meta.url));
const CHILD_EXIT_TIMEOUT_MS = 2_000;

const validBinding = {
  type: MSG_TYPES.BIND_WORKSPACE,
  bindingId: "binding-1",
  hostId: "test-host",
  mappingId: "mapping-1",
  mappingGeneration: 2,
  mappingVersion: 1,
  workspaceId: "workspace-1",
  workspaceGeneration: 3,
  sourcePlatform: "posix",
  routeFingerprint: "a".repeat(64),
  authorityFingerprint: "b".repeat(64),
  inventoryGeneration: 4,
};
const ROOT_IDENTITY_FINGERPRINT = "1".repeat(64);
const STORAGE_IDENTITY_FINGERPRINT = "2".repeat(64);
const receiptBinding = {
  type: MSG_TYPES.BIND_WORKSPACE,
  bindingId: "receipt-binding-1",
  authorityEpoch: 1,
  fenceGeneration: 1,
  hostId: "test-host",
  mappingId: "mapping-1",
  mappingGeneration: 2,
  mappingVersion: 1,
  workspaceId: "workspace-1",
  workspaceGeneration: 3,
  sourcePlatform: "posix",
  authorityFingerprint: "b".repeat(64),
};

function capabilityWorkspace(binding, workDir) {
  return {
    hostId: binding.hostId,
    workspaceId: binding.workspaceId,
    sourcePlatform: binding.sourcePlatform,
    workDir,
    rootIdentityFingerprint: ROOT_IDENTITY_FINGERPRINT,
    storageIdentityFingerprint: STORAGE_IDENTITY_FINGERPRINT,
  };
}

function serializedTestInventory({
  hostId = validBinding.hostId,
  inventoryGeneration = validBinding.inventoryGeneration,
  workspaces = [],
} = {}) {
  return workspaceInventoryBytes(buildWorkspaceInventory({
    hostId,
    inventoryGeneration,
    workspaces,
  })).toString("utf8");
}

test("replaced binding requests are disposed without touching other bindings", async () => {
  const connection = {};
  const otherConnection = {};
  const disposed = [];
  const inFlight = new Map([
    ["old-request", {
      connection,
      bindingId: "binding-old",
      session: {
        dispose: async () => {
          disposed.push("old-request");
        },
      },
    }],
    ["other-binding", {
      connection,
      bindingId: "binding-new",
      session: {
        dispose: async () => {
          disposed.push("other-binding");
        },
      },
    }],
    ["other-connection", {
      connection: otherConnection,
      bindingId: "binding-old",
      session: {
        dispose: async () => {
          disposed.push("other-connection");
        },
      },
    }],
  ]);

  invalidateBindingRequests(inFlight, connection, "binding-old");
  await new Promise((resolve) => setImmediate(resolve));

  assert.deepEqual(disposed, ["old-request"]);
  assert.equal(inFlight.has("old-request"), false);
  assert.equal(inFlight.has("other-binding"), true);
  assert.equal(inFlight.has("other-connection"), true);
});

test("workspace binding is path-free and validates the complete identity tuple", () => {
  assert.equal(isBindWorkspaceMessage(validBinding), true);
  assert.equal(
    isBindOkMessage({
      type: MSG_TYPES.BIND_OK,
      bindingId: "binding-1",
      bindingFingerprint: "c".repeat(64),
    }),
    true
  );

  for (const field of [
    "bindingId",
    "mappingId",
    "workspaceId",
    "routeFingerprint",
    "authorityFingerprint",
    "inventoryGeneration",
  ]) {
    const invalid = { ...validBinding };
    invalid[field] = field.endsWith("Fingerprint") ? "not-a-fingerprint" : "../escape";
    assert.equal(isBindWorkspaceMessage(invalid), false, field);
  }
  assert.equal(
    isBindWorkspaceMessage({ ...validBinding, workDir: "/srv/workspace" }),
    false,
    "managed binding must not carry a path"
  );
  assert.equal(
    isReadinessMessage({
      type: MSG_TYPES.READINESS,
      socketGeneration: 1,
      revision: 1,
      observedAt: Date.now(),
      ttlMs: 1000,
      bindingId: "../invalid",
      status: {
        connection: "online",
        runtime: "ready",
        providerAuth: "configured",
        modelProfile: "ready",
        workspace: "unknown",
      },
    }),
    false,
    "bindingId must be validated even without workspace identity"
  );
});

test("local workspace inventory v2 is capability-only and matches local identity", () => {
  const inventory = parseWorkspaceInventory(serializedTestInventory({
    inventoryGeneration: validBinding.inventoryGeneration,
    workspaces: [capabilityWorkspace(validBinding, "/srv/workspace")],
  }));
  assert.equal(inventory.version, 2);
  assert.equal(inventory.workspaces.length, 1);
  assert.ok(findWorkspaceInventory(inventory, validBinding));
  assert.ok(findWorkspaceInventory(inventory, {
    ...validBinding,
    mappingId: "different-mapping",
    mappingGeneration: 999,
    workspaceGeneration: 999,
    routeFingerprint: "c".repeat(64),
    authorityFingerprint: "d".repeat(64),
  }));
  assert.equal(findWorkspaceInventory(inventory, {
    ...validBinding,
    inventoryGeneration: validBinding.inventoryGeneration + 1,
  }), undefined);
  assert.throws(
    () => parseWorkspaceInventory(JSON.stringify({
      ...inventory,
      workspaces: [{ ...inventory.workspaces[0], routeFingerprint: "a".repeat(64) }],
    })),
    /WORKSPACE_INVENTORY_INVALID/
  );
});

async function stopChild(child, timeoutMs = CHILD_EXIT_TIMEOUT_MS) {
  if (child.exitCode !== null || child.signalCode !== null) return;

  const exited = once(child, "exit");
  child.kill("SIGTERM");

  let forceTimer;
  await Promise.race([
    exited,
    new Promise((resolve) => {
      forceTimer = setTimeout(resolve, timeoutMs);
    }),
  ]);
  clearTimeout(forceTimer);

  if (child.exitCode === null && child.signalCode === null) {
    child.kill("SIGKILL");
    await exited;
  }
}

async function startDaemon(extraEnv = {}) {
  const wss = new WebSocketServer({ port: 0 });
  if (!wss.address()) await once(wss, "listening");
  const { port } = wss.address();
  let peer;
  let stderr = "";
  const registration = new Promise((resolve) => {
    wss.once("connection", (connection) => {
      peer = connection;
      connection.once("message", (raw) => resolve(JSON.parse(raw.toString())));
    });
  });

  const child = spawn(process.env.BUN_BIN || "bun", [daemonEntry], {
    env: {
      ...process.env,
      HOST_ID: "test-host",
      HOST_TOKEN: "test-token",
      BOT_WS_URL: `ws://127.0.0.1:${port}`,
      ...extraEnv,
    },
    stdio: ["ignore", "pipe", "pipe"],
    windowsHide: true,
  });
  child.stderr.on("data", (chunk) => {
    stderr += chunk.toString();
  });

  const register = await Promise.race([
    registration,
    once(child, "exit").then(([code]) => {
      throw new Error(`daemon exited before registering (${code}): ${stderr}`);
    }),
  ]);
  assert.equal(register.type, "register");

  return {
    child,
    peer,
    wss,
    register,
    stderr: () => stderr,
    async close() {
      peer?.terminate();
      await stopChild(child);
      await new Promise((resolve, reject) => {
        wss.close((error) => (error ? reject(error) : resolve()));
      });
    },
  };
}

function onceMessage(socket, type) {
  return new Promise((resolve) => {
    const onMessage = (raw) => {
      const message = JSON.parse(raw.toString());
      if (message.type === type) {
        socket.off("message", onMessage);
        resolve(message);
      }
    };
    socket.on("message", onMessage);
  });
}

function waitForMessage(socket, predicate) {
  return new Promise((resolve) => {
    const onMessage = (raw) => {
      const message = JSON.parse(raw.toString());
      if (predicate(message)) {
        socket.off("message", onMessage);
        resolve(message);
      }
    };
    socket.on("message", onMessage);
  });
}

test("daemon accepts path-free workspace binding without promoting readiness", async () => {
  const daemon = await startDaemon({ GJC_READINESS_V2: "1" });
  try {
    const registerOk = new Promise((resolve) =>
      daemon.peer.once("message", (raw) => resolve(JSON.parse(raw.toString())))
    );
    daemon.peer.send(JSON.stringify({
      type: MSG_TYPES.REGISTER_OK,
      protocolVersion: PROTOCOL_VERSION_V2,
      capabilities: [WORKSPACE_READINESS_CAPABILITY],
    }));
    assert.equal((await registerOk).type, MSG_TYPES.READINESS);

    const bindOk = new Promise((resolve) => {
      const onMessage = (raw) => {
        const message = JSON.parse(raw.toString());
        if (message.type === MSG_TYPES.BIND_OK) {
          daemon.peer.off("message", onMessage);
          resolve(message);
        }
      };
      daemon.peer.on("message", onMessage);
    });
    const postBindReadiness = waitForMessage(
      daemon.peer,
      (message) =>
        message.type === MSG_TYPES.READINESS &&
        message.bindingId === validBinding.bindingId
    );
    daemon.peer.send(JSON.stringify(validBinding));
    const response = await bindOk;
    assert.equal(response.type, MSG_TYPES.BIND_OK);
    assert.equal(response.bindingId, validBinding.bindingId);

    const readiness = await postBindReadiness;
    assert.equal(readiness.status.workspace, "unknown");
    assert.equal(readiness.lastError?.code, PROTOCOL_ERROR_CODES.INVENTORY_PENDING);
  } finally {
    await daemon.close();
  }
});

test("daemon reports verified inventory absence as workspace not found", async () => {
  const daemon = await startDaemon({
    GJC_READINESS_V2: "1",
    GJC_READINESS_TEST_INJECTION: "1",
    GJC_READINESS_TEST_PROBE: "pass",
    GJC_WORKSPACE_INVENTORY: serializedTestInventory({
      inventoryGeneration: validBinding.inventoryGeneration,
      workspaces: [],
    }),
  });
  try {
    daemon.peer.send(JSON.stringify({
      type: MSG_TYPES.REGISTER_OK,
      protocolVersion: PROTOCOL_VERSION_V2,
      capabilities: [WORKSPACE_READINESS_CAPABILITY],
    }));
    await onceMessage(daemon.peer, MSG_TYPES.READINESS);
    daemon.peer.send(JSON.stringify(validBinding));
    await onceMessage(daemon.peer, MSG_TYPES.BIND_OK);
    const readiness = await waitForMessage(
      daemon.peer,
      (message) =>
        message.type === MSG_TYPES.READINESS &&
        message.bindingId === validBinding.bindingId
    );
    assert.equal(readiness.status.workspace, "unknown");
    assert.deepEqual(readiness.lastError, {
      code: PROTOCOL_ERROR_CODES.WORKSPACE_NOT_FOUND,
      at: readiness.lastError.at,
      remediation: {
        code: PROTOCOL_ERROR_CODES.WORKSPACE_NOT_FOUND,
        retryable: false,
        action: "refresh_workspace",
      },
    });
  } finally {
    await daemon.close();
  }
});

test("daemon promotes workspace readiness only after local inventory proof", async () => {
  const daemon = await startDaemon({
    GJC_READINESS_V2: "1",
    GJC_READINESS_TEST_INJECTION: "1",
    GJC_READINESS_TEST_PROBE: "pass",
    GJC_WORKSPACE_INVENTORY: serializedTestInventory({
      inventoryGeneration: validBinding.inventoryGeneration,
      workspaces: [capabilityWorkspace(validBinding, "/srv/workspace")],
    }),
  });
  try {
    const initialReadiness = onceMessage(daemon.peer, MSG_TYPES.READINESS);
    daemon.peer.send(JSON.stringify({
      type: MSG_TYPES.REGISTER_OK,
      protocolVersion: PROTOCOL_VERSION_V2,
      capabilities: [WORKSPACE_READINESS_CAPABILITY],
    }));
    await initialReadiness;
    const readinessPromise = waitForMessage(
      daemon.peer,
      (message) => message.type === MSG_TYPES.READINESS && message.status.workspace === "ready"
    );
    const bindOkPromise = onceMessage(daemon.peer, MSG_TYPES.BIND_OK);
    daemon.peer.send(JSON.stringify(validBinding));
    await bindOkPromise;
    const readiness = await readinessPromise;
    assert.equal(readiness.status.workspace, "ready");
    assert.equal(readiness.workspaceId, validBinding.workspaceId);
    assert.equal(readiness.workspaceGeneration, validBinding.workspaceGeneration);

    daemon.peer.send(JSON.stringify({
      type: MSG_TYPES.INVOKE,
      requestId: "native-serving-remains-disabled",
      bindingId: validBinding.bindingId,
      mappingId: validBinding.mappingId,
      mappingGeneration: validBinding.mappingGeneration,
      mappingVersion: validBinding.mappingVersion,
      workspaceId: validBinding.workspaceId,
      workspaceGeneration: validBinding.workspaceGeneration,
      command: { kind: "prompt", message: "blocked" },
    }));
    const response = await onceMessage(daemon.peer, MSG_TYPES.EVENT);
    assert.equal(response.requestId, "native-serving-remains-disabled");
    assert.equal(
      JSON.parse(response.error).code,
      PROTOCOL_ERROR_CODES.RUNTIME_INCOMPATIBLE
    );
  } finally {
    await daemon.close();
  }
});

test("v3 receipt bind derives local proof and unbind is bindingId-only", async () => {
  const inventory = serializedTestInventory({
    inventoryGeneration: 4,
    workspaces: [capabilityWorkspace(receiptBinding, "/srv/workspace")],
  });
  const daemon = await startDaemon({
    GJC_READINESS_V2: "1",
    GJC_READINESS_TEST_INJECTION: "1",
    GJC_READINESS_TEST_PROBE: "pass",
    GJC_NATIVE_INVENTORY_MODE: "verify",
    GJC_WORKSPACE_INVENTORY: inventory,
  });
  try {
    assert.equal(daemon.register.protocolVersion, PROTOCOL_VERSION_V3);
    assert.ok(daemon.register.capabilities.includes(WORKSPACE_INVENTORY_RECEIPT_CAPABILITY));
    daemon.peer.send(JSON.stringify({
      type: MSG_TYPES.REGISTER_OK,
      protocolVersion: PROTOCOL_VERSION_V3,
      capabilities: [
        WORKSPACE_READINESS_CAPABILITY,
        WORKSPACE_INVENTORY_RECEIPT_CAPABILITY,
      ],
    }));
    await onceMessage(daemon.peer, MSG_TYPES.READINESS);
    const receipt = onceMessage(daemon.peer, MSG_TYPES.BIND_OK);
    const pendingReadiness = waitForMessage(
      daemon.peer,
      (frame) => frame.type === MSG_TYPES.READINESS &&
        frame.bindingId === receiptBinding.bindingId &&
        frame.lastError?.code === PROTOCOL_ERROR_CODES.INVENTORY_PENDING
    );
    const receiptReadiness = waitForMessage(
      daemon.peer,
      (frame) => frame.type === MSG_TYPES.READINESS &&
        frame.bindingId === receiptBinding.bindingId &&
        frame.bindingFingerprint !== undefined
    );
    daemon.peer.send(JSON.stringify(receiptBinding));
    const pending = await pendingReadiness;
    assert.equal(Object.hasOwn(pending, "bindingFingerprint"), false);
    const bindOk = await receipt;
    const parsedInventory = parseWorkspaceInventory(inventory);
    assert.equal(bindOk.inventoryGeneration, parsedInventory.inventoryGeneration);
    assert.equal(bindOk.inventoryFingerprint, parsedInventory.inventoryFingerprint);
    assert.equal(bindOk.bindingFingerprint, workspaceBindingFingerprint({
      authority: {
        authorityEpoch: receiptBinding.authorityEpoch,
        fenceGeneration: receiptBinding.fenceGeneration,
        hostId: receiptBinding.hostId,
        mappingId: receiptBinding.mappingId,
        mappingGeneration: receiptBinding.mappingGeneration,
        workspaceGeneration: receiptBinding.workspaceGeneration,
        mappingVersion: receiptBinding.mappingVersion,
        sourcePlatform: receiptBinding.sourcePlatform,
        workspaceId: receiptBinding.workspaceId,
        authorityFingerprint: receiptBinding.authorityFingerprint,
      },
      inventoryGeneration: parsedInventory.inventoryGeneration,
      inventoryFingerprint: parsedInventory.inventoryFingerprint,
    }));
    const readiness = await receiptReadiness;
    assert.equal(readiness.ttlMs, INVENTORY_RECEIPT_TTL_MS);
    assert.equal(readiness.bindingFingerprint, bindOk.bindingFingerprint);
    const unbound = onceMessage(daemon.peer, MSG_TYPES.UNBIND_OK);
    daemon.peer.send(JSON.stringify({
      type: MSG_TYPES.UNBIND_WORKSPACE,
      bindingId: receiptBinding.bindingId,
    }));
    assert.deepEqual(await unbound, {
      type: MSG_TYPES.UNBIND_OK,
      bindingId: receiptBinding.bindingId,
    });
    const duplicateUnbound = onceMessage(daemon.peer, MSG_TYPES.UNBIND_OK);
    daemon.peer.send(JSON.stringify({
      type: MSG_TYPES.UNBIND_WORKSPACE,
      bindingId: receiptBinding.bindingId,
    }));
    assert.deepEqual(await duplicateUnbound, {
      type: MSG_TYPES.UNBIND_OK,
      bindingId: receiptBinding.bindingId,
    });
    const closed = once(daemon.peer, "close");
    daemon.peer.send(JSON.stringify(receiptBinding));
    const [code] = await closed;
    assert.equal(code, 1008);
  } finally {
    await daemon.close();
  }
});

test("v3 receipt refuses provider epoch drift without acknowledging", async () => {
  const inventory = serializedTestInventory({
    inventoryGeneration: 4,
    workspaces: [capabilityWorkspace(receiptBinding, "/srv/workspace")],
  });
  const daemon = await startDaemon({
    GJC_READINESS_V2: "1",
    GJC_READINESS_TEST_INJECTION: "1",
    GJC_READINESS_TEST_PROBE: "pass",
    GJC_NATIVE_INVENTORY_MODE: "verify",
    GJC_WORKSPACE_INVENTORY_TEST_EPOCH_MISMATCH: "1",
    GJC_WORKSPACE_INVENTORY: inventory,
  });
  try {
    daemon.peer.send(JSON.stringify({
      type: MSG_TYPES.REGISTER_OK,
      protocolVersion: PROTOCOL_VERSION_V3,
      capabilities: [
        WORKSPACE_READINESS_CAPABILITY,
        WORKSPACE_INVENTORY_RECEIPT_CAPABILITY,
      ],
    }));
    await onceMessage(daemon.peer, MSG_TYPES.READINESS);
    const readiness = waitForMessage(
      daemon.peer,
      (frame) => frame.type === MSG_TYPES.READINESS &&
        frame.bindingId === receiptBinding.bindingId
    );
    daemon.peer.send(JSON.stringify(receiptBinding));
    const frame = await readiness;
    assert.equal(frame.lastError?.code, PROTOCOL_ERROR_CODES.INVENTORY_PENDING);
    assert.equal(Object.hasOwn(frame, "bindingFingerprint"), false);
    assert.equal(Object.hasOwn(frame, "inventoryFingerprint"), false);
  } finally {
    await daemon.close();
  }
});

test("live cascade bulk-invalidates the workspace lease registry", () => {
  const registry = new WorkspaceLeaseRegistry();
  const candidate = {
    authorityEpoch: 1,
    fenceGeneration: 1,
    hostId: "test-host",
    mappingId: "mapping-1",
    mappingGeneration: 2,
    mappingVersion: 1,
    workspaceId: "workspace-1",
    workspaceGeneration: 3,
    sourcePlatform: "posix",
    authorityFingerprint: "b".repeat(64),
    inventoryGeneration: 4,
    inventoryFingerprint: "c".repeat(64),
    socketGeneration: 1,
    bindingId: "receipt-binding-1",
    bindingFingerprint: "d".repeat(64),
  };
  assert.equal(registry.adoptBinding(candidate), true);
  const lease = registry.acquireActivity(candidate);
  assert.equal(lease.isCurrent(), true);

  const invalidated = registry.invalidateAll();
  assert.deepEqual([...invalidated], ["workspace-1"]);
  // A held lease immediately reports non-current after a cascade.
  assert.equal(lease.isCurrent(), false);
  // Authorities are cleared, so a fresh acquire fails closed until a new adopt.
  assert.throws(
    () => registry.acquireActivity(candidate),
    (error) => error.code === PROTOCOL_ERROR_CODES.LEASE_CONFLICT
  );
  assert.equal(registry.snapshot().length, 0);
  // Releasing the stale holder is safe and drops the invalidated activity.
  lease.release();
  assert.equal(registry.snapshot().length, 0);
});

test("live cascade reports adopted authorities with no active activity holder", () => {
  const registry = new WorkspaceLeaseRegistry();
  const candidate = {
    authorityEpoch: 1,
    fenceGeneration: 1,
    hostId: "test-host",
    mappingId: "mapping-1",
    mappingGeneration: 2,
    mappingVersion: 1,
    workspaceId: "workspace-authority-only",
    workspaceGeneration: 3,
    sourcePlatform: "posix",
    authorityFingerprint: "b".repeat(64),
    inventoryGeneration: 4,
    inventoryFingerprint: "c".repeat(64),
    socketGeneration: 1,
    bindingId: "receipt-binding-authority-only",
    bindingFingerprint: "d".repeat(64),
  };
  // Adopt an authority but never acquire an activity: the workspace has an
  // authority and no activity holder.
  assert.equal(registry.adoptBinding(candidate), true);

  const invalidated = registry.invalidateAll();
  // The returned set must include the authority-only workspace even though it
  // never appeared in the activities map.
  assert.deepEqual([...invalidated], ["workspace-authority-only"]);
  assert.equal(registry.snapshot().length, 0);
  // Authority cleared: a fresh acquire fails closed until a new adopt.
  assert.throws(
    () => registry.acquireActivity(candidate),
    (error) => error.code === PROTOCOL_ERROR_CODES.LEASE_CONFLICT
  );
});

test("live inventory epoch drift retires the receipt socket without creating a session", async () => {
  const inventory = serializedTestInventory({
    inventoryGeneration: 4,
    workspaces: [capabilityWorkspace(receiptBinding, "/srv/workspace")],
  });
  const daemon = await startDaemon({
    GJC_READINESS_V2: "1",
    GJC_READINESS_TEST_INJECTION: "1",
    GJC_READINESS_TEST_PROBE: "pass",
    GJC_NATIVE_INVENTORY_MODE: "verify",
    GJC_WORKSPACE_INVENTORY_TEST_EPOCH_MISMATCH: "1",
    GJC_INVENTORY_POLL_MS: "40",
    GJC_WORKSPACE_INVENTORY: inventory,
  });
  try {
    const frames = [];
    daemon.peer.on("message", (raw) => frames.push(JSON.parse(raw.toString())));
    daemon.peer.send(JSON.stringify({
      type: MSG_TYPES.REGISTER_OK,
      protocolVersion: PROTOCOL_VERSION_V3,
      capabilities: [
        WORKSPACE_READINESS_CAPABILITY,
        WORKSPACE_INVENTORY_RECEIPT_CAPABILITY,
      ],
    }));
    await onceMessage(daemon.peer, MSG_TYPES.READINESS);
    const closed = once(daemon.peer, "close");
    daemon.peer.send(JSON.stringify(receiptBinding));
    const [code] = await closed;
    // The atomic cascade retires the socket with the dedicated close code.
    assert.equal(code, 1013);
    // Serving is hard-false: no positive receipt, no ready frame, no session.
    assert.equal(frames.some((f) => f.type === MSG_TYPES.BIND_OK), false);
    assert.equal(
      frames.some(
        (f) => f.type === MSG_TYPES.READINESS && f.status?.workspace === "ready"
      ),
      false
    );
  } finally {
    await daemon.close();
  }
});

test("stable inventory keeps a positive receipt binding alive across poll ticks", async () => {
  const inventory = serializedTestInventory({
    inventoryGeneration: 4,
    workspaces: [capabilityWorkspace(receiptBinding, "/srv/workspace")],
  });
  const daemon = await startDaemon({
    GJC_READINESS_V2: "1",
    GJC_READINESS_TEST_INJECTION: "1",
    GJC_READINESS_TEST_PROBE: "pass",
    GJC_NATIVE_INVENTORY_MODE: "verify",
    GJC_INVENTORY_POLL_MS: "40",
    GJC_WORKSPACE_INVENTORY: inventory,
  });
  try {
    let closedCode;
    daemon.peer.on("close", (code) => {
      closedCode = code;
    });
    daemon.peer.send(JSON.stringify({
      type: MSG_TYPES.REGISTER_OK,
      protocolVersion: PROTOCOL_VERSION_V3,
      capabilities: [
        WORKSPACE_READINESS_CAPABILITY,
        WORKSPACE_INVENTORY_RECEIPT_CAPABILITY,
      ],
    }));
    await onceMessage(daemon.peer, MSG_TYPES.READINESS);
    const bindOk = onceMessage(daemon.peer, MSG_TYPES.BIND_OK);
    daemon.peer.send(JSON.stringify(receiptBinding));
    const positive = await bindOk;
    // The binding proved against the stable inventory and went positive.
    assert.ok(positive.bindingFingerprint);
    // Across many poll ticks a stable read must never falsely cascade: the
    // proof-based drift check keeps matching, so no negative frame is emitted
    // and the socket is never retired.
    const negativeFrame = waitForMessage(
      daemon.peer,
      (f) =>
        f.type === MSG_TYPES.READINESS &&
        f.bindingId === receiptBinding.bindingId &&
        f.lastError?.code === PROTOCOL_ERROR_CODES.INVENTORY_STALE
    );
    const settled = await Promise.race([
      negativeFrame.then(() => "cascaded"),
      new Promise((resolve) => setTimeout(() => resolve("stable"), 300)),
    ]);
    assert.equal(settled, "stable");
    assert.equal(closedCode, undefined);
  } finally {
    await daemon.close();
  }
});

test("native inventory off mode withholds v3 receipt capability", async () => {
  const inventory = serializedTestInventory({
    inventoryGeneration: 4,
    workspaces: [capabilityWorkspace(receiptBinding, "/srv/workspace")],
  });
  const daemon = await startDaemon({
    GJC_READINESS_V2: "1",
    GJC_READINESS_TEST_INJECTION: "1",
    GJC_NATIVE_INVENTORY_MODE: "off",
    GJC_WORKSPACE_INVENTORY: inventory,
  });
  try {
    assert.equal(daemon.register.protocolVersion, PROTOCOL_VERSION_V2);
    assert.equal(
      daemon.register.capabilities.includes(WORKSPACE_INVENTORY_RECEIPT_CAPABILITY),
      false
    );
    daemon.peer.send(JSON.stringify({
      type: MSG_TYPES.REGISTER_OK,
      protocolVersion: PROTOCOL_VERSION_V2,
      capabilities: [WORKSPACE_READINESS_CAPABILITY],
    }));
    await onceMessage(daemon.peer, MSG_TYPES.READINESS);
  } finally {
    await daemon.close();
  }
});

test("v3 retired authority floor rejects a lower descriptor under a fresh id", async () => {
  const inventory = serializedTestInventory({
    inventoryGeneration: 4,
    workspaces: [capabilityWorkspace(receiptBinding, "/srv/workspace")],
  });
  const daemon = await startDaemon({
    GJC_READINESS_V2: "1",
    GJC_READINESS_TEST_INJECTION: "1",
    GJC_READINESS_TEST_PROBE: "pass",
    GJC_NATIVE_INVENTORY_MODE: "verify",
    GJC_WORKSPACE_INVENTORY: inventory,
  });
  try {
    daemon.peer.send(JSON.stringify({
      type: MSG_TYPES.REGISTER_OK,
      protocolVersion: PROTOCOL_VERSION_V3,
      capabilities: [
        WORKSPACE_READINESS_CAPABILITY,
        WORKSPACE_INVENTORY_RECEIPT_CAPABILITY,
      ],
    }));
    await onceMessage(daemon.peer, MSG_TYPES.READINESS);
    const newer = {
      ...receiptBinding,
      bindingId: "receipt-newer",
      authorityEpoch: 2,
      fenceGeneration: 2,
    };
    const bound = onceMessage(daemon.peer, MSG_TYPES.BIND_OK);
    daemon.peer.send(JSON.stringify(newer));
    await bound;
    const unbound = onceMessage(daemon.peer, MSG_TYPES.UNBIND_OK);
    daemon.peer.send(JSON.stringify({
      type: MSG_TYPES.UNBIND_WORKSPACE,
      bindingId: newer.bindingId,
    }));
    await unbound;
    const closed = once(daemon.peer, "close");
    daemon.peer.send(JSON.stringify({
      ...receiptBinding,
      bindingId: "receipt-regressed",
    }));
    const [code] = await closed;
    assert.equal(code, 1008);
  } finally {
    await daemon.close();
  }
});

test("v3 newer authority retires an already-positive older binding before pending", async () => {
  const inventory = serializedTestInventory({
    inventoryGeneration: 4,
    workspaces: [capabilityWorkspace(receiptBinding, "/srv/workspace")],
  });
  const daemon = await startDaemon({
    GJC_READINESS_V2: "1",
    GJC_READINESS_TEST_INJECTION: "1",
    GJC_READINESS_TEST_PROBE: "pass",
    GJC_NATIVE_INVENTORY_MODE: "verify",
    GJC_WORKSPACE_INVENTORY: inventory,
  });
  try {
    daemon.peer.send(JSON.stringify({
      type: MSG_TYPES.REGISTER_OK,
      protocolVersion: PROTOCOL_VERSION_V3,
      capabilities: [
        WORKSPACE_READINESS_CAPABILITY,
        WORKSPACE_INVENTORY_RECEIPT_CAPABILITY,
      ],
    }));
    await onceMessage(daemon.peer, MSG_TYPES.READINESS);
    const bound = onceMessage(daemon.peer, MSG_TYPES.BIND_OK);
    const oldReady = waitForMessage(
      daemon.peer,
      (frame) =>
        frame.type === MSG_TYPES.READINESS &&
        frame.bindingId === receiptBinding.bindingId &&
        frame.status.workspace === "ready"
    );
    daemon.peer.send(JSON.stringify(receiptBinding));
    await bound;
    await oldReady;

    const observed = [];
    const collect = (raw) => observed.push(JSON.parse(raw.toString()));
    daemon.peer.on("message", collect);
    const newer = {
      ...receiptBinding,
      bindingId: "receipt-newer-negative",
      mappingGeneration: receiptBinding.mappingGeneration + 1,
      sourcePlatform: "windows-drive",
    };
    const newerNegative = waitForMessage(
      daemon.peer,
      (frame) =>
        frame.type === MSG_TYPES.READINESS &&
        frame.bindingId === newer.bindingId &&
        frame.lastError?.code === PROTOCOL_ERROR_CODES.WORKSPACE_NOT_FOUND
    );
    daemon.peer.send(JSON.stringify(newer));
    await newerNegative;
    daemon.peer.off("message", collect);
    assert.equal(
      observed.some(
        (frame) =>
          frame.type === MSG_TYPES.READINESS &&
          frame.bindingId === receiptBinding.bindingId
      ),
      false
    );
    const retired = onceMessage(daemon.peer, MSG_TYPES.UNBIND_OK);
    daemon.peer.send(JSON.stringify({
      type: MSG_TYPES.UNBIND_WORKSPACE,
      bindingId: receiptBinding.bindingId,
    }));
    await retired;
  } finally {
    await daemon.close();
  }
});

test("v3 reserves the 64-id capacity before provider reads complete", async () => {
  const inventory = serializedTestInventory({
    inventoryGeneration: 4,
    workspaces: [],
  });
  const daemon = await startDaemon({
    GJC_READINESS_V2: "1",
    GJC_READINESS_TEST_INJECTION: "1",
    GJC_NATIVE_INVENTORY_MODE: "verify",
    GJC_WORKSPACE_INVENTORY: inventory,
  });
  try {
    daemon.peer.send(JSON.stringify({
      type: MSG_TYPES.REGISTER_OK,
      protocolVersion: PROTOCOL_VERSION_V3,
      capabilities: [
        WORKSPACE_READINESS_CAPABILITY,
        WORKSPACE_INVENTORY_RECEIPT_CAPABILITY,
      ],
    }));
    await onceMessage(daemon.peer, MSG_TYPES.READINESS);
    const closed = once(daemon.peer, "close");
    for (let index = 0; index < 65; index += 1) {
      daemon.peer.send(JSON.stringify({
        ...receiptBinding,
        bindingId: `receipt-capacity-${index}`,
        mappingId: `mapping-capacity-${index}`,
        workspaceId: `workspace-capacity-${index}`,
      }));
    }
    const [code] = await closed;
    assert.equal(code, 1008);
  } finally {
    await daemon.close();
  }
});

test("v3 rejects an unknown bindingId-only unbind", async () => {
  const inventory = serializedTestInventory({
    inventoryGeneration: 4,
    workspaces: [],
  });
  const daemon = await startDaemon({
    GJC_READINESS_V2: "1",
    GJC_READINESS_TEST_INJECTION: "1",
    GJC_NATIVE_INVENTORY_MODE: "verify",
    GJC_WORKSPACE_INVENTORY: inventory,
  });
  try {
    daemon.peer.send(JSON.stringify({
      type: MSG_TYPES.REGISTER_OK,
      protocolVersion: PROTOCOL_VERSION_V3,
      capabilities: [
        WORKSPACE_READINESS_CAPABILITY,
        WORKSPACE_INVENTORY_RECEIPT_CAPABILITY,
      ],
    }));
    await onceMessage(daemon.peer, MSG_TYPES.READINESS);
    const closed = once(daemon.peer, "close");
    daemon.peer.send(JSON.stringify({
      type: MSG_TYPES.UNBIND_WORKSPACE,
      bindingId: "unknown-binding",
    }));
    const [code] = await closed;
    assert.equal(code, 1008);
  } finally {
    await daemon.close();
  }
});

test("daemon publishes readiness independently for multiple workspace bindings", async () => {
  const firstBinding = { ...validBinding, inventoryGeneration: 5 };
  const secondBinding = {
    ...validBinding,
    bindingId: "binding-2",
    mappingId: "mapping-2",
    workspaceId: "workspace-2",
    mappingGeneration: 1,
    workspaceGeneration: 1,
    routeFingerprint: "c".repeat(64),
    authorityFingerprint: "d".repeat(64),
    inventoryGeneration: 5,
  };
  const daemon = await startDaemon({
    GJC_READINESS_V2: "1",
    GJC_READINESS_TEST_INJECTION: "1",
    GJC_READINESS_TEST_PROBE: "pass",
    GJC_WORKSPACE_INVENTORY: serializedTestInventory({
      inventoryGeneration: 5,
      workspaces: [
        capabilityWorkspace(validBinding, "/srv/workspace-1"),
        capabilityWorkspace(secondBinding, "/srv/workspace-2"),
      ],
    }),
  });
  try {
    const initial = onceMessage(daemon.peer, MSG_TYPES.READINESS);
    daemon.peer.send(JSON.stringify({
      type: MSG_TYPES.REGISTER_OK,
      protocolVersion: PROTOCOL_VERSION_V2,
      capabilities: [WORKSPACE_READINESS_CAPABILITY],
    }));
    await initial;
    const bindingReceipts = Promise.all([
      onceMessage(daemon.peer, MSG_TYPES.BIND_OK),
      onceMessage(daemon.peer, MSG_TYPES.BIND_OK),
    ]);
    const readinessFrames = [
      waitForMessage(
        daemon.peer,
        (frame) => frame.type === MSG_TYPES.READINESS &&
          frame.bindingId === firstBinding.bindingId && frame.status.workspace === "ready"
      ),
      waitForMessage(
        daemon.peer,
        (frame) => frame.type === MSG_TYPES.READINESS &&
          frame.bindingId === secondBinding.bindingId && frame.status.workspace === "ready"
      ),
    ];
    daemon.peer.send(JSON.stringify(firstBinding));
    daemon.peer.send(JSON.stringify(secondBinding));
    await bindingReceipts;
    const [firstReady, secondReady] = await Promise.all(readinessFrames);
    assert.equal(firstReady.workspaceId, firstBinding.workspaceId);
    assert.equal(secondReady.workspaceId, secondBinding.workspaceId);
  } finally {
    await daemon.close();
  }
});

test("daemon rejects an invoke with a stale workspace generation", async () => {
  const daemon = await startDaemon({
    GJC_READINESS_V2: "1",
    GJC_READINESS_TEST_INJECTION: "1",
    GJC_READINESS_TEST_PROBE: "pass",
    GJC_WORKSPACE_INVENTORY: serializedTestInventory({
      inventoryGeneration: validBinding.inventoryGeneration,
      workspaces: [capabilityWorkspace(validBinding, "/srv/workspace")],
    }),
  });
  try {
    daemon.peer.send(JSON.stringify({
      type: MSG_TYPES.REGISTER_OK,
      protocolVersion: PROTOCOL_VERSION_V2,
      capabilities: [WORKSPACE_READINESS_CAPABILITY],
    }));
    await onceMessage(daemon.peer, MSG_TYPES.READINESS);
    daemon.peer.send(JSON.stringify(validBinding));
    await onceMessage(daemon.peer, MSG_TYPES.BIND_OK);
    await waitForMessage(
      daemon.peer,
      (message) => message.type === MSG_TYPES.READINESS && message.status.workspace === "ready"
    );
    daemon.peer.send(JSON.stringify({
      type: MSG_TYPES.INVOKE,
      requestId: "stale-workspace-generation",
      bindingId: validBinding.bindingId,
      mappingId: validBinding.mappingId,
      mappingGeneration: validBinding.mappingGeneration,
      mappingVersion: validBinding.mappingVersion,
      workspaceId: validBinding.workspaceId,
      workspaceGeneration: validBinding.workspaceGeneration - 1,
      command: { kind: "prompt", message: "hello" },
    }));
    const response = await onceMessage(daemon.peer, MSG_TYPES.EVENT);
    assert.equal(response.requestId, "stale-workspace-generation");
    assert.equal(JSON.parse(response.error).code, PROTOCOL_ERROR_CODES.WORKSPACE_GENERATION_STALE);
  } finally {
    await daemon.close();
  }
});

test("daemon rejects stale workspace binding generations", async () => {
  const daemon = await startDaemon({ GJC_READINESS_V2: "1" });
  try {
    const registerOk = new Promise((resolve) => {
      const onMessage = (raw) => {
        const message = JSON.parse(raw.toString());
        if (message.type === MSG_TYPES.READINESS) {
          daemon.peer.off("message", onMessage);
          resolve(message);
        }
      };
      daemon.peer.on("message", onMessage);
    });
    daemon.peer.send(JSON.stringify({
      type: MSG_TYPES.REGISTER_OK,
      protocolVersion: PROTOCOL_VERSION_V2,
      capabilities: [WORKSPACE_READINESS_CAPABILITY],
    }));
    await registerOk;
    daemon.peer.send(JSON.stringify(validBinding));
    await onceMessage(daemon.peer, MSG_TYPES.BIND_OK);

    const closed = once(daemon.peer, "close");
    daemon.peer.send(JSON.stringify({
      ...validBinding,
      mappingGeneration: validBinding.mappingGeneration - 1,
    }));
    const [code] = await closed;
    assert.equal(code, 1008);
  } finally {
    await daemon.close();
  }
});

test("daemon rejects a stale workspace binding replayed on a new socket", async () => {
  const daemon = await startDaemon({ GJC_READINESS_V2: "1" });
  try {
    daemon.peer.send(JSON.stringify({
      type: MSG_TYPES.REGISTER_OK,
      protocolVersion: PROTOCOL_VERSION_V2,
      capabilities: [WORKSPACE_READINESS_CAPABILITY],
    }));
    await onceMessage(daemon.peer, MSG_TYPES.READINESS);
    const newer = {
      ...validBinding,
      bindingId: "binding-newer",
      mappingGeneration: validBinding.mappingGeneration + 1,
      workspaceGeneration: validBinding.workspaceGeneration + 1,
      inventoryGeneration: validBinding.inventoryGeneration + 1,
    };
    daemon.peer.send(JSON.stringify(newer));
    await onceMessage(daemon.peer, MSG_TYPES.BIND_OK);

    const reconnecting = once(daemon.wss, "connection");
    daemon.peer.terminate();
    const [nextPeer] = await reconnecting;
    assert.equal((await onceMessage(nextPeer, MSG_TYPES.REGISTER)).type, MSG_TYPES.REGISTER);
    nextPeer.send(JSON.stringify({
      type: MSG_TYPES.REGISTER_OK,
      protocolVersion: PROTOCOL_VERSION_V2,
      capabilities: [WORKSPACE_READINESS_CAPABILITY],
    }));
    await onceMessage(nextPeer, MSG_TYPES.READINESS);

    const closed = once(nextPeer, "close");
    nextPeer.send(JSON.stringify(validBinding));
    const [code] = await closed;
    assert.equal(code, 1008);
  } finally {
    await daemon.close();
  }
});

test("daemon rejects a second binding for the same workspace without a generation advance", async () => {
  const daemon = await startDaemon({ GJC_READINESS_V2: "1" });
  try {
    daemon.peer.send(JSON.stringify({
      type: MSG_TYPES.REGISTER_OK,
      protocolVersion: PROTOCOL_VERSION_V2,
      capabilities: [WORKSPACE_READINESS_CAPABILITY],
    }));
    await onceMessage(daemon.peer, MSG_TYPES.READINESS);
    daemon.peer.send(JSON.stringify(validBinding));
    await onceMessage(daemon.peer, MSG_TYPES.BIND_OK);

    const closed = once(daemon.peer, "close");
    daemon.peer.send(JSON.stringify({
      ...validBinding,
      bindingId: "binding-2",
    }));
    const [code] = await closed;
    assert.equal(code, 1008);
  } finally {
    await daemon.close();
  }
});

test("daemon replaces an older binding for the same workspace after a generation advance", async () => {
  const daemon = await startDaemon({ GJC_READINESS_V2: "1" });
  try {
    daemon.peer.send(JSON.stringify({
      type: MSG_TYPES.REGISTER_OK,
      protocolVersion: PROTOCOL_VERSION_V2,
      capabilities: [WORKSPACE_READINESS_CAPABILITY],
    }));
    await onceMessage(daemon.peer, MSG_TYPES.READINESS);
    daemon.peer.send(JSON.stringify(validBinding));
    await onceMessage(daemon.peer, MSG_TYPES.BIND_OK);

    const replacement = {
      ...validBinding,
      bindingId: "binding-2",
      mappingGeneration: validBinding.mappingGeneration + 1,
    };
    daemon.peer.send(JSON.stringify(replacement));
    const bindOk = await onceMessage(daemon.peer, MSG_TYPES.BIND_OK);
    assert.equal(bindOk.bindingId, replacement.bindingId);

    daemon.peer.send(JSON.stringify({
      type: MSG_TYPES.INVOKE,
      requestId: "old-binding",
      bindingId: validBinding.bindingId,
      mappingId: validBinding.mappingId,
      mappingGeneration: validBinding.mappingGeneration,
      mappingVersion: validBinding.mappingVersion,
      workspaceId: validBinding.workspaceId,
      workspaceGeneration: validBinding.workspaceGeneration,
      command: { kind: "prompt", message: "hello" },
    }));
    const response = await onceMessage(daemon.peer, MSG_TYPES.EVENT);
    assert.equal(JSON.parse(response.error).code, PROTOCOL_ERROR_CODES.WORKSPACE_MAPPING_CHANGED);
  } finally {
    await daemon.close();
  }
});

test("invoke validation rejects an empty model name", () => {
  assert.equal(
    isInvokeMessage({
      type: "invoke",
      requestId: "request-1",
      workDir: "/workspace",
      command: { kind: "set_model", modelName: "" },
    }),
    false
  );
});

test("daemon advertises protocol version and capabilities in its register frame", async () => {
  const daemon = await startDaemon();
  try {
    // startDaemon() captures the first register frame from the child daemon.
    assert.equal(daemon.register.protocolVersion, PROTOCOL_VERSION);
    assert.deepEqual(daemon.register.capabilities, [...CAPABILITIES]);
    assert.equal(isRegisterMessage(daemon.register), true);
    daemon.peer.send(JSON.stringify({ type: "register_ok" }));
  } finally {
    await daemon.close();
  }
});

test("stopChild escalates to SIGKILL after the graceful timeout", async () => {
  const child = new EventEmitter();
  child.exitCode = null;
  child.signalCode = null;
  const signals = [];
  child.kill = (signal) => {
    signals.push(signal);
    if (signal === "SIGKILL") {
      child.signalCode = signal;
      queueMicrotask(() => child.emit("exit", null, signal));
    }
    return true;
  };

  await stopChild(child, 1);

  assert.deepEqual(signals, ["SIGTERM", "SIGKILL"]);
});

test("protocol errors are non-empty and bounded for Error and non-Error throws", () => {
  assert.equal(normalizeProtocolError(new Error("")), "Unknown daemon error");
  assert.equal(normalizeProtocolError(""), "Unknown daemon error");
  assert.equal(normalizeProtocolError({ reason: "failure" }), "[object Object]");
  const malformedError = new Error("ignored");
  malformedError.message = 42;
  assert.equal(normalizeProtocolError(malformedError), "42");
  assert.equal(
    normalizeProtocolError({
      [Symbol.toPrimitive]() {
        throw new Error("cannot stringify");
      },
    }),
    "Unknown daemon error"
  );
  const throwingMessage = new Error("ignored");
  Object.defineProperty(throwingMessage, "message", {
    get() {
      throw new Error("cannot read message");
    },
  });
  assert.equal(normalizeProtocolError(throwingMessage), "Unknown daemon error");
  assert.equal(
    normalizeProtocolError("x".repeat(V0_LIMITS.ERROR + 1)).length,
    V0_LIMITS.ERROR
  );
  assert.equal(
    isEventMessage({ type: "event", requestId: "request-1", error: "" }),
    false
  );
});

test("malformed invoke closes with a policy violation", async () => {
  const daemon = await startDaemon();
  try {
    daemon.peer.send(JSON.stringify({ type: "register_ok" }));
    const closed = once(daemon.peer, "close");
    daemon.peer.send(
      JSON.stringify({
        type: "invoke",
        requestId: "request-1",
        workDir: process.cwd(),
        command: { kind: "set_model", modelName: "" },
      })
    );
    const [code] = await closed;
    assert.equal(code, 1008);

    // Stop the child after the peer observes the policy close.
    await stopChild(daemon.child);
  } finally {
    await daemon.close();
  }
});

test("daemon closes a socket that reuses an in-flight requestId", async () => {
  const daemon = await startDaemon();
  try {
    daemon.peer.send(JSON.stringify({ type: "register_ok" }));
    const closed = once(daemon.peer, "close");
    const invoke = {
      type: "invoke",
      requestId: "duplicate-request",
      workDir: process.cwd(),
      command: { kind: "prompt", message: "hold ownership" },
    };

    daemon.peer.send(JSON.stringify(invoke));
    daemon.peer.send(JSON.stringify(invoke));

    const [code] = await closed;
    assert.equal(code, 1008);
  } finally {
    await daemon.close();
  }
});

test("daemon permits requestId reuse only after the prior invoke settles", async () => {
  const daemon = await startDaemon();
  try {
    daemon.peer.send(JSON.stringify({ type: "register_ok" }));
    const invoke = {
      type: "invoke",
      requestId: "reusable-request",
      workDir: `${process.cwd()}/missing-request-id-fence-workdir`,
      command: { kind: "prompt", message: "fail setup" },
    };

    for (let attempt = 0; attempt < 2; attempt += 1) {
      const response = once(daemon.peer, "message");
      daemon.peer.send(JSON.stringify(invoke));
      const [raw] = await response;
      const event = JSON.parse(raw.toString());
      assert.equal(event.requestId, invoke.requestId);
      assert.equal(event.done, true);
      assert.equal(typeof event.error, "string");
    }
    assert.equal(daemon.peer.readyState, WebSocket.OPEN);
  } finally {
    await daemon.close();
  }
});

test("daemon sends a bounded error event when invoke setup fails", async () => {
  const daemon = await startDaemon();
  try {
    daemon.peer.send(JSON.stringify({ type: "register_ok" }));
    const response = once(daemon.peer, "message");
    daemon.peer.send(
      JSON.stringify({
        type: "invoke",
        requestId: "request-setup-failure",
        workDir: `${process.cwd()}/directory-that-does-not-exist-for-protocol-test`,
        command: { kind: "prompt", message: "hello" },
      })
    );

    const [raw] = await response;
    const event = JSON.parse(raw.toString());
    assert.equal(isEventMessage(event), true);
    assert.equal(event.requestId, "request-setup-failure");
    assert.equal(event.done, true);
    assert.equal(typeof event.error, "string");
    assert.ok(event.error.length > 0);
    assert.ok(event.error.length <= V0_LIMITS.ERROR);
  } finally {
    await daemon.close();
  }
});

test("daemon rejects an oversized inbound WebSocket payload", async () => {
  const daemon = await startDaemon();
  try {
    const closed = once(daemon.peer, "close");
    daemon.peer.send("x".repeat(MAX_WS_PAYLOAD_BYTES + 1));
    const [code] = await closed;
    assert.equal(code, 1009);
  } finally {
    await daemon.close();
  }
});
test("isAnswerMessage accepts a well-formed answer and rejects malformed ones (#35)", () => {
  assert.equal(
    isAnswerMessage({
      type: "answer",
      requestId: "request-1",
      gateId: "gate-1",
      answer: "yes",
    }),
    true
  );
  // Empty answer is allowed (a user may send an empty selection the daemon maps/rejects).
  assert.equal(
    isAnswerMessage({ type: "answer", requestId: "r", gateId: "g", answer: "" }),
    true
  );
  assert.equal(isAnswerMessage(null), false);
  assert.equal(isAnswerMessage({ type: "answer" }), false);
  assert.equal(
    isAnswerMessage({ type: "answer", requestId: "r", gateId: "g" }),
    false,
    "missing answer"
  );
  assert.equal(
    isAnswerMessage({ type: "answer", requestId: "", gateId: "g", answer: "x" }),
    false,
    "empty requestId"
  );
  assert.equal(
    isAnswerMessage({ type: "answer", requestId: "r", gateId: "", answer: "x" }),
    false,
    "empty gateId"
  );
  assert.equal(
    isAnswerMessage({
      type: "answer",
      requestId: "r",
      gateId: "x".repeat(V0_LIMITS.GATE_ID + 1),
      answer: "x",
    }),
    false,
    "oversized gateId"
  );
  assert.equal(
    isAnswerMessage({
      type: "answer",
      requestId: "r",
      gateId: "g",
      answer: "x".repeat(V0_LIMITS.MESSAGE + 1),
    }),
    false,
    "oversized answer"
  );
  assert.equal(
    isAnswerMessage({ type: "invoke", requestId: "r", gateId: "g", answer: "x" }),
    false,
    "wrong type"
  );
});

test("isGateRequestEvent validates the gate_request event subtype incl. bounds and choices (#35)", () => {
  assert.equal(
    isGateRequestEvent({
      type: "gate_request",
      requestId: "request-1",
      gateId: "gate-1",
      prompt: "Pick one",
      kind: "question",
      choices: [
        { value: 0, label: "First" },
        { value: "b", label: "Second" },
      ],
    }),
    true
  );
  // requestId and choices are optional.
  assert.equal(
    isGateRequestEvent({
      type: "gate_request",
      gateId: "g",
      prompt: "Approve?",
      kind: "approval",
    }),
    true
  );
  assert.equal(isGateRequestEvent({ type: "gate_request", gateId: "g", prompt: "p", kind: "execution" }), true);
  assert.equal(isGateRequestEvent(null), false);
  assert.equal(
    isGateRequestEvent({ type: "gate_request", gateId: "g", prompt: "p", kind: "bogus" }),
    false,
    "unknown kind"
  );
  assert.equal(
    isGateRequestEvent({ type: "gate_request", gateId: "", prompt: "p", kind: "question" }),
    false,
    "empty gateId"
  );
  assert.equal(
    isGateRequestEvent({ type: "gate_request", gateId: "g", prompt: "", kind: "question" }),
    false,
    "empty prompt"
  );
  assert.equal(
    isGateRequestEvent({
      type: "gate_request",
      gateId: "g",
      prompt: "x".repeat(V0_LIMITS.GATE_PROMPT + 1),
      kind: "question",
    }),
    false,
    "oversized prompt"
  );
  assert.equal(
    isGateRequestEvent({
      type: "gate_request",
      gateId: "g",
      prompt: "p",
      kind: "question",
      requestId: "",
    }),
    false,
    "present but empty requestId"
  );
  assert.equal(
    isGateRequestEvent({
      type: "gate_request",
      gateId: "g",
      prompt: "p",
      kind: "question",
      choices: "not-an-array",
    }),
    false,
    "choices must be an array"
  );
  assert.equal(
    isGateRequestEvent({
      type: "gate_request",
      gateId: "g",
      prompt: "p",
      kind: "question",
      choices: Array.from({ length: V0_LIMITS.MAX_CHOICES + 1 }, (_, i) => ({
        value: i,
        label: `c${i}`,
      })),
    }),
    false,
    "too many choices"
  );
  assert.equal(
    isGateRequestEvent({
      type: "gate_request",
      gateId: "g",
      prompt: "p",
      kind: "question",
      choices: [{ label: "missing value" }],
    }),
    false,
    "choice missing value"
  );
  assert.equal(
    isGateRequestEvent({
      type: "gate_request",
      gateId: "g",
      prompt: "p",
      kind: "question",
      choices: [{ value: 1, label: 123 }],
    }),
    false,
    "choice label must be a string"
  );
});

test("adding #35 message types does not break backward-compat validators", () => {
  // MSG_TYPES additions are present and additive.
  assert.equal(MSG_TYPES.ANSWER, "answer");
  assert.equal(MSG_TYPES.GATE_REQUEST, "gate_request");

  // A gate_request rides inside an EventMessage's `event` payload; isEventMessage
  // still accepts it as a normal event (it only requires event to be an object).
  const gateRequest = {
    type: "gate_request",
    gateId: "g",
    prompt: "p",
    kind: "question",
  };
  assert.equal(
    isEventMessage({ type: "event", requestId: "r", event: gateRequest }),
    true
  );

  // An unrecognized/new top-level type must not crash or be misclassified by the
  // legacy validators — a v0 peer safely ignores it.
  assert.equal(isEventMessage({ type: "answer", requestId: "r", gateId: "g", answer: "y" }), false);
  assert.equal(isInvokeMessage({ type: "answer", requestId: "r", gateId: "g", answer: "y" }), false);
  assert.equal(isAnswerMessage({ type: "event", requestId: "r", event: {} }), false);
  assert.equal(isGateRequestEvent({ type: "event", requestId: "r" }), false);
});
function makeReadinessFrame(overrides = {}) {
  return {
    type: MSG_TYPES.READINESS,
    socketGeneration: 1,
    revision: 1,
    observedAt: Date.now(),
    status: {
      connection: "online",
      runtime: "ready",
      providerAuth: "configured",
      modelProfile: "ready",
      workspace: "ready",
    },
    ...overrides,
  };
}

test("workspace readiness validates bounded opaque IDs and generation pairing", () => {
  assert.equal(isWorkspaceId("workspace-1"), true);
  assert.equal(isWorkspaceId("ws_01.alpha"), true);
  assert.equal(isWorkspaceId(""), false);
  assert.equal(isWorkspaceId("../escape"), false);
  assert.equal(isWorkspaceId("workspace/name"), false);
  assert.equal(isWorkspaceId("workspace\\name"), false);
  assert.equal(isWorkspaceId("workspace name"), false);
  assert.equal(isWorkspaceId("workspace\nname"), false);
  assert.equal(isWorkspaceId("x".repeat(WORKSPACE_ID_MAX_LENGTH + 1)), false);

  assert.equal(
    isReadinessMessage(
      makeReadinessFrame({ workspaceId: "workspace-1", workspaceGeneration: 7 })
    ),
    true
  );
  assert.equal(
    isReadinessMessage(makeReadinessFrame({ workspaceId: "workspace-1" })),
    false,
    "workspaceId requires workspaceGeneration"
  );
  assert.equal(
    isReadinessMessage(makeReadinessFrame({ workspaceGeneration: 7 })),
    false,
    "workspaceGeneration cannot be host-level"
  );
});

test("readiness validates all five dimensions and every documented status value", () => {
  assert.deepEqual(READINESS_DIMENSIONS, [
    "connection",
    "runtime",
    "providerAuth",
    "modelProfile",
    "workspace",
  ]);
  assert.equal(isReadinessStatus(makeReadinessFrame().status), true);

  for (const dimension of READINESS_DIMENSIONS) {
    for (const status of READINESS_STATUS_VALUES[dimension]) {
      const frame = makeReadinessFrame();
      frame.status[dimension] = status;
      assert.equal(
        isReadinessMessage(frame),
        true,
        `${dimension}=${status} should be valid`
      );
    }
  }

  assert.equal(
    isReadinessMessage(
      makeReadinessFrame({
        status: { ...makeReadinessFrame().status, runtime: "unknown" },
      })
    ),
    false,
    "unknown dimension value"
  );
  assert.equal(
    isReadinessStatus({
      ...makeReadinessFrame().status,
      unexpected: "ready",
    }),
    false,
    "unknown dimension"
  );
  assert.equal(
    isReadinessMessage(makeReadinessFrame({ status: { connection: "online" } })),
    false,
    "missing dimensions"
  );
});

test("readiness enforces TTL bounds/default and bounded frame fields", () => {
  assert.equal(isReadinessTtl(READINESS_MIN_TTL_MS), true);
  assert.equal(isReadinessTtl(READINESS_MAX_TTL_MS), true);
  assert.equal(isReadinessTtl(READINESS_MIN_TTL_MS - 1), false);
  assert.equal(isReadinessTtl(READINESS_MAX_TTL_MS + 1), false);
  assert.equal(isReadinessTtl(1.5), false);
  assert.equal(normalizeReadinessTtl(undefined), READINESS_DEFAULT_TTL_MS);

  assert.equal(
    isReadinessMessage(makeReadinessFrame({ ttlMs: READINESS_MIN_TTL_MS })),
    true
  );
  assert.equal(
    isReadinessMessage(makeReadinessFrame({ ttlMs: READINESS_MAX_TTL_MS })),
    true
  );
  assert.equal(
    isReadinessMessage(makeReadinessFrame({ ttlMs: READINESS_MIN_TTL_MS - 1 })),
    false
  );
  assert.equal(
    isReadinessMessage(makeReadinessFrame({ ttlMs: READINESS_MAX_TTL_MS + 1 })),
    false
  );
  assert.equal(
    isReadinessMessage(makeReadinessFrame({ observedAt: "2026-08-03T00:00:00.000Z" })),
    false,
    "timestamps are bounded numeric wire values"
  );
  assert.equal(
    isReadinessMessage(makeReadinessFrame({ revision: 0 })),
    false,
    "revision starts at one"
  );
  assert.equal(
    isReadinessMessage(makeReadinessFrame({ socketGeneration: Number.MAX_SAFE_INTEGER + 1 })),
    false,
    "socket generation is a safe integer"
  );
});

test("readiness revision fences accept only newer data on the current socket", () => {
  const previous = makeReadinessFrame({ socketGeneration: 4, revision: 10 });
  assert.equal(
    isReadinessMessage(
      makeReadinessFrame({ socketGeneration: 4, revision: 11 }),
      { currentSocketGeneration: 4, previous }
    ),
    true
  );
  assert.equal(
    isReadinessMessage(
      makeReadinessFrame({ socketGeneration: 4, revision: 10 }),
      { currentSocketGeneration: 4, previous }
    ),
    false,
    "duplicate revision"
  );
  assert.equal(
    isReadinessMessage(
      makeReadinessFrame({ socketGeneration: 4, revision: 9 }),
      { currentSocketGeneration: 4, previous }
    ),
    false,
    "lower revision"
  );
  assert.equal(
    isReadinessMessage(
      makeReadinessFrame({ socketGeneration: 3, revision: 11 }),
      { currentSocketGeneration: 4, previous }
    ),
    false,
    "old socket generation"
  );
});

test("readiness capability gate requires both bounded v2 register frames", () => {
  const register = {
    type: "register",
    hostId: "host-1",
    token: "token-1",
    protocolVersion: PROTOCOL_VERSION_V2,
    capabilities: [WORKSPACE_READINESS_CAPABILITY],
  };
  const registerOk = {
    type: "register_ok",
    protocolVersion: PROTOCOL_VERSION_V2,
    capabilities: [WORKSPACE_READINESS_CAPABILITY],
  };
  assert.equal(isReadinessCapabilityGate(register, registerOk), true);
  assert.equal(isReadinessCapabilityGate({ register, registerOk }), true);
  assert.equal(
    isReadinessCapabilityGate(
      { ...register, capabilities: [...CAPABILITIES] },
      registerOk
    ),
    false,
    "register advertisement is required"
  );
  assert.equal(
    isReadinessCapabilityGate(register, { ...registerOk, capabilities: [] }),
    false,
    "register response capability is required"
  );
  assert.equal(
    isReadinessCapabilityGate(register, { ...registerOk, protocolVersion: PROTOCOL_VERSION }),
    false,
    "protocol v1 cannot commit v2"
  );
  assert.equal(
    isReadinessCapabilityGate(register, { type: "register_ok" }),
    false,
    "missing response negotiation fields fail closed"
  );
});
test("protocol negotiation rejects future versions and never down-negotiates readiness", () => {
  const register = {
    type: "register",
    hostId: "host-1",
    token: "token-1",
    protocolVersion: PROTOCOL_VERSION_V2,
    capabilities: [WORKSPACE_READINESS_CAPABILITY],
  };
  const registerOk = {
    type: "register_ok",
    protocolVersion: PROTOCOL_VERSION_V2,
    capabilities: [WORKSPACE_READINESS_CAPABILITY],
  };

  assert.equal(
    isRegisterMessage({ ...register, protocolVersion: PROTOCOL_VERSION_V3 }),
    true
  );
  assert.equal(
    isRegisterOkMessage({ ...registerOk, protocolVersion: PROTOCOL_VERSION_V3 }),
    true
  );
  assert.equal(
    isRegisterMessage({ ...register, protocolVersion: PROTOCOL_VERSION_V3 + 1 }),
    false
  );
  assert.equal(
    isRegisterOkMessage({ ...registerOk, protocolVersion: PROTOCOL_VERSION_V3 + 1 }),
    false
  );
  assert.equal(
    isReadinessCapabilityGate(
      { ...register, protocolVersion: PROTOCOL_VERSION_V3 },
      registerOk
    ),
    false
  );
  assert.equal(
    isReadinessCapabilityGate(register, {
      ...registerOk,
      protocolVersion: PROTOCOL_VERSION_V3,
    }),
    false
  );
  assert.equal(
    isReadinessCapabilityGate({
      negotiatedVersion: PROTOCOL_VERSION_V2 + 1,
      localCapabilities: [WORKSPACE_READINESS_CAPABILITY],
      remoteCapabilities: [WORKSPACE_READINESS_CAPABILITY],
    }),
    false
  );
  assert.equal(
    isRegisterMessage({ ...register, protocolVersion: "2" }),
    false,
    "version strings are malformed"
  );
  assert.equal(
    isRegisterOkMessage({ ...registerOk, protocolVersion: null }),
    false,
    "null versions are malformed"
  );
});

test("v2 invoke identity is bounded, exact, and gated from legacy sockets", () => {
  const command = { kind: "prompt", message: "hello" };
  const legacy = {
    type: "invoke",
    requestId: "request-1",
    workDir: "/workspace",
    command,
  };
  assert.equal(isInvokeMessage(legacy), true);

  for (const field of [
    "mappingId",
    "mappingGeneration",
    "mappingVersion",
    "workspaceId",
    "workspaceGeneration",
  ]) {
    assert.equal(
      isInvokeMessage({ ...legacy, [field]: field === "mappingId" ? "mapping-1" : 1 }),
      false,
      `${field} is reserved before v2 capability commit`
    );
  }

  const valid = {
    type: "invoke",
    requestId: "request-2",
    mappingId: "mapping-1",
    mappingGeneration: 2,
    mappingVersion: 3,
    command,
  };
  assert.equal(isInvokeMessage(valid, { v2: true }), true);
  assert.equal(
    isInvokeMessage({ ...valid, workspaceId: "workspace-1" }, { v2: true }),
    true
  );
  assert.equal(
    isInvokeMessage({ ...valid, workDir: "/workspace" }, { v2: true }),
    false,
    "managed v2 invokes must remain path-free"
  );
  assert.equal(
    isInvokeMessage(
      { ...valid, workspaceId: "workspace-1", workDir: "workspace-1" },
      { v2: true }
    ),
    false
  );
  assert.equal(
    isInvokeMessage(
      { ...valid, workspaceId: "workspace-1", workDir: "other-workspace" },
      { v2: true }
    ),
    false,
    "managed v2 paths are rejected before canonical mapping resolution"
  );
  assert.equal(
    isInvokeMessage({ ...valid, mappingId: "../escape" }, { v2: true }),
    false
  );
  assert.equal(
    isInvokeMessage({ ...valid, mappingId: "x".repeat(129) }, { v2: true }),
    false
  );
  assert.equal(
    isInvokeMessage({ ...valid, mappingGeneration: 0 }, { v2: true }),
    false
  );
  assert.equal(
    isInvokeMessage({ ...valid, mappingGeneration: 1.5 }, { v2: true }),
    false
  );
  assert.equal(
    isInvokeMessage({ ...valid, mappingVersion: Number.MAX_SAFE_INTEGER + 1 }, { v2: true }),
    false
  );
  assert.equal(
    isInvokeMessage({ ...valid, futureMappingField: "ignored" }, { v2: true }),
    false,
    "unknown v2 fields are not silently ignored"
  );
});

test("readiness remediation tuples are canonical and stable", () => {
  const expected = {
    [PROTOCOL_ERROR_CODES.READINESS_TIMESTAMP_INVALID]: {
      code: PROTOCOL_ERROR_CODES.READINESS_TIMESTAMP_INVALID,
      retryable: false,
      action: "contact_admin",
    },
    [PROTOCOL_ERROR_CODES.READINESS_REPLAYED]: {
      code: PROTOCOL_ERROR_CODES.READINESS_REPLAYED,
      retryable: false,
      action: "contact_admin",
    },
    [PROTOCOL_ERROR_CODES.CONNECTION_LOST]: {
      code: PROTOCOL_ERROR_CODES.CONNECTION_LOST,
      retryable: true,
      action: "retry_later",
    },
    [PROTOCOL_ERROR_CODES.WORKSPACE_NOT_FOUND]: {
      code: PROTOCOL_ERROR_CODES.WORKSPACE_NOT_FOUND,
      retryable: false,
      action: "refresh_workspace",
    },
    [PROTOCOL_ERROR_CODES.INVENTORY_PENDING]: {
      code: PROTOCOL_ERROR_CODES.INVENTORY_PENDING,
      retryable: true,
      action: "retry_later",
    },
    [PROTOCOL_ERROR_CODES.PROVIDER_MISSING]: {
      code: PROTOCOL_ERROR_CODES.PROVIDER_MISSING,
      retryable: true,
      action: "login",
    },
    [PROTOCOL_ERROR_CODES.PROVIDER_INVALID]: {
      code: PROTOCOL_ERROR_CODES.PROVIDER_INVALID,
      retryable: false,
      action: "repair_profile",
    },
    [PROTOCOL_ERROR_CODES.MODEL_PROFILE_MISSING]: {
      code: PROTOCOL_ERROR_CODES.MODEL_PROFILE_MISSING,
      retryable: false,
      action: "repair_profile",
    },
    [PROTOCOL_ERROR_CODES.MODEL_PROFILE_INVALID]: {
      code: PROTOCOL_ERROR_CODES.MODEL_PROFILE_INVALID,
      retryable: false,
      action: "repair_profile",
    },
  };
  for (const [code, tuple] of Object.entries(expected)) {
    assert.deepEqual(READINESS_REMEDIATIONS[code], tuple);
    assert.equal(Object.isFrozen(READINESS_REMEDIATIONS[code]), true);
  }
});

test("WORKSPACE_ADMISSION_EXCEEDED is a first-class, classification-safe protocol code", () => {
  const code = PROTOCOL_ERROR_CODES.WORKSPACE_ADMISSION_EXCEEDED;
  assert.equal(code, "WORKSPACE_ADMISSION_EXCEEDED");

  // Blocking guard (#43): membership in the taxonomy value set is exactly what
  // makes daemon.classifyReadinessError PRESERVE this code rather than collapse
  // it to UNKNOWN_RUNTIME / a generic fallback. Mirror that membership check.
  const codeSet = new Set(Object.values(PROTOCOL_ERROR_CODES));
  assert.equal(codeSet.has(code), true);

  // Canonical remediation tuple: retryable, retry_later, frozen.
  assert.deepEqual(READINESS_REMEDIATIONS[code], {
    code,
    retryable: true,
    action: "retry_later",
  });
  assert.equal(Object.isFrozen(READINESS_REMEDIATIONS[code]), true);

  // Grouped with the resource/session admission taxonomy, next to SESSION_LIMIT.
  assert.equal(READINESS_ERROR_TAXONOMY.resourceSession.includes(code), true);
  assert.equal(
    READINESS_ERROR_TAXONOMY.resourceSession.includes(PROTOCOL_ERROR_CODES.SESSION_LIMIT),
    true
  );
});
