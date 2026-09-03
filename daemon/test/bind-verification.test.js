// Issue #179 Slice 2: independent per-bind verification of the LIVE
// managed-workspace receipt bind path (acceptReceiptBinding). Mirrors the
// spawn+WebSocket harness pattern from protocol-validation.test.js.
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { once } from "node:events";
import { fileURLToPath } from "node:url";
import test from "node:test";
import { mkdtemp, rm, mkdir } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import {
  MSG_TYPES,
  PROTOCOL_ERROR_CODES,
  PROTOCOL_VERSION_V3,
  WORKSPACE_READINESS_CAPABILITY,
  WORKSPACE_INVENTORY_RECEIPT_CAPABILITY,
  WORKSPACE_BIND_AUTHORITY_VERIFICATION_CAPABILITY,
} from "@gjc-remote/shared";
import { fingerprintManagedMappingRecord } from "@gjc-remote/shared/mapping-envelope";
import {
  buildWorkspaceInventory,
  workspaceInventoryBytes,
} from "@gjc-remote/shared/workspace-inventory";
import { WebSocketServer } from "ws";

const daemonEntry = fileURLToPath(new URL("../src/daemon.js", import.meta.url));
const CHILD_EXIT_TIMEOUT_MS = 2_000;
const ROOT_IDENTITY_FINGERPRINT = "1".repeat(64);
const STORAGE_IDENTITY_FINGERPRINT = "2".repeat(64);

const V3_CAPABILITIES = [
  WORKSPACE_READINESS_CAPABILITY,
  WORKSPACE_INVENTORY_RECEIPT_CAPABILITY,
  WORKSPACE_BIND_AUTHORITY_VERIFICATION_CAPABILITY,
];

function assertPolicyClose(code, reason, expectedReason) {
  assert.equal(code, 1008);
  const diagnostic = reason.toString();
  if (diagnostic !== "") assert.equal(diagnostic, expectedReason);
}

function buildValidReceiptBind(overrides = {}) {
  const {
    bindingId = "receipt-binding-1",
    authorityEpoch = 1,
    fenceGeneration = 1,
    hostId = "test-host",
    mappingId = "mapping-1",
    mappingGeneration = 2,
    mappingVersion = 1,
    workspaceId = "workspace-1",
    workspaceGeneration = 3,
    sourcePlatform = "posix",
    sourceRoot = sourcePlatform === "posix" ? "/srv/native/workspace-1" : "C:\\native\\workspace-1",
    containerRoot = null,
    ...rest
  } = overrides;
  const mapping = fingerprintManagedMappingRecord({
    mappingId,
    hostId,
    fenceGeneration,
    mappingGeneration,
    workspaceGeneration,
    mappingVersion,
    sourcePlatform,
    workspaceId,
    workDir: null,
    sourceRoot,
    containerRoot,
    volumeIdentity: "volume-1",
    casePolicy: sourcePlatform === "posix" ? "sensitive" : "insensitive",
    immutableDefault: false,
    mappingFingerprint: null,
  });
  return {
    type: MSG_TYPES.BIND_WORKSPACE,
    bindingId,
    authorityEpoch,
    fenceGeneration,
    hostId,
    mappingId,
    mappingGeneration,
    mappingVersion,
    workspaceId,
    workspaceGeneration,
    sourcePlatform,
    authorityFingerprint: mapping.mappingFingerprint,
    mapping,
    ...rest,
  };
}

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
  hostId = "test-host",
  inventoryGeneration = 4,
  workspaces = [],
} = {}) {
  return workspaceInventoryBytes(buildWorkspaceInventory({
    hostId,
    inventoryGeneration,
    workspaces,
  })).toString("utf8");
}

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

  let register;
  try {
    register = await Promise.race([
      registration,
      once(child, "exit").then(([code]) => {
        throw new Error(`daemon exited before registering (${code}): ${stderr}`);
      }),
    ]);
  } catch (error) {
    peer?.terminate();
    await stopChild(child);
    await new Promise((resolve) => wss.close(() => resolve()));
    throw error;
  }
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

async function registerV3(daemon) {
  daemon.peer.send(JSON.stringify({
    type: MSG_TYPES.REGISTER_OK,
    protocolVersion: PROTOCOL_VERSION_V3,
    capabilities: V3_CAPABILITIES,
  }));
  await onceMessage(daemon.peer, MSG_TYPES.READINESS);
}

test("acceptReceiptBinding accepts a fully valid receipt bind + mapping", async () => {
  const bind = buildValidReceiptBind();
  const inventory = serializedTestInventory({
    workspaces: [capabilityWorkspace(bind, "/srv/workspace")],
  });
  const daemon = await startDaemon({
    GJC_READINESS_V2: "1",
    GJC_READINESS_TEST_INJECTION: "1",
    GJC_READINESS_TEST_PROBE: "pass",
    GJC_NATIVE_INVENTORY_MODE: "verify",
    GJC_WORKSPACE_INVENTORY: inventory,
  });
  try {
    await registerV3(daemon);
    const bindOk = onceMessage(daemon.peer, MSG_TYPES.BIND_OK);
    daemon.peer.send(JSON.stringify(bind));
    const positive = await bindOk;
    assert.ok(positive.bindingFingerprint);
  } finally {
    await daemon.close();
  }
});

test("acceptReceiptBinding rejects a hash-tampered mapping (mutated without recomputing fingerprint)", async () => {
  const bind = buildValidReceiptBind();
  const tampered = {
    ...bind,
    mapping: { ...bind.mapping, sourceRoot: "/srv/native/tampered" },
  };
  const inventory = serializedTestInventory({
    workspaces: [capabilityWorkspace(bind, "/srv/workspace")],
  });
  const daemon = await startDaemon({
    GJC_READINESS_V2: "1",
    GJC_READINESS_TEST_INJECTION: "1",
    GJC_READINESS_TEST_PROBE: "pass",
    GJC_NATIVE_INVENTORY_MODE: "verify",
    GJC_WORKSPACE_INVENTORY: inventory,
  });
  try {
    await registerV3(daemon);
    let acknowledged = false;
    daemon.peer.on("message", (raw) => {
      if (JSON.parse(raw.toString()).type === MSG_TYPES.BIND_OK) acknowledged = true;
    });
    const closed = once(daemon.peer, "close");
    daemon.peer.send(JSON.stringify(tampered));
    const [code, reason] = await closed;
    assertPolicyClose(code, reason, PROTOCOL_ERROR_CODES.BIND_AUTHORITY_HASH_MISMATCH);
    assert.equal(acknowledged, false);
  } finally {
    await daemon.close();
  }
});

test("acceptReceiptBinding rejects a hostId mismatch (top-level vs daemon HOST_ID)", async () => {
  const bind = buildValidReceiptBind({ hostId: "other-host" });
  const inventory = serializedTestInventory({ workspaces: [] });
  const daemon = await startDaemon({
    GJC_READINESS_V2: "1",
    GJC_READINESS_TEST_INJECTION: "1",
    GJC_READINESS_TEST_PROBE: "pass",
    GJC_NATIVE_INVENTORY_MODE: "verify",
    GJC_WORKSPACE_INVENTORY: inventory,
  });
  try {
    await registerV3(daemon);
    let acknowledged = false;
    daemon.peer.on("message", (raw) => {
      if (JSON.parse(raw.toString()).type === MSG_TYPES.BIND_OK) acknowledged = true;
    });
    const closed = once(daemon.peer, "close");
    daemon.peer.send(JSON.stringify(bind));
    const [code] = await closed;
    assert.equal(code, 1008);
    assert.equal(acknowledged, false);
  } finally {
    await daemon.close();
  }
});

test("Finding-2: a same-bindingId re-send with a mapping-only tampered preimage is rejected (dedup bypass)", async () => {
  const bind = buildValidReceiptBind();
  const inventory = serializedTestInventory({
    workspaces: [capabilityWorkspace(bind, "/srv/workspace")],
  });
  const daemon = await startDaemon({
    GJC_READINESS_V2: "1",
    GJC_READINESS_TEST_INJECTION: "1",
    GJC_READINESS_TEST_PROBE: "pass",
    GJC_NATIVE_INVENTORY_MODE: "verify",
    GJC_WORKSPACE_INVENTORY: inventory,
  });
  try {
    await registerV3(daemon);
    const bindOk = onceMessage(daemon.peer, MSG_TYPES.BIND_OK);
    daemon.peer.send(JSON.stringify(bind));
    await bindOk;

    // Tamper a field INSIDE mapping only (outside receiptAuthority()'s
    // projection: hostId/mappingId/generations/mappingVersion/sourcePlatform/
    // workspaceId/authorityFingerprint), so sameReceiptBinding(existing,
    // message) would otherwise short-circuit true on a naive re-dedup that
    // never re-verified the preimage. The top-level fields (and therefore
    // receiptAuthority) are UNCHANGED; only mapping.sourceRoot differs and
    // mapping.mappingFingerprint is stale relative to it.
    const resend = {
      ...bind,
      mapping: { ...bind.mapping, sourceRoot: "/srv/native/tampered-resend" },
    };
    const closed = once(daemon.peer, "close");
    daemon.peer.send(JSON.stringify(resend));
    const [code] = await closed;
    assert.equal(code, 1008);
  } finally {
    await daemon.close();
  }
});

test("Finding-2: a same-workspaceId re-bind satisfying generation fencing but carrying a tampered preimage is rejected before adoptBinding", async () => {
  const bind = buildValidReceiptBind();
  const inventory = serializedTestInventory({
    workspaces: [capabilityWorkspace(bind, "/srv/workspace")],
  });
  const daemon = await startDaemon({
    GJC_READINESS_V2: "1",
    GJC_READINESS_TEST_INJECTION: "1",
    GJC_READINESS_TEST_PROBE: "pass",
    GJC_NATIVE_INVENTORY_MODE: "verify",
    GJC_WORKSPACE_INVENTORY: inventory,
  });
  try {
    await registerV3(daemon);
    const bindOk = onceMessage(daemon.peer, MSG_TYPES.BIND_OK);
    daemon.peer.send(JSON.stringify(bind));
    await bindOk;

    // A fresh bindingId, generation-advanced (fencing-legal) authority, but
    // whose mapping preimage has been tampered relative to its
    // authorityFingerprint. This must be rejected by the verifier BEFORE any
    // workspaceLeases.adoptBinding call, not merely by fencing.
    const advanced = buildValidReceiptBind({
      bindingId: "receipt-newer",
      mappingGeneration: bind.mappingGeneration + 1,
      workspaceGeneration: bind.workspaceGeneration + 1,
    });
    const tamperedAdvanced = {
      ...advanced,
      mapping: { ...advanced.mapping, sourceRoot: "/srv/native/tampered-advanced" },
    };
    const closed = once(daemon.peer, "close");
    daemon.peer.send(JSON.stringify(tamperedAdvanced));
    const [code] = await closed;
    assert.equal(code, 1008);
  } finally {
    await daemon.close();
  }
});

test("Finding-3 tier-2: forged mapping.sourceRoot escaping a configured root is rejected", async () => {
  const workspaceRoot = await mkdtemp(path.join(tmpdir(), "gjc-bind-root-"));
  try {
    const bind = buildValidReceiptBind({ sourceRoot: "/etc/evil" });
    const inventory = serializedTestInventory({
      workspaces: [capabilityWorkspace(bind, "/srv/workspace")],
    });
    const daemon = await startDaemon({
      GJC_READINESS_V2: "1",
      GJC_READINESS_TEST_INJECTION: "1",
      GJC_READINESS_TEST_PROBE: "pass",
      GJC_NATIVE_INVENTORY_MODE: "verify",
      GJC_WORKSPACE_INVENTORY: inventory,
      GJC_NATIVE_WORKSPACE_ROOT: workspaceRoot,
    });
    try {
      await registerV3(daemon);
      let acknowledged = false;
      daemon.peer.on("message", (raw) => {
        if (JSON.parse(raw.toString()).type === MSG_TYPES.BIND_OK) acknowledged = true;
      });
      const closed = once(daemon.peer, "close");
      daemon.peer.send(JSON.stringify(bind));
      const [code, reason] = await closed;
      assertPolicyClose(code, reason, PROTOCOL_ERROR_CODES.BIND_AUTHORITY_CONTAINMENT_ESCAPE);
      assert.equal(acknowledged, false);
    } finally {
      await daemon.close();
    }
  } finally {
    await rm(workspaceRoot, { recursive: true, force: true });
  }
});

test("Finding-3 tier-2: no configured root is a documented containment no-op", async () => {
  // sourceRoot deliberately points somewhere no plausible daemon root would
  // contain; with no GJC_NATIVE_WORKSPACE_ROOT set, containment must be a
  // no-op and the bind must still verify + serve.
  const bind = buildValidReceiptBind({ sourceRoot: "/etc/elsewhere" });
  const inventory = serializedTestInventory({
    workspaces: [capabilityWorkspace(bind, "/srv/workspace")],
  });
  const daemon = await startDaemon({
    GJC_READINESS_V2: "1",
    GJC_READINESS_TEST_INJECTION: "1",
    GJC_READINESS_TEST_PROBE: "pass",
    GJC_NATIVE_INVENTORY_MODE: "verify",
    GJC_WORKSPACE_INVENTORY: inventory,
  });
  try {
    await registerV3(daemon);
    const bindOk = onceMessage(daemon.peer, MSG_TYPES.BIND_OK);
    daemon.peer.send(JSON.stringify(bind));
    const positive = await bindOk;
    assert.ok(positive.bindingFingerprint);
  } finally {
    await daemon.close();
  }
});

test("Finding-3 tier-2 nit: mapping.containerRoot===null under a configured containment is a no-op, not an escape", async () => {
  const workspaceRoot = await mkdtemp(path.join(tmpdir(), "gjc-bind-root-"));
  try {
    // The bind's sourceRoot must lexically live under workspaceRoot for tier-2
    // to pass on the sourceRoot leg; containerRoot stays null (Slice-1
    // untested-null nit) and must not be treated as an escape.
    const sourceRoot = path.join(workspaceRoot, "workspace-1");
    await mkdir(sourceRoot, { recursive: true });
    const sourcePlatform = process.platform === "win32" ? "windows-drive" : "posix";
    const bind = buildValidReceiptBind({ sourceRoot, sourcePlatform, containerRoot: null });
    const inventory = serializedTestInventory({
      workspaces: [capabilityWorkspace(bind, "/srv/workspace")],
    });
    const daemon = await startDaemon({
      GJC_READINESS_V2: "1",
      GJC_READINESS_TEST_INJECTION: "1",
      GJC_READINESS_TEST_PROBE: "pass",
      GJC_NATIVE_INVENTORY_MODE: "verify",
      GJC_WORKSPACE_INVENTORY: inventory,
      GJC_NATIVE_WORKSPACE_ROOT: workspaceRoot,
    });
    try {
      await registerV3(daemon);
      const bindOk = onceMessage(daemon.peer, MSG_TYPES.BIND_OK);
      daemon.peer.send(JSON.stringify(bind));
      const positive = await bindOk;
      assert.ok(positive.bindingFingerprint);
    } finally {
      await daemon.close();
    }
  } finally {
    await rm(workspaceRoot, { recursive: true, force: true });
  }
});

test("managed REGISTER_OK floor rejects a peer missing bind-authority verification before commit", async () => {
  const inventory = serializedTestInventory({ workspaces: [] });
  const daemon = await startDaemon({
    GJC_READINESS_V2: "1",
    GJC_READINESS_TEST_INJECTION: "1",
    GJC_NATIVE_INVENTORY_MODE: "verify",
    GJC_WORKSPACE_INVENTORY: inventory,
  });
  try {
    const closed = once(daemon.peer, "close");
    let readinessSeen = false;
    daemon.peer.on("message", (raw) => {
      if (JSON.parse(raw.toString()).type === MSG_TYPES.READINESS) readinessSeen = true;
    });
    daemon.peer.send(JSON.stringify({
      type: MSG_TYPES.REGISTER_OK,
      protocolVersion: PROTOCOL_VERSION_V3,
      capabilities: [
        WORKSPACE_READINESS_CAPABILITY,
        WORKSPACE_INVENTORY_RECEIPT_CAPABILITY,
        // WORKSPACE_BIND_AUTHORITY_VERIFICATION_CAPABILITY deliberately absent
      ],
    }));
    const [code, reason] = await closed;
    assertPolicyClose(code, reason, PROTOCOL_ERROR_CODES.PROTOCOL_INCOMPATIBLE);
    assert.equal(readinessSeen, false);
  } finally {
    await daemon.close();
  }
});
