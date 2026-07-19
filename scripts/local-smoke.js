import { spawn } from "node:child_process";
import { once } from "node:events";
import { HostRegistry } from "../bot/src/host-registry.js";

const port = Number(process.env.SMOKE_HOST_WS_PORT || 7788);
const hostId = process.env.SMOKE_HOST_ID || "local-smoke";
const token = process.env.SMOKE_HOST_TOKEN || "local-smoke-token";
const workDir = process.env.SMOKE_WORK_DIR || process.cwd();
const expected = "SMOKE_OK";
const modelQuery = process.env.SMOKE_MODEL_QUERY;

const registry = new HostRegistry({
  port,
  tokensByHostId: new Map([[hostId, token]]),
});

await once(registry.wss, "listening");

const daemon = spawn(process.env.BUN_BIN || "bun", ["daemon/src/daemon.js"], {
  cwd: process.cwd(),
  env: {
    ...process.env,
    HOST_ID: hostId,
    HOST_TOKEN: token,
    HOST_LABEL: "local smoke test",
    BOT_WS_URL: `ws://localhost:${port}`,
  },
  stdio: ["ignore", "pipe", "pipe"],
});

daemon.stdout.on("data", (chunk) => process.stderr.write(chunk));
daemon.stderr.on("data", (chunk) => process.stderr.write(chunk));

try {
  await waitForHost(registry, hostId, 10_000);

  const result = await registry.invoke(
    hostId,
    workDir,
    { kind: "prompt", message: `reply with exactly: ${expected}` },
    () => {},
    120_000
  );

  if (!result.ok) {
    throw new Error(`invoke failed: ${result.error ?? "unknown error"}`);
  }
  if (result.text !== expected) {
    throw new Error(`unexpected text: ${JSON.stringify(result.text)} (expected ${expected})`);
  }

  let model;
  if (modelQuery) {
    const modelEvents = [];
    const modelResult = await registry.invoke(
      hostId,
      workDir,
      { kind: "set_model", modelName: modelQuery },
      (event) => modelEvents.push(event),
      120_000
    );
    if (!modelResult.ok) {
      throw new Error(`model invoke failed: ${modelResult.error ?? "unknown error"}`);
    }

    model = modelEvents.find((event) => event?.type === "model_resolved");
    if (!model) throw new Error("model invoke returned no model_resolved receipt");
  }
  console.log(JSON.stringify({ ok: true, hostId, workDir, text: result.text, model }));
} finally {
  daemon.kill();
  await closeRegistry(registry);
}

async function waitForHost(registry, id, timeoutMs) {
  const deadline = Date.now() + timeoutMs;
  while (!registry.isOnline(id)) {
    if (Date.now() > deadline) {
      throw new Error(`host '${id}' did not connect within ${timeoutMs}ms`);
    }
    await new Promise((resolve) => setTimeout(resolve, 100));
  }
}

async function closeRegistry(registry) {
  for (const socket of registry.connections.values()) socket.close();
  registry.wss.close();
  await once(registry.wss, "close").catch(() => {});
}
