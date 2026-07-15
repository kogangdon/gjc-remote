import { spawn } from "node:child_process";
import { existsSync, realpathSync } from "node:fs";
import { join } from "node:path";
import { IDLE_TIMEOUT_MS } from "@gjc-remote/shared";
import { RpcSession } from "./rpc-client.js";
import { validateNativeWorkDir } from "./work-dir.js";

const GJC_BIN = process.env.GJC_BIN || "gjc";

function normalizeCanonicalWorkDir(workDir, platform) {
  if (platform !== "win32") return workDir;
  return workDir
    .replace(/^\\\\\?\\UNC\\/i, "\\\\")
    .replace(/^\\\\\?\\/, "");
}

/**
 * Per-workDir pool of `gjc --mode=rpc` child processes talked to over
 * stdin/stdout (no unix-domain-socket, so this works identically on Windows,
 * Linux, and macOS). Spawns on first request for a workDir, reuses the live
 * process for subsequent requests, and reaps processes idle longer than
 * IDLE_TIMEOUT_MS (1 hour).
 */
export class SessionPool {
  constructor({
    spawnFn = spawn,
    existsSyncFn = existsSync,
    realpathSyncFn = realpathSync.native,
    platform = process.platform,
  } = {}) {
    /** @type {Map<string, { session: RpcSession, lastUsed: number }>} */
    this.sessions = new Map();
    this.spawnFn = spawnFn;
    this.existsSyncFn = existsSyncFn;
    this.realpathSyncFn = realpathSyncFn;
    this.platform = platform;
    this.reapTimer = setInterval(() => this.#reapIdle(), 5 * 60 * 1000);
    this.reapTimer.unref?.();
  }

  #reapIdle() {
    const now = Date.now();
    for (const [workDir, entry] of this.sessions) {
      if (now - entry.lastUsed > IDLE_TIMEOUT_MS) {
        console.log(`SessionPool: reaping idle session for ${workDir}`);
        entry.session.child.kill();
        this.sessions.delete(workDir);
      }
    }
  }

  /** @returns {RpcSession} */
  ensureSession(workDir) {
    const requestedWorkDir = validateNativeWorkDir(workDir, this.platform);
    const exact = this.sessions.get(requestedWorkDir);
    if (exact && !exact.session.closed) {
      exact.lastUsed = Date.now();
      return exact.session;
    }
    if (!this.existsSyncFn(requestedWorkDir)) {
      throw new Error(`workDir does not exist on this host: ${requestedWorkDir}`);
    }

    try {
      workDir = normalizeCanonicalWorkDir(
        this.realpathSyncFn(requestedWorkDir),
        this.platform
      );
      workDir = validateNativeWorkDir(workDir, this.platform);
    } catch (error) {
      throw new Error(`workDir cannot be resolved on this host: ${requestedWorkDir}`, {
        cause: error,
      });
    }

    const existing = this.sessions.get(workDir);
    if (existing && !existing.session.closed) {
      existing.lastUsed = Date.now();
      return existing.session;
    }

    const child = this.spawnFn(
      GJC_BIN,
      ["--mode=rpc", "--session-dir", join(workDir, ".gjc-remote-session")],
      { cwd: workDir, shell: false, windowsHide: true, stdio: ["pipe", "pipe", "pipe"] }
    );
    const session = new RpcSession(child);

    child.stderr.on("data", (d) => console.error(`[gjc:${workDir}]`, d.toString().trim()));
    child.on("exit", (code) => {
      console.log(`SessionPool: gjc rpc for ${workDir} exited (${code})`);
      if (this.sessions.get(workDir)?.session === session) {
        this.sessions.delete(workDir);
      }
    });
    // Without this handler, a spawn failure (e.g. GJC_BIN missing/ENOENT)
    // surfaces as an uncaught 'error' event and crashes the whole daemon
    // process — not just this one request. Route it through RpcSession
    // instead so in-flight/queued send() calls reject cleanly.
    child.on("error", (err) => {
      console.error(`SessionPool: gjc rpc spawn failed for ${workDir}:`, err.message);
      if (this.sessions.get(workDir)?.session === session) {
        this.sessions.delete(workDir);
      }
    });

    this.sessions.set(workDir, { session, lastUsed: Date.now() });
    return session;
  }

  shutdown() {
    clearInterval(this.reapTimer);
    for (const { session } of this.sessions.values()) session.child.kill();
    this.sessions.clear();
  }
}
