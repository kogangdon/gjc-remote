import { spawn } from "node:child_process";
import { existsSync } from "node:fs";
import { join } from "node:path";
import { IDLE_TIMEOUT_MS } from "@gjc-remote/shared";
import { RpcSession } from "./rpc-client.js";

const GJC_BIN = process.env.GJC_BIN || "gjc";

/**
 * Per-workDir pool of `gjc --mode=rpc` child processes talked to over
 * stdin/stdout (no unix-domain-socket, so this works identically on Windows,
 * Linux, and macOS). Spawns on first request for a workDir, reuses the live
 * process for subsequent requests, and reaps processes idle longer than
 * IDLE_TIMEOUT_MS (1 hour).
 */
export class SessionPool {
  constructor() {
    /** @type {Map<string, { session: RpcSession, lastUsed: number }>} */
    this.sessions = new Map();
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
    const existing = this.sessions.get(workDir);
    if (existing && !existing.session.closed) {
      existing.lastUsed = Date.now();
      return existing.session;
    }

    if (!existsSync(workDir)) {
      throw new Error(`workDir does not exist on this host: ${workDir}`);
    }

    const child = spawn(
      GJC_BIN,
      ["--mode=rpc", "--session-dir", join(workDir, ".gjc-remote-session")],
      { cwd: workDir, shell: false, windowsHide: true, stdio: ["pipe", "pipe", "pipe"] }
    );

    child.stderr.on("data", (d) => console.error(`[gjc:${workDir}]`, d.toString().trim()));
    child.on("exit", (code) => {
      console.log(`SessionPool: gjc rpc for ${workDir} exited (${code})`);
      this.sessions.delete(workDir);
    });
    // Without this handler, a spawn failure (e.g. GJC_BIN missing/ENOENT)
    // surfaces as an uncaught 'error' event and crashes the whole daemon
    // process — not just this one request. Route it through RpcSession
    // instead so in-flight/queued send() calls reject cleanly.
    child.on("error", (err) => {
      console.error(`SessionPool: gjc rpc spawn failed for ${workDir}:`, err.message);
      this.sessions.delete(workDir);
    });

    const session = new RpcSession(child);
    this.sessions.set(workDir, { session, lastUsed: Date.now() });
    return session;
  }

  shutdown() {
    clearInterval(this.reapTimer);
    for (const { session } of this.sessions.values()) session.child.kill();
    this.sessions.clear();
  }
}
