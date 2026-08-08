#!/usr/bin/env node
import "./node-version-guard.js";
import { runManagementCli } from "./management-cli.js";
import { parseProvisionedManagementRoleBindings } from "./config.js";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";

const configPath = resolve(
  process.env.CHANNELS_CONFIG ??
    fileURLToPath(new URL("../channels.json", import.meta.url))
);

async function loadNative(roles) {
  try {
    const module = await import("@gjc-remote/native-control");
    if (typeof module.createManagementNative !== "function") return null;
    const native = await module.createManagementNative({ configPath, roles });
    if (typeof native.runStartupSelfTest !== "function") return null;
    const selfTest = await native.runStartupSelfTest();
    return selfTest?.role === "management" && selfTest?.mst === true && selfTest?.bst === false && selfTest?.writes === 0
      ? native
      : null;
  } catch {
    return null;
  }
}

const roles = process.env.GJC_MANAGEMENT_ROLE_BINDINGS?.trim()
  ? (() => {
    try {
      return parseProvisionedManagementRoleBindings(process.env.GJC_MANAGEMENT_ROLE_BINDINGS);
    } catch {
      return null;
    }
  })()
  : null;
const native = roles ? await loadNative(roles) : null;
const exitCode = await runManagementCli({ argv: process.argv.slice(2), stdin: process.stdin, stdout: process.stdout, stderr: process.stderr, native });
process.exitCode = exitCode;
