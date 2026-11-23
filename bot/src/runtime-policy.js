const REQUIRED_NODE_MAJOR = 26;
const REQUIRED_BUN_VERSION = "1.4.5";

export function nodeVersionRefusal(runtime) {
  // Unsupported real Node must fail before dotenv, discord.js or native-control
  // evaluate. Node 24 has crashed on Windows with STATUS_STACK_BUFFER_OVERRUN
  // instead of the structured fatal + exit 1 (see the ADR and PR #56 evidence).
  const major = Number(runtime.versions.node?.split(".")[0]);
  if (Number.isInteger(major) && major >= REQUIRED_NODE_MAJOR) return null;
  return {
    level: "error",
    event: "unsupported_node_version",
    error: `gjc-remote/bot requires Node.js >=${REQUIRED_NODE_MAJOR}.0.0 (running ${runtime.version}). Node 24 is known to crash this process on Windows instead of exiting cleanly; install Node ${REQUIRED_NODE_MAJOR}+.`,
  };
}

export function foregroundRuntimeRefusal(runtime) {
  // Bun's Node compatibility version is not its runtime identity.
  if (runtime.versions.bun === undefined) return nodeVersionRefusal(runtime);
  if (runtime.platform === "win32" && runtime.arch === "x64" &&
      runtime.versions.bun === REQUIRED_BUN_VERSION) return null;
  return {
    level: "error",
    event: "unsupported_bot_runtime",
    error: `The Bun foreground bot requires Windows x64 and Bun ${REQUIRED_BUN_VERSION} exactly (running ${runtime.platform}-${runtime.arch}, Bun ${runtime.versions.bun}). Launch with npm run start:windows, or use Node.js >=${REQUIRED_NODE_MAJOR}.0.0 with npm start.`,
  };
}
