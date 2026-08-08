// Runs as bot.js's very first import so it evaluates before dotenv, discord.js,
// and @gjc-remote/native-control load. Node 24 on Windows has been observed in
// CI to crash the bot process with a native STATUS_STACK_BUFFER_OVERRUN
// (exit 3221226505 / 0xC0000409) instead of the contracted structured fatal +
// exit 1 (see docs/adr and PR #56 evidence). That crash did not reproduce
// against multiple Node 24.x builds on this maintainer's Windows host, so it
// is treated as an unresolved Node/Windows runtime defect rather than an
// application bug: refuse to run on an unsupported Node major instead of
// risking an unreported native crash later in startup.
const REQUIRED_MAJOR = 26;

const [major] = process.versions.node.split(".").map(Number);

if (!Number.isInteger(major) || major < REQUIRED_MAJOR) {
  console.error(
    JSON.stringify({
      level: "error",
      event: "unsupported_node_version",
      error: `gjc-remote/bot requires Node.js >=${REQUIRED_MAJOR}.0.0 (running ${process.version}). Node 24 is known to crash this process on Windows instead of exiting cleanly; install Node ${REQUIRED_MAJOR}+.`,
    })
  );
  process.exit(1);
}
