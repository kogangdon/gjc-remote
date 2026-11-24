// Administrative and registration entrypoints retain their Node-major guard.
// Only the foreground bot's separate guard selects Bun by its own identity.
import { nodeVersionRefusal } from "./runtime-policy.js";

const refusal = nodeVersionRefusal(process);

if (refusal !== null) {
  console.error(JSON.stringify(refusal));
  process.exit(1);
}
