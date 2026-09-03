import { constants } from "node:fs";
import { open, readFile, unlink } from "node:fs/promises";
import {
  ROLE_PATHS,
  assertContainerSecurityPreflight,
} from "/app/daemon/src/container-security-preflight.js";

const mode = process.argv[2];
const marker = "gjc-role-persistence-v1\n";
const markerName = ".gjc-persistence-probe";

try {
  await assertContainerSecurityPreflight();
  if (mode === "write") {
    for (const rolePath of Object.values(ROLE_PATHS)) {
      const handle = await open(
        `${rolePath}/${markerName}`,
        constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL,
        0o600,
      );
      try {
        await handle.writeFile(marker);
        await handle.sync();
      } finally {
        await handle.close();
      }
    }
    console.log("PERSISTENCE_WRITE_OK");
  } else if (mode === "read") {
    for (const rolePath of Object.values(ROLE_PATHS)) {
      const path = `${rolePath}/${markerName}`;
      if (await readFile(path, "utf8") !== marker) throw new Error("mismatch");
      await unlink(path);
    }
    console.log("PERSISTENCE_READ_OK");
  } else {
    throw new Error("invalid mode");
  }
} catch {
  console.error("PERSISTENCE_PROBE_FAILED");
  process.exit(1);
}
