import {
  ContainerPreflightError,
  assertContainerSecurityPreflight,
} from "/app/daemon/src/container-security-preflight.js";

try {
  await assertContainerSecurityPreflight();
  console.log("PREFLIGHT_OK");
} catch (error) {
  const code = error instanceof ContainerPreflightError
    ? error.code
    : "internal-error";
  console.error(`PREFLIGHT_FAILED:${code}`);
  process.exit(1);
}
