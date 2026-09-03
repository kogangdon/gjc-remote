import {
  ContainerPreflightError,
  ROLE_PATHS,
  assertContainerSecurityPreflight,
} from "./container-security-preflight.js";

const REQUIRED_ENVIRONMENT = Object.freeze({
  GJC_CONTAINER_RUNTIME: "1",
  GJC_DAEMON_SESSION_ROOT: ROLE_PATHS.session,
  GJC_DAEMON_STATE_ROOT: ROLE_PATHS.state,
  GJC_NATIVE_WORKSPACE_ROOT: ROLE_PATHS.workspace,
  GJC_NATIVE_INVENTORY_MODE: "off",
  GJC_NATIVE_WORKSPACE_SERVING: "0",
  HOME: "/home/gjc",
});

function environmentMatchesContract(env) {
  return Object.entries(REQUIRED_ENVIRONMENT).every(
    ([name, expected]) => env[name] === expected
  );
}

try {
  if (!environmentMatchesContract(process.env)) {
    console.error("daemon-container: preflight failed: environment-contract");
    process.exit(1);
  }
  await assertContainerSecurityPreflight();
} catch (error) {
  const code = error instanceof ContainerPreflightError
    ? error.code
    : "internal-error";
  console.error(`daemon-container: preflight failed: ${code}`);
  process.exit(1);
}

await import("./daemon.js");
