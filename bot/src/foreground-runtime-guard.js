// This synchronous first import refuses unsupported runtimes before dotenv or
// application imports. It does not authorize a claimed Windows service launch;
// the signed service-bootstrap guard still evaluates immediately afterwards.
import { foregroundRuntimeRefusal } from "./runtime-policy.js";

const refusal = foregroundRuntimeRefusal(process);

if (refusal !== null) {
  console.error(JSON.stringify(refusal));
  process.exit(1);
}
