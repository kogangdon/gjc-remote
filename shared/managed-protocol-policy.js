import {
  PROTOCOL_VERSION_V3,
  WORKSPACE_BIND_AUTHORITY_VERIFICATION_CAPABILITY,
  WORKSPACE_INVENTORY_RECEIPT_CAPABILITY,
  WORKSPACE_READINESS_CAPABILITY,
} from "./protocol.js";

export const MANAGED_PROTOCOL_CAPABILITIES = Object.freeze([
  WORKSPACE_READINESS_CAPABILITY,
  WORKSPACE_INVENTORY_RECEIPT_CAPABILITY,
  WORKSPACE_BIND_AUTHORITY_VERIFICATION_CAPABILITY,
]);

/**
 * Managed workspace serving never negotiates down. Both registration frames
 * must advertise protocol v3 and every authority/readiness capability.
 */
export function satisfiesManagedProtocolFloor(registration, response) {
  return [registration, response].every((frame) =>
    frame !== null &&
    typeof frame === "object" &&
    frame.protocolVersion === PROTOCOL_VERSION_V3 &&
    Array.isArray(frame.capabilities) &&
    MANAGED_PROTOCOL_CAPABILITIES.every((capability) =>
      frame.capabilities.includes(capability)
    )
  );
}
