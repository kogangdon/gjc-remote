export const WORKSPACE_MAPPING_UNAVAILABLE = "WORKSPACE_MAPPING_UNAVAILABLE";

const DIAGNOSTIC = `Workspace mapping unavailable (${WORKSPACE_MAPPING_UNAVAILABLE}).`;

export function dispatchGate(mapping, respond, verifyLegacyFence) {
  const legacyAllowed = mapping?.sourceKind === "legacy-v0" &&
    typeof verifyLegacyFence === "function" &&
    verifyLegacyFence(mapping.legacyFence) === true;
  if (legacyAllowed) return true;
  Promise.resolve(respond(DIAGNOSTIC)).catch(() => {});
  return false;
}

export function workspaceMappingDiagnostic() {
  return DIAGNOSTIC;
}
