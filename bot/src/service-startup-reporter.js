import { managedHostSetFingerprint } from "@gjc-remote/shared/mapping-envelope";
import { createServiceStartupObservationEmitter } from "@gjc-remote/shared/service-startup-observation";

// Reports real bot startup transitions (WebSocket listener, Discord session,
// exact configured connected-host set) as service startup observation events.
// Only created for a verified service launch; readiness is decided by the
// native startup gate, never by this process.
export function createBotServiceStartupReporter({ context, tokensByHostId, writable, onFailure }) {
  if (context === null || typeof context !== "object" || context.component !== "bot") {
    throw new TypeError("bot service startup reporter requires a bot bootstrap context");
  }
  if (!(tokensByHostId instanceof Map) || typeof onFailure !== "function") {
    throw new TypeError("invalid bot service startup reporter options");
  }
  const expectedState = Object.freeze({
    expectedHostSetFingerprint: managedHostSetFingerprint(tokensByHostId),
    expectedHostCount: tokensByHostId.size,
  });
  const emitter = createServiceStartupObservationEmitter({
    binding: {
      component: context.component,
      serviceKey: context.serviceKey,
      processEpochFingerprint: context.processEpochFingerprint,
      effectiveConfigFingerprint: context.effectiveConfigFingerprint,
      configSourceIdentityFingerprint: context.configSourceIdentityFingerprint,
    },
    expectedState,
    writable,
  });
  let discord = "disconnected";
  let registrySnapshot = () => ({ listener: "closed", connectedHostIds: [] });
  let lastState = null;
  let failed = false;

  function report() {
    if (failed) return;
    const snapshot = registrySnapshot();
    const connected = new Map(snapshot.connectedHostIds
      .filter((hostId) => tokensByHostId.has(hostId))
      .map((hostId) => [hostId, true]));
    const state = {
      listener: snapshot.listener,
      discord,
      expectedHostSetFingerprint: expectedState.expectedHostSetFingerprint,
      expectedHostCount: expectedState.expectedHostCount,
      connectedHostSetFingerprint: managedHostSetFingerprint(connected),
      connectedHostCount: connected.size,
    };
    const key = JSON.stringify(state);
    if (key === lastState) return;
    lastState = key;
    emitter.emit(state).catch((error) => {
      if (failed) return;
      failed = true;
      onFailure(error);
    });
  }

  return Object.freeze({
    expectedState,
    attachRegistry(registry) {
      if (registry === null || typeof registry?.getServiceStartupSnapshot !== "function") {
        throw new TypeError("invalid host registry");
      }
      registrySnapshot = () => registry.getServiceStartupSnapshot();
      report();
    },
    setDiscord(value) {
      if (value !== "connected" && value !== "disconnected") throw new TypeError("invalid discord state");
      discord = value;
      report();
    },
    report,
    flush: () => emitter.flush(),
    close: () => emitter.close(),
  });
}
