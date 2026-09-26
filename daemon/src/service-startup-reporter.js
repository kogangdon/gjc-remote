import {
  createServiceStartupObservationEmitter,
  serviceDaemonTargetFingerprint,
} from "@gjc-remote/shared/service-startup-observation";

// Reports real daemon registration transitions against the exact configured
// bot target as service startup observation events. Provider and workspace
// health are never probed or reported here. Only created for a verified
// service launch; readiness is decided by the native startup gate.
export function createDaemonServiceStartupReporter({ context, botWsUrl, hostId, writable, onFailure }) {
  if (context === null || typeof context !== "object" || context.component !== "daemon") {
    throw new TypeError("daemon service startup reporter requires a daemon bootstrap context");
  }
  if (typeof onFailure !== "function") throw new TypeError("invalid daemon service startup reporter options");
  const expectedState = Object.freeze({ targetFingerprint: serviceDaemonTargetFingerprint({ botWsUrl, hostId }) });
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
  let connectionGeneration = 0;
  let attemptedGeneration = null;
  let acceptedGeneration = null;
  let failed = false;

  function emit(registration) {
    if (failed) return;
    emitter.emit({
      targetFingerprint: expectedState.targetFingerprint,
      connectionGeneration,
      attemptedGeneration,
      acceptedGeneration,
      registration,
    }).catch((error) => {
      if (failed) return;
      failed = true;
      onFailure(error);
    });
  }

  return Object.freeze({
    expectedState,
    // A registration frame was sent on a new transport; returns its generation.
    registrationAttempted() {
      if (connectionGeneration >= Number.MAX_SAFE_INTEGER) throw new RangeError("connection generation exhausted");
      connectionGeneration += 1;
      attemptedGeneration = connectionGeneration;
      emit("attempted");
      return connectionGeneration;
    },
    registrationAccepted(generation) {
      if (generation !== connectionGeneration || attemptedGeneration !== generation ||
          acceptedGeneration === generation) return;
      acceptedGeneration = generation;
      emit("accepted");
    },
    registrationDenied(generation) {
      if (generation !== connectionGeneration || attemptedGeneration !== generation ||
          acceptedGeneration === generation) return;
      emit("denied");
    },
    connectionClosed(generation) {
      if (generation === null || generation !== connectionGeneration) return;
      emit("disconnected");
    },
    flush: () => emitter.flush(),
    close: () => emitter.close(),
  });
}
