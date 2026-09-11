function report(event) {
  if (typeof process.send === "function" && process.connected === true) {
    process.send({ type: "gate_fixture", ...event }, () => {});
  }
}

const controls = new Set();
process.on("message", (message) => {
  if (message?.type === "gate_fixture_force_terminal") {
    for (const control of controls) control.forceTerminal();
  }
  if (message?.type === "gate_fixture_release_answer") {
    for (const control of controls) control.releaseAnswer();
  }
});

const factory = () => {
  let emit;
  let finish;
  let gateId;
  let presentationId;
  let ownerId;
  let phase = "terminal";
  let gateState = "terminal";
  let releaseBlockedAnswer;
  const blockAnswer = process.env.GJC_GATE_FIXTURE_BLOCK_ANSWER === "1";

  const complete = ({ preserveGate = false } = {}) => {
    if (!finish) return;
    const resolve = finish;
    finish = undefined;
    if (!preserveGate) {
      gateId = undefined;
      presentationId = undefined;
      gateState = "terminal";
    }
    phase = "terminal";
    resolve({ disposition: "completed" });
  };

  const session = {
    sendOwned(nextOwnerId, command, onEvent, _timeoutMs, { onActivate } = {}) {
      if (
        command?.type === "get_available_models" ||
        command?.type === "set_model"
      ) {
        let ticketPhase = "queued";
        const result = new Promise((resolve) => {
          queueMicrotask(() => {
            if (ticketPhase !== "queued") return;
            ticketPhase = "active";
            onActivate?.();
            if (command.type === "get_available_models") {
              onEvent({
                command: "get_available_models",
                data: {
                  models: [
                    { provider: "fixture", id: "model-a", name: "Model A" },
                  ],
                },
              });
            }
            ticketPhase = "terminal";
            resolve({ disposition: "completed" });
          });
        });
        return {
          result,
          revokeBeforeStart() {
            if (ticketPhase !== "queued") return false;
            ticketPhase = "terminal";
            return true;
          },
          get phase() {
            return ticketPhase;
          },
        };
      }
      ownerId = nextOwnerId;
      emit = onEvent;
      phase = "queued";
      const result = new Promise((resolve) => {
        finish = resolve;
      });
      queueMicrotask(() => {
        if (phase !== "queued") return;
        phase = "active";
        onActivate?.();
        gateId = "first";
        presentationId = "presentation-first";
        gateState = "awaiting_presentation";
        emit({
          type: "gate_request",
          gateId,
          presentationId,
          prompt: "Choose yes",
          kind: "question",
          choices: [{ value: "yes", label: "yes" }],
        });
      });
      return {
        result,
        revokeBeforeStart() {
          if (phase !== "queued") return false;
          phase = "terminal";
          finish?.({ revokedBeforeStart: true });
          finish = undefined;
          return true;
        },
        get phase() {
          return phase;
        },
      };
    },
    presentGate(candidateOwner, candidateGate, candidatePresentation, attemptId) {
      const accepted =
        candidateOwner === ownerId &&
        candidateGate === gateId &&
        candidatePresentation === presentationId;
      report({
        event: "present",
        ownerId: candidateOwner,
        gateId: candidateGate,
        presentationId: candidatePresentation,
        attemptId,
        accepted,
      });
      if (accepted) gateState = "answerable";
      return accepted;
    },
    async answerGate(candidateOwner, candidateGate, candidatePresentation, answer) {
      if (blockAnswer) {
        report({ event: "answer_started" });
        await new Promise((resolve) => {
          releaseBlockedAnswer = resolve;
        });
      }
      const accepted =
        candidateOwner === ownerId &&
        candidateGate === gateId &&
        candidatePresentation === presentationId &&
        gateState === "answerable" &&
        answer === "yes";
      report({ event: "answer", accepted });
      if (accepted) complete();
      return accepted
        ? { ok: true }
        : { ok: false, error: "fixture rejection" };
    },
    abandonGate(candidateOwner, candidateGate, candidatePresentation) {
      const accepted =
        candidateOwner === ownerId &&
        candidateGate === gateId &&
        candidatePresentation === presentationId;
      report({ event: "abandon", accepted });
      if (accepted) complete();
      return accepted;
    },
    quarantineOwnedGates(candidateOwner) {
      const accepted = candidateOwner === ownerId && gateId !== undefined;
      report({ event: "quarantine", ownerId: candidateOwner, accepted });
      if (accepted) complete();
      return accepted;
    },
    answerGateLegacy: async () => ({ ok: false }),
    dispose: async () => complete(),
  };
  controls.add({
    forceTerminal: () => complete({ preserveGate: true }),
    releaseAnswer: () => releaseBlockedAnswer?.(),
  });
  return session;
};

Object.defineProperty(globalThis, Symbol.for("@gjc-remote/daemon/test-session-factory"), {
  configurable: false,
  enumerable: false,
  writable: false,
  value: factory,
});

await import("../src/daemon.js");
