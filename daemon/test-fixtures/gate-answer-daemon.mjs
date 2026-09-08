const factory = () => {
  let emit;
  let finish;
  let gateId;
  const gate = (id) => ({ type: "gate_request", gateId: id, prompt: "Choose yes", kind: "question" });
  return {
    send: async (_command, onEvent) => {
      emit = onEvent;
      gateId = "first";
      const pending = new Promise((resolve) => { finish = resolve; });
      emit(gate(gateId));
      await pending;
    },
    answerGate: async (id, answer) => {
      if (id !== gateId || answer !== "yes") {
        return { ok: false, error: "fixture-private-rejection-do-not-send" };
      }
      if (id === "first") {
        gateId = "second";
        emit(gate(gateId));
      } else {
        gateId = undefined;
        finish();
      }
      return { ok: true };
    },
    dispose: async () => { finish?.(); },
  };
};
Object.defineProperty(globalThis, Symbol.for("@gjc-remote/daemon/test-session-factory"), {
  configurable: false,
  enumerable: false,
  writable: false,
  value: factory,
});
await import("../src/daemon.js");
