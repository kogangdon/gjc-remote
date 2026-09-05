const sessionFactorySymbol = Symbol.for("@gjc-remote/daemon/test-session-factory");

const sessionFactory = Object.freeze(() => Object.freeze({
  send: async () => {},
  answerGate: async () => {},
  dispose: async () => {
    if (typeof process.send === "function" && process.connected === true) {
      await new Promise((resolve) => {
        process.send(
          { type: "invoke_admission_fixture_disposed" },
          () => resolve(),
        );
      });
    }
  },
}));

Object.defineProperty(globalThis, sessionFactorySymbol, {
  configurable: false,
  enumerable: false,
  writable: false,
  value: sessionFactory,
});

await import("../src/daemon.js");
