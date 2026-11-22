// Bun subprocess preload only. This models the consumed management-only
// context; it is NOT signed bootstrap, native authority, ACL, or service evidence.
import { mock } from "bun:test";
import "./isolated-host-state.mjs";

if (process.env.GJC_MANAGEMENT_ONLY_BOOT_FIXTURE !== "1" ||
    !process.env.GJC_FIXTURE_HOST_STATE || typeof process.send !== "function") {
  throw new Error("management-only boot fixture requires its isolated IPC harness");
}

const counters = {
  bootstrapConsumes: 0,
  sessionFactoryReads: 0,
  sessionFactoryCalls: 0,
  sdkSessionManagerCreates: 0,
  sdkSessionCreates: 0,
};
const context = Object.freeze({
  component: "daemon",
  serviceKey: `daemon-${"a".repeat(64)}`,
  processEpochFingerprint: "1".repeat(64),
  effectiveConfigFingerprint: "2".repeat(64),
  configSourceIdentityFingerprint: "3".repeat(64),
  managementOnly: true,
});
mock.module("@gjc-remote/native-control/service-bootstrap", () => ({
  consumeServiceBootstrapContext() {
    counters.bootstrapConsumes += 1;
    if (arguments.length !== 0 || counters.bootstrapConsumes !== 1) {
      throw new Error("fixture bootstrap context must be consumed exactly once");
    }
    return context;
  },
}));

const hostileFactory = () => {
  counters.sessionFactoryCalls += 1;
  throw new Error("management-only boot must not call the fixture session factory");
};
Object.defineProperty(globalThis, Symbol.for("@gjc-remote/daemon/test-session-factory"), {
  configurable: false,
  enumerable: false,
  get() {
    counters.sessionFactoryReads += 1;
    return hostileFactory;
  },
});

// Fail unexpected SDK admission before any real SDK module can discover
// credentials or create a dummy profile. Neither guard supplies a session.
mock.module("@gajae-code/coding-agent/sdk", () => ({
  createAgentSession() {
    counters.sdkSessionCreates += 1;
    throw new Error("management-only boot must not create an SDK session");
  },
}));
mock.module("@gajae-code/coding-agent/session/session-manager", () => ({
  SessionManager: {
    create() {
      counters.sdkSessionManagerCreates += 1;
      throw new Error("management-only boot must not create SDK session storage");
    },
  },
}));

process.on("message", (message) => {
  if (message?.type !== "management_only_boot_snapshot_request") return;
  setImmediate(() => {
    process.send({
      type: "management_only_boot_snapshot",
      requestId: message.requestId,
      ...counters,
    });
  });
});
