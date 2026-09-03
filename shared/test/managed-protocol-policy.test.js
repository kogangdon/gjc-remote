import assert from "node:assert/strict";
import test from "node:test";
import {
  MANAGED_PROTOCOL_CAPABILITIES,
  satisfiesManagedProtocolFloor,
} from "../managed-protocol-policy.js";
import { PROTOCOL_VERSION_V3 } from "../protocol.js";

function frame(overrides = {}) {
  return {
    protocolVersion: PROTOCOL_VERSION_V3,
    capabilities: [...MANAGED_PROTOCOL_CAPABILITIES],
    ...overrides,
  };
}

test("managed serving requires exact v3 and all authority capabilities on both frames", () => {
  assert.equal(satisfiesManagedProtocolFloor(frame(), frame()), true);
  for (const protocolVersion of [undefined, 0, 1, 2, 4]) {
    assert.equal(
      satisfiesManagedProtocolFloor(frame({ protocolVersion }), frame()),
      false,
    );
    assert.equal(
      satisfiesManagedProtocolFloor(frame(), frame({ protocolVersion })),
      false,
    );
  }
  for (const capability of MANAGED_PROTOCOL_CAPABILITIES) {
    const capabilities = MANAGED_PROTOCOL_CAPABILITIES.filter(
      (candidate) => candidate !== capability,
    );
    assert.equal(
      satisfiesManagedProtocolFloor(frame({ capabilities }), frame()),
      false,
    );
    assert.equal(
      satisfiesManagedProtocolFloor(frame(), frame({ capabilities })),
      false,
    );
  }
});

test("managed serving never manufactures defaults from malformed frames", () => {
  for (const value of [undefined, null, false, 1, "v3", [], {}]) {
    assert.equal(satisfiesManagedProtocolFloor(value, frame()), false);
    assert.equal(satisfiesManagedProtocolFloor(frame(), value), false);
  }
  assert.equal(Object.isFrozen(MANAGED_PROTOCOL_CAPABILITIES), true);
});
