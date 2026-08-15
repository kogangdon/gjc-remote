import assert from "node:assert/strict";
import test from "node:test";

import {
  HOSTS_REPLY_MAX_LENGTH,
  formatHostList,
  formatHostProjection,
} from "../src/host-projection.js";

function projection(index, bindingCount = 4) {
  return {
    hostId: `host-${index}-${"h".repeat(128)}`,
    aggregate: "ready",
    dimensions: {
      connection: "online",
      runtime: "ready",
      providerAuth: "configured",
      modelProfile: "ready",
      workspace: "ready",
    },
    bindings: Array.from({ length: bindingCount }, (_, bindingIndex) => ({
      bindingId: `binding-${bindingIndex}-${"b".repeat(128)}`,
      workspaceId: `workspace-${bindingIndex}-${"w".repeat(128)}`,
      aggregate: "ready",
    })),
  };
}

test("host projection rendering bounds visible bindings and identifiers", () => {
  const rendered = formatHostProjection(projection(1, 6));

  assert.equal(rendered.includes("+2 more"), true);
  assert.equal(rendered.includes("binding-4"), false);
  assert.equal(rendered.includes("..."), true);
});

test("host list rendering stays within the Discord reply budget", () => {
  const rendered = formatHostList(
    Array.from({ length: 20 }, (_, index) => projection(index))
  );

  assert.equal(rendered.length <= HOSTS_REPLY_MAX_LENGTH, true);
  assert.match(rendered, /\+\d+ hosts omitted/);
});

test("empty host list keeps the existing operator message", () => {
  assert.equal(formatHostList([]), "No hosts connected.");
});
