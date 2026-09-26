import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import test from "node:test";
import { DEPLOYMENT_FORMAT_REGISTRY } from "@gjc-remote/shared/deployment-format-registry";
import { validateTokenFloorReservation } from "@gjc-remote/shared/genesis-envelope";
import { canonicalJsonHash } from "@gjc-remote/shared/strict-json";

const BASELINE_CANONICAL_SHA256 = "54ad5370c5db28fc9bc7b7ad06362b8a4b3e99fb9e8dc86e879bbb75c7a0e86a";
const BASELINE_CANONICAL_BYTES = 9607;
const BASELINE_DOMAIN_VECTOR = [
  { key: "bot", domain: "bot-mapping-reader", formatCount: 58 },
  { key: "daemonAppSession", domain: "daemon-app-session", formatCount: 1 },
  { key: "workspaceLifecycle", domain: "workspace-lifecycle", formatCount: 4 },
];

function canonicalize(value) {
  if (Array.isArray(value)) {
    return value.map(canonicalize);
  }

  if (value !== null && typeof value === "object") {
    return Object.fromEntries(
      Object.keys(value)
        .sort()
        .map((key) => [key, canonicalize(value[key])]),
    );
  }

  return value;
}

function findFormat(domainKey, formatId) {
  const format = DEPLOYMENT_FORMAT_REGISTRY[domainKey].formats.find(
    (candidate) => candidate.formatId === formatId,
  );
  assert.ok(format, `missing ${domainKey} format ${formatId}`);
  return format;
}

function assertDeepFrozen(value, path = "registry") {
  if (value === null || typeof value !== "object") {
    return;
  }

  assert.ok(Object.isFrozen(value), `${path} must be frozen`);
  for (const [key, nestedValue] of Object.entries(value)) {
    assertDeepFrozen(nestedValue, `${path}.${key}`);
  }
}

test("token reservation records use the existing token-generation-floor format", () => {
  const reservation = {
    version: 1,
    kind: "token-generation-floor",
    anchorFingerprint: "a".repeat(64),
    fenceGeneration: 1,
    genesisGeneration: 1,
    highestReservedGeneration: 1,
    highestCommittedGeneration: 0,
    lastReservationTxId: "registry-reservation-tx",
    lastCommittedTxId: null,
    lastAttestationFingerprint: null,
    floorPhase: "reserved",
    attestedProofFingerprint: null,
  };
  reservation.floorFingerprint = canonicalJsonHash(reservation);
  assert.equal(validateTokenFloorReservation(reservation), reservation);
  const matches = DEPLOYMENT_FORMAT_REGISTRY.bot.formats.filter(({ marker }) =>
    Object.entries(marker).every(([key, value]) => reservation[key] === value));
  assert.deepEqual(matches.map(({ formatId }) => formatId), ["floor:token-generation-floor@1"]);
  assert.throws(() => validateTokenFloorReservation({
    ...reservation, kind: "token-floor-reservation",
  }), /token floor schema/);
});

test("registry preserves its baseline except for the extracted floor validator locations", () => {
  const baseline = structuredClone(DEPLOYMENT_FORMAT_REGISTRY);
  for (const kind of ["authority-epoch-floor", "fence-generation-floor"]) {
    const entry = baseline.bot.formats.find(({ formatId }) => formatId === `floor:${kind}@1`);
    assert.equal(entry.source, "shared/managed-authority-proof.js");
    entry.source = "bot/src/managed-authority-reader.js";
  }
  const canonical = JSON.stringify(canonicalize(baseline));
  assert.equal(Buffer.byteLength(canonical, "utf8"), BASELINE_CANONICAL_BYTES);
  assert.equal(
    createHash("sha256").update(canonical, "utf8").digest("hex"),
    BASELINE_CANONICAL_SHA256,
  );

  const domainVector = Object.entries(DEPLOYMENT_FORMAT_REGISTRY).map(
    ([key, { domain, formats }]) => ({ key, domain, formatCount: formats.length }),
  );
  assert.deepEqual(domainVector, BASELINE_DOMAIN_VECTOR);
  assert.equal(
    domainVector.reduce((total, entry) => total + entry.formatCount, 0),
    63,
  );
});

test("reader-null and reader-2 marker variants retain distinct explicit values", () => {
  assert.deepEqual(
    [
      findFormat("bot", "floor:reader-version-floor@1:null"),
      findFormat("bot", "floor:reader-version-floor@1:reader-2"),
      findFormat("bot", "wrapper:managed-v1-wrapper@1:reader-null"),
      findFormat("bot", "wrapper:managed-v1-wrapper@1:reader-2"),
    ],
    [
      {
        formatId: "floor:reader-version-floor@1:null",
        marker: { version: 1, kind: "reader-version-floor", readerVersionFloor: null },
        source: "shared/genesis-envelope.js",
      },
      {
        formatId: "floor:reader-version-floor@1:reader-2",
        marker: { version: 1, kind: "reader-version-floor", readerVersionFloor: 2 },
        source: "shared/genesis-envelope.js",
      },
      {
        formatId: "wrapper:managed-v1-wrapper@1:reader-null",
        marker: {
          version: 1,
          kind: "managed-v1-wrapper",
          managementStamp: "gjc-management-envelope/v1",
          readerVersion: null,
        },
        source: "shared/mapping-envelope.js",
      },
      {
        formatId: "wrapper:managed-v1-wrapper@1:reader-2",
        marker: {
          version: 1,
          kind: "managed-v1-wrapper",
          managementStamp: "gjc-management-envelope/v1",
          readerVersion: 2,
        },
        source: "shared/mapping-envelope.js",
      },
    ],
  );
});

test("identical cleanup markers remain separately scoped to bot and workspace lifecycle", () => {
  const botCleanup = findFormat("bot", "recovery:manual-cleanup@1");
  const workspaceCleanup = findFormat("workspaceLifecycle", "workspace:manual-cleanup@1");

  assert.deepEqual(botCleanup.marker, { version: 1, kind: "manual-cleanup" });
  assert.deepEqual(workspaceCleanup.marker, { version: 1, kind: "manual-cleanup" });
  assert.equal(botCleanup.source, "shared/recovery-envelope.js");
  assert.equal(workspaceCleanup.source, "shared/recovery-envelope.js");
  assert.notEqual(botCleanup.formatId, workspaceCleanup.formatId);
  assert.notEqual(
    DEPLOYMENT_FORMAT_REGISTRY.bot.domain,
    DEPLOYMENT_FORMAT_REGISTRY.workspaceLifecycle.domain,
  );
});

test("registry, domains, format arrays, records, and markers are deeply immutable", () => {
  assertDeepFrozen(DEPLOYMENT_FORMAT_REGISTRY);
  assert.throws(() => {
    DEPLOYMENT_FORMAT_REGISTRY.bot.formats[0].marker.kind = "changed";
  }, TypeError);
  assert.throws(() => {
    DEPLOYMENT_FORMAT_REGISTRY.workspaceLifecycle.formats.push({});
  }, TypeError);
});
