import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import test from "node:test";
import { canonicalJsonBytes, canonicalJsonHash } from "../strict-json.js";
import {
  APPLICATION_DEPLOYMENT_REPOSITORY,
  DEPLOYMENT_ENVELOPE_LIMITS,
  DEPLOYMENT_SIGNATURE_DOMAINS,
  SHAWL_UPSTREAM,
  applicationDeploymentManifestFingerprint,
  assertReleaseTransitionCompatible,
  buildApplicationDeploymentManifest,
  buildBundleInventory,
  buildDeploymentCompatibility,
  buildSdkExternalStateContract,
  buildShawlDeploymentManifest,
  bundleInventoryFingerprint,
  bundleTreeFingerprint,
  deploymentBootstrapAssetNames,
  deploymentSignaturePreimage,
  validateApplicationDeploymentManifest,
  validateBundleInventory,
  validateDeploymentSignature,
  validateDeploymentSource,
  validateReleaseSelector,
  validateSdkExternalStateContract,
  validateShawlDeploymentManifest,
} from "../deployment-envelope.js";
import {
  SERVICE_STATUS_VALUES,
  SERVICE_LIFECYCLE_LIMITS,
  SERVICE_STORE_NAMESPACES,
  buildServiceArtifactBinding,
  buildServiceCandidateProof,
  buildServiceFinalProof,
  buildServiceFloorHistoryIntent,
  buildServiceFloorHistoryState,
  buildServiceFloorWitness,
  buildServiceJournalHead,
  buildServiceManifest,
  buildServiceManualCleanup,
  buildServiceOldProof,
  buildServicePlatformState,
  buildServiceResourceProof,
  buildServiceReferenceRecord,
  buildServiceReferenceSlot,
  buildServiceSequenceFloor,
  buildServiceStartupProof,
  buildServiceStatusReceipt,
  buildServiceTombstone,
  buildServiceTransaction,
  buildServiceTransitionProof,
  buildServiceStoreRegistration,
  buildServiceStoreRegistrationIncarnation,
  buildServiceZeroReferenceObservation,
  deriveServiceInstanceKey,
  serviceConfigurationFingerprint,
  serviceArtifactPhysicalTargetFingerprint,
  serviceNativeIdentityFingerprint,
  serviceKeyForTarget,
  serviceRolesFingerprint,
  buildServiceArtifactCleanup,
  buildServiceArtifactScratchCleanup,
  validateServiceArtifactBinding,
  validateServiceArtifactCleanup,
  validateServiceControlRootBinding,
  validateServiceFloorWitness,
  validateServiceFloorHistoryIntent,
  validateServiceFloorHistoryState,
  validateServiceHostId,
  validateServiceJournalHead,
  validateServiceKey,
  validateServiceLifecycleRequest,
  validateServiceManifest,
  validateServiceManualCleanup,
  validateServicePlatformState,
  validateServiceResourceProof,
  validateServiceReferenceRecord,
  validateServiceSequenceFloor,
  validateServiceStoreRegistration,
  validateServiceStoreRegistrationIncarnation,
  validateServiceStartupProof,
  validateServiceStatusReceipt,
  validateServiceTombstone,
  validateServiceTransaction,
  validateServiceZeroReferenceObservation,
} from "../service-lifecycle-envelope.js";

const hex = (character = "a") => character.repeat(64);
const sha256 = (bytes) => createHash("sha256").update(bytes).digest("hex");

function compatibility({
  mappingReadable = ["mapping-v1"],
  mappingWritable = ["mapping-v1"],
  sessionReadable = ["session-v1"],
  sessionWritable = ["session-v1"],
  workspaceReadable = ["workspace-v1"],
  workspaceWritable = ["workspace-v1"],
  sdkFingerprint = hex("9"),
} = {}) {
  return buildDeploymentCompatibility({
    bot: {
      domains: [{ domain: "bot-mapping-reader", readableFormats: mappingReadable, writableFormats: mappingWritable }],
    },
    daemon: {
      domains: [
        { domain: "daemon-app-session", readableFormats: sessionReadable, writableFormats: sessionWritable },
        { domain: "workspace-lifecycle", readableFormats: workspaceReadable, writableFormats: workspaceWritable },
      ],
      sdkExternalStateContractFingerprint: sdkFingerprint,
    },
  });
}

function inventory(platform = "linux") {
  return buildBundleInventory({
    payloadEntries: [
      { path: "native-control/build/Release/native-control.manifest.json", size: 7, sha256: hex("3"), executablePolicy: "forbidden" },
      { path: "daemon/src/daemon.js", size: 5, sha256: hex("2"), executablePolicy: "forbidden" },
      { path: "bot/src/bot.js", size: 3, sha256: hex("1"), executablePolicy: "forbidden" },
    ],
  }, { platform });
}

function applicationManifest({
  platform = "linux",
  architecture = "x64",
  version = "1.2.3",
  sequence = 7,
  archiveByteLength = 4096,
  deploymentCompatibility = compatibility(),
} = {}) {
  const files = inventory(platform);
  const inventoryBytes = canonicalJsonBytes(files, { maxBytes: 32 * 1024 * 1024, maxDepth: 16, maxNodes: 600_032 });
  return {
    manifest: buildApplicationDeploymentManifest({
      signingKeyId: "deployment-prod-1",
      releaseId: `v${version}`,
      releaseVersion: version,
      releaseSequence: sequence,
      source: {
        repository: APPLICATION_DEPLOYMENT_REPOSITORY,
        tag: `v${version}`,
        commit: "1".repeat(40),
        tree: "2".repeat(40),
        bunLockSha256: hex("3"),
      },
      target: { platform, architecture },
      archive: {
        name: `gjc-remote-service-${version}-${platform}-${architecture}.tar.gz`,
        mediaType: "application/gzip",
        byteLength: archiveByteLength,
        sha256: hex("4"),
        entryCount: files.payloadEntryCount + 1,
      },
      inventory: {
        path: "bundle-files.json",
        byteLength: inventoryBytes.byteLength,
        sha256: sha256(inventoryBytes),
        payloadEntryCount: files.payloadEntryCount,
        unpackedPayloadBytes: files.unpackedPayloadBytes,
        treeFingerprint: files.treeFingerprint,
      },
      entrypoints: { bot: "bot/src/bot.js", daemon: "daemon/src/daemon.js" },
      runtimes: { node: { minimumVersion: "26.0.0" }, bun: { minimumVersion: "1.4.0" } },
      nativeControl: {
        manifestPath: "native-control/build/Release/native-control.manifest.json",
        manifestFingerprint: hex("5"),
        contractVersion: 4,
        contractRevision: 4,
      },
      wireCapabilities: ["gate_presentation_v1", "terminal_disposition_v1"],
      compatibility: deploymentCompatibility,
    }),
    inventory: files,
  };
}

function shawlManifest() {
  return buildShawlDeploymentManifest({
    signingKeyId: "deployment-prod-1",
    releaseSequence: 4,
    target: { platform: "win32", architecture: "x64" },
    upstream: {
      repository: SHAWL_UPSTREAM.repository,
      tag: SHAWL_UPSTREAM.tag,
      commit: SHAWL_UPSTREAM.commit,
      assetId: 123456,
      assetName: "shawl-v1.9.0-win64.zip",
      zipSha256: hex("6"),
    },
    executable: {
      name: "shawl.exe",
      byteLength: 1234,
      sha256: hex("7"),
      version: "1.9.0",
      versionOutput: "shawl 1.9.0",
      authenticode: "unsigned",
    },
    projectAsset: {
      repository: APPLICATION_DEPLOYMENT_REPOSITORY,
      tag: "v1.2.3",
      name: "gjc-remote-shawl-win32-x64.exe",
    },
  });
}

const linuxRoles = Object.freeze({
  management: Object.freeze({ kind: "uid", value: "uid:1000" }),
  bot: Object.freeze({ kind: "uid", value: "uid:1001" }),
  recovery: Object.freeze({ kind: "uid", value: "uid:1002" }),
  daemon: Object.freeze({ kind: "uid", value: "uid:1003" }),
  system: Object.freeze({ kind: "uid", value: "uid:0" }),
});
const windowsRoles = Object.freeze({
  management: Object.freeze({ kind: "sid", value: "S-1-5-21-1" }),
  bot: Object.freeze({ kind: "sid", value: "S-1-5-21-2" }),
  recovery: Object.freeze({ kind: "sid", value: "S-1-5-21-3" }),
  daemon: Object.freeze({ kind: "sid", value: "S-1-5-21-4" }),
  system: Object.freeze({ kind: "sid", value: "S-1-5-18" }),
});
const linuxBotConfiguration = Object.freeze({
  runtimePath: "/usr/bin/node",
  workingDirectory: "/srv/gjc-remote-bot",
  homeDirectory: "/var/lib/gjc-bot",
  logDirectory: "/var/log/gjc-remote-bot",
  channelsConfig: "/etc/gjc-remote/channels.json",
  expectedHostSetFingerprint: hex("8"),
  expectedHostCount: 2,
});
const windowsDaemonConfiguration = Object.freeze({
  runtimePath: String.raw`C:\Program Files\Bun\bun.exe`,
  workingDirectory: String.raw`D:\GJC Remote\daemon`,
  homeDirectory: String.raw`D:\Service Homes\daemon`,
  logDirectory: String.raw`D:\Service Logs\daemon`,
});

test("bundle inventory has non-self-referential canonical fingerprints and exact totals", () => {
  const value = inventory();
  assert.equal(validateBundleInventory(value, { platform: "linux" }), value);
  assert.equal(value.treeFingerprint, bundleTreeFingerprint(value.payloadEntries, { platform: "linux" }));
  assert.equal(value.inventoryFingerprint, bundleInventoryFingerprint(value));
  assert.equal(value.payloadEntryCount, 3);
  assert.equal(value.unpackedPayloadBytes, 15);
  assert.throws(() => validateBundleInventory({ ...value, extra: true }, { platform: "linux" }));
  assert.throws(() => validateBundleInventory({ ...value, payloadEntryCount: 4 }, { platform: "linux" }));
  assert.throws(() => buildBundleInventory({ payloadEntries: [{ path: "bundle-files.json", size: 0, sha256: hex(), executablePolicy: "forbidden" }] }, { platform: "linux" }));
  assert.throws(() => buildBundleInventory({ payloadEntries: [{ path: ".env", size: 0, sha256: hex(), executablePolicy: "forbidden" }] }, { platform: "linux" }));
  assert.doesNotThrow(() => buildBundleInventory({ payloadEntries: [
    { path: "node_modules/provider/lib/credentials/state.js", size: 0, sha256: hex(), executablePolicy: "forbidden" },
    { path: "node_modules/provider/lib/logs/index.js", size: 0, sha256: hex(), executablePolicy: "forbidden" },
  ] }, { platform: "linux" }));
  assert.throws(() => buildBundleInventory({ payloadEntries: [{ path: "pkg/.cache/x", size: 0, sha256: hex(), executablePolicy: "forbidden" }] }, { platform: "linux" }));
  assert.throws(() => buildBundleInventory({ payloadEntries: [
    { path: "A/file", size: 0, sha256: hex("1"), executablePolicy: "forbidden" },
    { path: "a/file", size: 0, sha256: hex("2"), executablePolicy: "forbidden" },
  ] }, { platform: "win32" }));
  assert.equal(buildBundleInventory({ payloadEntries: [
    { path: "a".repeat(DEPLOYMENT_ENVELOPE_LIMITS.pathBytes), size: DEPLOYMENT_ENVELOPE_LIMITS.unpackedPayloadBytes, sha256: hex(), executablePolicy: "forbidden" },
  ] }, { platform: "linux" }).unpackedPayloadBytes, DEPLOYMENT_ENVELOPE_LIMITS.unpackedPayloadBytes);
  assert.throws(() => buildBundleInventory({ payloadEntries: [
    { path: "a".repeat(DEPLOYMENT_ENVELOPE_LIMITS.pathBytes + 1), size: 0, sha256: hex(), executablePolicy: "forbidden" },
  ] }, { platform: "linux" }));
  assert.throws(() => buildBundleInventory({ payloadEntries: [
    { path: "payload", size: DEPLOYMENT_ENVELOPE_LIMITS.unpackedPayloadBytes + 1, sha256: hex(), executablePolicy: "forbidden" },
  ] }, { platform: "linux" }));
});

test("application manifest binds canonical inventory, tuple, runtime, native, and archive contracts", () => {
  const { manifest, inventory: files } = applicationManifest();
  assert.equal(validateApplicationDeploymentManifest(manifest, files), manifest);
  const preimage = Object.fromEntries(Object.entries(manifest).filter(([key]) => key !== "manifestFingerprint"));
  assert.equal(manifest.manifestFingerprint, canonicalJsonHash(preimage));
  assert.equal(applicationDeploymentManifestFingerprint(manifest), manifest.manifestFingerprint);
  assert.throws(() => validateApplicationDeploymentManifest({ ...manifest, extra: true }));
  assert.throws(() => validateApplicationDeploymentManifest({ ...manifest, releaseSequence: 0 }));
  assert.throws(() => validateApplicationDeploymentManifest({ ...manifest, archive: { ...manifest.archive, entryCount: manifest.archive.entryCount + 1 } }));
  const missingEntrypoint = buildBundleInventory({ payloadEntries: files.payloadEntries.filter((entry) => entry.path !== "daemon/src/daemon.js") }, { platform: "linux" });
  assert.throws(() => validateApplicationDeploymentManifest(manifest, missingEntrypoint));
  assert.equal(applicationManifest({ archiveByteLength: DEPLOYMENT_ENVELOPE_LIMITS.archiveBytes }).manifest.archive.byteLength, DEPLOYMENT_ENVELOPE_LIMITS.archiveBytes);
  assert.throws(() => applicationManifest({ archiveByteLength: DEPLOYMENT_ENVELOPE_LIMITS.archiveBytes + 1 }));
});

test("Shawl manifest stays pinned to v1.9.0 and truthfully records unsigned upstream provenance", () => {
  const manifest = shawlManifest();
  assert.equal(validateShawlDeploymentManifest(manifest), manifest);
  assert.equal(manifest.executable.authenticode, "unsigned");
  assert.throws(() => validateShawlDeploymentManifest({ ...manifest, executable: { ...manifest.executable, authenticode: "signed" } }));
  assert.throws(() => validateShawlDeploymentManifest({ ...manifest, upstream: { ...manifest.upstream, commit: "0".repeat(40) } }));
  assert.throws(() => validateShawlDeploymentManifest({ ...manifest, target: { platform: "win32", architecture: "arm64" } }));
});

test("deployment signature envelopes and preimages are purpose-separated and exact", () => {
  const { manifest } = applicationManifest();
  const shawl = shawlManifest();
  const signature = {
    schemaVersion: 1,
    kind: "application-deployment-signature",
    domain: DEPLOYMENT_SIGNATURE_DOMAINS.application,
    keyId: manifest.signingKeyId,
    algorithm: "ed25519",
    manifestFingerprint: manifest.manifestFingerprint,
    signature: Buffer.alloc(64, 7).toString("base64"),
  };
  assert.equal(validateDeploymentSignature(signature, "application", manifest), signature);
  const applicationPreimage = deploymentSignaturePreimage("application", manifest);
  assert.ok(applicationPreimage.subarray(0, DEPLOYMENT_SIGNATURE_DOMAINS.application.length).equals(Buffer.from(DEPLOYMENT_SIGNATURE_DOMAINS.application)));
  assert.equal(applicationPreimage[DEPLOYMENT_SIGNATURE_DOMAINS.application.length], 0);
  assert.ok(applicationPreimage.subarray(DEPLOYMENT_SIGNATURE_DOMAINS.application.length + 1).equals(canonicalJsonBytes(manifest)));
  assert.notEqual(sha256(applicationPreimage), sha256(deploymentSignaturePreimage("shawl", shawl)));
  assert.throws(() => validateDeploymentSignature({ ...signature, domain: DEPLOYMENT_SIGNATURE_DOMAINS.shawl }, "application", manifest));
  assert.throws(() => validateDeploymentSignature({ ...signature, signature: Buffer.alloc(63).toString("base64") }, "application", manifest));
  assert.throws(() => validateDeploymentSignature({ ...signature, extra: true }, "application", manifest));
});

test("deployment source and bootstrap schemas reject caller URLs and platform-incomplete offline sets", () => {
  assert.equal(validateReleaseSelector("v1.2.3"), "v1.2.3");
  assert.equal(validateReleaseSelector("a".repeat(128)), "a".repeat(128));
  assert.throws(() => validateReleaseSelector("a".repeat(129)));
  assert.deepEqual(deploymentBootstrapAssetNames("linux", "arm64"), {
    applicationManifest: "gjc-remote-service-linux-arm64.manifest.json",
    applicationSignature: "gjc-remote-service-linux-arm64.manifest.json.sig",
    shawlManifest: null,
    shawlSignature: null,
    shawlExecutable: null,
  });
  assert.equal(validateDeploymentSource({ kind: "github-release", tag: "v1.2.3" }, { platform: "linux", architecture: "x64" }).tag, "v1.2.3");
  assert.throws(() => validateDeploymentSource({ kind: "github-release", tag: "v1.2.3", url: "https://example.test" }, { platform: "linux", architecture: "x64" }));
  assert.equal(validateDeploymentSource({
    kind: "offline",
    applicationManifestPath: "/retained/app.manifest.json",
    applicationSignaturePath: "/retained/app.manifest.json.sig",
    applicationArchivePath: "/retained/app.tar.gz",
  }, { platform: "linux", architecture: "x64" }).kind, "offline");
  assert.throws(() => validateDeploymentSource({
    kind: "offline",
    applicationManifestPath: "relative.json",
    applicationSignaturePath: "/retained/app.sig",
    applicationArchivePath: "/retained/app.tar.gz",
  }, { platform: "linux", architecture: "x64" }));
  assert.throws(() => validateDeploymentSource({
    kind: "offline",
    applicationManifestPath: String.raw`C:\retained\app.json`,
    applicationSignaturePath: String.raw`C:\retained\app.sig`,
    applicationArchivePath: String.raw`C:\retained\app.tar.gz`,
  }, { platform: "win32", architecture: "x64" }));
});

test("release transition checks complete observed format sets and opaque SDK equality in both directions", () => {
  const current = applicationManifest({ sequence: 1, version: "1.0.0", deploymentCompatibility: compatibility() }).manifest;
  const candidate = applicationManifest({
    sequence: 2,
    version: "1.1.0",
    deploymentCompatibility: compatibility({ mappingReadable: ["mapping-v1", "mapping-v2"], mappingWritable: ["mapping-v2"] }),
  }).manifest;
  const predecessor = applicationManifest({
    sequence: 1,
    version: "1.0.0",
    deploymentCompatibility: compatibility({ mappingReadable: ["mapping-v1", "mapping-v2"] }),
  }).manifest;
  assert.equal(assertReleaseTransitionCompatible({
    current,
    candidate,
    predecessor,
    component: "bot",
    observedRetainedFormats: { "bot-mapping-reader": ["mapping-v1"] },
  }), candidate);
  const unreadable = applicationManifest({
    sequence: 2,
    version: "1.1.0",
    deploymentCompatibility: compatibility({ mappingReadable: ["mapping-v2"], mappingWritable: ["mapping-v2"] }),
  }).manifest;
  assert.throws(() => assertReleaseTransitionCompatible({
    current,
    candidate: unreadable,
    predecessor,
    component: "bot",
    observedRetainedFormats: { "bot-mapping-reader": ["mapping-v1"] },
  }), /candidate cannot read/);
  assert.equal(assertReleaseTransitionCompatible({
    current,
    candidate: current,
    predecessor: current,
    component: "daemon",
    observedRetainedFormats: { "daemon-app-session": [], "workspace-lifecycle": [] },
    sdkExternalStateContractFingerprint: hex("9"),
  }), current);
  assert.throws(() => assertReleaseTransitionCompatible({
    current,
    candidate: current,
    predecessor: current,
    component: "daemon",
    observedRetainedFormats: { "daemon-app-session": [], "workspace-lifecycle": [] },
    sdkExternalStateContractFingerprint: hex("8"),
  }), /SDK external-state contract mismatch/);
});

test("opaque SDK compatibility fingerprint binds package, integrity, schema, and audited source contracts", () => {
  const contract = buildSdkExternalStateContract({
    packageName: "@gajae-code/coding-agent",
    packageVersion: "0.16.6",
    lockIntegrity: `sha512-${Buffer.alloc(64, 5).toString("base64")}`,
    configSchemaVersion: 2,
    sourceContracts: {
      settings: hex("1"),
      model: hex("2"),
      auth: hex("3"),
      session: hex("4"),
    },
  });
  assert.equal(validateSdkExternalStateContract(contract), contract);
  assert.throws(() => validateSdkExternalStateContract({ ...contract, configSchemaVersion: 3 }));
  assert.throws(() => validateSdkExternalStateContract({ ...contract, lockIntegrity: "sha512-not-base64" }));
  assert.throws(() => validateSdkExternalStateContract({ ...contract, sourceContracts: { ...contract.sourceContracts, profile: hex("5") } }));
});

test("HOST_ID validation preserves exact UTF-16 identity without trim, normalization, or Unicode case folding", () => {
  const spaced = "  Host A  ";
  assert.equal(validateServiceHostId(spaced), spaced);
  const expectedHash = sha256(Buffer.from(spaced, "utf8"));
  assert.equal(deriveServiceInstanceKey(spaced), `host-a-${expectedHash}`);
  assert.equal(deriveServiceInstanceKey("K"), `host-${sha256(Buffer.from("K", "utf8"))}`);
  assert.notEqual(deriveServiceInstanceKey("é"), deriveServiceInstanceKey("é"));
  assert.equal(validateServiceHostId("😀".repeat(64)), "😀".repeat(64));
  const mixedBoundary = ` \u00a0é${"😀".repeat(62)} `;
  assert.equal(mixedBoundary.length, 128);
  assert.equal(validateServiceHostId(mixedBoundary), mixedBoundary);
  assert.equal(validateServiceHostId(" ".repeat(128)), " ".repeat(128));
  assert.throws(() => validateServiceHostId("😀".repeat(65)));
  for (const forbidden of [
    "\u0000",
    "\u0085",
    "\u00ad",
    "\u200b",
    "\u200c",
    "\u200d",
    "\u200e",
    "\u2028",
    "\u2029",
    "\u202e",
    "\u2066",
    "\ufeff",
    "\u{e0001}",
    "\u{e0020}",
  ]) {
    assert.throws(() => validateServiceHostId(`host${forbidden}name`));
  }
  assert.throws(() => validateServiceHostId("\ud800"));
  const collisionA = deriveServiceInstanceKey("Host/A");
  const collisionB = deriveServiceInstanceKey("Host A");
  assert.equal(collisionA.split("-").slice(0, -1).join("-"), collisionB.split("-").slice(0, -1).join("-"));
  assert.notEqual(collisionA, collisionB);
  assert.equal(serviceKeyForTarget({ component: "bot" }), "bot");
  assert.equal(validateServiceKey(collisionA, "daemon"), collisionA);
  assert.throws(() => validateServiceKey(collisionA, "bot"));
  assert.throws(() => validateServiceKey("daemon-host"));
});

test("service lifecycle requests have operation-specific exact keys, principals, CAS, and platform bounds", () => {
  const install = {
    schemaVersion: 1,
    target: { component: "bot" },
    roles: linuxRoles,
    source: { kind: "github-release", tag: "v1.2.3" },
    configuration: linuxBotConfiguration,
    expected: { serviceGeneration: 0, resourceProof: null, applicationSequenceFloor: 0 },
  };
  assert.equal(validateServiceLifecycleRequest("install", install, { platform: "linux", architecture: "x64" }), install);
  assert.equal(serviceRolesFingerprint(linuxRoles, "linux"), canonicalJsonHash(linuxRoles));
  assert.equal(serviceConfigurationFingerprint(linuxBotConfiguration, { component: "bot", platform: "linux" }), canonicalJsonHash(linuxBotConfiguration));
  assert.throws(() => validateServiceLifecycleRequest("install", { ...install, extra: true }, { platform: "linux", architecture: "x64" }));
  assert.throws(() => validateServiceLifecycleRequest("install", { ...install, roles: { ...linuxRoles, daemon: linuxRoles.bot } }, { platform: "linux", architecture: "x64" }));
  const update = {
    schemaVersion: 1,
    target: { component: "bot" },
    roles: linuxRoles,
    source: { kind: "github-release", tag: "v1.2.4" },
    expected: { serviceGeneration: 1, resourceProof: hex("1"), currentManifestFingerprint: hex("2"), applicationSequenceFloor: 7 },
    acceptServiceDisruption: true,
  };
  assert.equal(validateServiceLifecycleRequest("update", update, { platform: "linux", architecture: "x64" }), update);
  assert.throws(() => validateServiceLifecycleRequest("update", { ...update, acceptServiceDisruption: false }, { platform: "linux", architecture: "x64" }));
  const rollback = {
    schemaVersion: 1,
    target: { component: "bot" },
    roles: linuxRoles,
    expected: { serviceGeneration: 2, resourceProof: hex("1"), currentManifestFingerprint: hex("2"), predecessorManifestFingerprint: hex("3") },
    acceptServiceDisruption: true,
  };
  assert.equal(validateServiceLifecycleRequest("rollback", rollback, { platform: "linux", architecture: "x64" }), rollback);
  const uninstall = {
    schemaVersion: 1,
    target: { component: "bot" },
    roles: linuxRoles,
    expected: { serviceGeneration: 2, resourceProof: hex("1"), currentManifestFingerprint: hex("2") },
    acceptServiceDisruption: true,
  };
  assert.equal(validateServiceLifecycleRequest("uninstall", uninstall, { platform: "linux", architecture: "x64" }), uninstall);
  const recover = {
    schemaVersion: 1,
    target: { component: "bot" },
    roles: linuxRoles,
    expected: { transactionId: "tx-active", journalFingerprint: hex("4") },
    acceptServiceDisruption: false,
  };
  assert.equal(validateServiceLifecycleRequest("recover", recover, { platform: "linux", architecture: "x64" }), recover);
  const windowsInstall = {
    schemaVersion: 1,
    target: { component: "daemon", hostId: " Exact Host " },
    roles: windowsRoles,
    source: { kind: "github-release", tag: "v1.2.3" },
    configuration: windowsDaemonConfiguration,
    expected: { serviceGeneration: 0, resourceProof: null, applicationSequenceFloor: 0, shawlSequenceFloor: 0 },
    servicePassword: "line one\nline two",
  };
  assert.equal(validateServiceLifecycleRequest("install", windowsInstall, { platform: "win32", architecture: "x64" }), windowsInstall);
  assert.equal(validateServiceLifecycleRequest("install", { ...windowsInstall, servicePassword: "p".repeat(SERVICE_LIFECYCLE_LIMITS.servicePasswordBytes) }, { platform: "win32", architecture: "x64" }).servicePassword.length, SERVICE_LIFECYCLE_LIMITS.servicePasswordBytes);
  assert.throws(() => validateServiceLifecycleRequest("install", { ...windowsInstall, servicePassword: "p".repeat(SERVICE_LIFECYCLE_LIMITS.servicePasswordBytes + 1) }, { platform: "win32", architecture: "x64" }));
  const { shawlSequenceFloor, ...missingShawlFloor } = windowsInstall.expected;
  assert.throws(() => validateServiceLifecycleRequest("install", { ...windowsInstall, expected: missingShawlFloor }, { platform: "win32", architecture: "x64" }));
  assert.throws(() => validateServiceLifecycleRequest("install", { ...windowsInstall, servicePassword: "bad\0password" }, { platform: "win32", architecture: "x64" }));
  const linuxStatus = {
    schemaVersion: 1,
    target: { component: "bot" },
    roles: linuxRoles,
  };
  assert.equal(validateServiceLifecycleRequest("status", linuxStatus, { platform: "linux", architecture: "x64" }), linuxStatus);
  const windowsStatus = {
    schemaVersion: 1,
    target: { component: "daemon", hostId: " Exact Host " },
    roles: windowsRoles,
  };
  assert.equal(validateServiceLifecycleRequest("status", windowsStatus, { platform: "win32", architecture: "x64" }), windowsStatus);
  assert.throws(() => validateServiceLifecycleRequest("status", {
    schemaVersion: 1,
    target: { component: "bot" },
  }, { platform: "linux", architecture: "x64" }));
  assert.throws(() => validateServiceLifecycleRequest("status", {
    ...linuxStatus,
    roles: { ...linuxRoles, system: { kind: "uid", value: "uid:999" } },
  }, { platform: "linux", architecture: "x64" }));
  assert.throws(() => validateServiceLifecycleRequest("status", {
    ...linuxStatus,
    roles: { ...linuxRoles, daemon: linuxRoles.bot },
  }, { platform: "linux", architecture: "x64" }));
  for (const mutationField of [
    { expected: { serviceGeneration: 1 } },
    { acceptServiceDisruption: true },
    { source: { kind: "github-release", tag: "v1.2.3" } },
    { configuration: linuxBotConfiguration },
    { servicePassword: "secret" },
  ]) {
    assert.throws(() => validateServiceLifecycleRequest("status", {
      ...linuxStatus,
      ...mutationField,
    }, { platform: "linux", architecture: "x64" }));
  }
});

test("platform service states encode executable trials separately from disabled and final activation", () => {
  const linuxTrial = buildServicePlatformState("linux", "trial");
  assert.equal(validateServicePlatformState(linuxTrial, "linux"), linuxTrial);
  assert.deepEqual(linuxTrial, {
    schemaVersion: 1,
    kind: "linux-service-state",
    phase: "trial",
    loaded: true,
    masked: false,
    unitFileState: "disabled",
    restartPolicy: "no",
    inboundActivatorCount: 0,
    hasStartBlockingCondition: false,
    activation: "suppressed-controller-startable",
  });
  assert.throws(() => validateServicePlatformState({ ...linuxTrial, masked: true }, "linux"));
  assert.throws(() => validateServicePlatformState({ ...linuxTrial, hasStartBlockingCondition: true }, "linux"));
  const windowsCreated = buildServicePlatformState("win32", "created-protected");
  const windowsTrial = buildServicePlatformState("win32", "trial");
  assert.equal(windowsCreated.startType, "disabled");
  assert.equal(windowsCreated.activation, "disabled-not-startable");
  assert.equal(windowsTrial.startType, "demand");
  assert.equal(windowsTrial.failureActions, "none");
  assert.equal(windowsTrial.activation, "suppressed-controller-startable");
  assert.equal(buildServicePlatformState("win32", "final").failureActions, "restart-10s,restart-10s,restart-10s,none");
  assert.equal(buildServicePlatformState("win32", "final").failureResetSeconds, 600);
});

function installedServiceGraph() {
  const platformState = buildServicePlatformState("linux", "final");
  const resource = buildServiceResourceProof({
    serviceKey: "bot",
    component: "bot",
    platform: "linux",
    architecture: "x64",
    operation: "install",
    serviceGeneration: 1,
    applicationManifestFingerprint: hex("a"),
    shawlManifestFingerprint: null,
    configurationFingerprint: serviceConfigurationFingerprint(linuxBotConfiguration, { component: "bot", platform: "linux" }),
    rolesFingerprint: serviceRolesFingerprint(linuxRoles, "linux"),
    transactionId: "tx-install",
    transactionNonce: "1".repeat(32),
    predecessorResourceProof: null,
    platformResourceFingerprint: hex("b"),
    platformState,
  });
  const manifest = buildServiceManifest({
    serviceKey: "bot",
    component: "bot",
    platform: "linux",
    architecture: "x64",
    serviceGeneration: 1,
    applicationManifestFingerprint: hex("a"),
    shawlManifestFingerprint: null,
    predecessorManifestFingerprint: null,
    configuration: linuxBotConfiguration,
    configurationFingerprint: serviceConfigurationFingerprint(linuxBotConfiguration, { component: "bot", platform: "linux" }),
    roles: linuxRoles,
    rolesFingerprint: serviceRolesFingerprint(linuxRoles, "linux"),
    resourceProof: resource.resourceProof,
    platformState,
  });
  const old = buildServiceOldProof({
    disposition: "absent",
    manifestFingerprint: null,
    resourceProof: null,
    applicationManifestFingerprint: null,
    shawlManifestFingerprint: null,
    serviceGeneration: 0,
    activation: "disabled-not-startable",
  }, "linux");
  const candidate = buildServiceCandidateProof({
    disposition: "release",
    applicationManifestFingerprint: hex("a"),
    shawlManifestFingerprint: null,
    releaseSequence: 7,
    releaseTreeFingerprint: hex("c"),
    compatibilityFingerprint: hex("d"),
  }, "linux");
  const transition = buildServiceTransitionProof({
    oldFingerprint: old.oldFingerprint,
    candidateFingerprint: candidate.candidateFingerprint,
    expectedBeforeResourceFingerprint: null,
    expectedAfterResourceFingerprint: hex("e"),
    platformResourceFingerprint: hex("f"),
    platformState: buildServicePlatformState("linux", "trial"),
  }, "linux");
  const final = buildServiceFinalProof({
    disposition: "stable",
    manifestFingerprint: manifest.manifestFingerprint,
    resourceProof: resource.resourceProof,
    applicationManifestFingerprint: hex("a"),
    shawlManifestFingerprint: null,
    serviceGeneration: 1,
    activation: "enabled",
  }, "linux");
  const transaction = buildServiceTransaction({
    transactionId: "tx-install",
    transactionNonce: "1".repeat(32),
    operation: "install",
    component: "bot",
    serviceKey: "bot",
    platform: "linux",
    architecture: "x64",
    serviceGeneration: 1,
    old,
    candidate,
    transition,
    final,
    phase: "prepared",
    substep: "none",
    previousJournalFingerprint: null,
  });
  return { resource, manifest, transaction };
}

test("resource, protected manifest, and O/C/T/F transaction proofs are exact canonical hashes", () => {
  const { resource, manifest, transaction } = installedServiceGraph();
  assert.equal(validateServiceResourceProof(resource), resource);
  assert.equal(validateServiceManifest(manifest), manifest);
  assert.equal(validateServiceTransaction(transaction), transaction);
  assert.throws(() => validateServiceResourceProof({ ...resource, resourceProof: hex("0") }));
  assert.throws(() => validateServiceManifest({ ...manifest, configuration: { ...manifest.configuration, extra: true } }));
  assert.throws(() => validateServiceTransaction({ ...transaction, serviceGeneration: 2 }));
  assert.throws(() => validateServiceTransaction({ ...transaction, extra: true }));
});

test("startup proof accepts only current trial epoch, bounded time, and component-specific evidence", () => {
  const { resource } = installedServiceGraph();
  const proof = buildServiceStartupProof({
    component: "bot",
    serviceKey: "bot",
    platform: "linux",
    architecture: "x64",
    serviceGeneration: 1,
    transactionId: "tx-install",
    resourceProof: resource.resourceProof,
    applicationManifestFingerprint: hex("a"),
    bootFingerprint: hex("1"),
    processEpochFingerprint: hex("2"),
    platformEvidenceFingerprint: hex("3"),
    applicationEvidenceFingerprint: hex("4"),
    platformState: buildServicePlatformState("linux", "trial"),
    startBoundaryMs: 1_000,
    observedAtMs: 50_000,
    expiresAtMs: 61_000,
    startupEvidence: "fresh-current-epoch",
    connectivityObservation: "last-observed-connected",
  });
  assert.equal(validateServiceStartupProof(proof), proof);
  assert.throws(() => validateServiceStartupProof({ ...proof, observedAtMs: 61_001 }));
  assert.throws(() => validateServiceStartupProof({ ...proof, platformState: buildServicePlatformState("linux", "final") }));
  assert.throws(() => validateServiceStartupProof({ ...proof, connectivityObservation: "startup-only" }));
  const disabledWindowsProof = {
    ...proof,
    platform: "win32",
    platformState: buildServicePlatformState("win32", "created-protected"),
  };
  assert.throws(() => validateServiceStartupProof(disabledWindowsProof));
});

test("tombstone and absorbing manual-cleanup records preserve safe exact recovery evidence", () => {
  const { resource, manifest, transaction } = installedServiceGraph();
  const tombstone = buildServiceTombstone({
    component: "bot",
    serviceKey: "bot",
    platform: "linux",
    architecture: "x64",
    serviceGeneration: 2,
    transactionId: "tx-uninstall",
    transactionFingerprint: transaction.transactionFingerprint,
    resourceProof: resource.resourceProof,
    currentManifestFingerprint: manifest.manifestFingerprint,
    applicationSequenceFloor: 7,
    shawlSequenceFloor: null,
  });
  assert.equal(validateServiceTombstone(tombstone), tombstone);
  assert.throws(() => validateServiceTombstone({ ...tombstone, shawlSequenceFloor: 0 }));
  const cleanup = buildServiceManualCleanup({
    component: "bot",
    serviceKey: "bot",
    platform: "linux",
    architecture: "x64",
    serviceGeneration: 1,
    transactionId: "tx-install",
    journalFingerprint: transaction.transactionFingerprint,
    phase: "trial-start-observed",
    reason: "recreated-resource",
    operatorAction: "remove-unmarked-resource",
    expectedDisposition: "absent",
    expectedOldProofFingerprint: transaction.old.oldFingerprint,
    observedDisposition: "foreign",
    observedFingerprint: hex("f"),
    blockedUntilOperatorAction: true,
  });
  assert.equal(validateServiceManualCleanup(cleanup), cleanup);
  assert.throws(() => validateServiceManualCleanup({ ...cleanup, blockedUntilOperatorAction: false }));
  assert.throws(() => validateServiceManualCleanup({ ...cleanup, operatorAction: "adopt-resource" }));
});

test("status receipt has closed truthful dimensions and never upgrades startup evidence to live health", () => {
  const { resource, manifest } = installedServiceGraph();
  const status = buildServiceStatusReceipt({
    component: "bot",
    serviceKey: "bot",
    platform: "linux",
    architecture: "x64",
    serviceGeneration: 1,
    manifestFingerprint: manifest.manifestFingerprint,
    resourceProof: resource.resourceProof,
    transactionFingerprint: null,
    ownership: "owned",
    service: "running",
    activation: "enabled",
    tree: "exact-current",
    startupEvidence: "historical-current-epoch",
    connectivityObservation: "last-observed-connected",
    providerHealth: "unknown",
    workspaceHealth: "unknown",
    supervisorProvenance: "not-applicable",
    recovery: "clean",
    observedAtMs: 100_000,
  });
  assert.equal(validateServiceStatusReceipt(status), status);
  assert.deepEqual(Object.keys(SERVICE_STATUS_VALUES), ["ownership", "service", "activation", "tree", "startupEvidence", "connectivityObservation", "health", "supervisorProvenance", "recovery"]);
  assert.throws(() => validateServiceStatusReceipt({ ...status, providerHealth: "healthy" }));
  assert.throws(() => validateServiceStatusReceipt({ ...status, startupEvidence: "ready" }));
  assert.throws(() => validateServiceStatusReceipt({ ...status, component: "daemon", serviceKey: deriveServiceInstanceKey("host-a") }));
  const absent = buildServiceStatusReceipt({
    component: "daemon",
    serviceKey: deriveServiceInstanceKey("host-a"),
    platform: "linux",
    architecture: "arm64",
    serviceGeneration: 0,
    manifestFingerprint: null,
    resourceProof: null,
    transactionFingerprint: null,
    ownership: "absent",
    service: "missing",
    activation: "disabled-not-startable",
    tree: "empty",
    startupEvidence: "none",
    connectivityObservation: "unknown",
    providerHealth: "unknown",
    workspaceHealth: "unknown",
    supervisorProvenance: "not-applicable",
    recovery: "clean",
    observedAtMs: 100_000,
  });
  assert.equal(validateServiceStatusReceipt(absent), absent);
  const windowsOwned = buildServiceStatusReceipt({
    component: "daemon",
    serviceKey: deriveServiceInstanceKey("host-a"),
    platform: "win32",
    architecture: "x64",
    serviceGeneration: 3,
    manifestFingerprint: hex("1"),
    resourceProof: hex("2"),
    transactionFingerprint: null,
    ownership: "owned",
    service: "running",
    activation: "enabled",
    tree: "exact-current",
    startupEvidence: "historical-current-epoch",
    connectivityObservation: "startup-only",
    providerHealth: "unknown",
    workspaceHealth: "unknown",
    supervisorProvenance: "project-attested-unsigned-upstream",
    recovery: "clean",
    observedAtMs: 100_001,
  });
  assert.equal(validateServiceStatusReceipt(windowsOwned), windowsOwned);
  assert.throws(() => validateServiceStatusReceipt({ ...windowsOwned, supervisorProvenance: "signed" }));
});

function linuxNativeIdentity(profile, inode = "1") {
  return {
    profile,
    kind: "linux-service-object-v1",
    device: "1",
    inode,
    mode: profile.endsWith("directory") ? 16832 : 33152,
    owner: "uid:1000",
    securitySha256: hex("a"),
  };
}

function linuxFileFacts(identity, value) {
  return {
    kind: "linux-file-v1",
    device: identity.device,
    inode: identity.inode,
    size: canonicalJsonBytes(value).length,
    sha256: canonicalJsonHash(value),
    mode: identity.mode,
    owner: identity.owner,
    securitySha256: identity.securitySha256,
  };
}

function controlRootBinding() {
  return {
    schemaVersion: 1,
    rootKind: "control",
    rootPath: "/var/lib/gjc-remote/service-control",
    rootNonce: "1".repeat(32),
    rolesFingerprint: hex("b"),
    identity: linuxNativeIdentity("service-control-directory", "10"),
    directoryIdentities: Object.fromEntries(
      SERVICE_STORE_NAMESPACES.map((name, index) => [
        name,
        linuxNativeIdentity("service-control-directory", String(20 + index)),
      ])
    ),
    bindingFingerprint: hex("c"),
  };
}

test("protected store registration and floor witness bind exact native root identity without equating role hashes", () => {
  const rootBinding = controlRootBinding();
  const historyRootIdentity = linuxNativeIdentity("service-control-directory", "30");
  assert.equal(validateServiceControlRootBinding(rootBinding, "linux"), rootBinding);
  const registration = buildServiceStoreRegistration({
    platform: "linux",
    architecture: "x64",
    roles: linuxRoles,
    serviceRolesFingerprint: serviceRolesFingerprint(linuxRoles, "linux"),
    rootBinding,
    historyRootIdentity,
    historyRootIdentityFingerprint: serviceNativeIdentityFingerprint(
      historyRootIdentity,
      "linux",
      "service-control-directory"
    ),
  });
  assert.equal(validateServiceStoreRegistration(registration), registration);
  assert.equal(registration.rootBinding.rolesFingerprint, hex("b"));
  assert.notEqual(registration.rootBinding.rolesFingerprint, serviceRolesFingerprint(linuxRoles, "linux"));
  assert.equal(registration.serviceRolesFingerprint, serviceRolesFingerprint(linuxRoles, "linux"));
  assert.throws(() => validateServiceStoreRegistration({
    ...registration,
    serviceRolesFingerprint: hex("d"),
  }));
  assert.throws(() => validateServiceStoreRegistration({
    ...registration,
    rootBinding: {
      ...registration.rootBinding,
      identity: { ...registration.rootBinding.identity, owner: "uid:2000" },
    },
  }));
  const registrationFileIdentity = linuxNativeIdentity("service-control-file", "31");
  const registrationIncarnation = buildServiceStoreRegistrationIncarnation({
    platform: "linux",
    architecture: "x64",
    rootBindingFingerprint: rootBinding.bindingFingerprint,
    historyRootIdentityFingerprint: registration.historyRootIdentityFingerprint,
    registrationFingerprint: registration.registrationFingerprint,
    registrationRecordSha256: canonicalJsonHash(registration),
    registrationFileFacts: linuxFileFacts(registrationFileIdentity, registration),
  });
  assert.equal(
    validateServiceStoreRegistrationIncarnation(registrationIncarnation),
    registrationIncarnation
  );
  const historyEntryIdentity = linuxNativeIdentity("service-control-directory", "32");
  const historyEntryIdentityFingerprint = serviceNativeIdentityFingerprint(
    historyEntryIdentity,
    "linux",
    "service-control-directory"
  );
  const floor = buildServiceSequenceFloor({
    scope: "application:linux:x64",
    revision: 0,
    historyEntryIdentityFingerprint,
    previousHistoryStateFingerprint: null,
    highestReservedSequence: 0,
    highestReservedManifestFingerprint: null,
    committedSequence: 0,
    committedManifestFingerprint: null,
    committedPublicationFingerprint: null,
    committedTransactionId: null,
    committedTransactionNonce: null,
    committedTransactionFingerprint: null,
    activeReservation: null,
  });
  assert.equal(validateServiceSequenceFloor(floor), floor);
  const witness = buildServiceFloorWitness({
    scope: floor.scope,
    platform: "linux",
    architecture: "x64",
    rootBindingFingerprint: rootBinding.bindingFingerprint,
    revision: 0,
    historyEntryIdentityFingerprint,
    previousHistoryStateFingerprint: null,
    state: "stable",
    action: null,
    component: null,
    serviceKey: null,
    currentFloorFingerprint: floor.floorFingerprint,
    intendedFloorFingerprint: null,
    transactionId: null,
    transactionNonce: null,
    transactionFingerprint: null,
  });
  assert.equal(validateServiceFloorWitness(witness), witness);
  const floorIdentity = linuxNativeIdentity("service-control-file", "33");
  const witnessIdentity = linuxNativeIdentity("service-control-file", "34");
  const state = buildServiceFloorHistoryState({
    scope: floor.scope,
    platform: "linux",
    architecture: "x64",
    rootBindingFingerprint: rootBinding.bindingFingerprint,
    registrationFingerprint: registration.registrationFingerprint,
    revision: 0,
    action: null,
    component: null,
    serviceKey: null,
    transactionId: null,
    transactionNonce: null,
    transactionFingerprint: null,
    historyEntryIdentity,
    historyEntryIdentityFingerprint,
    previousHistoryStateFingerprint: null,
    intentFingerprint: null,
    floorFingerprint: floor.floorFingerprint,
    witnessFingerprint: witness.witnessFingerprint,
    floorRecordSha256: canonicalJsonHash(floor),
    witnessRecordSha256: canonicalJsonHash(witness),
    floorFileFacts: linuxFileFacts(floorIdentity, floor),
    witnessFileFacts: linuxFileFacts(witnessIdentity, witness),
  });
  assert.equal(validateServiceFloorHistoryState(state), state);
  const nextHistoryIdentity = linuxNativeIdentity("service-control-directory", "35");
  const nextHistoryIdentityFingerprint = serviceNativeIdentityFingerprint(
    nextHistoryIdentity,
    "linux",
    "service-control-directory"
  );
  const intendedFloor = buildServiceSequenceFloor({
    ...floor,
    revision: 1,
    historyEntryIdentityFingerprint: nextHistoryIdentityFingerprint,
    previousHistoryStateFingerprint: state.stateFingerprint,
    highestReservedSequence: 7,
    highestReservedManifestFingerprint: hex("1"),
    activeReservation: {
      component: "bot",
      serviceKey: "bot",
      transactionId: "tx-7",
      transactionNonce: "7".repeat(32),
      transactionFingerprint: hex("2"),
      sequence: 7,
      manifestFingerprint: hex("1"),
    },
  });
  const intendedWitness = buildServiceFloorWitness({
    ...witness,
    revision: 1,
    historyEntryIdentityFingerprint: nextHistoryIdentityFingerprint,
    previousHistoryStateFingerprint: state.stateFingerprint,
    state: "intent",
    action: "reserve",
    component: "bot",
    serviceKey: "bot",
    currentFloorFingerprint: floor.floorFingerprint,
    intendedFloorFingerprint: intendedFloor.floorFingerprint,
    transactionId: "tx-7",
    transactionNonce: "7".repeat(32),
    transactionFingerprint: hex("2"),
  });
  const nextStableWitness = buildServiceFloorWitness({
    ...witness,
    revision: 1,
    historyEntryIdentityFingerprint: nextHistoryIdentityFingerprint,
    previousHistoryStateFingerprint: state.stateFingerprint,
    currentFloorFingerprint: intendedFloor.floorFingerprint,
  });
  const intent = buildServiceFloorHistoryIntent({
    scope: floor.scope,
    platform: "linux",
    architecture: "x64",
    rootBindingFingerprint: rootBinding.bindingFingerprint,
    registrationFingerprint: registration.registrationFingerprint,
    revision: 1,
    action: "reserve",
    component: "bot",
    serviceKey: "bot",
    transactionId: "tx-7",
    transactionNonce: "7".repeat(32),
    transactionFingerprint: hex("2"),
    historyEntryIdentity: nextHistoryIdentity,
    historyEntryIdentityFingerprint: nextHistoryIdentityFingerprint,
    previousHistoryStateFingerprint: state.stateFingerprint,
    previousFloorFingerprint: floor.floorFingerprint,
    previousWitnessFingerprint: witness.witnessFingerprint,
    previousFloorRecordSha256: canonicalJsonHash(floor),
    previousWitnessRecordSha256: canonicalJsonHash(witness),
    previousFloorFileFacts: linuxFileFacts(floorIdentity, floor),
    previousWitnessFileFacts: linuxFileFacts(witnessIdentity, witness),
    intendedFloor,
    intendedWitness,
    stableWitness: nextStableWitness,
  });
  assert.equal(validateServiceFloorHistoryIntent(intent), intent);
  const transitionState = buildServiceFloorHistoryState({
    scope: floor.scope,
    platform: "linux",
    architecture: "x64",
    rootBindingFingerprint: rootBinding.bindingFingerprint,
    registrationFingerprint: registration.registrationFingerprint,
    revision: 1,
    action: "reserve",
    component: "bot",
    serviceKey: "bot",
    transactionId: "tx-7",
    transactionNonce: "7".repeat(32),
    transactionFingerprint: hex("2"),
    historyEntryIdentity: nextHistoryIdentity,
    historyEntryIdentityFingerprint: nextHistoryIdentityFingerprint,
    previousHistoryStateFingerprint: state.stateFingerprint,
    intentFingerprint: intent.intentFingerprint,
    floorFingerprint: intendedFloor.floorFingerprint,
    witnessFingerprint: nextStableWitness.witnessFingerprint,
    floorRecordSha256: canonicalJsonHash(intendedFloor),
    witnessRecordSha256: canonicalJsonHash(nextStableWitness),
    floorFileFacts: linuxFileFacts(
      linuxNativeIdentity("service-control-file", "36"),
      intendedFloor
    ),
    witnessFileFacts: linuxFileFacts(
      linuxNativeIdentity("service-control-file", "37"),
      nextStableWitness
    ),
  });
  assert.equal(validateServiceFloorHistoryState(transitionState), transitionState);
  assert.throws(() => validateServiceFloorHistoryIntent({
    ...intent,
    previousFloorFileFacts: {
      ...intent.previousFloorFileFacts,
      inode: "999",
    },
  }));
  assert.throws(() => validateServiceFloorWitness({ ...witness, action: "reserve" }));
  assert.throws(() => validateServiceFloorWitness({
    ...witness,
    scope: "application:linux:arm64",
  }));
  assert.throws(() => validateServiceSequenceFloor({
    ...floor,
    highestReservedSequence: 1,
    highestReservedManifestFingerprint: hex("1"),
  }));
});

test("sequence floor preserves high-water while active reservations and publication commits stay exact", () => {
  const reserved = buildServiceSequenceFloor({
    scope: "application:linux:x64",
    revision: 2,
    historyEntryIdentityFingerprint: hex("a"),
    previousHistoryStateFingerprint: hex("b"),
    highestReservedSequence: 9,
    highestReservedManifestFingerprint: hex("1"),
    committedSequence: 7,
    committedManifestFingerprint: hex("2"),
    committedPublicationFingerprint: hex("3"),
    committedTransactionId: "tx-7",
    committedTransactionNonce: "7".repeat(32),
    committedTransactionFingerprint: hex("8"),
    activeReservation: {
      component: "bot",
      serviceKey: "bot",
      transactionId: "tx-9",
      transactionNonce: "4".repeat(32),
      transactionFingerprint: hex("9"),
      sequence: 9,
      manifestFingerprint: hex("1"),
    },
  });
  assert.equal(validateServiceSequenceFloor(reserved), reserved);
  const abandoned = buildServiceSequenceFloor({
    ...reserved,
    revision: 3,
    activeReservation: null,
  });
  assert.equal(abandoned.highestReservedSequence, 9);
  assert.equal(abandoned.committedSequence, 7);
  assert.throws(() => validateServiceSequenceFloor({
    ...reserved,
    activeReservation: { ...reserved.activeReservation, transactionId: "other" },
  }));
});

test("artifact reference slots close current, previous, and provisional identities without a GC permission flag", () => {
  const application = buildServiceArtifactBinding({
    artifactKind: "application",
    rootKind: "releases",
    artifactFingerprint: hex("1"),
    manifestFingerprint: hex("2"),
    treeFingerprint: hex("3"),
    directoryIdentity: linuxNativeIdentity("service-release-directory", "50"),
    directoryIdentityFingerprint: canonicalJsonHash(linuxNativeIdentity("service-release-directory", "50")),
  }, "linux");
  const template = buildServiceArtifactBinding({
    artifactKind: "shared-template",
    rootKind: null,
    artifactFingerprint: hex("4"),
    manifestFingerprint: null,
    treeFingerprint: null,
    directoryIdentity: null,
    directoryIdentityFingerprint: null,
  }, "linux");
  assert.equal(validateServiceArtifactBinding(application, "linux"), application);
  const current = buildServiceReferenceSlot({
    serviceGeneration: 2,
    transactionId: "tx-current",
    transactionNonce: "5".repeat(32),
    artifacts: [application, template],
  }, { platform: "linux", component: "daemon" });
  const provisional = buildServiceReferenceSlot({
    serviceGeneration: 3,
    transactionId: "tx-next",
    transactionNonce: "6".repeat(32),
    artifacts: [
      buildServiceArtifactBinding({
        ...application,
        artifactFingerprint: hex("7"),
        manifestFingerprint: hex("8"),
        treeFingerprint: hex("9"),
      }, "linux"),
      template,
    ],
  }, { platform: "linux", component: "daemon" });
  const record = buildServiceReferenceRecord({
    serviceKey: deriveServiceInstanceKey("daemon-a"),
    component: "daemon",
    platform: "linux",
    architecture: "x64",
    serviceGeneration: 2,
    current,
    previous: null,
    provisional,
  });
  assert.equal(validateServiceReferenceRecord(record), record);
  assert.throws(() => validateServiceReferenceRecord({
    ...record,
    provisional: { ...provisional, serviceGeneration: 4 },
  }));
  const zeroObservation = buildServiceZeroReferenceObservation({
    platform: "linux",
    architecture: "x64",
    artifactBindingFingerprint: application.bindingFingerprint,
    artifactRootKind: application.rootKind,
    artifactFingerprint: application.artifactFingerprint,
    artifactDirectoryIdentity: application.directoryIdentity,
    artifactDirectoryIdentityFingerprint: application.directoryIdentityFingerprint,
    artifactPhysicalTargetFingerprint: serviceArtifactPhysicalTargetFingerprint(
      application,
      "linux"
    ),
    controlRootBindingFingerprint: hex("c"),
    referenceDirectoryIdentity: linuxNativeIdentity("service-control-directory", "24"),
    artifactLockIdentity: linuxNativeIdentity("service-control-file", "60"),
    referenceRecordFingerprints: [record.referenceRecordFingerprint],
  });
  assert.equal(validateServiceZeroReferenceObservation(zeroObservation), zeroObservation);
  assert.equal(Object.hasOwn(zeroObservation, "permission"), false);
  assert.equal(Object.hasOwn(zeroObservation, "allowed"), false);
});

test("journal head binds the exact transaction record and predecessor chain", () => {
  const { transaction } = installedServiceGraph();
  const head = buildServiceJournalHead({
    serviceKey: transaction.serviceKey,
    component: transaction.component,
    platform: transaction.platform,
    architecture: transaction.architecture,
    sequence: 1,
    serviceGeneration: transaction.serviceGeneration,
    transactionId: transaction.transactionId,
    transactionNonce: transaction.transactionNonce,
    transactionFingerprint: transaction.transactionFingerprint,
    previousJournalFingerprint: transaction.previousJournalFingerprint,
  });
  assert.equal(validateServiceJournalHead(head), head);
  assert.throws(() => validateServiceJournalHead({ ...head, transactionNonce: "f".repeat(32) }));
  assert.throws(() => validateServiceJournalHead({ ...head, sequence: 0 }));
});

test("artifact cleanup records are an exact published/scratch discriminated union", () => {
  const nonce = "7".repeat(32);
  const common = {
    component: "bot",
    serviceKey: "bot",
    platform: "linux",
    architecture: "x64",
    serviceGeneration: 1,
    transactionId: "tx-cleanup",
    transactionNonce: nonce,
    transactionFingerprint: hex("1"),
    transactionIdentity: hex("2"),
    purpose: "application",
    manifestFingerprint: hex("3"),
    signingKeyId: "release-key",
    signingKeyFingerprint: hex("4"),
    retainedEnvelopeRecordSha256: hex("5"),
    controlRootBindingFingerprint: hex("6"),
    roles: linuxRoles,
    rolesFingerprint: serviceRolesFingerprint(linuxRoles, "linux"),
    artifactLockIdentity: linuxNativeIdentity("service-control-file", "60"),
  };
  const binding = buildServiceArtifactBinding({
    artifactKind: "application",
    rootKind: "releases",
    artifactFingerprint: hex("7"),
    manifestFingerprint: hex("3"),
    treeFingerprint: hex("8"),
    directoryIdentity: linuxNativeIdentity("service-release-directory", "61"),
    directoryIdentityFingerprint: canonicalJsonHash(linuxNativeIdentity("service-release-directory", "61")),
  }, "linux");
  const published = buildServiceArtifactCleanup({
    ...common,
    artifactBinding: binding,
    artifactPhysicalTargetFingerprint: serviceArtifactPhysicalTargetFingerprint(binding, "linux"),
    artifactRootBindingFingerprint: hex("9"),
    artifactRootIdentity: linuxNativeIdentity("service-release-directory", "62"),
    zeroReferenceObservationFingerprint: hex("a"),
    phase: "payload-removing",
    revision: 0,
  });
  assert.equal(published.scope, "published");
  assert.equal(validateServiceArtifactCleanup(published), published);
  assert.throws(() => validateServiceArtifactCleanup({ ...published, scope: undefined }));
  assert.throws(() => validateServiceArtifactCleanup({ ...published, scope: "scratch" }));
  assert.throws(() => validateServiceArtifactCleanup({ ...published, scope: "published", scratchName: "x" }));

  const scratchAuthority = {
    stagingRootBindingFingerprint: hex("b"),
    stagingRootIdentity: linuxNativeIdentity("service-staging-directory", "70"),
    scratchName: `bot-${nonce}-application`,
    scratchIdentity: linuxNativeIdentity("service-staging-directory", "71"),
    releaseSequence: 1,
    markerFingerprint: hex("c"),
    markerFacts: linuxFileFacts(linuxNativeIdentity("service-staging-file", "72"), { marker: true }),
    assetName: "archive",
    assetSize: 4096,
    assetSha256: hex("7"),
    assetFacts: linuxFileFacts(linuxNativeIdentity("service-staging-file", "73"), { partial: true }),
    candidateIdentity: linuxNativeIdentity("service-staging-directory", "74"),
  };
  const scratch = buildServiceArtifactScratchCleanup({
    ...common,
    ...scratchAuthority,
    phase: "candidate-payload-removing",
    revision: 0,
  });
  assert.equal(scratch.scope, "scratch");
  assert.equal(validateServiceArtifactCleanup(scratch), scratch);
  assert.throws(() => validateServiceArtifactCleanup({ ...scratch, scope: "published" }));
  assert.throws(() => validateServiceArtifactCleanup({ ...scratch, artifactBinding: binding }));
  assert.throws(() => validateServiceArtifactCleanup({ ...scratch, scratchName: `bot-${nonce}-shawl` }));
  assert.throws(() => validateServiceArtifactCleanup({ ...scratch, assetName: "raw-shawl" }));
  assert.throws(() => validateServiceArtifactCleanup({ ...scratch, assetFacts: { ...scratch.assetFacts, owner: "uid:1001" } }));
  assert.throws(() => validateServiceArtifactCleanup({ ...scratch, candidateIdentity: linuxNativeIdentity("service-control-file", "75") }));
  assert.throws(() => validateServiceArtifactCleanup({ ...scratch, phase: "root-removing" }));
  assert.throws(() => validateServiceArtifactCleanup({ ...scratch, revision: 1 }));
  assert.throws(() => validateServiceArtifactCleanup({ ...scratch, cleanupFingerprint: hex("f") }));
  assert.ok(canonicalJsonBytes(scratch).byteLength <= SERVICE_LIFECYCLE_LIMITS.protectedRecordBytes);

  const resumed = buildServiceArtifactScratchCleanup({
    ...common,
    ...scratchAuthority,
    phase: "marker-removing",
    revision: 4,
  });
  assert.equal(validateServiceArtifactCleanup(resumed), resumed);
  assert.throws(() => validateServiceArtifactCleanup({ ...resumed, revision: 3 }));

  const windowsRoles = {
    management: { kind: "sid", value: "S-1-5-21-1-2-3-1000" },
    bot: { kind: "sid", value: "S-1-5-21-1-2-3-1001" },
    recovery: { kind: "sid", value: "S-1-5-21-1-2-3-1002" },
    daemon: { kind: "sid", value: "S-1-5-21-1-2-3-1003" },
    system: { kind: "sid", value: "S-1-5-18" },
  };
  const windowsIdentity = (profile, id) => ({
    profile,
    kind: "win32-service-object-v1",
    volumeSerial: "0000000000000001",
    fileId: id,
    attributes: profile.endsWith("directory") ? 16 : 128,
    owner: "S-1-5-21-1-2-3-1000",
    securitySha256: hex("d"),
  });
  const shawl = buildServiceArtifactScratchCleanup({
    ...common,
    platform: "win32",
    purpose: "shawl",
    roles: windowsRoles,
    rolesFingerprint: serviceRolesFingerprint(windowsRoles, "win32"),
    artifactLockIdentity: windowsIdentity("service-control-file", "4".repeat(32)),
    stagingRootBindingFingerprint: hex("b"),
    stagingRootIdentity: windowsIdentity("service-staging-directory", "1".repeat(32)),
    scratchName: `bot-${nonce}-shawl`,
    scratchIdentity: windowsIdentity("service-staging-directory", "2".repeat(32)),
    releaseSequence: 1,
    markerFingerprint: hex("c"),
    markerFacts: {
      kind: "win32-file-v1",
      volumeSerial: "0000000000000001",
      fileId: "3".repeat(32),
      size: 128,
      sha256: hex("f"),
      attributes: 128,
      owner: "S-1-5-21-1-2-3-1000",
      securitySha256: hex("e"),
    },
    assetName: "raw-shawl",
    assetSize: 64,
    assetSha256: hex("8"),
    assetFacts: null,
    candidateIdentity: null,
    phase: "asset-removing",
    revision: 2,
  });
  assert.equal(validateServiceArtifactCleanup(shawl), shawl);
  assert.throws(() => validateServiceArtifactCleanup({ ...shawl, phase: "candidate-inventory-removing" }));
  assert.throws(() => validateServiceArtifactCleanup({ ...shawl, phase: "asset-removing", revision: 1 }));
  assert.throws(() => buildServiceArtifactScratchCleanup({
    ...common,
    ...scratchAuthority,
    platform: "linux",
    purpose: "shawl",
    scratchName: `bot-${nonce}-shawl`,
    assetName: "raw-shawl",
    phase: "asset-removing",
    revision: 2,
  }));
});
