import { canonicalJsonBytes, canonicalJsonHash, isHex64, utf8Compare, assertStrictText } from "./strict-json.js";

export const DEPLOYMENT_ENVELOPE_LIMITS = Object.freeze({
  manifestBytes: 1024 * 1024,
  signatureBytes: 16 * 1024,
  archiveBytes: 1024 * 1024 * 1024,
  unpackedPayloadBytes: 2 * 1024 * 1024 * 1024,
  inventoryBytes: 32 * 1024 * 1024,
  payloadEntries: 100_000,
  pathBytes: 4096,
  pathSegments: 64,
  selectorBytes: 128,
  keyIdBytes: 128,
  formatIdBytes: 128,
  formatsPerDomain: 256,
  redirects: 3,
  connectTimeoutMs: 10_000,
  idleTimeoutMs: 10_000,
  acquisitionTimeoutMs: 10 * 60_000,
});

export const DEPLOYMENT_SIGNATURE_DOMAINS = Object.freeze({
  application: "gjc-remote/application-deployment/v1",
  shawl: "gjc-remote/shawl-deployment/v1",
});

export const APPLICATION_DEPLOYMENT_REPOSITORY = "kogangdon/gjc-remote";
export const SHAWL_UPSTREAM = Object.freeze({
  repository: "mtkennerly/shawl",
  version: "1.9.0",
  tag: "v1.9.0",
  commit: "dbc4014c6d67027dc75a565d79fe9f493e897eb2",
});
export const APPLICATION_BUNDLE_INVENTORY_PATH = "bundle-files.json";
export const REQUIRED_NATIVE_CONTROL_CONTRACT = Object.freeze({ version: 4, revision: 4 });

const INVENTORY_CANONICAL_LIMITS = Object.freeze({
  maxBytes: DEPLOYMENT_ENVELOPE_LIMITS.inventoryBytes,
  maxDepth: 16,
  maxNodes: DEPLOYMENT_ENVELOPE_LIMITS.payloadEntries * 6 + 32,
});
const MANIFEST_CANONICAL_LIMITS = Object.freeze({
  maxBytes: DEPLOYMENT_ENVELOPE_LIMITS.manifestBytes,
  maxDepth: 32,
  maxNodes: 10_000,
});
const SELECTOR = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/;
const SEMVER = /^(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)(?:-[0-9A-Za-z]+(?:[.-][0-9A-Za-z]+)*)?$/;
const GIT_OBJECT_ID = /^[0-9a-f]{40}$/;
const KEY_ID = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/;
const FORMAT_ID = /^[A-Za-z0-9][A-Za-z0-9._:@/-]{0,127}$/;
const WINDOWS_RESERVED_SEGMENT = /^(?:con|prn|aux|nul|conin\$|conout\$|com[1-9¹²³]|lpt[1-9¹²³])(?:\..*)?$/i;
const FORBIDDEN_BUNDLE_SEGMENTS = new Set([".env", ".git", ".gjc", ".gjc-remote-session", ".cache"]);
const PLATFORM_TUPLES = new Set(["linux:x64", "linux:arm64", "win32:x64"]);
const FORMAT_DOMAINS = Object.freeze({
  bot: Object.freeze(["bot-mapping-reader"]),
  daemon: Object.freeze(["daemon-app-session", "workspace-lifecycle"]),
});

const plain = (value) => value !== null && typeof value === "object" && !Array.isArray(value) && Object.getPrototypeOf(value) === Object.prototype;
const exact = (value, keys) => plain(value) && Object.keys(value).length === keys.length && keys.every((key) => Object.hasOwn(value, key));
const fail = (message) => { throw new TypeError(`DEPLOYMENT_ENVELOPE_INVALID: ${message}`); };
const positive = (value) => Number.isSafeInteger(value) && value >= 1;
const nonnegative = (value) => Number.isSafeInteger(value) && value >= 0;
const nullableHash = (value) => value === null || isHex64(value);

function strictText(value, name, maxBytes, { allowEmpty = false } = {}) {
  try {
    assertStrictText(value, name, maxBytes);
  } catch {
    fail(name);
  }
  if (!allowEmpty && value.length === 0) fail(name);
  return value;
}

function fingerprint(record, field, limits = MANIFEST_CANONICAL_LIMITS) {
  if (!plain(record) || !Object.hasOwn(record, field)) fail(`${field} preimage`);
  return canonicalJsonHash(
    Object.fromEntries(Object.entries(record).filter(([key]) => key !== field)),
    limits
  );
}

function assertCanonicalSize(value, maximum, name, limits = MANIFEST_CANONICAL_LIMITS) {
  let size;
  try {
    size = canonicalJsonBytes(value, limits).byteLength;
  } catch {
    fail(`${name} canonical JSON`);
  }
  if (size > maximum) fail(`${name} byte limit`);
  return size;
}

function validateTuple(target) {
  if (!exact(target, ["platform", "architecture"]) ||
      !PLATFORM_TUPLES.has(`${target.platform}:${target.architecture}`)) {
    fail("unsupported target tuple");
  }
  return target;
}

export function validateReleaseSelector(value) {
  if (typeof value !== "string" || Buffer.byteLength(value, "utf8") > DEPLOYMENT_ENVELOPE_LIMITS.selectorBytes || !SELECTOR.test(value)) {
    fail("release selector");
  }
  return value;
}

function validateBundlePath(value, platform, name = "bundle path") {
  strictText(value, name, DEPLOYMENT_ENVELOPE_LIMITS.pathBytes);
  if (value.startsWith("/") || value.startsWith("\\") || /^[A-Za-z]:/.test(value) || value.includes("\\")) fail(name);
  const segments = value.split("/");
  if (segments.length > DEPLOYMENT_ENVELOPE_LIMITS.pathSegments ||
      segments.some((segment) => segment.length === 0 || segment === "." || segment === "..")) fail(name);
  if (segments.some((segment) => FORBIDDEN_BUNDLE_SEGMENTS.has(segment.toLowerCase()))) fail(`${name} mutable-state segment`);
  if (platform === "win32" && segments.some((segment) =>
    /[<>:"|?*]/.test(segment) || /[. ]$/.test(segment) || WINDOWS_RESERVED_SEGMENT.test(segment))) fail(name);
  return value;
}

function validatePayloadRecord(record, platform) {
  if (!exact(record, ["path", "size", "sha256", "executablePolicy"]) ||
      !nonnegative(record.size) ||
      record.size > DEPLOYMENT_ENVELOPE_LIMITS.unpackedPayloadBytes ||
      !isHex64(record.sha256) ||
      !["forbidden", "required"].includes(record.executablePolicy)) fail("inventory payload record");
  validateBundlePath(record.path, platform, "inventory payload path");
  if (record.path === APPLICATION_BUNDLE_INVENTORY_PATH) fail("inventory cannot enumerate itself");
  return record;
}

function validateSortedUniqueStrings(values, name, predicate, maximum = DEPLOYMENT_ENVELOPE_LIMITS.formatsPerDomain, allowEmpty = false) {
  if (!Array.isArray(values) || (!allowEmpty && values.length === 0) || values.length > maximum) fail(name);
  let previous = null;
  for (const value of values) {
    if (typeof value !== "string" || !predicate(value)) fail(name);
    if (previous !== null && utf8Compare(previous, value) >= 0) fail(`${name} ordering`);
    previous = value;
  }
  return values;
}

function validatePayloadTreePaths(entries, platform) {
  // Reserve the separately stored inventory without including it in the hash.
  // Segment ordering keeps a file adjacent to its first descendant even when
  // punctuation would separate them in ordinary whole-path ordering.
  const paths = [APPLICATION_BUNDLE_INVENTORY_PATH, ...entries.map((entry) => entry.path)]
    .map((path) => {
      const parts = path.split("/");
      // Conservative Unicode caseless policy, not an exact NTFS collation
      // claim. Lowercase alone misses aliases such as I and dotless ı.
      const keys = platform === "win32"
        ? parts.map((part) => part.toLowerCase().toUpperCase())
        : parts;
      return { parts, keys };
    });
  paths.sort((left, right) => {
    const count = Math.min(left.keys.length, right.keys.length);
    for (let index = 0; index < count; index += 1) {
      if (left.keys[index] !== right.keys[index]) {
        return left.keys[index] < right.keys[index] ? -1 : 1;
      }
    }
    return left.keys.length - right.keys.length;
  });
  for (let index = 1; index < paths.length; index += 1) {
    const previous = paths[index - 1];
    const current = paths[index];
    let common = 0;
    while (common < previous.keys.length && common < current.keys.length &&
        previous.keys[common] === current.keys[common]) common += 1;
    if (common === previous.keys.length) fail("payload file/directory or platform path collision");
    if (platform === "win32") {
      for (let segment = 0; segment < common; segment += 1) {
        if (previous.parts[segment] !== current.parts[segment]) {
          fail("payload directory platform path collision");
        }
      }
    }
  }
}

export function bundleTreeFingerprint(payloadEntries, { platform } = {}) {
  if (!Array.isArray(payloadEntries) || payloadEntries.length > DEPLOYMENT_ENVELOPE_LIMITS.payloadEntries) fail("payload entries");
  const copy = payloadEntries.map((entry) => ({ ...entry }));
  let previous = null;
  let canonicalBudget = 2;
  for (const entry of copy) {
    validatePayloadRecord(entry, platform);
    canonicalBudget += Buffer.byteLength(JSON.stringify(entry), "utf8") + 1;
    if (canonicalBudget > DEPLOYMENT_ENVELOPE_LIMITS.inventoryBytes) fail("payload record byte limit");
    if (previous !== null && utf8Compare(previous, entry.path) >= 0) fail("payload entry ordering");
    previous = entry.path;
  }
  validatePayloadTreePaths(copy, platform);
  return canonicalJsonHash(copy, INVENTORY_CANONICAL_LIMITS);
}

export function bundleInventoryFingerprint(inventory) {
  return fingerprint(inventory, "inventoryFingerprint", INVENTORY_CANONICAL_LIMITS);
}

export function validateBundleInventory(inventory, { platform } = {}) {
  const keys = ["schemaVersion", "kind", "payloadEntries", "payloadEntryCount", "unpackedPayloadBytes", "treeFingerprint", "inventoryFingerprint"];
  if (!exact(inventory, keys) || inventory.schemaVersion !== 1 || inventory.kind !== "application-bundle-inventory" ||
      !Array.isArray(inventory.payloadEntries) || inventory.payloadEntries.length > DEPLOYMENT_ENVELOPE_LIMITS.payloadEntries ||
      inventory.payloadEntryCount !== inventory.payloadEntries.length ||
      !nonnegative(inventory.unpackedPayloadBytes) || inventory.unpackedPayloadBytes > DEPLOYMENT_ENVELOPE_LIMITS.unpackedPayloadBytes ||
      !isHex64(inventory.treeFingerprint) || !isHex64(inventory.inventoryFingerprint)) fail("bundle inventory schema");
  let total = 0;
  let previous = null;
  let canonicalBudget = 1024;
  for (const entry of inventory.payloadEntries) {
    validatePayloadRecord(entry, platform);
    canonicalBudget += Buffer.byteLength(JSON.stringify(entry), "utf8") + 1;
    if (canonicalBudget > DEPLOYMENT_ENVELOPE_LIMITS.inventoryBytes) fail("inventory byte limit");
    if (previous !== null && utf8Compare(previous, entry.path) >= 0) fail("inventory path ordering");
    previous = entry.path;
    total += entry.size;
    if (!Number.isSafeInteger(total) || total > DEPLOYMENT_ENVELOPE_LIMITS.unpackedPayloadBytes) fail("inventory payload byte total");
  }
  if (total !== inventory.unpackedPayloadBytes) fail("inventory payload byte relation");
  if (bundleTreeFingerprint(inventory.payloadEntries, { platform }) !== inventory.treeFingerprint) fail("inventory tree fingerprint");
  if (bundleInventoryFingerprint(inventory) !== inventory.inventoryFingerprint) fail("inventory fingerprint");
  assertCanonicalSize(inventory, DEPLOYMENT_ENVELOPE_LIMITS.inventoryBytes, "inventory", INVENTORY_CANONICAL_LIMITS);
  return inventory;
}

export function buildBundleInventory({ payloadEntries }, { platform } = {}) {
  if (!Array.isArray(payloadEntries) || payloadEntries.length > DEPLOYMENT_ENVELOPE_LIMITS.payloadEntries) fail("payload entries");
  const entries = payloadEntries.map((entry) => ({ ...entry })).sort((left, right) => utf8Compare(left.path, right.path));
  const inventory = {
    schemaVersion: 1,
    kind: "application-bundle-inventory",
    payloadEntries: entries,
    payloadEntryCount: entries.length,
    unpackedPayloadBytes: entries.reduce((total, entry) => total + entry.size, 0),
    treeFingerprint: bundleTreeFingerprint(entries, { platform }),
    inventoryFingerprint: null,
  };
  inventory.inventoryFingerprint = bundleInventoryFingerprint(inventory);
  return validateBundleInventory(inventory, { platform });
}

export function sdkExternalStateContractFingerprint(contract) {
  return fingerprint(contract, "sdkExternalStateContractFingerprint");
}

export function validateSdkExternalStateContract(contract) {
  const keys = ["schemaVersion", "kind", "packageName", "packageVersion", "lockIntegrity", "configSchemaVersion", "sourceContracts", "sdkExternalStateContractFingerprint"];
  if (!exact(contract, keys) || contract.schemaVersion !== 1 || contract.kind !== "sdk-external-state-contract" ||
      contract.packageName !== "@gajae-code/coding-agent" || typeof contract.packageVersion !== "string" ||
      !SEMVER.test(contract.packageVersion) || typeof contract.lockIntegrity !== "string" ||
      !positive(contract.configSchemaVersion) || !exact(contract.sourceContracts, ["settings", "model", "auth", "session"]) ||
      Object.values(contract.sourceContracts).some((value) => !isHex64(value)) ||
      !isHex64(contract.sdkExternalStateContractFingerprint)) fail("SDK external-state contract schema");
  let integrity;
  if (!contract.lockIntegrity.startsWith("sha512-")) fail("SDK lock integrity");
  try { integrity = Buffer.from(contract.lockIntegrity.slice(7), "base64"); } catch { fail("SDK lock integrity"); }
  if (integrity.byteLength !== 64 || `sha512-${integrity.toString("base64")}` !== contract.lockIntegrity) fail("SDK lock integrity");
  if (sdkExternalStateContractFingerprint(contract) !== contract.sdkExternalStateContractFingerprint) fail("SDK external-state contract fingerprint");
  return contract;
}

export function buildSdkExternalStateContract(fields) {
  const contract = { schemaVersion: 1, kind: "sdk-external-state-contract", ...fields, sdkExternalStateContractFingerprint: null };
  contract.sdkExternalStateContractFingerprint = sdkExternalStateContractFingerprint(contract);
  return validateSdkExternalStateContract(contract);
}

function validateFormatDomain(record, expectedDomain) {
  if (!exact(record, ["domain", "readableFormats", "writableFormats"]) || record.domain !== expectedDomain) fail("compatibility domain schema");
  validateSortedUniqueStrings(record.readableFormats, `${expectedDomain} readable formats`, (value) =>
    Buffer.byteLength(value, "utf8") <= DEPLOYMENT_ENVELOPE_LIMITS.formatIdBytes && FORMAT_ID.test(value));
  validateSortedUniqueStrings(record.writableFormats, `${expectedDomain} writable formats`, (value) =>
    Buffer.byteLength(value, "utf8") <= DEPLOYMENT_ENVELOPE_LIMITS.formatIdBytes && FORMAT_ID.test(value));
  return record;
}

function validateCompatibilityRole(record, component) {
  if (!exact(record, ["domains", "sdkExternalStateContractFingerprint"]) || !Array.isArray(record.domains) ||
      record.domains.length !== FORMAT_DOMAINS[component].length) fail(`${component} compatibility schema`);
  for (let index = 0; index < record.domains.length; index += 1) validateFormatDomain(record.domains[index], FORMAT_DOMAINS[component][index]);
  if (component === "bot" ? record.sdkExternalStateContractFingerprint !== null : !isHex64(record.sdkExternalStateContractFingerprint)) {
    fail(`${component} SDK external-state contract`);
  }
  return record;
}

function compatibilityRegistryFingerprint(compatibility) {
  return canonicalJsonHash({
    bot: compatibility.roles.bot.domains,
    daemon: compatibility.roles.daemon.domains,
  });
}

export function validateDeploymentCompatibility(compatibility) {
  if (!exact(compatibility, ["schemaVersion", "kind", "formatRegistryFingerprint", "roles"]) ||
      compatibility.schemaVersion !== 1 || compatibility.kind !== "deployment-compatibility" ||
      !isHex64(compatibility.formatRegistryFingerprint) || !exact(compatibility.roles, ["bot", "daemon"])) fail("compatibility schema");
  validateCompatibilityRole(compatibility.roles.bot, "bot");
  validateCompatibilityRole(compatibility.roles.daemon, "daemon");
  if (compatibilityRegistryFingerprint(compatibility) !== compatibility.formatRegistryFingerprint) fail("format registry fingerprint");
  return compatibility;
}

export function buildDeploymentCompatibility({ bot, daemon }) {
  const compatibility = {
    schemaVersion: 1,
    kind: "deployment-compatibility",
    formatRegistryFingerprint: null,
    roles: {
      bot: {
        domains: bot.domains.map((domain) => ({ ...domain, readableFormats: [...domain.readableFormats], writableFormats: [...domain.writableFormats] })),
        sdkExternalStateContractFingerprint: null,
      },
      daemon: {
        domains: daemon.domains.map((domain) => ({ ...domain, readableFormats: [...domain.readableFormats], writableFormats: [...domain.writableFormats] })),
        sdkExternalStateContractFingerprint: daemon.sdkExternalStateContractFingerprint,
      },
    },
  };
  compatibility.formatRegistryFingerprint = compatibilityRegistryFingerprint(compatibility);
  return validateDeploymentCompatibility(compatibility);
}

function validateApplicationSource(source, releaseVersion, releaseId) {
  if (!exact(source, ["repository", "tag", "commit", "tree", "bunLockSha256"]) ||
      source.repository !== APPLICATION_DEPLOYMENT_REPOSITORY ||
      source.tag !== `v${releaseVersion}` || releaseId !== source.tag ||
      !GIT_OBJECT_ID.test(source.commit) || !GIT_OBJECT_ID.test(source.tree) || !isHex64(source.bunLockSha256)) fail("application source");
  validateReleaseSelector(source.tag);
  return source;
}

function validateArchive(archive, releaseVersion, target, payloadEntryCount) {
  const expectedName = `gjc-remote-service-${releaseVersion}-${target.platform}-${target.architecture}.tar.gz`;
  if (!exact(archive, ["name", "mediaType", "byteLength", "sha256", "entryCount"]) ||
      archive.name !== expectedName || archive.mediaType !== "application/gzip" ||
      !positive(archive.byteLength) || archive.byteLength > DEPLOYMENT_ENVELOPE_LIMITS.archiveBytes ||
      !isHex64(archive.sha256) || archive.entryCount !== payloadEntryCount + 1) fail("application archive");
  return archive;
}

function validateInventoryBinding(binding) {
  if (!exact(binding, ["path", "byteLength", "sha256", "payloadEntryCount", "unpackedPayloadBytes", "treeFingerprint"]) ||
      binding.path !== APPLICATION_BUNDLE_INVENTORY_PATH ||
      !positive(binding.byteLength) || binding.byteLength > DEPLOYMENT_ENVELOPE_LIMITS.inventoryBytes ||
      !isHex64(binding.sha256) || !nonnegative(binding.payloadEntryCount) ||
      binding.payloadEntryCount > DEPLOYMENT_ENVELOPE_LIMITS.payloadEntries ||
      !nonnegative(binding.unpackedPayloadBytes) || binding.unpackedPayloadBytes > DEPLOYMENT_ENVELOPE_LIMITS.unpackedPayloadBytes ||
      !isHex64(binding.treeFingerprint)) fail("application inventory binding");
  return binding;
}

function validateApplicationEntrypoints(entrypoints, platform) {
  if (!exact(entrypoints, ["bot", "daemon"]) || entrypoints.bot !== "bot/src/bot.js" || entrypoints.daemon !== "daemon/src/daemon.js") {
    fail("application entrypoints");
  }
  validateBundlePath(entrypoints.bot, platform, "bot entrypoint");
  validateBundlePath(entrypoints.daemon, platform, "daemon entrypoint");
  return entrypoints;
}

function validateRuntimeContract(runtimes) {
  if (!exact(runtimes, ["node", "bun"]) ||
      !exact(runtimes.node, ["minimumVersion"]) || runtimes.node.minimumVersion !== "26.0.0" ||
      !exact(runtimes.bun, ["minimumVersion"]) || runtimes.bun.minimumVersion !== "1.4.0") fail("runtime contract");
  return runtimes;
}

function validateNativeControlContract(contract, platform) {
  if (!exact(contract, ["manifestPath", "manifestFingerprint", "contractVersion", "contractRevision"]) ||
      contract.manifestPath !== "native-control/build/Release/native-control.manifest.json" ||
      !isHex64(contract.manifestFingerprint) ||
      contract.contractVersion !== REQUIRED_NATIVE_CONTROL_CONTRACT.version ||
      contract.contractRevision !== REQUIRED_NATIVE_CONTROL_CONTRACT.revision) fail("native-control contract");
  validateBundlePath(contract.manifestPath, platform, "native-control manifest path");
  return contract;
}

function validateWireCapabilities(capabilities) {
  return validateSortedUniqueStrings(capabilities, "wire capabilities", (value) =>
    Buffer.byteLength(value, "utf8") <= 64 && /^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$/.test(value), 32);
}

export function applicationDeploymentManifestFingerprint(manifest) {
  return fingerprint(manifest, "manifestFingerprint");
}

export function validateApplicationDeploymentManifest(manifest, inventory = undefined) {
  const keys = ["schemaVersion", "kind", "signingKeyId", "releaseId", "releaseVersion", "releaseSequence", "source", "target", "archive", "inventory", "entrypoints", "runtimes", "nativeControl", "wireCapabilities", "compatibility", "manifestFingerprint"];
  if (!exact(manifest, keys) || manifest.schemaVersion !== 1 || manifest.kind !== "application-deployment-manifest" ||
      typeof manifest.signingKeyId !== "string" || !KEY_ID.test(manifest.signingKeyId) ||
      typeof manifest.releaseVersion !== "string" || !SEMVER.test(manifest.releaseVersion) ||
      !positive(manifest.releaseSequence) || !isHex64(manifest.manifestFingerprint)) fail("application manifest schema");
  validateReleaseSelector(manifest.releaseId);
  validateTuple(manifest.target);
  validateApplicationSource(manifest.source, manifest.releaseVersion, manifest.releaseId);
  validateInventoryBinding(manifest.inventory);
  validateArchive(manifest.archive, manifest.releaseVersion, manifest.target, manifest.inventory.payloadEntryCount);
  validateApplicationEntrypoints(manifest.entrypoints, manifest.target.platform);
  validateRuntimeContract(manifest.runtimes);
  validateNativeControlContract(manifest.nativeControl, manifest.target.platform);
  validateWireCapabilities(manifest.wireCapabilities);
  validateDeploymentCompatibility(manifest.compatibility);
  if (applicationDeploymentManifestFingerprint(manifest) !== manifest.manifestFingerprint) fail("application manifest fingerprint");
  assertCanonicalSize(manifest, DEPLOYMENT_ENVELOPE_LIMITS.manifestBytes, "application manifest");
  if (inventory !== undefined) {
    validateBundleInventory(inventory, { platform: manifest.target.platform });
    const bytes = canonicalJsonBytes(inventory, INVENTORY_CANONICAL_LIMITS);
    if (bytes.byteLength !== manifest.inventory.byteLength || canonicalJsonHash(inventory, INVENTORY_CANONICAL_LIMITS) !== manifest.inventory.sha256 ||
        inventory.payloadEntryCount !== manifest.inventory.payloadEntryCount || inventory.unpackedPayloadBytes !== manifest.inventory.unpackedPayloadBytes ||
        inventory.treeFingerprint !== manifest.inventory.treeFingerprint) fail("manifest inventory relation");
    const payloadPaths = new Set(inventory.payloadEntries.map((entry) => entry.path));
    for (const path of [manifest.entrypoints.bot, manifest.entrypoints.daemon, manifest.nativeControl.manifestPath]) {
      if (!payloadPaths.has(path)) fail("manifest required payload relation");
    }
  }
  return manifest;
}

export function buildApplicationDeploymentManifest(fields) {
  const manifest = { schemaVersion: 1, kind: "application-deployment-manifest", ...fields, manifestFingerprint: null };
  manifest.manifestFingerprint = applicationDeploymentManifestFingerprint(manifest);
  return validateApplicationDeploymentManifest(manifest);
}

export function shawlDeploymentManifestFingerprint(manifest) {
  return fingerprint(manifest, "manifestFingerprint");
}

export function validateShawlDeploymentManifest(manifest) {
  const keys = ["schemaVersion", "kind", "signingKeyId", "releaseSequence", "target", "upstream", "executable", "projectAsset", "manifestFingerprint"];
  if (!exact(manifest, keys) || manifest.schemaVersion !== 1 || manifest.kind !== "shawl-deployment-manifest" ||
      typeof manifest.signingKeyId !== "string" || !KEY_ID.test(manifest.signingKeyId) || !positive(manifest.releaseSequence) ||
      !isHex64(manifest.manifestFingerprint)) fail("Shawl manifest schema");
  if (!exact(manifest.target, ["platform", "architecture"]) || manifest.target.platform !== "win32" || manifest.target.architecture !== "x64") fail("Shawl target");
  if (!exact(manifest.upstream, ["repository", "tag", "commit", "assetId", "assetName", "zipSha256"]) ||
      manifest.upstream.repository !== SHAWL_UPSTREAM.repository || manifest.upstream.tag !== SHAWL_UPSTREAM.tag ||
      manifest.upstream.commit !== SHAWL_UPSTREAM.commit || !positive(manifest.upstream.assetId) ||
      !/^[A-Za-z0-9][A-Za-z0-9._-]{0,255}\.zip$/i.test(manifest.upstream.assetName) || !isHex64(manifest.upstream.zipSha256)) fail("Shawl upstream provenance");
  if (!exact(manifest.executable, ["name", "byteLength", "sha256", "version", "versionOutput", "authenticode"]) ||
      manifest.executable.name !== "shawl.exe" || !positive(manifest.executable.byteLength) ||
      manifest.executable.byteLength > DEPLOYMENT_ENVELOPE_LIMITS.archiveBytes || !isHex64(manifest.executable.sha256) ||
      manifest.executable.version !== SHAWL_UPSTREAM.version || manifest.executable.authenticode !== "unsigned") fail("Shawl executable provenance");
  strictText(manifest.executable.versionOutput, "Shawl version output", 256);
  if (!manifest.executable.versionOutput.includes(SHAWL_UPSTREAM.version)) fail("Shawl version output relation");
  if (!exact(manifest.projectAsset, ["repository", "tag", "name"]) ||
      manifest.projectAsset.repository !== APPLICATION_DEPLOYMENT_REPOSITORY ||
      manifest.projectAsset.name !== "gjc-remote-shawl-win32-x64.exe") fail("Shawl project asset");
  validateReleaseSelector(manifest.projectAsset.tag);
  if (shawlDeploymentManifestFingerprint(manifest) !== manifest.manifestFingerprint) fail("Shawl manifest fingerprint");
  assertCanonicalSize(manifest, DEPLOYMENT_ENVELOPE_LIMITS.manifestBytes, "Shawl manifest");
  return manifest;
}

export function buildShawlDeploymentManifest(fields) {
  const manifest = { schemaVersion: 1, kind: "shawl-deployment-manifest", ...fields, manifestFingerprint: null };
  manifest.manifestFingerprint = shawlDeploymentManifestFingerprint(manifest);
  return validateShawlDeploymentManifest(manifest);
}

function validatePurpose(purpose) {
  if (!Object.hasOwn(DEPLOYMENT_SIGNATURE_DOMAINS, purpose)) fail("signature purpose");
  return purpose;
}

export function deploymentSignaturePreimage(purpose, manifest) {
  validatePurpose(purpose);
  if (purpose === "application") validateApplicationDeploymentManifest(manifest);
  else validateShawlDeploymentManifest(manifest);
  return Buffer.concat([
    Buffer.from(DEPLOYMENT_SIGNATURE_DOMAINS[purpose], "utf8"),
    Buffer.from([0]),
    canonicalJsonBytes(manifest, MANIFEST_CANONICAL_LIMITS),
  ]);
}

export function validateDeploymentSignature(signature, purpose, manifest = undefined) {
  validatePurpose(purpose);
  const expectedKind = `${purpose}-deployment-signature`;
  if (!exact(signature, ["schemaVersion", "kind", "domain", "keyId", "algorithm", "manifestFingerprint", "signature"]) ||
      signature.schemaVersion !== 1 || signature.kind !== expectedKind ||
      signature.domain !== DEPLOYMENT_SIGNATURE_DOMAINS[purpose] ||
      typeof signature.keyId !== "string" || !KEY_ID.test(signature.keyId) ||
      signature.algorithm !== "ed25519" || !isHex64(signature.manifestFingerprint) || typeof signature.signature !== "string") {
    fail("deployment signature schema");
  }
  let decoded;
  try { decoded = Buffer.from(signature.signature, "base64"); } catch { fail("deployment signature encoding"); }
  if (decoded.byteLength !== 64 || decoded.toString("base64") !== signature.signature) fail("deployment signature encoding");
  if (manifest !== undefined) {
    if (purpose === "application") validateApplicationDeploymentManifest(manifest);
    else validateShawlDeploymentManifest(manifest);
    if (signature.keyId !== manifest.signingKeyId || signature.manifestFingerprint !== manifest.manifestFingerprint) fail("deployment signature manifest relation");
  }
  assertCanonicalSize(signature, DEPLOYMENT_ENVELOPE_LIMITS.signatureBytes, "deployment signature");
  return signature;
}

function absolutePath(value, platform, name) {
  strictText(value, name, DEPLOYMENT_ENVELOPE_LIMITS.pathBytes);
  const valid = platform === "win32"
    ? /^(?:[A-Za-z]:[\\/]|\\\\[^\\/]+[\\/][^\\/]+)/.test(value)
    : value.startsWith("/");
  if (!valid) fail(name);
  return value;
}

export function validateDeploymentSource(source, { platform, architecture }) {
  validateTuple({ platform, architecture });
  if (!plain(source) || typeof source.kind !== "string") fail("deployment source");
  if (source.kind === "github-release") {
    if (!exact(source, ["kind", "tag"])) fail("GitHub release source");
    validateReleaseSelector(source.tag);
    return source;
  }
  const applicationKeys = ["kind", "applicationManifestPath", "applicationSignaturePath", "applicationArchivePath"];
  const windowsKeys = [...applicationKeys, "shawlManifestPath", "shawlSignaturePath", "shawlExecutablePath"];
  const expectedKeys = platform === "win32" ? windowsKeys : applicationKeys;
  if (source.kind !== "offline" || !exact(source, expectedKeys)) fail("offline deployment source");
  const paths = expectedKeys.slice(1).map((key) => absolutePath(source[key], platform, key));
  const identities = paths.map((value) => platform === "win32" ? value.toLowerCase() : value);
  if (new Set(identities).size !== identities.length) fail("offline deployment source path collision");
  return source;
}

export function deploymentBootstrapAssetNames(platform, architecture) {
  validateTuple({ platform, architecture });
  const applicationManifest = `gjc-remote-service-${platform}-${architecture}.manifest.json`;
  return Object.freeze({
    applicationManifest,
    applicationSignature: `${applicationManifest}.sig`,
    shawlManifest: platform === "win32" ? "gjc-remote-shawl-win32-x64.manifest.json" : null,
    shawlSignature: platform === "win32" ? "gjc-remote-shawl-win32-x64.manifest.json.sig" : null,
    shawlExecutable: platform === "win32" ? "gjc-remote-shawl-win32-x64.exe" : null,
  });
}

export function deploymentSequenceFloorFingerprint(floor) {
  return fingerprint(floor, "floorFingerprint");
}

export function validateDeploymentSequenceFloor(floor) {
  const keys = ["schemaVersion", "kind", "scope", "reservedSequence", "reservedManifestFingerprint", "reservationTransactionId", "committedSequence", "committedManifestFingerprint", "floorFingerprint"];
  if (!exact(floor, keys) || floor.schemaVersion !== 1 || floor.kind !== "deployment-sequence-floor" ||
      !/^(?:application:(?:linux:(?:x64|arm64)|win32:x64)|shawl:win32:x64)$/.test(floor.scope) ||
      !nonnegative(floor.reservedSequence) || !nullableHash(floor.reservedManifestFingerprint) ||
      (floor.reservationTransactionId !== null && (typeof floor.reservationTransactionId !== "string" || !SELECTOR.test(floor.reservationTransactionId))) ||
      !nonnegative(floor.committedSequence) || !nullableHash(floor.committedManifestFingerprint) ||
      !isHex64(floor.floorFingerprint)) fail("deployment sequence floor schema");
  if ((floor.reservedSequence === 0) !== (floor.reservedManifestFingerprint === null) ||
      (floor.committedSequence === 0) !== (floor.committedManifestFingerprint === null) ||
      floor.committedSequence > floor.reservedSequence ||
      (floor.committedSequence === floor.reservedSequence && floor.committedSequence > 0 && floor.committedManifestFingerprint !== floor.reservedManifestFingerprint) ||
      (floor.committedSequence === floor.reservedSequence && floor.reservationTransactionId !== null) ||
      (floor.reservedSequence > floor.committedSequence && floor.reservationTransactionId === null)) fail("deployment sequence floor relation");
  if (deploymentSequenceFloorFingerprint(floor) !== floor.floorFingerprint) fail("deployment sequence floor fingerprint");
  return floor;
}

export function buildDeploymentSequenceFloor(fields) {
  const floor = { schemaVersion: 1, kind: "deployment-sequence-floor", ...fields, floorFingerprint: null };
  floor.floorFingerprint = deploymentSequenceFloorFingerprint(floor);
  return validateDeploymentSequenceFloor(floor);
}

export function assertDeploymentSequenceAdmission({ floor, candidateSequence, candidateManifestFingerprint, transactionId, operation, currentSequence = 0 }) {
  validateDeploymentSequenceFloor(floor);
  if (!positive(candidateSequence) || !isHex64(candidateManifestFingerprint) ||
      typeof transactionId !== "string" || !SELECTOR.test(transactionId) ||
      !["install", "update", "replay"].includes(operation) || !nonnegative(currentSequence)) fail("sequence admission input");
  if (operation === "update" && candidateSequence <= currentSequence) fail("RELEASE_SEQUENCE_NOT_ADVANCING");
  if (floor.reservationTransactionId !== null &&
      (candidateSequence !== floor.reservedSequence ||
       candidateManifestFingerprint !== floor.reservedManifestFingerprint ||
       transactionId !== floor.reservationTransactionId)) fail("RELEASE_SEQUENCE_RESERVED");
  if (candidateSequence < floor.reservedSequence || candidateSequence < floor.committedSequence) fail("RELEASE_SEQUENCE_DOWNGRADE");
  if (candidateSequence === floor.reservedSequence && floor.reservedSequence > 0) {
    if (candidateManifestFingerprint !== floor.reservedManifestFingerprint) fail("RELEASE_SEQUENCE_CONFLICT");
    if (floor.reservationTransactionId !== null && transactionId !== floor.reservationTransactionId) fail("RELEASE_SEQUENCE_RESERVED");
  }
  if (candidateSequence === floor.committedSequence && floor.committedSequence > 0 && candidateManifestFingerprint !== floor.committedManifestFingerprint) {
    fail("RELEASE_SEQUENCE_CONFLICT");
  }
  return true;
}

function findDomain(compatibility, component, domain) {
  return compatibility.roles[component].domains.find((entry) => entry.domain === domain);
}

function assertContainsAll(values, required, message) {
  const available = new Set(values);
  if ([...required].some((value) => !available.has(value))) fail(message);
}

export function assertReleaseTransitionCompatible({ current, candidate, predecessor, component, observedRetainedFormats, sdkExternalStateContractFingerprint = null }) {
  validateApplicationDeploymentManifest(current);
  validateApplicationDeploymentManifest(candidate);
  validateApplicationDeploymentManifest(predecessor);
  if (!FORMAT_DOMAINS[component]) fail("transition component");
  if (!exact(observedRetainedFormats, FORMAT_DOMAINS[component])) fail("observed retained formats schema");
  for (const domain of FORMAT_DOMAINS[component]) {
    validateSortedUniqueStrings(observedRetainedFormats[domain], `${domain} observed formats`, (value) => FORMAT_ID.test(value), DEPLOYMENT_ENVELOPE_LIMITS.formatsPerDomain, true);
  }
  const stableFields = ["target", "runtimes", "nativeControl", "wireCapabilities"];
  for (const field of stableFields) {
    const expected = canonicalJsonHash(current[field]);
    if (canonicalJsonHash(candidate[field]) !== expected || canonicalJsonHash(predecessor[field]) !== expected) fail(`transition ${field} contract`);
  }
  if (candidate.entrypoints[component] !== current.entrypoints[component] || predecessor.entrypoints[component] !== current.entrypoints[component]) {
    fail("transition entrypoint contract");
  }
  for (const domain of FORMAT_DOMAINS[component]) {
    const currentDomain = findDomain(current.compatibility, component, domain);
    const candidateDomain = findDomain(candidate.compatibility, component, domain);
    const predecessorDomain = findDomain(predecessor.compatibility, component, domain);
    const observed = observedRetainedFormats[domain];
    assertContainsAll(candidateDomain.readableFormats, new Set([...observed, ...currentDomain.writableFormats]), `candidate cannot read ${domain}`);
    assertContainsAll(predecessorDomain.readableFormats, new Set([...observed, ...candidateDomain.writableFormats]), `predecessor cannot read ${domain}`);
  }
  const sdkValues = [current, candidate, predecessor].map((manifest) => manifest.compatibility.roles[component].sdkExternalStateContractFingerprint);
  if (component === "daemon") sdkValues.push(sdkExternalStateContractFingerprint);
  if (sdkValues.some((value) => value !== sdkValues[0])) fail("SDK external-state contract mismatch");
  if (component === "bot" && sdkExternalStateContractFingerprint !== null) fail("bot SDK external-state contract");
  return candidate;
}
