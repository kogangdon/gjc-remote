import { execFile as execFileCallback } from "node:child_process";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { existsSync, readFileSync, symlinkSync } from "node:fs";
import { promisify } from "node:util";
import { chmod, mkdtemp, mkdir, rm, writeFile } from "node:fs/promises";
import { createRequire } from "node:module";
import { fileURLToPath } from "node:url";
import { basename, join } from "node:path";
import { tmpdir } from "node:os";
import test from "node:test";

import { capabilities, capabilitySignatures, validateBuildManifest } from "../src/index.js";
const execFile = promisify(execFileCallback);

const require = createRequire(import.meta.url);
const packageRoot = new URL("..", import.meta.url);
const releaseRoot = new URL("../build/Release/", import.meta.url);
const addonUrl = new URL("native_control.node", releaseRoot);
const manifestUrl = new URL("native-control.manifest.json", releaseRoot);
const packageUrl = new URL("package.json", packageRoot);

function platformRoles(current) {
  if (process.platform === "linux" && current?.kind === "uid") {
    const management = current.value;
    const reserved = new Set([management, "uid:0"]);
    const candidates = ["uid:4294967293", "uid:4294967294", "uid:4294967292"]
      .filter((value) => !reserved.has(value));
    return [management, candidates[0], candidates[1], "uid:0"];
  }
  if (process.platform === "win32" && current?.kind === "sid") {
    return [
      current.value,
      "S-1-5-21-111111111-222222222-333333333-1001",
      "S-1-5-21-111111111-222222222-333333333-1002",
      "S-1-5-18",
    ];
  }
  return null;
}

test("verified native addon enforces retained-handle, ACL, replacement, durability, and no-follow primitives", async (t) => {
  if (!existsSync(addonUrl) || !existsSync(manifestUrl)) {
    t.skip("verified native addon is not built for this checkout");
    return;
  }

  const addonBytes = readFileSync(addonUrl);
  const manifest = JSON.parse(readFileSync(manifestUrl, "utf8"));
  const packageJson = JSON.parse(readFileSync(packageUrl, "utf8"));
  if (!validateBuildManifest(manifest, packageJson, addonBytes)) {
    t.skip("native build belongs to a different platform or architecture");
    return;
  }

  const addon = require(fileURLToPath(addonUrl));
  const contract = addon.native_control_contract();
  assert.equal(contract.contractVersion, 1);
  assert.equal(contract.napi, 8);
  assert.deepEqual(contract.capabilities, capabilities);
  assert.deepEqual(contract.capabilitySignatures, capabilitySignatures);
  assert.equal(manifest.sha256, createHash("sha256").update(addonBytes).digest("hex"));
  const signatureDrift = structuredClone(manifest);
  signatureDrift.capabilitySignatures.principal_access_check = ["path", "kind", "principal"];
  assert.equal(validateBuildManifest(signatureDrift, packageJson, addonBytes), false);

  const roles = platformRoles(addon.current_os_principal());
  if (roles === null) {
    t.skip("native authority integration requires a supported OS principal");
    return;
  }

  const root = await mkdtemp(join(tmpdir(), "gjc-native-control-"));
  const destination = join(root, "authority.json");
  const initial = Buffer.from('{"phase":"prepared"}');
  const replacement = Buffer.from('{"phase":"committed"}');
  try {
    await addon.create_absent_exclusive(destination, initial, ...roles, "authority");
    await addon.flush_file(destination);
    await addon.flush_directory_or_volume(root);
    assert.deepEqual(Buffer.from(await addon.read_verified_bytes(destination)), initial);
    assert.ok(await addon.read_identity(destination));
    assert.ok(await addon.open_no_follow(destination));
    assert.ok(await addon.read_acl(destination));
    assert.equal(await addon.verify_exact_role_acl(destination, ...roles, "authority"), true);
    const kind = process.platform === "win32" ? "sid" : "uid";
    assert.equal(await addon.principal_access_check(destination, kind, roles[0], "read"), true);
    assert.equal(await addon.principal_access_check(destination, kind, roles[0], "write"), true);
    for (const principal of roles.slice(1, 3)) {
      assert.equal(await addon.principal_access_check(destination, kind, principal, "read"), true);
      assert.equal(await addon.principal_access_check(destination, kind, principal, "write"), false);
    }
    const authorityParent = join(root, "authority-parent");
    await addon.ensure_control_directory(authorityParent, ...roles, "authority");
    assert.equal(await addon.verify_exact_role_acl(authorityParent, ...roles, "authority"), true);
    const authorityParentIdentity = await addon.read_identity(authorityParent);
    assert.equal(authorityParentIdentity.owner, roles[0], "native identity proves authority parent ownership by M");
    for (const principal of roles.slice(1, 3)) {
      assert.equal(await addon.principal_access_check(authorityParent, kind, principal, "write"), false,
        "B/R lack directory mutation permission, denying rename and unlink of authority entries");
    }

    const authDestination = join(root, "management-auth.json");
    const authBytes = Buffer.from('{"verifier":"redacted"}');
    await addon.create_absent_exclusive(authDestination, authBytes, ...roles, "management-auth");
    assert.equal(await addon.principal_access_check(authDestination, kind, roles[0], "read"), true);
    assert.equal(await addon.principal_access_check(authDestination, kind, roles[0], "write"), true);
    for (const principal of roles.slice(1, 3)) {
      assert.equal(await addon.principal_access_check(authDestination, kind, principal, "read"), false);
      assert.equal(await addon.principal_access_check(authDestination, kind, principal, "write"), false);
    }
    assert.throws(() => addon.principal_access_check(destination, kind, roles[0]), /missing string argument/);
    assert.throws(() => addon.principal_access_check(destination, kind, roles[0], "execute"), /access mode must be read or write/);

    const parentHandle = await addon.open_verified_parent_handle(destination);
    const objectHandle = await addon.open_verified_object_handle(parentHandle, basename(destination));
    assert.ok(objectHandle);
    assert.deepEqual(Buffer.from(await addon.read_handle_bytes(objectHandle)), initial);
    assert.ok(await addon.read_handle_identity(objectHandle));

    const temporary = await addon.create_exclusive_temp(root, "authority", replacement, ...roles, "authority");
    await addon.flush_file(temporary);
    await addon.replace_existing_atomic(temporary, destination, ...roles, "authority");
    await addon.flush_file(destination);
    await addon.flush_directory_or_volume(root);
    assert.deepEqual(Buffer.from(await addon.read_verified_bytes(destination)), replacement);

    const lock = await addon.acquire_native_lock(join(root, "authority.lock"), ...roles, "authority");
    await lock.release();

    if (process.platform === "linux") {
      const link = join(root, "authority-link.json");
      symlinkSync(destination, link);
      assert.throws(() => addon.open_no_follow(link), /without following symlinks/);
    }
      const realParent = join(root, "real-parent");
      const linkedParent = join(root, "linked-parent");
      await mkdir(realParent);
      symlinkSync(realParent, linkedParent);
      const substituted = join(linkedParent, "nested", "authority.json");
      assert.throws(() => addon.open_verified_parent(substituted), /verified parent/);
      assert.throws(() => addon.open_verified_parent_handle(substituted), /verified parent handle/);

    await addon.remove_verified_file(destination, replacement);
    assert.equal(await addon.read_verified_bytes(destination), null);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});
test("POSIX principal access rejects writable ACL_OTHER, ACL_GROUP, and named groups", async (t) => {
  if (process.platform !== "linux") {
    t.skip("POSIX ACL probe is Linux-only");
    return;
  }
  if (!existsSync(addonUrl) || !existsSync(manifestUrl)) {
    t.skip("verified native addon is not built for this checkout");
    return;
  }
  const addonBytes = readFileSync(addonUrl);
  const manifest = JSON.parse(readFileSync(manifestUrl, "utf8"));
  const packageJson = JSON.parse(readFileSync(packageUrl, "utf8"));
  if (!validateBuildManifest(manifest, packageJson, addonBytes, "linux", process.arch)) {
    t.skip("native build belongs to a different platform or architecture");
    return;
  }
  const addon = require(fileURLToPath(addonUrl));
  const currentUid = Number(String(addon.current_os_principal().value).replace(/^uid:/, ""));
  const currentGid = typeof process.getgid === "function" ? process.getgid() : null;
  const candidate = readFileSync("/etc/passwd", "utf8").split("\n")
    .map((line) => line.split(":"))
    .find((fields) => fields.length > 3 && Number.isInteger(Number(fields[2])) &&
      Number(fields[2]) !== currentUid && (currentGid === null || Number(fields[3]) !== currentGid));
  if (!candidate) {
    t.skip("no distinct local POSIX principal is available");
    return;
  }
  const root = await mkdtemp(join(tmpdir(), "gjc-native-acl-"));
  const target = join(root, "acl-group-other.txt");
  try {
    await writeFile(target, Buffer.from("acl-group-other"));
    const principal = `uid:${candidate[2]}`;

    // A readable ACL_OTHER remains a valid read proof, but any broad write bit
    // invalidates the mutation proof even when this principal is not in the group.
    await chmod(target, 0o644);
    assert.equal(await addon.principal_access_check(target, "uid", principal, "read"), true);
    assert.equal(await addon.principal_access_check(target, "uid", principal, "write"), false);
    await chmod(target, 0o666);
    assert.equal(await addon.principal_access_check(target, "uid", principal, "read"), true);
    assert.equal(await addon.principal_access_check(target, "uid", principal, "write"), false);

    // A named ACL_GROUP is likewise rejected for mutation regardless of
    // whether the probed principal happens to match that group.
    await chmod(target, 0o644);
    try {
      await execFile("setfacl", ["-m", `g:${currentGid ?? candidate[3]}:rw`, target]);
      assert.equal(await addon.principal_access_check(target, "uid", principal, "write"), false);
    } catch (error) {
      if (error?.code !== "ENOENT") throw error;
      t.diagnostic("setfacl unavailable; ACL_GROUP named-entry probe skipped");
    }
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});
test("native source contains fail-closed ACL and publication guards", () => {
  const source = readFileSync(fileURLToPath(new URL("../src/addon.cc", import.meta.url)), "utf8");
  const parentMutation = source.match(/constexpr DWORD kWindowsMutationParentAccess =([\s\S]*?);/)?.[1] ?? "";
  const directoryMutation = source.match(/constexpr ACCESS_MASK kWindowsDirectoryMutationAccess =([\s\S]*?);/)?.[1] ?? "";
  for (const access of [parentMutation, directoryMutation]) {
    assert.match(access, /READ_CONTROL/);
    assert.match(access, /WRITE_DAC/);
    assert.match(access, /WRITE_OWNER/);
  }
  const unresolvedSidOffset = source.indexOf("if (lookup_error == ERROR_NONE_MAPPED");
  assert.notEqual(unresolvedSidOffset, -1);
  const unresolvedSidEnd = source.indexOf("}", unresolvedSidOffset);
  const unresolvedSidBranch = source.slice(unresolvedSidOffset, unresolvedSidEnd);
  assert.match(unresolvedSidBranch, /valid = false/);
  assert.match(unresolvedSidBranch, /break/);
  assert.doesNotMatch(unresolvedSidBranch, /continue/);
  assert.match(source, /napi_create_uint32\(env, 0, &value\)/);
  assert.match(source, /bool PrincipalGroups\(uid_t principal/);
  assert.match(source, /ACL_GROUP_OBJ/);
  assert.match(source, /ACL_OTHER/);
  assert.match(source, /writable_group_class/);
  assert.match(source, /group_object_bits & S_IWUSR/);
  assert.match(source, /named_group_bits & S_IWUSR/);
  assert.match(source, /other_bits & S_IWUSR/);
  assert.match(source, /AT_EMPTY_PATH/);
  assert.match(source, /bool VerifyNoGroupMutationAcl\(HANDLE handle\)/);
  assert.match(source, /ConvertStringSidToSidW\(L"S-1-5-18", &configured_system_sid\)/);
  assert.match(source, /const bool is_configured_system_sid = EqualSid\(sid, configured_system_sid\)/);
  assert.match(source, /!is_configured_system_sid &&/);
  assert.match(source, /bool VerifyWindowsNamedIdentity\(HANDLE parent/);
  assert.match(source, /published_info\.nFileIndexHigh == temporary_info\.nFileIndexHigh/);
  assert.match(source, /source_absent/);
});
