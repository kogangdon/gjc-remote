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
    const destinationIdentity = await addon.read_identity(destination);
    assert.equal(destinationIdentity.owner, roles[0], "native identity proves authority file ownership by M");
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
    const parentHandleIdentity = await addon.read_handle_identity(parentHandle);
    assert.equal(parentHandleIdentity.owner, roles[0], "retained parent identity proves authority parent ownership by M");
    assert.deepEqual(Buffer.from(await addon.read_handle_bytes(objectHandle)), initial);
    const objectHandleIdentity = await addon.read_handle_identity(objectHandle);
    assert.equal(objectHandleIdentity.owner, roles[0], "retained object identity proves authority file ownership by M");

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
    let symlinkUnavailable = false;
    try {
      symlinkSync(realParent, linkedParent);
    } catch (error) {
      if (error?.code === "EPERM" || error?.code === "EACCES") {
        symlinkUnavailable = true;
      } else {
        throw error;
      }
    }
    if (symlinkUnavailable) {
      t.diagnostic(
        "Windows reparse/symlink traversal rejection is UNPROVEN in this run: " +
          "the current non-elevated principal lacks SeCreateSymbolicLinkPrivilege " +
          "and Developer Mode is not enabled, so symlinkSync(EPERM/EACCES) could not " +
          "create the linked-parent fixture. All other no-follow, ACL, replacement, " +
          "and durability assertions in this test still ran and passed.",
      );
    } else {
      const substituted = join(linkedParent, "nested", "authority.json");
      assert.throws(() => addon.open_verified_parent(substituted), /verified parent/);
      assert.throws(() => addon.open_verified_parent_handle(substituted), /verified parent handle/);
    }

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
  const parent = join(root, "acl-parent");
  try {
    await writeFile(target, Buffer.from("acl-group-other"));
    await mkdir(parent);
    const principal = `uid:${candidate[2]}`;

    // A readable ACL_OTHER remains a valid read proof, but any broad write bit
    // invalidates the mutation proof even when this principal is not in the group.
    await chmod(target, 0o644);
    assert.equal(await addon.principal_access_check(target, "uid", principal, "read"), true);
    assert.equal(await addon.principal_access_check(target, "uid", principal, "write"), false);
    await chmod(target, 0o666);
    assert.equal(await addon.principal_access_check(target, "uid", principal, "read"), true);
    assert.equal(await addon.principal_access_check(target, "uid", principal, "write"), false);

    // Named ACL users with write permission are not valid mutation proofs,
    // including a foreign principal that otherwise matches the ACL entry.
    await chmod(target, 0o644);
    try {
      await execFile("setfacl", ["-m", `u:${candidate[2]}:rw`, target]);
      assert.equal(await addon.principal_access_check(target, "uid", principal, "write"), false);

      // A named ACL_GROUP is likewise rejected for mutation regardless of
      // whether the probed principal happens to match that group.
      await execFile("setfacl", ["-m", `g:${currentGid ?? candidate[3]}:rw`, target]);
      assert.equal(await addon.principal_access_check(target, "uid", principal, "write"), false);
      await execFile("setfacl", ["-m", `u:${candidate[2]}:rwx`, parent]);
      assert.equal(await addon.principal_access_check(parent, "uid", principal, "write"), false);
    } catch (error) {
      if (error?.code !== "ENOENT" && !/not supported|operation not permitted/i.test(error?.stderr ?? "")) throw error;
    }
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});
test("POSIX named ACL groups match only principals that belong to each GID", async (t) => {
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
  const users = readFileSync("/etc/passwd", "utf8").split("\n")
    .map((line) => line.split(":"))
    .filter((fields) => fields.length > 3 && fields[0] && /^\d+$/.test(fields[2]) && /^\d+$/.test(fields[3]));
  let matching = null;
  let nonMatching = null;
  for (const fields of users) {
    const uid = Number(fields[2]);
    const gid = Number(fields[3]);
    if (uid === currentUid) continue;
    let groups;
    try {
      const result = await execFile("id", ["-G", fields[0]]);
      groups = new Set(result.stdout.trim().split(/\s+/).filter(Boolean).map(Number));
    } catch {
      continue;
    }
    groups.add(gid);
    if (matching === null) {
      matching = { uid, gid };
      continue;
    }
    if (uid !== matching.uid && !groups.has(matching.gid)) {
      nonMatching = { uid, gid };
      break;
    }
  }
  if (!matching || !nonMatching) {
    t.skip("no distinct local POSIX principals with separate group membership are available");
    return;
  }

  const root = await mkdtemp(join(tmpdir(), "gjc-native-named-group-"));
  const target = join(root, "named-group.txt");
  try {
    await writeFile(target, Buffer.from("named-group"));
    await chmod(target, 0o600);
    try {
      await execFile("setfacl", ["-m", `g:${matching.gid}:r--`, target]);
    } catch (error) {
      if (error?.code === "ENOENT" || /not supported|operation not permitted/i.test(error?.stderr ?? "")) {
        t.skip("setfacl or filesystem ACL support is unavailable");
        return;
      }
      throw error;
    }

    assert.equal(
      await addon.principal_access_check(target, "uid", `uid:${matching.uid}`, "read"),
      true,
      "a principal belonging to the named ACL group receives that group's read permission",
    );
    assert.equal(
      await addon.principal_access_check(target, "uid", `uid:${nonMatching.uid}`, "read"),
      false,
      "a principal outside the named ACL group does not receive its read permission",
    );
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
  assert.match(source, /HANDLE h = OpenNoFollowDirectory\(parent\.u8string\(\), READ_CONTROL \| FILE_READ_ATTRIBUTES\);/);
  assert.match(source, /HANDLE h = OpenNoFollowObject\(path, READ_CONTROL \| FILE_READ_ATTRIBUTES\);/);
  assert.match(source, /value->handle = OpenNoFollowDirectory\(value->path, READ_CONTROL \| FILE_READ_ATTRIBUTES\);/);
  const identitySourceStart = source.indexOf("void SetIdentity(napi_env env, napi_value result, HANDLE handle)");
  const identitySourceEnd = source.indexOf("#else", identitySourceStart);
  const identitySource = source.slice(identitySourceStart, identitySourceEnd);
  assert.match(identitySource, /GetFileInformationByHandle\(handle, &info\)/);
  assert.match(identitySource, /GetSecurityInfo\(handle, SE_FILE_OBJECT, OWNER_SECURITY_INFORMATION/);
  const windowsPathStart = source.indexOf("HANDLE OpenWindowsPathNoFollow");
  const windowsPathEnd = source.indexOf("HANDLE OpenNoFollow(", windowsPathStart);
  const windowsPath = source.slice(windowsPathStart, windowsPathEnd);
  assert.match(source, /FILE_FLAG_OPEN_REPARSE_POINT/);
  assert.match(source, /VerifyWindowsHandle\(handle, expected_type\)/);
  assert.match(windowsPath, /final \? expected_type : VerifiedObjectType::Directory/);
  assert.match(windowsPath, /parts\.components\.empty\(\) \? access : kWindowsTraversalAccess/);
  const retainedObjectStart = source.indexOf("napi_value OpenVerifiedObjectHandle");
  const retainedObjectEnd = source.indexOf("napi_value ReadHandleBytes", retainedObjectStart);
  assert.match(source.slice(retainedObjectStart, retainedObjectEnd),
    /GENERIC_READ \| GENERIC_WRITE \| READ_CONTROL \| DELETE/);
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
  const noGroupSourceStart = source.indexOf("bool VerifyNoGroupMutationAcl(HANDLE");
  const noGroupSourceEnd = source.indexOf("HANDLE CreateProtectedFileNoFollow", noGroupSourceStart);
  const noGroupSource = source.slice(noGroupSourceStart, noGroupSourceEnd);
  assert.match(noGroupSource, /kForeignMutationRights/);
  assert.match(noGroupSource, /EqualSid\(owner, sid\)/);
  assert.match(source, /foreign_named_user_mutation/);
  assert.match(noGroupSource, /WRITE_DAC/);
  assert.match(noGroupSource, /WRITE_OWNER/);
  const exactRoleAclStart = source.indexOf("bool VerifyExactRoleAcl(HANDLE");
  const exactRoleAclEnd = source.indexOf("bool ApplyExactRoleAcl(HANDLE", exactRoleAclStart);
  const exactRoleAcl = source.slice(exactRoleAclStart, exactRoleAclEnd);
  assert.match(exactRoleAcl, /header->AceType != ACCESS_ALLOWED_ACE_TYPE \|\| header->AceFlags != 0/);
  const noGroupAclStart = source.indexOf("bool VerifyNoGroupMutationAcl(HANDLE");
  const noGroupAclEnd = source.indexOf("HANDLE CreateProtectedFileNoFollow", noGroupAclStart);
  const noGroupAcl = source.slice(noGroupAclStart, noGroupAclEnd);
  assert.match(noGroupAcl, /header->AceType != ACCESS_ALLOWED_ACE_TYPE \|\| header->AceFlags != 0/);
  assert.match(source, /struct NamedGroupPermission \{ gid_t gid; mode_t bits; \}/);
  assert.match(source, /named_groups\.push_back\(\{\*qualifier, group_bits\}\)/);
  assert.match(source, /effective_group \|= named\.bits/);
});
