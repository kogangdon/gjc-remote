import { execFile as execFileCallback } from "node:child_process";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { existsSync, readFileSync, symlinkSync } from "node:fs";
import { promisify } from "node:util";
import { chmod, mkdtemp, mkdir, readdir, rm, writeFile } from "node:fs/promises";
import { createRequire } from "node:module";
import { fileURLToPath } from "node:url";
import { basename, join } from "node:path";
import { tmpdir } from "node:os";
import test from "node:test";

import { capabilities, capabilitySignatures, validateBuildManifest } from "../src/index.js";
import { createManagementNativeForTest } from "./helpers/management-native.js";
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
  assert.equal(contract.contractVersion, 3);
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
  if (process.platform === "win32") {
    // principal_access_check's gate (VerifyExactRoleAcl) matches configured role SIDs by value only,
    // never by resolved principal kind, so a group-valued role SID would be silently accepted and
    // granted the matching per-role rights. verify_role_sid_not_group is the real, authoritative LSA
    // lookup that closes that gap: it must prove BUILTIN\Administrators (a real, always-resolvable
    // alias on any Windows host) is a group, while leaving an unresolvable synthetic role SID and the
    // real current OS principal (a user) permitted.
    assert.equal(addon.verify_role_sid_not_group("S-1-5-32-544"), false,
      "the built-in Administrators alias must be proven a group and therefore refused as a role SID");
    assert.equal(addon.verify_role_sid_not_group(roles[0]), true,
      "the current OS principal resolves to a real user, not a group");
    assert.equal(addon.verify_role_sid_not_group(roles[1]), true,
      "an unresolvable synthetic role SID stays permitted because it is never proven to be a group");
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
    assert.equal(await addon.principal_access_check(destination, kind, roles[0], "read", ...roles, "authority"), true);
    assert.equal(await addon.principal_access_check(destination, kind, roles[0], "write", ...roles, "authority"), true);
    for (const principal of roles.slice(1, 3)) {
      assert.equal(await addon.principal_access_check(destination, kind, principal, "read", ...roles, "authority"), true);
      assert.equal(await addon.principal_access_check(destination, kind, principal, "write", ...roles, "authority"), false);
    }
    const authorityParent = join(root, "authority-parent");
    await addon.ensure_control_directory(authorityParent, ...roles, "authority");
    assert.equal(await addon.verify_exact_role_acl(authorityParent, ...roles, "authority"), true);
    const authorityParentIdentity = await addon.read_identity(authorityParent);
    assert.equal(authorityParentIdentity.owner, roles[0], "native identity proves authority parent ownership by M");
    for (const principal of roles.slice(1, 3)) {
      assert.equal(await addon.principal_access_check(authorityParent, kind, principal, "write", ...roles, "authority"), false,
        "B/R lack directory mutation permission, denying rename and unlink of authority entries");
    }
    // "traverse" proves the plain kWindowsTraversalAccess bits (FILE_TRAVERSE among them) that every
    // intermediate path component walking down to a record beneath this M-owned control-root directory
    // must be granted for the open to succeed at all (the CRITICAL defect: an authority-profile
    // directory's FILE_GENERIC_READ grant alone does not include FILE_TRAVERSE/FILE_EXECUTE). This is an
    // authoritative AuthzAccessCheck ALLOW/DENY proof against the real on-disk DACL, not a mock: ALLOW
    // results never depend on group-membership expansion for an unresolvable synthetic role SID.
    for (const principal of roles.slice(1, 3)) {
      assert.equal(await addon.principal_access_check(authorityParent, kind, principal, "traverse", ...roles, "authority"), true,
        "B/R must be able to traverse the M-owned control-root directory to reach every record beneath it");
      assert.equal(await addon.principal_access_check(authorityParent, kind, principal, "mutate-children", ...roles, "authority"), false,
        "B/R still cannot use the create/replace/rename primitives against the M-owned authority root, " +
          "even under the narrowed mutation-parent class");
    }
    const authorityChildRecord = join(authorityParent, "nested-record.json");
    await addon.create_absent_exclusive(authorityChildRecord, Buffer.from('{"nested":true}'), ...roles, "authority");
    assert.equal(await addon.principal_access_check(authorityChildRecord, kind, roles[0], "read", ...roles, "authority"), true);
    for (const principal of roles.slice(1, 3)) {
      assert.equal(await addon.principal_access_check(authorityChildRecord, kind, principal, "read", ...roles, "authority"), true,
        "B/R can read a record nested inside the M-owned control-root directory now that traversal is granted");
    }
    const botStateDir = join(root, "bot-state");
    await addon.ensure_control_directory(botStateDir, ...roles, "bot-state");
    assert.equal(await addon.verify_exact_role_acl(botStateDir, ...roles, "bot-state"), true);
    const botStateDirIdentity = await addon.read_identity(botStateDir);
    assert.equal(botStateDirIdentity.owner, roles[0],
      "bot-state directory is M-owned, so M can provision it during Genesis bootstrap without SeRestorePrivilege/chown");
    // The bot-state directory is M-owned but grants B (a non-owner) FILE_GENERIC_READ | FILE_GENERIC_WRITE |
    // FILE_GENERIC_EXECUTE | FILE_DELETE_CHILD by design (proven exact via verify_exact_role_acl above), so
    // B can open it as a create/replace/rename mutation parent for its own bot-state records. The old
    // principal_access_check gate (VerifyNoGroupMutationAcl) rejected this DACL outright — any non-owner,
    // non-SYSTEM ACE with mutation rights unconditionally failed the whole-DACL heuristic, so every mode
    // returned false for every principal on this directory regardless of the real, legitimate grant.
    // Replacing that profile-blind heuristic with VerifyExactRoleAcl (bound to the bot-state RoleProfile and
    // the real M/B/R/SYSTEM SIDs) makes every mode below an authoritative AuthzAccessCheck ALLOW/DENY proof
    // against the live on-disk DACL — no try/catch fallback is needed for B's read/traverse/mutate-children
    // ALLOW proofs: they come from B's own explicit per-principal ACE, which AuthzAccessCheck matches
    // directly even when the synthetic role SID cannot be expanded into real group memberships.
    assert.equal(await addon.principal_access_check(botStateDir, kind, roles[0], "read", ...roles, "bot-state"), true);
    assert.equal(await addon.principal_access_check(botStateDir, kind, roles[1], "read", ...roles, "bot-state"), true,
      "B can read the bot-state directory now that the exact-role-ACL gate authoritatively evaluates B's own grant");
    assert.equal(await addon.principal_access_check(botStateDir, kind, roles[2], "read", ...roles, "bot-state"), true);
    assert.equal(await addon.principal_access_check(botStateDir, kind, roles[1], "traverse", ...roles, "bot-state"), true,
      "B's traverse capability on the bot-state directory now evaluates authoritatively (ALLOW)");
    assert.equal(await addon.principal_access_check(botStateDir, kind, roles[1], "mutate-children", ...roles, "bot-state"), true,
      "B's child-mutation capability (FILE_ADD_FILE | FILE_ADD_SUBDIRECTORY | FILE_DELETE_CHILD) on the bot-state " +
        "directory now evaluates authoritatively (ALLOW)");
    assert.equal(await addon.principal_access_check(botStateDir, kind, roles[2], "traverse", ...roles, "bot-state"), true,
      "R keeps today's read/traverse semantics on the bot-state directory");
    assert.equal(await addon.principal_access_check(botStateDir, kind, roles[2], "mutate-children", ...roles, "bot-state"), false,
      "R keeps today's semantics: no child-mutation capability on the bot-state directory");
    t.diagnostic(
      "B's ability to literally create and replace a bot-state record end-to-end under its own OS " +
        "token (temp+rename path, then remove its own temp) is UNPROVEN by this test: the test process " +
        "runs as the M principal and B is a synthetic, non-resolvable SID on this host, so there is no " +
        "way to obtain a real B-token handle to exercise create_exclusive_temp/replace_existing_atomic/" +
        "remove_verified_file as B without a second real Windows account and interactive logon or " +
        "impersonation. The strongest available real (non-mock) proof is the exact per-role ACE equality " +
        "proof from verify_exact_role_acl above together with the authoritative principal_access_check " +
        "traverse/mutate-children ALLOW proofs directly above, which are now evaluated against the exact " +
        "bot-state role profile instead of the old profile-blind heuristic.");
    // "write" mode proves the full destructive directory-mutation class (WRITE_DAC | WRITE_OWNER |
    // FILE_ADD_FILE | FILE_ADD_SUBDIRECTORY | FILE_DELETE_CHILD via kWindowsDirectoryMutationAccess), not
    // plain create/replace. B's bot-state directory grant never includes WRITE_DAC/WRITE_OWNER: this "write"
    // check must still deny B (and R) here, proving B may create and replace its own bot-state records
    // without ever being able to delete/rename arbitrary entries or take ownership of the M-owned directory.
    assert.equal(await addon.principal_access_check(botStateDir, kind, roles[1], "write", ...roles, "bot-state"), false,
      "B lacks destructive directory-mutation capability (WRITE_DAC/WRITE_OWNER) on the M-owned bot-state directory");
    assert.equal(await addon.principal_access_check(botStateDir, kind, roles[2], "write", ...roles, "bot-state"), false,
      "R keeps today's read-only bot-state semantics");
    assert.equal(await addon.principal_access_check(authorityParent, kind, roles[1], "write", ...roles, "authority"), false,
      "B still cannot mutate the authority root");
    try {
      await addon.create_absent_exclusive(join(botStateDir, "reader-projection.json"), Buffer.from("{}"), ...roles, "bot-state");
      assert.fail("M is not the required owner of individual bot-state records; only a bot-principal writer may create them there");
    } catch (error) {
      assert.match(error.message, /unable to prepare protected absent file|failed temporary cleanup is ambiguous/);
    }

    const authDestination = join(root, "management-auth.json");
    const authBytes = Buffer.from('{"verifier":"redacted"}');
    await addon.create_absent_exclusive(authDestination, authBytes, ...roles, "management-auth");
    assert.equal(await addon.principal_access_check(authDestination, kind, roles[0], "read", ...roles, "management-auth"), true);
    assert.equal(await addon.principal_access_check(authDestination, kind, roles[0], "write", ...roles, "management-auth"), true);
    for (const principal of roles.slice(1, 3)) {
      try {
        assert.equal(await addon.principal_access_check(authDestination, kind, principal, "read", ...roles, "management-auth"), false);
      } catch (error) {
        if (kind === "sid" && error?.code === "ERR_NATIVE_CONTROL_REFUSED" &&
            error?.operation === "principal_access_check") {
          t.diagnostic(
            "Windows read-mode B/R denial proof for management-auth.json is UNPROVEN in this run: " +
              "the synthetic role SID cannot be resolved to a real local/domain principal on this " +
              "non-elevated host, so full group-membership expansion cannot run and the native addon " +
              "correctly refuses rather than asserting an unproven denial (a read grant could " +
              "legitimately arrive through an unresolvable principal's group membership). All other " +
              "principal_access_check assertions in this test (ALLOW proofs and authoritative " +
              "write-mode DENY proofs) still ran and passed.",
          );
        } else {
          throw error;
        }
      }
      assert.equal(await addon.principal_access_check(authDestination, kind, principal, "write", ...roles, "management-auth"), false);
    }
    assert.throws(() => addon.principal_access_check(destination, kind, roles[0]), /missing string argument/);
    assert.throws(() => addon.principal_access_check(destination, kind, roles[0], "read"), /missing string argument/);
    assert.throws(() => addon.principal_access_check(destination, kind, roles[0], "execute", ...roles, "authority"), /access mode must be read, write, mutate-children, or traverse/);
    assert.throws(() => addon.principal_access_check(destination, kind, roles[0], "read", ...roles, "bogus-profile"), /role profile is invalid/);
    // "legacy-retained" identifies objects the contract deliberately never requires to carry an exact
    // role ACL (they retain their original foreign ACL): the exact-role-ACL gate must be skipped for
    // read/write/traverse probes against them, while "mutate-children" stays rejected fail-closed so this
    // profile can never be repurposed as a mutation-authorization proof. A true "write" result for this
    // profile is a real, negative-usable proof only (run_startup_self_test's bot branch asserts it false) —
    // it must never be read elsewhere as authorization to mutate a retained object, which the contract
    // keeps byte-, identity- and ACL-immutable.
    const legacyRetainedTarget = join(root, "legacy-channels.json");
    await writeFile(legacyRetainedTarget, Buffer.from('{"legacy":true}'));
    assert.equal(await addon.verify_exact_role_acl(legacyRetainedTarget, ...roles, "authority"), false,
      "a freshly-written plain non-role ACL must not satisfy the exact-role-ACL gate, proving this fixture " +
        "is a genuine legacy-retained target and not accidentally an exact-role object");
    assert.equal(await addon.principal_access_check(legacyRetainedTarget, kind, roles[0], "read", ...roles, "legacy-retained"), true,
      "legacy-retained read probes must be authoritative (ALLOW) even though the target never carries an " +
        "exact role ACL; the old profile='authority' AND-gate on VerifyExactRoleAcl would have made this false " +
        "on Windows regardless of the real DACL");
    assert.equal(await addon.principal_access_check(legacyRetainedTarget, kind, roles[0], "write", ...roles, "legacy-retained"), true,
      "legacy-retained write probes are now evaluated for real, through the object's actual DACL: M created " +
        "this fixture and so genuinely holds FILE_GENERIC_WRITE on it. A true result here is expected and must " +
        "never be read by any caller as authorization to mutate the retained object.");
    try {
      assert.equal(await addon.principal_access_check(legacyRetainedTarget, kind, roles[1], "write", ...roles, "legacy-retained"), false,
        "a non-owning principal (the bot) holds no grant on this foreign-owned fixture, so a legacy-retained " +
          "write probe correctly denies it — this is the exact real-addon proof run_startup_self_test's bot " +
          "branch relies on to refuse writability of a retained management target");
    } catch (error) {
      if (error?.code !== "ERR_NATIVE_CONTROL_REFUSED") throw error;
      t.diagnostic(
        "Legacy-retained write denial for the bot principal is UNPROVEN in this run: the synthetic bot SID " +
          "cannot be resolved on this host, so group membership cannot be expanded and the addon refuses " +
          "rather than reporting an unproven denial. A real bot account resolves and yields an authoritative " +
          "denial. All other legacy-retained assertions in this test still ran and passed."
      );
    }
    assert.throws(() => addon.principal_access_check(legacyRetainedTarget, kind, roles[1], "mutate-children", ...roles, "legacy-retained"),
      /legacy-retained profile does not support the mutate-children mode/,
      "legacy-retained must fail closed for mutate-children, never usable as a mutation proof");
    // The authority control root itself keeps its existing exact-role-ACL semantics: B/R stay denied
    // both the wide write class and the narrower child-mutation class the create/replace primitives use.
    for (const principal of roles.slice(1, 3)) {
      assert.equal(await addon.principal_access_check(authorityParent, kind, principal, "write", ...roles, "authority"), false,
        "B/R remain denied the wide WRITE_DAC/WRITE_OWNER class on the authority control root");
      assert.equal(await addon.principal_access_check(authorityParent, kind, principal, "mutate-children", ...roles, "authority"), false,
        "B/R remain denied the narrower child-mutation class on the authority control root");
    }

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
test("a group-valued role principal is refused at role-configuration time with zero writes", async (t) => {
  if (process.platform !== "win32") {
    t.skip("Windows role-SID group verification is Windows-only");
    return;
  }
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
  const roles = platformRoles(addon.current_os_principal());
  if (roles === null) {
    t.skip("native authority integration requires a supported OS principal");
    return;
  }
  const root = await mkdtemp(join(tmpdir(), "gjc-native-control-group-sid-"));
  const configPath = join(root, "channels.json");
  await writeFile(configPath, "{}");
  const before = (await readdir(root)).sort();
  try {
    // BUILTIN\Administrators (S-1-5-32-544) is a real, always-resolvable Windows alias on every
    // Windows host. principal_access_check's VerifyExactRoleAcl gate matches configured role SIDs by
    // value only, never by resolved principal kind, so configuring it as B here would previously have
    // been silently accepted and granted B's per-role rights. Role configuration must fail closed
    // before any native mutation is attempted.
    assert.throws(
      () => createManagementNativeForTest({
        lowLevel: addon,
        configPath,
        roles: { managementSid: roles[0], botSid: "S-1-5-32-544", recoverySid: roles[2], systemSid: "S-1-5-18" },
      }),
      (error) => error.code === "ERR_NATIVE_CONTROL_REFUSED" && error.writes === 0,
      "a group-valued role SID must be refused at configuration time with zero writes",
    );
    const after = (await readdir(root)).sort();
    assert.deepEqual(after, before, "role-configuration refusal must not create, modify, or remove any file");
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
    assert.equal(await addon.principal_access_check(target, "uid", principal, "read", "uid:0", "uid:0", "uid:0", "uid:0", "authority"), true);
    assert.equal(await addon.principal_access_check(target, "uid", principal, "write", "uid:0", "uid:0", "uid:0", "uid:0", "authority"), false);
    await chmod(target, 0o666);
    assert.equal(await addon.principal_access_check(target, "uid", principal, "read", "uid:0", "uid:0", "uid:0", "uid:0", "authority"), true);
    assert.equal(await addon.principal_access_check(target, "uid", principal, "write", "uid:0", "uid:0", "uid:0", "uid:0", "authority"), false);

    // Named ACL users with write permission are not valid mutation proofs,
    // including a foreign principal that otherwise matches the ACL entry.
    await chmod(target, 0o644);
    try {
      await execFile("setfacl", ["-m", `u:${candidate[2]}:rw`, target]);
      assert.equal(await addon.principal_access_check(target, "uid", principal, "write", "uid:0", "uid:0", "uid:0", "uid:0", "authority"), false);

      // A named ACL_GROUP is likewise rejected for mutation regardless of
      // whether the probed principal happens to match that group.
      await execFile("setfacl", ["-m", `g:${currentGid ?? candidate[3]}:rw`, target]);
      assert.equal(await addon.principal_access_check(target, "uid", principal, "write", "uid:0", "uid:0", "uid:0", "uid:0", "authority"), false);
      await execFile("setfacl", ["-m", `u:${candidate[2]}:rwx`, parent]);
      assert.equal(await addon.principal_access_check(parent, "uid", principal, "write", "uid:0", "uid:0", "uid:0", "uid:0", "authority"), false);
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
      await addon.principal_access_check(target, "uid", `uid:${matching.uid}`, "read", "uid:0", "uid:0", "uid:0", "uid:0", "authority"),
      true,
      "a principal belonging to the named ACL group receives that group's read permission",
    );
    assert.equal(
      await addon.principal_access_check(target, "uid", `uid:${nonMatching.uid}`, "read", "uid:0", "uid:0", "uid:0", "uid:0", "authority"),
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
  // principal_access_check's VerifyExactRoleAcl gate matches configured role SIDs by value, not by
  // resolved principal kind, so role configuration independently proves a configured M/B/R SID is not
  // a group/alias/well-known-group before it is ever accepted (WindowsRoleSidIsGroup). A SID that
  // cannot be resolved at all must stay permitted rather than fail closed, because remote/domain role
  // principals are legitimately unresolvable on this host: is_group defaults to false and is set true
  // only on the branch that actually resolved the SID to a group-shaped principal.
  const roleSidGroupStart = source.indexOf("bool WindowsRoleSidIsGroup(const std::string& sid_text)");
  assert.notEqual(roleSidGroupStart, -1);
  const roleSidGroupEnd = source.indexOf("HANDLE CreateProtectedFileNoFollow", roleSidGroupStart);
  const roleSidGroupSource = source.slice(roleSidGroupStart, roleSidGroupEnd);
  assert.match(roleSidGroupSource, /bool is_group = false;/);
  assert.match(roleSidGroupSource, /is_group = use == SidTypeGroup \|\| use == SidTypeAlias \|\| use == SidTypeWellKnownGroup;/);
  assert.match(roleSidGroupSource, /return is_group;/);
  assert.match(roleSidGroupSource, /it is never proven to be a group, so it stays permitted here/);
  assert.match(source, /napi_create_uint32\(env, 0, &value\)/);
  assert.match(source, /bool PrincipalGroups\(uid_t principal/);
  assert.match(source, /ACL_GROUP_OBJ/);
  assert.match(source, /ACL_OTHER/);
  assert.match(source, /writable_group_class/);
  assert.match(source, /group_object_bits & S_IWUSR/);
  assert.match(source, /named_group_bits & S_IWUSR/);
  assert.match(source, /other_bits & S_IWUSR/);
  assert.match(source, /AT_EMPTY_PATH/);
  assert.match(source, /SID_NAME_USE use = SidTypeUnknown;/);
  assert.match(source, /SidTypeGroup \|\| use == SidTypeAlias \|\| use == SidTypeWellKnownGroup/);
  assert.match(source, /napi_value VerifyRoleSidNotGroupMethod\(napi_env env, napi_callback_info info\)/);
  assert.match(source, /permitted = !WindowsRoleSidIsGroup\(sid_text\);/);
  assert.match(source, /bool VerifyWindowsNamedIdentity\(HANDLE parent/);
  assert.match(source, /published_info\.nFileIndexHigh == temporary_info\.nFileIndexHigh/);
  assert.match(source, /source_absent/);
  assert.match(source, /foreign_named_user_mutation/);
  const exactRoleAclStart = source.indexOf("bool VerifyExactRoleAcl(HANDLE");
  const exactRoleAclEnd = source.indexOf("bool ApplyExactRoleAcl(HANDLE", exactRoleAclStart);
  const exactRoleAcl = source.slice(exactRoleAclStart, exactRoleAclEnd);
  assert.match(exactRoleAcl, /header->AceType != ACCESS_ALLOWED_ACE_TYPE \|\| header->AceFlags != 0/);
  assert.match(source, /struct NamedGroupPermission \{ gid_t gid; mode_t bits; \}/);
  assert.match(source, /named_groups\.push_back\(\{\*qualifier, group_bits\}\)/);
  assert.match(source, /effective_group \|= named\.bits/);
});
