import assert from 'node:assert/strict';
import { execFile as execFileCallback } from 'node:child_process';
import { existsSync, readFileSync } from 'node:fs';
import { lstat } from 'node:fs/promises';
import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';
import test from 'node:test';

import { validateBuildManifest } from '../src/index.js';
import { diagnoseInventoryBootstrapRefusal } from '../test-fixtures/inventory-bootstrap-diagnostic.mjs';

const execFile = promisify(execFileCallback);
const require = createRequire(import.meta.url);
const addonUrl = new URL('../build/Release/native_control.node', import.meta.url);
const manifestUrl = new URL('../build/Release/native-control.manifest.json', import.meta.url);
const packageUrl = new URL('../package.json', import.meta.url);

const WINDOWS_IDENTITY_SCRIPT = String.raw`
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$definition = @'
using System;
using System.Runtime.InteropServices;
using System.Text;
public static class GjcInventoryProvisioningE2E {
  [DllImport("kernel32.dll", EntryPoint = "GetSystemWindowsDirectoryW", CharSet = CharSet.Unicode, ExactSpelling = true, SetLastError = true)]
  public static extern uint GetSystemWindowsDirectory(StringBuilder path, uint size);
}
'@
Add-Type -TypeDefinition $definition -Language CSharp
$buffer = New-Object System.Text.StringBuilder(32768)
$length = [GjcInventoryProvisioningE2E]::GetSystemWindowsDirectory($buffer, [uint32]$buffer.Capacity)
if ($length -eq 0 -or $length -ge $buffer.Capacity) { throw 'GetSystemWindowsDirectoryW failed' }
$systemDirectory = $buffer.ToString()
$driveRoot = [System.IO.Path]::GetPathRoot($systemDirectory)
$currentSid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$users = @(
  Get-LocalUser | ForEach-Object {
    [pscustomobject]@{
      name = [string]$_.Name
      sid = [string]$_.SID.Value
      enabled = [bool]$_.Enabled
    }
  }
)
$result = [ordered]@{
  systemDirectory = $systemDirectory
  driveRoot = $driveRoot
  currentSid = $currentSid
  users = [object[]]$users
}
[Console]::Out.WriteLine((ConvertTo-Json -InputObject $result -Depth 6 -Compress))
`;

const ACL_SNAPSHOT_SCRIPT = String.raw`
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$sections = [System.Security.AccessControl.AccessControlSections]::Owner -bor
  [System.Security.AccessControl.AccessControlSections]::Group -bor
  [System.Security.AccessControl.AccessControlSections]::Access
$specs = [System.Collections.Generic.List[object]]::new()
$specs.Add([pscustomobject]@{ name = 'parent'; path = $env:GJC_REMOTE_INVENTORY_E2E_PARENT; checkAces = $false }) | Out-Null
if ($env:GJC_REMOTE_INVENTORY_E2E_BASES -eq '1') {
  $specs.Add([pscustomobject]@{ name = 'inventory'; path = $env:GJC_REMOTE_INVENTORY_E2E_INVENTORY; checkAces = $true }) | Out-Null
  $specs.Add([pscustomobject]@{ name = 'reader'; path = $env:GJC_REMOTE_INVENTORY_E2E_READER; checkAces = $true }) | Out-Null
}
$entries = [System.Collections.Generic.List[object]]::new()
foreach ($spec in $specs) {
  $attributes = [System.IO.File]::GetAttributes($spec.path)
  $isDirectory = ($attributes -band [System.IO.FileAttributes]::Directory) -ne 0
  $isReparsePoint = ($attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0
  if (-not $isDirectory -or $isReparsePoint) { throw "Expected a real directory at $($spec.path)" }
  $acl = Get-Acl -LiteralPath $spec.path
  $ownerSid = $acl.GetOwner([System.Security.Principal.SecurityIdentifier]).Value
  $entry = [ordered]@{
    name = $spec.name
    path = $spec.path
    ownerSid = $ownerSid
    daclProtected = [bool]$acl.AreAccessRulesProtected
    sddl = $acl.GetSecurityDescriptorSddlForm($sections)
    isDirectory = $isDirectory
    isReparsePoint = $isReparsePoint
  }
  if ($spec.checkAces) {
    $descriptor = [System.Security.AccessControl.RawSecurityDescriptor]::new(
      $acl.GetSecurityDescriptorSddlForm([System.Security.AccessControl.AccessControlSections]::Access)
    )
    $aces = [System.Collections.Generic.List[object]]::new()
    foreach ($ace in $descriptor.DiscretionaryAcl) {
      $knownAce = $ace -as [System.Security.AccessControl.KnownAce]
      if ($null -eq $knownAce) { throw "Unexpected non-user ACL entry at $($spec.path)" }
      $aces.Add([pscustomobject]@{
        sid = $knownAce.SecurityIdentifier.Value
        mask = ('0x{0:X8}' -f [uint32]$knownAce.AccessMask)
        type = $ace.AceType.ToString()
        flags = [int]$ace.AceFlags
      }) | Out-Null
    }
    $entry['aces'] = [object[]]$aces.ToArray()
  }
  $entries.Add([pscustomobject]$entry) | Out-Null
}
[Console]::Out.WriteLine((ConvertTo-Json -InputObject ([object[]]$entries.ToArray()) -Depth 8 -Compress))
`;

async function powershellJson(script, extraEnv = {}) {
  const { stdout } = await execFile('powershell.exe', [
    '-NoLogo', '-NoProfile', '-NonInteractive', '-Command', script,
  ], {
    encoding: 'utf8',
    timeout: 30_000,
    maxBuffer: 1024 * 1024,
    windowsHide: true,
    env: { ...process.env, ...extraEnv },
  });
  assert.notEqual(stdout.trim(), '', 'PowerShell prerequisite or observation must return JSON');
  return JSON.parse(stdout.trim());
}

function localRoleIdentities(users, currentSid) {
  assert.ok(Array.isArray(users), 'Get-LocalUser must return local account SID records');
  const bySid = new Map();
  for (const user of users) {
    assert.equal(typeof user?.name, 'string');
    assert.match(user.sid, /^S-1-5-21-(?:[0-9]+-){3}[0-9]+$/,
      'every role account must be an actual machine-local user SID');
    assert.equal(bySid.has(user.sid), false, 'Get-LocalUser must not return duplicate SIDs');
    bySid.set(user.sid, user);
  }
  assert.ok(bySid.has(currentSid), 'the actual current principal must resolve to a Get-LocalUser account');

  const preferredRids = [500, 501, 503];
  const preferredRank = new Map(preferredRids.map((rid, index) => [String(rid), index]));
  const candidates = [...bySid.values()]
    .filter((user) => user.sid !== currentSid)
    .sort((left, right) => {
      const leftRid = left.sid.slice(left.sid.lastIndexOf('-') + 1);
      const rightRid = right.sid.slice(right.sid.lastIndexOf('-') + 1);
      const leftRank = preferredRank.get(leftRid) ?? preferredRids.length;
      const rightRank = preferredRank.get(rightRid) ?? preferredRids.length;
      return leftRank - rightRank || left.sid.localeCompare(right.sid, 'en');
    });
  assert.ok(candidates.length >= 3,
    'three distinct existing local user SIDs besides the management principal are required');

  return {
    management: { kind: 'sid', value: currentSid },
    bot: { kind: 'sid', value: candidates[0].sid },
    recovery: { kind: 'sid', value: candidates[1].sid },
    daemon: { kind: 'sid', value: candidates[2].sid },
    system: { kind: 'sid', value: 'S-1-5-18' },
  };
}

async function assertPathAbsent(path) {
  let stat;
  try {
    stat = await lstat(path);
  } catch (error) {
    if (error?.code === 'ENOENT') return;
    throw error;
  }
  assert.fail(`Refusing to adopt pre-existing canonical gjc-remote root ${path} (${stat.mode.toString(8)})`);
}

function isExpectedWindowsPath(actual, expected) {
  return typeof actual === 'string' &&
    actual.replaceAll('/', '\\').toLowerCase() === expected.replaceAll('/', '\\').toLowerCase();
}

function observeAclSnapshotPaths(containerPath, inventoryBase, readerBase, includeBases) {
  return {
    GJC_REMOTE_INVENTORY_E2E_PARENT: containerPath,
    GJC_REMOTE_INVENTORY_E2E_INVENTORY: inventoryBase,
    GJC_REMOTE_INVENTORY_E2E_READER: readerBase,
    GJC_REMOTE_INVENTORY_E2E_BASES: includeBases ? '1' : '0',
  };
}

function readWitness(native, path) {
  const bytes = native.read_verified_bytes(path);
  assert.ok(bytes !== null && bytes !== undefined, `expected witnessed bytes at ${path}`);
  const retained = Buffer.from(bytes);
  assert.ok(retained.length > 0, `expected non-empty witness bytes at ${path}`);
  return retained;
}

function assertProvisionedAcl(entry, expectedOwner, expectedMasks) {
  assert.equal(entry.isDirectory, true);
  assert.equal(entry.isReparsePoint, false);
  assert.equal(entry.daclProtected, true, `${entry.name} DACL must be protected`);
  assert.equal(entry.ownerSid, expectedOwner, `${entry.name} owner SID`);
  assert.ok(Array.isArray(entry.aces));
  assert.equal(entry.aces.length, 4, `${entry.name} must have exactly four explicit ACEs`);

  const actualMasks = new Map();
  for (const ace of entry.aces) {
    assert.equal(ace.type, 'AccessAllowed', `${entry.name} must contain only allow ACEs`);
    assert.equal(ace.flags, 0, `${entry.name} ACEs must not inherit`);
    assert.equal(actualMasks.has(ace.sid), false, `${entry.name} must not duplicate an ACE principal`);
    actualMasks.set(ace.sid, ace.mask);
  }
  const actualEntries = [...actualMasks].sort(([left], [right]) => left.localeCompare(right, 'en'));
  const expectedEntries = [...expectedMasks].sort(([left], [right]) => left.localeCompare(right, 'en'));
  assert.deepEqual(actualEntries, expectedEntries,
    `${entry.name} must have exact M/D/SYSTEM full and counterpart/recovery read-execute rights, with no bot ACE`);
}

test('opted-in Windows hosted runner provisions fixed native inventory bases and refuses a duplicate', async (t) => {
  if (process.env.GJC_REMOTE_INVENTORY_BASES_E2E !== '1') {
    t.skip('set GJC_REMOTE_INVENTORY_BASES_E2E=1 only on a clean disposable GitHub-hosted Windows runner');
    return;
  }

  assert.equal(process.platform, 'win32', 'the opt-in fixture is Windows-only');
  assert.equal(process.env.GITHUB_ACTIONS, 'true', 'the opt-in fixture requires GitHub Actions');
  assert.equal(process.env.RUNNER_ENVIRONMENT, 'github-hosted', 'the opt-in fixture requires a hosted runner');
  assert.equal(existsSync(addonUrl), true, 'the verified Windows native addon must be built');
  assert.equal(existsSync(manifestUrl), true, 'the native addon build manifest must exist');

  const addonBytes = readFileSync(addonUrl);
  const manifest = JSON.parse(readFileSync(manifestUrl, 'utf8'));
  const packageJson = JSON.parse(readFileSync(packageUrl, 'utf8'));
  assert.equal(packageJson.version, '2.1.0');
  assert.equal(packageJson.nativeControlContract.version, 5);
  assert.equal(packageJson.nativeControlContract.revision, 2);
  assert.equal(validateBuildManifest(manifest, packageJson, addonBytes), true,
    'the built native addon must match the ABI 5/revision 2 contract and package payload');

  const native = require(fileURLToPath(addonUrl));
  const contract = native.native_control_contract();
  assert.equal(contract.contractVersion, 5);
  assert.equal(contract.contractRevision, 2);
  assert.ok(contract.capabilities.includes('provision_inventory_bases'));
  assert.deepEqual(contract.capabilitySignatures.provision_inventory_bases, ['roles']);
  for (const method of ['current_os_principal', 'open_service_root', 'close_service_handle',
    'provision_inventory_bases', 'read_identity', 'read_verified_bytes']) {
    assert.equal(typeof native[method], 'function', `native capability ${method}`);
  }

  const windowsIdentity = await powershellJson(WINDOWS_IDENTITY_SCRIPT);
  assert.match(windowsIdentity.systemDirectory, /^[A-Za-z]:\\/,
    'GetSystemWindowsDirectoryW must return a local Windows system directory');
  assert.match(windowsIdentity.driveRoot, /^[A-Za-z]:\\$/,
    'the operating-system root must be derived from GetSystemWindowsDirectoryW');
  assert.match(windowsIdentity.currentSid, /^S-1-5-21-(?:[0-9]+-){3}[0-9]+$/,
    'PowerShell must resolve the current local user SID');
  const current = native.current_os_principal();
  assert.deepEqual(current, { kind: 'sid', value: windowsIdentity.currentSid },
    'native current_os_principal must match the actual Windows process identity');
  const roles = localRoleIdentities(windowsIdentity.users, current.value);
  for (const role of Object.values(roles)) Object.freeze(role);
  Object.freeze(roles);
  assert.equal(new Set([
    roles.management.value, roles.bot.value, roles.recovery.value, roles.daemon.value,
  ]).size, 4, 'M/B/R/D must be distinct real local user SIDs');

  const driveRoot = windowsIdentity.driveRoot.toUpperCase();
  const containerPath = `${driveRoot}gjc-remote`;
  const controlRootPath = `${containerPath}\\service-control`;
  const inventoryBase = `${containerPath}\\native`;
  const readerBase = `${containerPath}\\native-reader`;
  const platformWitnessPath = `${driveRoot}.gjc-service-platform-container.v1`;
  const platformPendingPath = `${driveRoot}.gjc-service-system-drive-gjc-remote.pending`;
  const controlWitnessPath = `${containerPath}\\.gjc-service-control-root.v1`;

  // Never adopt, inspect as fixture state, or clean up a live canonical root.
  // The root is checked before the only mutating operation below.
  await assertPathAbsent(containerPath);
  await assertPathAbsent(platformWitnessPath);
  await assertPathAbsent(platformPendingPath);

  // This is the existing low-level creator. Its callback contract is
  // { handle, rootBinding, writes }; the opaque handle stays open until all
  // filesystem and witness observations have completed.
  let opened;
  try {
    opened = native.open_service_root('control', roles, 'create-new');
  } catch (error) {
    if (error?.code === 'SERVICE_ACCESS_DENIED' &&
        error?.operation === 'open_service_root' && error?.writes === 0 &&
        error?.ambiguous === false) {
      try {
        const diagnostic = await diagnoseInventoryBootstrapRefusal(roles, driveRoot);
        t.diagnostic(JSON.stringify(diagnostic));
      } catch {
        t.diagnostic('INVENTORY_BOOTSTRAP_DIAGNOSTIC_FAILED');
      }
    }
    throw error;
  }
  const controlHandle = opened?.handle;
  try {
    assert.deepEqual(Object.keys(opened ?? {}).sort(), ['handle', 'rootBinding', 'writes']);
    assert.ok(controlHandle !== null && controlHandle !== undefined);
    assert.ok(Number.isSafeInteger(opened.writes) && opened.writes > 0,
      'create-new must report its actual canonical bootstrap writes');
    const binding = opened.rootBinding;
    assert.deepEqual(Object.keys(binding ?? {}).sort(), [
      'bindingFingerprint', 'directoryIdentities', 'identity', 'rolesFingerprint',
      'rootKind', 'rootNonce', 'rootPath', 'schemaVersion',
    ]);
    assert.equal(binding.schemaVersion, 1);
    assert.equal(binding.rootKind, 'control');
    assert.ok(isExpectedWindowsPath(binding.rootPath, controlRootPath),
      'the root callback must witness the fixed OS-drive service-control root');
    assert.equal(binding.identity.owner, roles.management.value);
    assert.equal(binding.identity.profile, 'service-control-directory');

    const captureParent = async () => {
      const observations = await powershellJson(ACL_SNAPSHOT_SCRIPT,
        observeAclSnapshotPaths(containerPath, inventoryBase, readerBase, false));
      assert.ok(Array.isArray(observations) && observations.length === 1);
      assert.equal(observations[0].name, 'parent');
      return {
        identity: native.read_identity(containerPath),
        controlIdentity: native.read_identity(controlRootPath),
        platformWitness: readWitness(native, platformWitnessPath),
        controlWitness: readWitness(native, controlWitnessPath),
        sddl: observations[0].sddl,
      };
    };

    const beforeProvisioning = await captureParent();
    const receipt = native.provision_inventory_bases(roles);
    assert.deepEqual(Object.keys(receipt ?? {}).sort(), ['inventoryBase', 'readerBase', 'writes']);
    assert.ok(isExpectedWindowsPath(receipt.inventoryBase, inventoryBase),
      'native inventory base must be the OS-drive fixed path');
    assert.ok(isExpectedWindowsPath(receipt.readerBase, readerBase),
      'native reader base must be the OS-drive fixed path');
    assert.equal(receipt.writes, 4, 'provisioning must report exactly four writes');

    const observations = await powershellJson(ACL_SNAPSHOT_SCRIPT,
      observeAclSnapshotPaths(containerPath, inventoryBase, readerBase, true));
    assert.ok(Array.isArray(observations) && observations.length === 3);
    const entries = new Map(observations.map((entry) => [entry.name, entry]));
    assert.deepEqual(new Set(entries.keys()), new Set(['parent', 'inventory', 'reader']));

    const full = '0x001F01FF'; // FILE_ALL_ACCESS
    const readExecute = '0x001200A9'; // FILE_GENERIC_READ | FILE_GENERIC_EXECUTE
    assertProvisionedAcl(entries.get('inventory'), roles.management.value, new Map([
      [roles.management.value, full],
      [roles.system.value, full],
      [roles.daemon.value, readExecute],
      [roles.recovery.value, readExecute],
    ]));
    assertProvisionedAcl(entries.get('reader'), roles.daemon.value, new Map([
      [roles.daemon.value, full],
      [roles.system.value, full],
      [roles.management.value, readExecute],
      [roles.recovery.value, readExecute],
    ]));

    const afterProvisioning = {
      parent: await captureParent(),
      inventoryIdentity: native.read_identity(inventoryBase),
      readerIdentity: native.read_identity(readerBase),
      inventoryAcl: entries.get('inventory'),
      readerAcl: entries.get('reader'),
    };
    assert.deepEqual(afterProvisioning.parent, beforeProvisioning,
      'parent SDDL/file ID and both native witness byte snapshots must remain unchanged');

    assert.throws(
      () => native.provision_inventory_bases(roles),
      (error) => error?.operation === 'provision_inventory_bases' &&
        error?.writes === 0 && error?.ambiguous === false,
      'a second call must refuse existing bases with zero writes and no ambiguous result',
    );

    const duplicateObservations = await powershellJson(ACL_SNAPSHOT_SCRIPT,
      observeAclSnapshotPaths(containerPath, inventoryBase, readerBase, true));
    assert.equal(duplicateObservations.length, 3);
    const duplicateEntries = new Map(duplicateObservations.map((entry) => [entry.name, entry]));
    const afterDuplicate = {
      parent: await captureParent(),
      inventoryIdentity: native.read_identity(inventoryBase),
      readerIdentity: native.read_identity(readerBase),
      inventoryAcl: duplicateEntries.get('inventory'),
      readerAcl: duplicateEntries.get('reader'),
    };
    assert.deepEqual(afterDuplicate, afterProvisioning,
      'duplicate refusal must leave both bases, their ACLs, the parent, and witness bytes unchanged');

    t.diagnostic('Provisioning passed its native flush gate; this fixture does not simulate or claim power-loss durability. The owned canonical root is intentionally retained on the ephemeral hosted runner; no recursive cleanup is performed.');
  } finally {
    if (controlHandle !== null && controlHandle !== undefined) native.close_service_handle(controlHandle);
  }
});
