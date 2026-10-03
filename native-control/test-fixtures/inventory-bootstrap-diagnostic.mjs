import assert from 'node:assert/strict';
import { execFile as execFileCallback } from 'node:child_process';
import { copyFile, lstat, mkdir, mkdtemp, readFile, writeFile } from 'node:fs/promises';
import { createRequire } from 'node:module';
import { tmpdir } from 'node:os';
import { isAbsolute, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';

const execFile = promisify(execFileCallback);
const require = createRequire(new URL('../package.json', import.meta.url));
const self = fileURLToPath(import.meta.url);
const childFlag = '--inventory-bootstrap-diagnostic-child';

function requireHostedOptIn() {
  assert.equal(process.platform, 'win32');
  assert.equal(process.env.GITHUB_ACTIONS, 'true');
  assert.equal(process.env.RUNNER_ENVIRONMENT, 'github-hosted');
  assert.equal(process.env.GJC_REMOTE_INVENTORY_BASES_E2E, '1');
}

function requireFrozenRoles(roles) {
  assert.equal(Object.isFrozen(roles), true);
  assert.deepEqual(Object.keys(roles).sort(), ['bot', 'daemon', 'management', 'recovery', 'system']);
  for (const [name, role] of Object.entries(roles)) {
    assert.equal(Object.isFrozen(role), true);
    assert.deepEqual(Object.keys(role).sort(), ['kind', 'value']);
    assert.equal(role.kind, 'sid');
    if (name === 'system') assert.equal(role.value, 'S-1-5-18');
    else assert.match(role.value, /^S-1-5-21-(?:[0-9]+-){3}[0-9]+$/);
  }
  assert.equal(new Set(['management', 'bot', 'recovery', 'daemon']
    .map((name) => roles[name].value)).size, 4);
}

async function requireAbsent(driveRoot) {
  assert.match(driveRoot, /^[A-Z]:\\$/);
  for (const name of ['gjc-remote', '.gjc-service-platform-container.v1',
    '.gjc-service-system-drive-gjc-remote.pending']) {
    try {
      await lstat(`${driveRoot}${name}`);
    } catch (error) {
      if (error?.code === 'ENOENT') continue;
      throw new Error('DIAGNOSTIC_ABSENCE_UNPROVEN');
    }
    throw new Error('DIAGNOSTIC_PREEXISTING_STATE');
  }
}

function replaceUnique(source, before, after) {
  assert.equal(source.split(before).length, 2, 'diagnostic source guard must match exactly once');
  return source.replace(before, after);
}

function instrument(source) {
  // Preserve the native short circuit: B is evaluated only when valid, and D
  // only when valid and B. Errors are observational GetLastError snapshots,
  // not a claim that AuthzAccessCheck's reply error equals GetLastError.
  // ANCHOR fields: valid, B evaluated, B allowed, D evaluated, D allowed,
  // then the three last-error snapshots. IDENTITY fields: evaluated, valid,
  // last-error. An unevaluated access check is not an access denial.
  source = replaceUnique(source, `  return valid &&
      WindowsPrincipalHasDirectoryAccess(
          directory, roles.bot, kWindowsTraversalAccess) &&
      WindowsPrincipalHasDirectoryAccess(
          directory, roles.daemon, kWindowsTraversalAccess);
}`, `  const DWORD diagnostic_valid_error = GetLastError();
  const bool diagnostic_bot = valid && WindowsPrincipalHasDirectoryAccess(
      directory, roles.bot, kWindowsTraversalAccess);
  const DWORD diagnostic_bot_error = GetLastError();
  const bool diagnostic_daemon = diagnostic_bot && WindowsPrincipalHasDirectoryAccess(
      directory, roles.daemon, kWindowsTraversalAccess);
  const DWORD diagnostic_daemon_error = GetLastError();
  std::fprintf(stderr, "GJC_BOOTSTRAP_ANCHOR %u %u %u %u %u %lu %lu %lu\\n",
      valid ? 1u : 0u, valid ? 1u : 0u, diagnostic_bot ? 1u : 0u,
      diagnostic_bot ? 1u : 0u, diagnostic_daemon ? 1u : 0u,
      static_cast<unsigned long>(diagnostic_valid_error),
      static_cast<unsigned long>(diagnostic_bot_error),
      static_cast<unsigned long>(diagnostic_daemon_error));
  SetLastError(diagnostic_daemon_error);
  return diagnostic_daemon;
}`);
  // Narrow open/identity status, before the existing error classification.
  // No additional native open or identity call is introduced.
  source = replaceUnique(source, `  if (!ServiceStoreOpenBootstrapAnchor(
          spec.anchor_path, false, &anchor)) {`, `  const bool diagnostic_anchor_opened = ServiceStoreOpenBootstrapAnchor(
      spec.anchor_path, false, &anchor);
#ifdef _WIN32
  const DWORD diagnostic_open_error = GetLastError();
  std::fprintf(stderr, "GJC_BOOTSTRAP_OPEN %u %lu\\n",
      diagnostic_anchor_opened ? 1u : 0u,
      static_cast<unsigned long>(diagnostic_open_error));
  SetLastError(diagnostic_open_error);
#endif
  if (!diagnostic_anchor_opened) {`);
  return replaceUnique(source, `  ServiceStoreIdentity anchor_identity;
  if (!VerifyBootstrapAnchor(anchor, roles, true) ||
      !CaptureExternalAncestorIdentity(
          anchor, &anchor_identity)) {`, `  ServiceStoreIdentity anchor_identity;
  const bool diagnostic_anchor_verified = VerifyBootstrapAnchor(anchor, roles, true);
  const bool diagnostic_identity = diagnostic_anchor_verified &&
      CaptureExternalAncestorIdentity(anchor, &anchor_identity);
#ifdef _WIN32
  const DWORD diagnostic_identity_error = GetLastError();
  std::fprintf(stderr, "GJC_BOOTSTRAP_IDENTITY %u %u %lu\\n",
      diagnostic_anchor_verified ? 1u : 0u, diagnostic_identity ? 1u : 0u,
      static_cast<unsigned long>(diagnostic_identity_error));
  SetLastError(diagnostic_identity_error);
#endif
  if (!diagnostic_identity) {`);
}

async function runChild() {
  let result = { code: 'DIAGNOSTIC_CHILD_FAILED' };
  try {
    requireHostedOptIn();
    const roles = JSON.parse(process.env.GJC_INVENTORY_DIAGNOSTIC_ROLES);
    for (const role of Object.values(roles)) Object.freeze(role);
    Object.freeze(roles);
    requireFrozenRoles(roles);
    await requireAbsent(process.env.GJC_INVENTORY_DIAGNOSTIC_DRIVE);
    const addonPath = process.env.GJC_INVENTORY_DIAGNOSTIC_ADDON;
    assert.equal(isAbsolute(addonPath), true);
    const native = require(addonPath);
    assert.deepEqual(native.current_os_principal(), roles.management);
    // Recheck after loading, immediately before the single read-only open.
    await requireAbsent(process.env.GJC_INVENTORY_DIAGNOSTIC_DRIVE);
    let opened;
    try {
      opened = native.open_service_root('control', roles, 'read-existing');
      result = opened?.writes === 0
        ? { code: 'DIAGNOSTIC_UNEXPECTED_HANDLE', writes: 0 }
        : { code: opened?.writes === undefined
          ? 'DIAGNOSTIC_WRITES_UNPROVEN' : 'DIAGNOSTIC_NONZERO_WRITES' };
    } catch (error) {
      if (error?.writes !== 0) result = { code: error?.writes === undefined
        ? 'DIAGNOSTIC_WRITES_UNPROVEN' : 'DIAGNOSTIC_NONZERO_WRITES' };
      else if (error?.operation !== 'open_service_root' || error?.ambiguous !== false) {
        result = { code: 'DIAGNOSTIC_UNEXPECTED_FAILURE', writes: 0 };
      } else {
        const allowed = new Set(['SERVICE_ACCESS_DENIED', 'SERVICE_IO_FAILED']);
        result = { code: allowed.has(error.code) ? error.code : 'DIAGNOSTIC_OTHER_REFUSAL', writes: 0 };
      }
    } finally {
      if (opened?.handle !== null && opened?.handle !== undefined) {
        native.close_service_handle(opened.handle);
      }
    }
  } catch {
    result = { code: 'DIAGNOSTIC_CHILD_FAILED' };
  }
  process.stdout.write(`${JSON.stringify(result)}\n`);
}

export async function diagnoseInventoryBootstrapRefusal(roles, driveRoot) {
  requireHostedOptIn();
  requireFrozenRoles(roles);
  await requireAbsent(driveRoot);
  let nodeGyp;
  let source;
  try {
    nodeGyp = require.resolve('node-gyp/bin/node-gyp.js');
    assert.equal(isAbsolute(nodeGyp), true);
    source = instrument(await readFile(new URL('../src/addon.cc', import.meta.url), 'utf8'));
  } catch {
    return { code: 'DIAGNOSTIC_SOURCE_OR_TOOL_GUARD_FAILED' };
  }
  // Only the fresh mkdtemp directory is written. It is intentionally retained
  // on failure and success; no cleanup can remove an unproven path.
  const owned = await mkdtemp(join(tmpdir(), 'gjc-inventory-bootstrap-diagnostic-'));
  await mkdir(join(owned, 'src'));
  await copyFile(new URL('../src/addon.cc', import.meta.url), join(owned, 'src', 'addon.cc'));
  await copyFile(new URL('../src/service-log-observer.inc', import.meta.url),
    join(owned, 'src', 'service-log-observer.inc'));
  await copyFile(new URL('../binding.gyp', import.meta.url), join(owned, 'binding.gyp'));
  await writeFile(join(owned, 'src', 'addon.cc'), source, 'utf8');
  try {
    await execFile(process.execPath, [nodeGyp, 'rebuild'], {
      cwd: owned, timeout: 120_000, maxBuffer: 1024 * 1024,
      windowsHide: true, encoding: 'utf8',
    });
  } catch {
    // Never surface compiler output (which may contain paths or identity).
    return { code: 'DIAGNOSTIC_COMPILE_FAILED' };
  }
  await requireAbsent(driveRoot);
  try {
    const { stdout, stderr } = await execFile(process.execPath, [self, childFlag], {
      cwd: owned, timeout: 30_000, maxBuffer: 8192, windowsHide: true,
      encoding: 'utf8',
      env: {
        ...process.env,
        GJC_INVENTORY_DIAGNOSTIC_ROLES: JSON.stringify(roles),
        GJC_INVENTORY_DIAGNOSTIC_DRIVE: driveRoot,
        GJC_INVENTORY_DIAGNOSTIC_ADDON: join(owned, 'build', 'Release', 'native_control.node'),
      },
    });
    const result = JSON.parse(stdout.trim());
    const codes = new Set(['DIAGNOSTIC_CHILD_FAILED', 'DIAGNOSTIC_UNEXPECTED_HANDLE',
      'DIAGNOSTIC_NONZERO_WRITES', 'DIAGNOSTIC_WRITES_UNPROVEN',
      'DIAGNOSTIC_UNEXPECTED_FAILURE', 'DIAGNOSTIC_OTHER_REFUSAL',
      'SERVICE_ACCESS_DENIED', 'SERVICE_IO_FAILED']);
    assert.equal(codes.has(result.code), true);
    assert.ok(Object.keys(result).every((key) => key === 'code' || key === 'writes'));
    if ('writes' in result) assert.equal(result.writes, 0);
    const stages = stderr.trim() === '' ? [] : stderr.trim().split(/\r?\n/);
    assert.ok(stages.length <= 4);
    for (const stage of stages) {
      assert.match(stage, /^(?:GJC_BOOTSTRAP_ANCHOR [01] [01] [01] [01] [01](?: [0-9]{1,10}){3}|GJC_BOOTSTRAP_OPEN [01] [0-9]{1,10}|GJC_BOOTSTRAP_IDENTITY [01] [01] [0-9]{1,10})$/);
    }
    return { ...result, stages };
  } catch {
    return { code: 'DIAGNOSTIC_CHILD_OUTPUT_FAILED' };
  }
}

if (process.argv[1] === self && process.argv[2] === childFlag) await runChild();
