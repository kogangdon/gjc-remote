import { mkdirSync, mkdtempSync, realpathSync, rmSync, writeFileSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { tmpdir } from 'node:os';
import { win32 } from 'node:path';

const FILE_GENERIC_READ = 0x00120089;
const FILE_GENERIC_WRITE = 0x00120116;
const FILE_GENERIC_EXECUTE = 0x001200a0;
const FILE_DELETE_CHILD = 0x00000040;

function checkedSpawn(command, args) {
  const result = spawnSync(command, args, {
    encoding: 'utf8',
    timeout: 10_000,
    windowsHide: true,
  });
  if (result.error) throw result.error;
  if (result.status !== 0) {
    throw new Error(`${command} failed: ${result.stderr || result.stdout}`);
  }
}

function applySdkInstallAcl(path, roles, directory) {
  checkedSpawn('icacls.exe', [path, '/setowner', `*${roles.management.value}`]);

  const read = FILE_GENERIC_READ;
  const write = FILE_GENERIC_WRITE;
  const execute = FILE_GENERIC_EXECUTE;
  const roleMasks = directory
    ? [
      [roles.management, read | write | execute | FILE_DELETE_CHILD],
      [roles.recovery, read | execute],
      [roles.daemon, read | execute],
      [roles.system, read | execute],
    ]
    : [
      [roles.management, read | write],
      [roles.recovery, read],
      [roles.daemon, read | execute],
      [roles.system, read],
    ];
  const dacl = `D:P${roleMasks.map(([principal, mask]) =>
    `(A;;0x${mask.toString(16).padStart(8, '0')};;;${principal.value})`).join('')}`;
  const pathLiteral = `'${path.replaceAll("'", "''")}'`;
  const script = [
    "$ErrorActionPreference = 'Stop'",
    "Import-Module (Join-Path $PSHOME 'Modules\\Microsoft.PowerShell.Security\\Microsoft.PowerShell.Security.psd1') -ErrorAction Stop",
    `$path = ${pathLiteral}`,
    `$sddl = '${dacl}'`,
    '$acl = Get-Acl -LiteralPath $path',
    '$acl.SetSecurityDescriptorSddlForm($sddl, [System.Security.AccessControl.AccessControlSections]::Access)',
    'Set-Acl -LiteralPath $path -AclObject $acl -ErrorAction Stop',
  ].join('; ');
  const encodedScript = Buffer.from(script, 'utf16le').toString('base64');
  checkedSpawn('powershell.exe', [
    '-NoLogo', '-NoProfile', '-NonInteractive', '-EncodedCommand', encodedScript,
  ]);
}

function resetAndRemove(root) {
  const reset = spawnSync('icacls.exe', [root, '/reset', '/T', '/C'], {
    encoding: 'utf8',
    timeout: 10_000,
    windowsHide: true,
  });
  try {
    rmSync(root, { recursive: true, force: true });
  } catch (error) {
    const details = reset.error?.message || reset.stderr || reset.stdout || 'ACL reset failed';
    throw new AggregateError([error], `unable to remove temporary observation fixture: ${details}`);
  }
}

export function createServiceObservationDirectoryFixture(roles) {
  const temporaryBase = realpathSync(tmpdir());
  const serviceRoot = win32.join(win32.parse(temporaryBase).root, 'gjc-remote');
  const relativeToServiceRoot = win32.relative(serviceRoot, temporaryBase);
  if (relativeToServiceRoot === '' ||
      (relativeToServiceRoot !== '..' &&
       !relativeToServiceRoot.startsWith(`..${win32.sep}`) &&
       !win32.isAbsolute(relativeToServiceRoot))) {
    throw new Error('temporary service observation fixture cannot live under the native service root');
  }
  const root = realpathSync(mkdtempSync(win32.join(temporaryBase, 'gjc-service-observation-')));
  const build = win32.join(root, 'build');
  const files = ['CHANGELOG.md', 'index.js', 'LICENSE'].map((name) => win32.join(root, name));
  try {
    mkdirSync(build);
    for (const path of files) writeFileSync(path, 'temporary service observation fixture\n');

    // The protected SDK-install ACL is confined to this disposable test tree.
    applySdkInstallAcl(build, roles, true);
    for (const path of files) applySdkInstallAcl(path, roles, false);
    applySdkInstallAcl(root, roles, true);
  } catch (error) {
    try {
      resetAndRemove(root);
    } catch (cleanupError) {
      throw new AggregateError([error, cleanupError], 'temporary observation fixture setup and cleanup failed');
    }
    throw error;
  }

  let cleaned = false;
  return Object.freeze({
    root,
    cleanup() {
      if (cleaned) return;
      resetAndRemove(root);
      cleaned = true;
    },
  });
}
