// Fixed per OS, never per account, configured host ID, cwd or repository.
// The operator provisions this local, protected directory before daemon startup.
export function hostStateDirectory() {
  switch (process.platform) {
    case 'win32': return 'C:\\ProgramData\\gjc-remote\\host-state';
    case 'linux': return '/var/lib/gjc-remote/host-state';
    case 'darwin': return '/Library/Application Support/gjc-remote/host-state';
    default: throw new Error('Unsupported host state platform');
  }
}
