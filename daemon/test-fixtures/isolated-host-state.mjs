// Bun preload for subprocess tests only. Production has no env-selected lock path.
import { mock } from 'bun:test';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
const supplied = process.env.GJC_FIXTURE_HOST_STATE;
const directory = supplied ?? mkdtempSync(join(tmpdir(), 'gjc-host-state-'));
if (!supplied) process.on('exit', () => {
  try { rmSync(directory, { recursive: true, force: true }); } catch { /* OS may still be closing a handle */ }
});
mock.module(fileURLToPath(new URL('../src/host-state-directory.js', import.meta.url)), () => ({ hostStateDirectory: () => directory }));
