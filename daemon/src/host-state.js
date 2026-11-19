import { lstatSync } from 'node:fs';
import { hostStateDirectory } from './host-state-directory.js';
import { acquireHostOwnerLock } from './host-owner-lock.js';
import { openHostDecisionDb } from './host-decision-db.js';

// Provisioning owns the fixed directory and its parent ACLs. Never create a
// missing parent from daemon credentials, resolve against cwd, or select a
// different store after an open failure.
export function openHostState() {
  const directory = hostStateDirectory();
  const stat = lstatSync(directory);
  if (!stat.isDirectory() || (process.platform !== 'win32' &&
      (stat.uid !== process.getuid() || (stat.mode & 0o077) !== 0))) {
    throw new Error('invalid daemon state directory');
  }
  const lock = acquireHostOwnerLock(directory);
  let decisions;
  try {
    decisions = openHostDecisionDb(directory);
  } catch (error) {
    lock.close();
    throw error;
  }
  return {
    decisions,
    close() {
      // If DB close fails, the exiting process, not another live daemon,
      // remains responsible for the lock until the OS releases its handles.
      decisions.close();
      lock.close();
    },
  };
}
