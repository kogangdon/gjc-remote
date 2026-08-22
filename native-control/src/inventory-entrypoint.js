#!/usr/bin/env node
import { createInventoryPublisher } from './public.js';
import { isPrincipal } from '@gjc-remote/shared/identity';
import {
  STRICT_JSON_LIMITS, assertStrictText, canonicalJson, parseStrictJsonBytes,
} from '@gjc-remote/shared/strict-json';
import { workspaceInventoryHostKey } from '@gjc-remote/shared/workspace-inventory';

const INPUT_LIMIT = 1024 * 1024;
const ROLE_LIMIT = 32 * 1024;
const ROLE_KEYS = ['management', 'bot', 'recovery', 'daemon', 'system'];
const REQUEST_KEYS = ['hostId', 'expectedInventoryGeneration', 'workspaces'];
const WORKSPACE_KEYS = ['workspaceId', 'sourcePlatform', 'workDir'];
const MAX = Number.MAX_SAFE_INTEGER;

function failure(code = 'INVENTORY_INVALID', operation = 'inventory_entrypoint', writes = 0, ambiguous = false) {
  const error = new Error('inventory operation failed');
  Object.assign(error, { code, operation, writes, ambiguous });
  return error;
}

function exact(value, expected) {
  if (value === null || typeof value !== 'object' || Array.isArray(value) ||
      Object.getPrototypeOf(value) !== Object.prototype) return null;
  const actual = Object.keys(value);
  return actual.length === expected.length && expected.every((key) => Object.hasOwn(value, key))
    ? value
    : null;
}

function validWorkDir(value) {
  try {
    return typeof value === 'string' && value.length > 0 &&
      assertStrictText(value, 'workDir', 4096) === value;
  } catch {
    return false;
  }
}

function validateRequest(value) {
  const request = exact(value, REQUEST_KEYS);
  if (!request || !Number.isSafeInteger(request.expectedInventoryGeneration) ||
      request.expectedInventoryGeneration < 0 || request.expectedInventoryGeneration > MAX ||
      !Array.isArray(request.workspaces) || request.workspaces.length > 64) {
    throw failure('INVENTORY_INVALID', 'publish_inventory');
  }
  try {
    workspaceInventoryHostKey(request.hostId);
  } catch {
    throw failure('INVENTORY_INVALID', 'publish_inventory');
  }
  const workspaceIds = new Set();
  for (const workspace of request.workspaces) {
    const item = exact(workspace, WORKSPACE_KEYS);
    if (!item || typeof item.workspaceId !== 'string' ||
        !/^[A-Za-z0-9][A-Za-z0-9._-]*$/.test(item.workspaceId) ||
        Buffer.byteLength(item.workspaceId, 'utf8') > 128 ||
        workspaceIds.has(item.workspaceId) ||
        !['posix', 'windows-drive', 'windows-unc'].includes(item.sourcePlatform) ||
        !validWorkDir(item.workDir)) {
      throw failure('INVENTORY_INVALID', 'publish_inventory');
    }
    workspaceIds.add(item.workspaceId);
  }
  return request;
}

function isWindowsSidShape(value) {
  const fields = value.split('-');
  if (fields.length < 4 || fields.length > 18 || fields[0] !== 'S' || fields[1] !== '1' ||
      !fields.slice(2).every((field) => /^(0|[1-9][0-9]*)$/.test(field))) return false;
  try {
    return BigInt(fields[2]) <= 281474976710655n &&
      fields.slice(3).every((field) => BigInt(field) <= 4294967295n);
  } catch {
    return false;
  }
}

function validateRoles(value) {
  const bindings = exact(value, ROLE_KEYS);
  if (!bindings) throw failure();
  const roles = {};
  for (const role of ROLE_KEYS) {
    const principal = exact(bindings[role], ['kind', 'value']);
    if (!principal || typeof principal.value !== 'string' ||
        Buffer.byteLength(principal.value, 'utf8') > 4096 ||
        (principal.kind === 'sid' && !isWindowsSidShape(principal.value)) ||
        !isPrincipal(principal)) throw failure();
    roles[role] = Object.freeze({ kind: principal.kind, value: principal.value });
  }
  const kind = process.platform === 'win32' ? 'sid' : process.platform === 'linux' ? 'uid' : null;
  if (kind === null || !ROLE_KEYS.every((role) => roles[role].kind === kind) ||
      new Set(ROLE_KEYS.map((role) => roles[role].value)).size !== ROLE_KEYS.length ||
      roles.system.value !== (kind === 'sid' ? 'S-1-5-18' : 'uid:0')) throw failure();
  return Object.freeze(roles);
}

async function readStdin() {
  if (process.stdin.isTTY) throw failure();
  const chunks = [];
  let size = 0;
  for await (const chunk of process.stdin) {
    const bytes = Buffer.from(chunk);
    size += bytes.length;
    if (size > INPUT_LIMIT) throw failure();
    chunks.push(bytes);
  }
  return Buffer.concat(chunks, size);
}

function readRoles() {
  const raw = process.env.GJC_INVENTORY_ROLE_BINDINGS;
  if (typeof raw !== 'string' || Buffer.byteLength(raw, 'utf8') > ROLE_LIMIT) throw failure();
  try {
    return validateRoles(parseStrictJsonBytes(Buffer.from(raw, 'utf8'), {
      ...STRICT_JSON_LIMITS, maxBytes: ROLE_LIMIT,
    }));
  } catch (caught) {
    if (caught?.code) throw caught;
    throw failure();
  }
}

function errorReceipt(caught) {
  const code = typeof caught?.code === 'string' && /^[A-Z0-9_]{1,64}$/.test(caught.code)
    ? caught.code : 'INVENTORY_IO_FAILED';
  const operation = typeof caught?.operation === 'string' &&
    /^[a-z_]{1,64}$/.test(caught.operation) ? caught.operation : 'inventory_entrypoint';
  return {
    status: 'error',
    code,
    operation,
    writes: Number.isSafeInteger(caught?.writes) && caught.writes >= 0 ? caught.writes : 0,
    ambiguous: caught?.ambiguous === true,
  };
}

async function main() {
  if (process.argv.length !== 3 || process.argv[2] !== 'publish') throw failure();
  const input = await readStdin();
  let request;
  try {
    request = validateRequest(parseStrictJsonBytes(input, { ...STRICT_JSON_LIMITS, maxBytes: INPUT_LIMIT }));
  } catch (caught) {
    if (caught?.code) throw caught;
    throw failure('INVENTORY_INVALID', 'publish_inventory');
  }
  const roles = readRoles();
  const publisher = await createInventoryPublisher({ hostId: request.hostId, roles });
  const receipt = await publisher.publish({
    expectedInventoryGeneration: request.expectedInventoryGeneration,
    workspaces: request.workspaces,
  });
  process.stdout.write(`${canonicalJson(receipt)}\n`);
}

try {
  await main();
} catch (caught) {
  process.stderr.write(`${canonicalJson(errorReceipt(caught))}\n`);
  process.exitCode = 1;
}
