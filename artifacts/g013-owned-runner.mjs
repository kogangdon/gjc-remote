import { readFile, readdir, writeFile } from 'node:fs/promises';
import { createRequire } from 'node:module';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';

const [configPath, mode, outputPath, inputPath] = process.argv.slice(2);
const config = JSON.parse(await readFile(configPath, 'utf8'));
const require = createRequire(import.meta.url);
const addon = require(config.addonPath);
const inventoryAdapter = await import(
  pathToFileURL(`${config.repo}/native-control/src/inventory.js`));
const workspace = await import(pathToFileURL(`${config.repo}/shared/workspace-inventory.js`));
const strict = await import(pathToFileURL(`${config.repo}/shared/strict-json.js`));
const inventoryRoot = await addon.resolve_native_state_root(config.hostKey, 'inventory');
const readerRoot = await addon.resolve_native_state_root(config.hostKey, 'reader');
const fencePath = join(inventoryRoot, 'inventory-publication.lock');

async function emit(value) {
  await writeFile(outputPath, `${JSON.stringify(value, null, 2)}\n`, 'utf8');
}

if (mode === 'publish' || mode === 'publish-allow-error') {
  const request = JSON.parse(await readFile(inputPath, 'utf8'));
  const candidate = {
    expectedInventoryGeneration: request.expectedInventoryGeneration,
    workspaces: request.workspaces,
  };
  try {
    const publisher = await inventoryAdapter.createInventoryPublisherAdapter(
      async () => addon, { hostId: config.hostId, roles: config.roles });
    await emit(await publisher.publish(candidate));
  } catch (error) {
    await emit({
      status: 'error',
      code: error.code,
      operation: error.operation,
      writes: error.writes,
      ambiguous: error.ambiguous,
    });
    if (mode === 'publish') process.exitCode = 1;
  }
} else if (mode === 'hold') {
  const fence = await addon.acquire_inventory_fence(fencePath, config.roles);
  await writeFile(config.ready, 'ready\n', 'utf8');
  await new Promise((resolve) => setTimeout(resolve, 3500));
  await fence.release();
  await emit({ status: 'passed', writes: fence.writes });
} else if (mode === 'read') {
  try {
    const reader = await inventoryAdapter.createInventoryReaderAdapter(
      async () => addon, { hostId: config.hostId, roles: config.roles });
    const result = await reader.readAccepted();
    const floorEnvelope = result.status === 'present'
      ? await addon.read_inventory_object(
        join(readerRoot, 'inventory-floor.v1.json'),
        strict.STRICT_JSON_LIMITS.maxBytes, config.roles, 'inventory-floor')
      : null;
    await emit({
      ...result,
      floorIdentity: floorEnvelope?.identity ?? null,
    });
  } catch (error) {
    await emit({
      status: 'error',
      code: error.code,
      operation: error.operation,
      writes: error.writes,
      ambiguous: error.ambiguous,
    });
    process.exitCode = 1;
  }
} else if (mode === 'floor') {
  const inventoryPath = join(inventoryRoot, 'workspace-inventory.v2.json');
  const inventoryEnvelope = await addon.read_inventory_object(
    inventoryPath, strict.STRICT_JSON_LIMITS.maxBytes, config.roles, 'inventory-file');
  const inventory = workspace.parseWorkspaceInventory(inventoryEnvelope.bytes);
  const floor = {
    version: 1,
    hostId: config.hostId,
    inventoryGeneration: inventory.inventoryGeneration,
    inventoryFingerprint: inventory.inventoryFingerprint,
  };
  floor.floorFingerprint = strict.canonicalJsonHash(floor);
  const result = await addon.publish_inventory_object_atomic(
    join(readerRoot, 'inventory-floor.v1.json'), '.inventory-floor.',
    strict.canonicalJsonBytes(floor), null, config.roles, 'inventory-floor');
  const reopened = await addon.read_inventory_object(
    join(readerRoot, 'inventory-floor.v1.json'), strict.STRICT_JSON_LIMITS.maxBytes,
    config.roles, 'inventory-floor');
  await emit({
    status: 'passed',
    writes: result.writes,
    identity: result.identity,
    reopenedIdentity: reopened.identity,
    floor,
  });
} else if (mode === 'corrupt-commit') {
  await writeFile(join(inventoryRoot, 'inventory-commit.v1.json'), '{}', 'utf8');
  await emit({ status: 'passed' });
} else if (mode === 'list-inventory') {
  await emit({ status: 'passed', files: (await readdir(inventoryRoot)).sort() });
} else if (mode === 'list-reader') {
  await emit({ status: 'passed', files: (await readdir(readerRoot)).sort() });
} else {
  throw new Error('unknown mode');
}
