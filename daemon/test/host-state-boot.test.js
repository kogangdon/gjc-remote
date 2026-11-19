import test from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { once } from 'node:events';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { WebSocketServer } from 'ws';

const local = (path) => fileURLToPath(new URL(path, import.meta.url));
test('daemon registration requires the shared lock and a usable decision DB', { timeout: 25000 }, async (t) => {
  const dir = mkdtempSync(join(tmpdir(), 'gjc-host-boot-'));
  const server = new WebSocketServer({ host: '127.0.0.1', port: 0 });
  const processes = [];
  t.after(async () => {
    for (const { child, exited } of processes) {
      if (child.exitCode === null && child.signalCode === null) child.kill('SIGKILL');
      await exited;
    }
    for (const socket of server.clients) socket.terminate();
    await new Promise((resolve) => server.close(resolve));
    rmSync(dir, { recursive: true, force: true });
  });
  await once(server, 'listening');
  const registrations = [];
  server.on('connection', socket => socket.on('message', frame => {
    const message = JSON.parse(frame);
    if (message.type === 'register') { registrations.push(message.hostId); server.emit('registered', message.hostId); }
  }));
  function start(hostId) {
    const child = spawn(process.env.BUN_BIN || 'bun', ['--preload', local('../test-fixtures/isolated-host-state.mjs'), local('../src/daemon.js')], {
      env: { ...process.env, HOST_ID: hostId, HOST_TOKEN: 'fixture-token', BOT_WS_URL: `ws://127.0.0.1:${server.address().port}`, GJC_FIXTURE_HOST_STATE: dir, GJC_NATIVE_INVENTORY_MODE: 'off' },
      stdio: ['ignore', 'ignore', 'pipe'],
    });
    let diagnostic = '';
    child.stderr.on('data', chunk => { diagnostic += chunk; });
    const exited = once(child, 'exit');
    processes.push({ child, exited });
    return { child, exited, diagnostic: () => diagnostic };
  }
  async function registered(owner) {
    const id = await Promise.race([once(server, 'registered'), owner.exited.then(() => {throw new Error(owner.diagnostic());})]);
    return id[0];
  }
  const first = start('owner-a');
  assert.equal(await registered(first), 'owner-a');
  const other = start('owner-b');
  assert.equal((await other.exited)[0], 1, other.diagnostic());
  assert.match(other.diagnostic(), /host state unavailable/);
  first.child.kill('SIGKILL'); await first.exited;
  const successor = start('owner-c');
  assert.equal(await registered(successor), 'owner-c');
  successor.child.kill('SIGKILL'); await successor.exited;
  writeFileSync(join(dir, 'gjc-lifecycle.sqlite3'), 'corrupt-fixture');
  const broken = start('owner-d');
  assert.equal((await broken.exited)[0], 1);
  assert.match(broken.diagnostic(), /host state unavailable/);
  assert.deepEqual(registrations, ['owner-a', 'owner-c']);
});
