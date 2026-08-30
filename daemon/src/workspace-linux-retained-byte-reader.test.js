import assert from "node:assert/strict";
import test from "node:test";

import { createLinuxRetainedByteReader } from "./workspace-linux-retained-byte-reader.js";

function handle(fd, { directory = false, bytes = null, closes }) {
  return {
    fd,
    async stat() {
      return {
        dev: 1,
        ino: fd,
        size: bytes?.byteLength ?? 0,
        isFile: () => !directory,
      };
    },
    async readFile() { return bytes; },
    async close() { closes.push(fd); },
  };
}

test("retains the exact root and traverses every component with no-follow handles", async () => {
  const calls = [];
  const closes = [];
  const open = async (path, flags) => {
    calls.push({ path, flags });
    if (path === "/stage") return handle(10, { directory: true, closes });
    if (path === "/proc/self/fd/10/nested") {
      return handle(11, { directory: true, closes });
    }
    if (path === "/proc/self/fd/11/file.txt") {
      return handle(12, { bytes: Buffer.from("safe"), closes });
    }
    throw new Error(`unexpected path ${path}`);
  };
  const reader = await createLinuxRetainedByteReader({
    root: "/stage",
    runtimePlatform: "linux",
    open,
    realpath: async () => "/stage",
    readlink: async () => "/stage",
  });
  assert.equal(new TextDecoder().decode(await reader.readBytes("nested/file.txt")), "safe");
  assert.deepEqual(calls.map((call) => call.path), [
    "/stage",
    "/proc/self/fd/10/nested",
    "/proc/self/fd/11/file.txt",
  ]);
  await reader.close();
  await reader.close();
  assert.deepEqual(closes, [12, 11, 10]);
});

test("rejects a symlinked or ambiguously retained root", async () => {
  await assert.rejects(
    createLinuxRetainedByteReader({
      root: "/stage",
      runtimePlatform: "linux",
      open: async () => { throw new Error("must not open"); },
      realpath: async () => "/elsewhere",
      readlink: async () => "/stage",
    }),
    (error) => error.code === "WORKSPACE_ROOT_ESCAPE"
  );
  const closes = [];
  await assert.rejects(
    createLinuxRetainedByteReader({
      root: "/stage",
      runtimePlatform: "linux",
      open: async () => handle(20, { directory: true, closes }),
      realpath: async () => "/stage",
      readlink: async () => "/replacement",
    }),
    (error) => error.code === "WORKSPACE_ROOT_ESCAPE"
  );
  assert.deepEqual(closes, [20]);
});

test("rejects traversal and use after close", async () => {
  const closes = [];
  const reader = await createLinuxRetainedByteReader({
    root: "/stage",
    runtimePlatform: "linux",
    open: async () => handle(30, { directory: true, closes }),
    realpath: async () => "/stage",
    readlink: async () => "/stage",
  });
  await assert.rejects(reader.readBytes("../escape"));
  await reader.close();
  await assert.rejects(
    reader.readBytes("file.txt"),
    (error) => error.code === "CONFIG_INVALID"
  );
});
