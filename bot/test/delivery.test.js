import assert from "node:assert/strict";
import test from "node:test";
import { AttachmentBuilder } from "discord.js";
import { CHUNK_LIMIT, MAX_CHUNKS, createTextAttachment, deliverResult } from "../src/delivery.js";

function captureDelivery() {
  const first = [];
  const follow = [];
  return {
    first,
    follow,
    sendFirst: async (payload) => first.push(payload),
    sendFollow: async (payload) => follow.push(payload),
  };
}

async function deliver(text, capture, options = {}) {
  await deliverResult({
    result: { ok: true, text },
    header: "**GJC** result:",
    outputName: "gjc-output.md",
    components: options.components ?? [],
    sendFirst: capture.sendFirst,
    sendFollow: capture.sendFollow,
    delayMs: 0,
  });
}

test("short Windows absolute paths remain plain text without attachments", async () => {
  const capture = captureDelivery();
  const text = String.raw`C:\remote\workspace\report.md`;

  await deliver(text, capture);

  assert.equal(capture.first.length, 1);
  assert.equal(capture.first[0].content, `**GJC** result:\n${text}`);
  assert.equal("files" in capture.first[0], false);
  assert.equal(capture.follow.length, 0);
});

test("short POSIX absolute paths remain plain text without attachments", async () => {
  const capture = captureDelivery();
  const text = "/remote/workspace/report.md";

  await deliver(text, capture);

  assert.equal(capture.first.length, 1);
  assert.equal(capture.first[0].content, `**GJC** result:\n${text}`);
  assert.equal("files" in capture.first[0], false);
  assert.equal(capture.follow.length, 0);
});

test("text attachment helper returns one Buffer-backed AttachmentBuilder", () => {
  const text = "generated output";
  const file = createTextAttachment(text, "generated.md");

  assert.equal(file instanceof AttachmentBuilder, true);
  assert.equal(file.name, "generated.md");
  assert.equal(Buffer.isBuffer(file.attachment), true);
  assert.equal(file.attachment.toString("utf8"), text);
});

test("output exceeding the chunk count becomes a Buffer-backed generated attachment", async () => {
  const capture = captureDelivery();
  const text = "x".repeat(CHUNK_LIMIT * (MAX_CHUNKS + 1));

  await deliver(text, capture);

  assert.equal(capture.first.length, 1);
  assert.equal(capture.follow.length, 0);
  assert.match(capture.first[0].content, /output attached/);
  assert.equal(capture.first[0].files.length, 1);
  assert.equal(capture.first[0].files[0].name, "gjc-output.md");
  assert.equal(Buffer.isBuffer(capture.first[0].files[0].attachment), true);
  assert.equal(capture.first[0].files[0].attachment.toString("utf8"), text);
});

test("normal long output is chunked and components are attached to the last part", async () => {
  const capture = captureDelivery();
  const components = [{ type: "tool-log" }];
  const text = `${"a".repeat(1000)}\n${"b".repeat(1000)}`;

  await deliver(text, capture, { components });

  const payloads = [...capture.first, ...capture.follow];
  assert.equal(capture.first.length, 1);
  assert.equal(capture.follow.length, 1);
  assert.match(payloads[0].content, /^_\(Part 1\/2\)_\n/);
  assert.match(payloads[1].content, /^_\(Part 2\/2\)_\n/);
  assert.equal("files" in payloads[0], false);
  assert.equal("files" in payloads[1], false);
  assert.equal("components" in payloads[0], false);
  assert.equal(payloads[1].components, components);
});

test("delivery rejects and stops after the first send fails", async () => {
  let followCalls = 0;
  const failure = new Error("Discord send failed");

  await assert.rejects(
    deliverResult({
      result: { ok: true, text: `${"a".repeat(1000)}\n${"b".repeat(1000)}` },
      header: "**GJC** result:",
      outputName: "gjc-output.md",
      sendFirst: async () => {
        throw failure;
      },
      sendFollow: async () => {
        followCalls++;
      },
      delayMs: 0,
    }),
    failure
  );

  assert.equal(followCalls, 0);
});
