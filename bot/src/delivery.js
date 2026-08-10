import { AttachmentBuilder } from "discord.js";

export const CHUNK_LIMIT = 1900;
export const MAX_CHUNKS = 7;
const CHUNK_DELAY_MS = 600;

export function createTextAttachment(text, name) {
  return new AttachmentBuilder(Buffer.from(text, "utf8"), { name });
}
export function formatDeliveryError(error) {
  if (!error || typeof error !== "object") return String(error ?? "unknown error");
  if (
    typeof error.code === "string" &&
    typeof error.retryable === "boolean" &&
    typeof error.action === "string"
  ) {
    return `${error.code} (action: ${error.action}; ${
      error.retryable ? "retryable" : "not retryable"
    })`;
  }
  try {
    return JSON.stringify(error);
  } catch {
    return "unknown error";
  }
}

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

/**
 * Deliver remote output as inline Discord messages or an in-memory attachment.
 * Paths in the output are always treated as plain text.
 */
export async function deliverResult({
  result,
  header,
  outputName,
  components = [],
  sendFirst,
  sendFollow,
  delayMs = CHUNK_DELAY_MS,
}) {
  const text = result.ok
    ? result.text ?? "(no text output)"
    : formatDeliveryError(result.error);
  const body = `${header}\n${text}`;

  if (body.length <= CHUNK_LIMIT) {
    await sendFirst({ content: body, components });
    return;
  }

  const chunks = splitForDiscord(body, CHUNK_LIMIT);
  if (chunks.length <= MAX_CHUNKS) {
    for (let i = 0; i < chunks.length; i++) {
      const isLast = i === chunks.length - 1;
      const label = chunks.length > 1 ? `_(Part ${i + 1}/${chunks.length})_\n` : "";
      const payload = { content: `${label}${chunks[i]}` };
      if (isLast && components.length > 0) payload.components = components;
      await (i === 0 ? sendFirst(payload) : sendFollow(payload));
      if (!isLast && delayMs > 0) await sleep(delayMs);
    }
    return;
  }

  const file = createTextAttachment(text, outputName);
  await sendFirst({ content: `${header} (output attached, ${text.length} chars)`, files: [file], components });
}

function splitForDiscord(text, limit) {
  const budget = limit - 8;
  const lines = [];
  for (const line of text.split("\n")) {
    if (line.length <= budget) {
      lines.push(line);
      continue;
    }
    for (let i = 0; i < line.length; i += budget) lines.push(line.slice(i, i + budget));
  }

  const chunks = [];
  let current = "";
  let inFence = false;
  const flush = () => {
    if (!current) return;
    chunks.push(inFence ? `${current}\n\`\`\`` : current);
    current = inFence ? "```" : "";
  };

  for (const line of lines) {
    const projected = current ? current.length + 1 + line.length : line.length;
    const reserve = inFence ? 4 : 0;
    if (current && projected + reserve > limit) flush();
    current += current ? `\n${line}` : line;
    if (/^\s*```/.test(line)) inFence = !inFence;
  }
  if (current) chunks.push(current);
  return chunks;
}
