/**
 * Tool-call aggregation for the remote command stream.
 *
 * The GJC SDK streams a tool_use block as a sequence of partial assistant
 * messages: the `toolCall` part first appears with empty `arguments` ({}), then
 * the arguments fill in over later frames that reuse the same tool-call `id`.
 * Deduping purely by identity would freeze the earliest empty snapshot, so the
 * `View tool log` button rendered `read` with a bare `{}`. Aggregation here
 * merges frames that share an identity and keeps the most complete arguments.
 */

export function truncate(text, maxLength) {
  return text.length <= maxLength ? text : `${text.slice(0, maxLength - 1)}…`;
}

export function extractToolCall(evt) {
  if (evt?.type === "toolCall" && typeof evt.name === "string") return normalizeToolCall(evt);

  const content = Array.isArray(evt?.message?.content) ? evt.message.content : [];
  const call = content.find((part) => part?.type === "toolCall" && typeof part.name === "string");
  return call ? normalizeToolCall(call) : undefined;
}

export function normalizeToolCall(call) {
  const input = call.input ?? call.arguments ?? call.args ?? call.parameters;
  return {
    id: call.id ?? call.toolCallId ?? call.callId,
    name: call.name,
    label: toolInputLabel(input),
    input,
  };
}

function toolInputLabel(input) {
  if (!input || typeof input !== "object") return typeof input === "string" ? truncate(input, 80) : "";
  const label = input._i ?? input.command ?? input.path ?? input.pattern ?? input.subject ?? input.name ?? input.action;
  return typeof label === "string" ? label : "";
}

/**
 * Stable identity for a tool call across its streaming frames. Prefers the SDK
 * `id` so partial and final frames of the same call collapse regardless of how
 * complete their arguments are.
 */
export function toolCallIdentity(toolCall) {
  if (toolCall.id) return JSON.stringify(["id", toolCall.id]);
  if (toolCall.label) return JSON.stringify(["label", toolCall.name, toolCall.label]);
  return JSON.stringify(["input", toolCall.name, toolCall.input]);
}

/** How much argument detail a frame carries; higher wins when merging. */
function inputCompleteness(input) {
  if (input && typeof input === "object") return Object.keys(input).length;
  if (typeof input === "string") return input.length;
  return input === undefined || input === null ? 0 : 1;
}

/**
 * Record a tool call, merging streaming partials that share an identity.
 *
 * `index` is a Map from identity to the entry's position in `toolCalls`. A later
 * frame with strictly more complete arguments replaces the earlier snapshot in
 * place, so the final arguments are shown instead of the empty `{}` the SDK
 * emits when a tool_use block first streams in. Returns true when the visible
 * entry changed (new call or an in-place enrichment), false otherwise.
 */
export function recordToolCall(toolCalls, index, toolCall) {
  const identity = toolCallIdentity(toolCall);
  const existingPos = index.get(identity);
  if (existingPos === undefined) {
    index.set(identity, toolCalls.length);
    toolCalls.push(toolCall);
    return true;
  }

  const existing = toolCalls[existingPos];
  if (inputCompleteness(toolCall.input) > inputCompleteness(existing.input)) {
    toolCalls[existingPos] = toolCall;
    return true;
  }
  return false;
}

export function summarizeToolCalls(toolCalls) {
  return toolCalls
    .slice(-5)
    .map((call, index, recent) => {
      const number = toolCalls.length - recent.length + index + 1;
      const label = call.label ? ` ${truncate(call.label, 60)}` : "";
      return `#${number} \`${call.name}\`${label}`;
    })
    .join("; ");
}

export function formatToolLog(toolCalls) {
  return toolCalls
    .map((call, index) => {
      const input = call.input === undefined ? "" : `\n\`\`\`json\n${JSON.stringify(call.input, null, 2)}\n\`\`\``;
      return `**${index + 1}. ${call.name}**${call.label ? ` — ${call.label}` : ""}${input}`;
    })
    .join("\n\n");
}
