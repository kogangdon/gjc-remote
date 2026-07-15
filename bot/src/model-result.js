const MAX_RECEIPT_FIELD_LENGTH = 1024;
const MAX_DISPLAY_FIELD_LENGTH = 160;
const MAX_OUTPUT_LENGTH = 700;

/**
 * Return a normalized model receipt, or undefined when the event is not safe to use.
 */
export function validateModelResolvedEvent(event) {
  if (!event || event.type !== "model_resolved") return undefined;

  const receipt = {};
  for (const field of ["name", "provider", "modelId"]) {
    const value = event[field];
    if (typeof value !== "string" || value.length > MAX_RECEIPT_FIELD_LENGTH) return undefined;

    const normalized = normalizeField(value);
    if (!normalized) return undefined;
    receipt[field] = normalized;
  }

  return receipt;
}

/** Format a validated receipt as bounded, Discord-safe text. */
export function formatModelResolvedResult(receipt) {
  const safe = validateModelResolvedEvent({ type: "model_resolved", ...receipt });
  if (!safe) return undefined;

  const name = displayField(safe.name);
  const provider = displayField(safe.provider);
  const modelId = displayField(safe.modelId);
  return truncate(`Model switched to \`${name}\` (provider: \`${provider}\`, model ID: \`${modelId}\`).`, MAX_OUTPUT_LENGTH);
}

/** Apply the explicit /model delivery contract without changing other command results. */
export function transformModelResult(command, result, receipt) {
  if (command?.kind !== "set_model" || !result?.ok) return result;

  const text = receipt && formatModelResolvedResult(receipt);
  if (!text) {
    return {
      ...result,
      ok: false,
      text: undefined,
      error: "Model switch failed: the host did not return a valid model confirmation.",
    };
  }

  return { ...result, text };
}

function normalizeField(value) {
  return value.replace(/[\p{Cc}\p{Cf}\s]+/gu, " ").trim();
}

function displayField(value) {
  const neutralized = value.replaceAll("`", "'").replaceAll("@", "@\u200b");
  return truncate(neutralized, MAX_DISPLAY_FIELD_LENGTH);
}

function truncate(value, maxLength) {
  return value.length <= maxLength ? value : `${value.slice(0, maxLength - 1)}…`;
}
