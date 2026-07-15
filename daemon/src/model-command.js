import { resolveModel } from "./model-lookup.js";

const LIST_ERROR = "Could not read the available model list.";
const NOT_FOUND_ERROR = "No matching model was found. Use provider:modelId for an exact selection.";
const SET_ERROR = "Could not set the selected model.";
const DISPLAY_PROVIDER_LENGTH = 64;
const DISPLAY_ID_LENGTH = 96;
const DISPLAY_NAME_LENGTH = 96;

/**
 * Resolve and set a session model using serialized RPC commands.
 *
 * @param {{send: (command: object, onEvent: (event: object) => void) => Promise<void>}} session
 * @param {{modelName?: unknown}} command
 * @param {(event: object) => void} onEvent
 * @returns {Promise<void>}
 */
export async function setSessionModel(session, command, onEvent) {
  let listResponse;
  try {
    await session.send({ type: "get_available_models" }, (event) => {
      if (event?.command === "get_available_models") listResponse = event;
    });
  } catch {
    throw new Error(LIST_ERROR);
  }

  let result;
  try {
    result = resolveModel(listResponse?.data?.models, command?.modelName);
  } catch {
    throw new Error(LIST_ERROR);
  }

  if (result.status === "not_found") throw new Error(NOT_FOUND_ERROR);
  if (result.status === "ambiguous") throw new Error(ambiguousMessage(result.candidates));

  try {
    await session.send(
      { type: "set_model", provider: result.provider, modelId: result.modelId },
      onEvent
    );
  } catch {
    throw new Error(SET_ERROR);
  }

  onEvent({
    type: "model_resolved",
    name: result.name,
    provider: result.provider,
    modelId: result.modelId,
  });
}

function ambiguousMessage(candidates) {
  const lines = candidates.slice(0, 5).map(
    (model) =>
      `${safeToken(model.provider, DISPLAY_PROVIDER_LENGTH)}:${safeToken(
        model.id,
        DISPLAY_ID_LENGTH
      )} — ${safeName(model.name, DISPLAY_NAME_LENGTH)}`
  );
  return `Model selection is ambiguous. Use provider:modelId. Candidates:\n${lines.join("\n")}`;
}

function safeToken(value, maximumLength) {
  return value
    .slice(0, maximumLength)
    .replace(/[^A-Za-z0-9._/+\-]/g, "?");
}

function safeName(value, maximumLength) {
  return value
    .slice(0, maximumLength)
    .replace(/[^A-Za-z0-9 .,+()/:'\-]/g, "?");
}
