import { resolveModel } from "./model-lookup.js";

const LIST_ERROR = "Could not read the available model list.";
const NOT_FOUND_ERROR = "No matching model was found. Use provider:modelId for an exact selection.";
const SET_ERROR = "Could not set the selected model.";
const DISPLAY_PROVIDER_LENGTH = 64;
const DISPLAY_ID_LENGTH = 96;
const DISPLAY_NAME_LENGTH = 96;
const REVOKED_BEFORE_START = "INVOKE_REVOKED_BEFORE_START";

function rejectRevoked(result) {
  if (result?.revokedBeforeStart !== true) return;
  const error = new Error("Request ownership was revoked before SDK dispatch");
  error.code = REVOKED_BEFORE_START;
  throw error;
}

class ModelCommandError extends Error {
  constructor(message, operation, cause) {
    super(message, { cause });
    this.name = "ModelCommandError";
    this.operation = operation;
  }
}

export function modelCommandDiagnostic(error) {
  if (!(error instanceof ModelCommandError)) return undefined;
  return `operation=${error.operation} category=${causeCategory(error.cause)}`;
}

function causeCategory(cause) {
  if (!(cause instanceof Error)) return "unknown";
  switch (cause.message) {
    case "SDK command timed out":
      return "timeout";
    case "SDK command exceeded absolute hard-cap":
      return "hard_cap";
    case "GJC SDK session is not running":
      return "session_closed";
    case "Available model list is invalid.":
      return "invalid_model_list";
    default:
      return "unknown";
  }
}

/**
 * Resolve and set a session model using serialized SDK commands.
 *
 * @param {{send: (command: object, onEvent: (event: object) => void) => Promise<void>}} session
 * @param {{modelName?: unknown}} command
 * @param {(event: object) => void} onEvent
 * @param {{sendCommand?: (command: object, onEvent: (event: object) => void) => Promise<unknown>}} [options]
 * @returns {Promise<void>}
 */
export async function setSessionModel(
  session,
  command,
  onEvent,
  { sendCommand = (sdkCommand, handler) => session.send(sdkCommand, handler) } = {}
) {
  let listResponse;
  try {
    const listResult = await sendCommand({ type: "get_available_models" }, (event) => {
      if (
        listResponse === undefined &&
        event?.command === "get_available_models" &&
        event.data &&
        Object.prototype.hasOwnProperty.call(event.data, "models")
      ) {
        listResponse = event;
      }
    });
    rejectRevoked(listResult);
  } catch (cause) {
    throw new ModelCommandError(LIST_ERROR, "list_models", cause);
  }

  let result;
  try {
    result = resolveModel(listResponse?.data?.models, command?.modelName);
  } catch (cause) {
    throw new ModelCommandError(LIST_ERROR, "validate_models", cause);
  }

  if (result.status === "not_found") throw new Error(NOT_FOUND_ERROR);
  if (result.status === "ambiguous") throw new Error(ambiguousMessage(result.candidates));

  try {
    const setResult = await sendCommand(
      { type: "set_model", provider: result.provider, modelId: result.modelId },
      onEvent
    );
    rejectRevoked(setResult);
  } catch (cause) {
    throw new ModelCommandError(SET_ERROR, "set_model", cause);
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
