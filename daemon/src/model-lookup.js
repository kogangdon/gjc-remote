const MAX_MODELS = 1_000;
const MAX_MODEL_FIELD_LENGTH = 256;
const MAX_QUERY_LENGTH = 256;
const MAX_CANDIDATES = 5;
const INVALID_MODEL_LIST_MESSAGE = "Available model list is invalid.";

/**
 * Validate and copy an RPC model list without including its contents in errors.
 *
 * @param {unknown} value
 * @returns {Array<{id: string, name: string, provider: string}>}
 */
export function validateModelList(value) {
  if (!Array.isArray(value) || value.length > MAX_MODELS) {
    throw new Error(INVALID_MODEL_LIST_MESSAGE);
  }

  const identities = new Set();
  const models = value.map((entry) => {
    if (!isPlainRecord(entry)) throw new Error(INVALID_MODEL_LIST_MESSAGE);

    const id = validatedField(entry.id);
    const name = validatedField(entry.name);
    const provider = validatedField(entry.provider);
    if (id === undefined || name === undefined || provider === undefined) {
      throw new Error(INVALID_MODEL_LIST_MESSAGE);
    }

    const identity = `${provider.toLowerCase()}\0${id.toLowerCase()}`;
    if (identities.has(identity)) throw new Error(INVALID_MODEL_LIST_MESSAGE);
    identities.add(identity);
    return { id, name, provider };
  });

  return models;
}

/**
 * Resolve a query to an exact model identity or an explicit failure outcome.
 *
 * @param {unknown} value
 * @param {unknown} query
 * @returns {
 *   | {status: "resolved", name: string, provider: string, modelId: string}
 *   | {status: "not_found"}
 *   | {status: "ambiguous", candidates: Array<{id: string, name: string, provider: string}>}
 * }
 */
export function resolveModel(value, query) {
  const models = validateModelList(value);
  const normalizedQuery = normalizeQuery(query);
  if (normalizedQuery === undefined) return { status: "not_found" };

  const separator = normalizedQuery.indexOf(":");
  if (separator !== -1) {
    const provider = normalizedQuery.slice(0, separator).trim();
    const modelId = normalizedQuery.slice(separator + 1).trim();
    if (!provider || !modelId) return { status: "not_found" };

    const match = models.find(
      (model) =>
        model.provider.toLowerCase() === provider && model.id.toLowerCase() === modelId
    );
    return match ? resolved(match) : { status: "not_found" };
  }

  const exact = models.filter((model) => model.id.toLowerCase() === normalizedQuery);
  if (exact.length === 1) return resolved(exact[0]);
  if (exact.length > 1) return ambiguous(exact);

  const fuzzy = models.filter(
    (model) =>
      model.id.toLowerCase().includes(normalizedQuery) ||
      model.name.toLowerCase().includes(normalizedQuery)
  );
  if (fuzzy.length === 0) return { status: "not_found" };

  fuzzy.sort(compareModels);
  const best = fuzzy[0];
  const tied = fuzzy.filter((model) => sameRank(model, best));
  return tied.length === 1 ? resolved(best) : ambiguous(tied);
}

function normalizeQuery(query) {
  if (typeof query !== "string" || query.length > MAX_QUERY_LENGTH) return undefined;
  const normalized = query.trim().toLowerCase();
  return normalized || undefined;
}

function resolved(model) {
  return {
    status: "resolved",
    name: model.name,
    provider: model.provider,
    modelId: model.id,
  };
}

function ambiguous(models) {
  return {
    status: "ambiguous",
    candidates: [...models].sort(compareModels).slice(0, MAX_CANDIDATES),
  };
}

function compareModels(a, b) {
  const rank = latestRank(a) - latestRank(b) || a.id.length - b.id.length;
  if (rank !== 0) return rank;
  return (
    compareText(a.provider, b.provider) ||
    compareText(a.id, b.id) ||
    compareText(a.name, b.name)
  );
}

function compareText(a, b) {
  if (a === b) return 0;
  return a < b ? -1 : 1;
}

function sameRank(a, b) {
  return latestRank(a) === latestRank(b) && a.id.length === b.id.length;
}

function latestRank(model) {
  return model.name.toLowerCase().includes("(latest)") ? 0 : 1;
}

function validatedField(value) {
  if (
    typeof value !== "string" ||
    value.length === 0 ||
    value.length > MAX_MODEL_FIELD_LENGTH ||
    value.trim() !== value ||
    /[\p{Cc}\p{Cf}]/u.test(value)
  ) {
    return undefined;
  }
  return value;
}

function isPlainRecord(value) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}
