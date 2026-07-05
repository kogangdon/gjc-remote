/**
 * Resolves a free-text model name (as typed into Discord's /model command,
 * e.g. "haiku", "opus", "gpt-5.2") against GJC's `get_available_models` list
 * to the exact {provider, modelId} pair `set_model` requires. GJC's CLI
 * `--model` flag does this fuzzy matching internally; the RPC protocol does
 * not expose that helper, so it is reimplemented here against the same data.
 *
 * @param {Array<{id: string, name: string, provider: string}>} models
 * @param {string} query
 * @returns {{ provider: string, modelId: string, name: string } | undefined}
 */
export function resolveModel(models, query) {
  const q = query.trim().toLowerCase();
  if (!q) return undefined;

  // Exact id match wins outright (e.g. "claude-haiku-4-5").
  const exact = models.find((m) => m.id.toLowerCase() === q);
  if (exact) return { provider: exact.provider, modelId: exact.id, name: exact.name };

  // Substring match against id or display name, preferring:
  //   1. names marked "(latest)"
  //   2. shorter ids (less likely to be a dated/pinned snapshot)
  const candidates = models.filter(
    (m) => m.id.toLowerCase().includes(q) || m.name.toLowerCase().includes(q)
  );
  if (candidates.length === 0) return undefined;

  candidates.sort((a, b) => {
    const aLatest = a.name.toLowerCase().includes("(latest)") ? 0 : 1;
    const bLatest = b.name.toLowerCase().includes("(latest)") ? 0 : 1;
    if (aLatest !== bLatest) return aLatest - bLatest;
    return a.id.length - b.id.length;
  });

  const best = candidates[0];
  return { provider: best.provider, modelId: best.id, name: best.name };
}
