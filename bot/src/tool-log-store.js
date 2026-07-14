export const TOOL_LOG_TTL_MS = 60 * 60 * 1000;
export const TOOL_LOG_MAX_ENTRIES = 100;

export class ToolLogStore {
  #entries = new Map();
  #nextId = 0;
  #now;
  #ttlMs;
  #maxEntries;

  constructor({ now = Date.now, ttlMs = TOOL_LOG_TTL_MS, maxEntries = TOOL_LOG_MAX_ENTRIES } = {}) {
    this.#now = now;
    this.#ttlMs = ttlMs;
    this.#maxEntries = maxEntries;
  }

  add(toolCalls) {
    const now = this.#now();
    this.#pruneExpired(now);

    const id = String(++this.#nextId);
    this.#entries.set(id, { toolCalls, createdAt: now });
    this.#trimToLimit();
    return id;
  }

  get(id) {
    this.#pruneExpired(this.#now());
    return this.#entries.get(id);
  }

  get size() {
    return this.#entries.size;
  }

  #pruneExpired(now) {
    for (const [id, entry] of this.#entries) {
      if (now - entry.createdAt >= this.#ttlMs) this.#entries.delete(id);
    }
  }

  #trimToLimit() {
    while (this.#entries.size > this.#maxEntries) {
      const oldestId = this.#entries.keys().next().value;
      this.#entries.delete(oldestId);
    }
  }
}
