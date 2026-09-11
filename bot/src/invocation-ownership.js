export class InvocationOwnership {
  constructor() {
    this.entries = new Map();
  }

  reserve(channelId, userId, hostId) {
    const key = `${channelId}:${userId}`;
    if (this.entries.has(key)) return undefined;
    const ownership = { key, hostId, requestId: undefined };
    this.entries.set(key, ownership);
    return ownership;
  }

  attachRequest(ownership, requestId) {
    if (this.entries.get(ownership?.key) !== ownership) return false;
    ownership.requestId = requestId;
    return true;
  }

  get(channelId, userId) {
    return this.entries.get(`${channelId}:${userId}`);
  }

  release(ownership) {
    if (this.entries.get(ownership?.key) !== ownership) return false;
    this.entries.delete(ownership.key);
    return true;
  }
}
