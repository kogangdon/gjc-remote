export class RequestIdFence {
  constructor() {
    this.reservations = new Map();
  }

  tryAcquire(requestId) {
    if (this.reservations.has(requestId)) return undefined;
    const token = Symbol(requestId);
    this.reservations.set(requestId, token);
    let released = false;
    return () => {
      if (released) return;
      released = true;
      if (this.reservations.get(requestId) === token) {
        this.reservations.delete(requestId);
      }
    };
  }

  has(requestId) {
    return this.reservations.has(requestId);
  }

  get size() {
    return this.reservations.size;
  }
}
