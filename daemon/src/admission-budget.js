export const DEFAULT_MAX_IN_FLIGHT_INVOKES = 64;

export class AdmissionBudget {
  constructor({ maxInFlightInvokes = DEFAULT_MAX_IN_FLIGHT_INVOKES } = {}) {
    if (!Number.isSafeInteger(maxInFlightInvokes) || maxInFlightInvokes < 1) {
      throw new TypeError("maxInFlightInvokes must be a positive safe integer");
    }
    this.maxInFlightInvokes = maxInFlightInvokes;
    this.inFlightInvokes = 0;
  }

  tryAcquireInvoke() {
    if (this.inFlightInvokes >= this.maxInFlightInvokes) return undefined;
    this.inFlightInvokes += 1;
    let released = false;
    return () => {
      if (released) return;
      released = true;
      this.inFlightInvokes -= 1;
    };
  }

  snapshot() {
    return Object.freeze({
      inFlightInvokes: this.inFlightInvokes,
      maxInFlightInvokes: this.maxInFlightInvokes,
    });
  }
}
