import { emitOwnerEvent, validateOwnerObserver } from "./daemon-observability.js";

export const DEFAULT_MAX_IN_FLIGHT_INVOKES = 64;
export const LEGACY_RESOURCE_EXHAUSTED_ERROR =
  "Host invoke capacity is exhausted; retry later.";

export class AdmissionBudget {
  constructor({
    maxInFlightInvokes = DEFAULT_MAX_IN_FLIGHT_INVOKES,
    observer,
  } = {}) {
    if (!Number.isSafeInteger(maxInFlightInvokes) || maxInFlightInvokes < 1) {
      throw new TypeError("maxInFlightInvokes must be a positive safe integer");
    }
    const validatedObserver = validateOwnerObserver(observer);
    this.maxInFlightInvokes = maxInFlightInvokes;
    this.inFlightInvokes = 0;
    this.observer = validatedObserver;
  }

  tryAcquireInvoke() {
    if (this.inFlightInvokes >= this.maxInFlightInvokes) {
      emitOwnerEvent(this.observer, {
        name: "admission_budget",
        action: "invoke_capacity",
        outcome: "denied",
        code: "RESOURCE_EXHAUSTED",
      });
      return undefined;
    }
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
