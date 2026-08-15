/**
 * Dispose requests that captured a binding which has been replaced.
 *
 * The request map is deliberately supplied by the daemon so this helper does
 * not own transport or session lifecycle state.
 */
export function invalidateBindingRequests(inFlightByRequestId, connection, bindingId) {
  for (const [requestId, request] of inFlightByRequestId) {
    if (request.connection !== connection || request.bindingId !== bindingId) {
      continue;
    }
    void Promise.resolve(request.session.dispose()).catch(() => {});
    inFlightByRequestId.delete(requestId);
  }
}
