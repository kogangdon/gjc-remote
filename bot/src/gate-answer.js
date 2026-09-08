// A chat reply to a gate is never reinterpreted as a new prompt on failure.
// Remote acceptance, not transport submission, retires its presentation.
export async function deliverGateAnswer({
  pendingGateByChannel,
  channelId,
  answer,
  answerGate,
  onAccepted,
  onRejected,
}) {
  const pending = pendingGateByChannel.get(channelId);
  if (!pending) return false;
  let result;
  try {
    result = await answerGate(
      pending.hostId,
      pending.requestId,
      pending.gateId,
      answer
    );
  } catch {
    result = { ok: false, error: "gate answer delivery failed" };
  }
  if (result?.ok === true) {
    // A successor may have been presented before the predecessor's receipt.
    if (pendingGateByChannel.get(channelId) === pending) {
      pendingGateByChannel.delete(channelId);
    }
    await onAccepted();
  } else {
    await onRejected({
      ...(result ?? { ok: false, error: "gate answer was not accepted" }),
      retryable: pendingGateByChannel.get(channelId) === pending,
    });
  }
  return true;
}
