export const HOSTS_REPLY_MAX_LENGTH = 1_900;
const MAX_VISIBLE_BINDINGS = 4;
const MAX_VISIBLE_ID_LENGTH = 96;

function boundedId(value) {
  const text = typeof value === "string" ? value : "unknown";
  return text.length <= MAX_VISIBLE_ID_LENGTH
    ? text
    : `${text.slice(0, MAX_VISIBLE_ID_LENGTH - 3)}...`;
}

export function formatHostProjection(projection) {
  const hostId = boundedId(projection?.hostId);
  const aggregate =
    typeof projection?.aggregate === "string" ? projection.aggregate : "unknown";
  const dimensions =
    projection?.dimensions && typeof projection.dimensions === "object"
      ? Object.entries(projection.dimensions)
          .map(([name, value]) => `${name}=${String(value)}`)
          .join(", ")
      : "";
  const details = [`${hostId}: ${aggregate}`];
  if (dimensions) details.push(dimensions);
  if (Array.isArray(projection?.bindings) && projection.bindings.length > 0) {
    const visible = projection.bindings.slice(0, MAX_VISIBLE_BINDINGS).map(
      (binding) =>
        `${boundedId(binding?.bindingId)}/${boundedId(binding?.workspaceId)}=` +
        `${typeof binding?.aggregate === "string" ? binding.aggregate : "unknown"}`
    );
    const omitted = projection.bindings.length - visible.length;
    details.push(`bindings: ${visible.join(", ")}${omitted > 0 ? `, +${omitted} more` : ""}`);
  }
  return details.join(" — ");
}

export function formatHostList(projections, maxLength = HOSTS_REPLY_MAX_LENGTH) {
  if (!Array.isArray(projections) || projections.length === 0) {
    return "No hosts connected.";
  }
  const lines = [];
  for (let index = 0; index < projections.length; index += 1) {
    const line = formatHostProjection(projections[index]);
    const remaining = projections.length - index - 1;
    const omission = remaining > 0 ? `\n... +${remaining} hosts omitted` : "";
    const candidate = [...lines, line].join("\n");
    if (`${candidate}${omission}`.length > maxLength) {
      const omitted = projections.length - index;
      const suffix = `... +${omitted} hosts omitted`;
      if (lines.length === 0) {
        return `${line.slice(0, Math.max(0, maxLength - suffix.length - 1))}\n${suffix}`;
      }
      return `${lines.join("\n")}\n${suffix}`;
    }
    lines.push(line);
  }
  return lines.join("\n");
}
