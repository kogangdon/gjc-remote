export function parseRequireAllowlist(raw) {
  if (raw === undefined || raw === "" || raw === "0") return false;
  if (raw === "1") return true;

  throw new TypeError('GJC_REMOTE_REQUIRE_ALLOWLIST must be unset, empty, "0", or "1".');
}

export function createAuthorizationPolicy(allowedUsers, { required } = {}) {
  if (!Array.isArray(allowedUsers)) {
    throw new TypeError("GJC_BOT_ALLOWED_USERS must be an array of user IDs.");
  }
  if (allowedUsers.some((userId) => typeof userId !== "string")) {
    throw new TypeError("GJC_BOT_ALLOWED_USERS must contain only string user IDs.");
  }
  if (typeof required !== "boolean") {
    throw new TypeError("Authorization policy required must be a boolean.");
  }

  const allowedUserIds = new Set(allowedUsers);
  const unrestricted = allowedUserIds.size === 0;
  if (required && unrestricted) {
    throw new TypeError("GJC_BOT_ALLOWED_USERS must contain at least one user ID when GJC_REMOTE_REQUIRE_ALLOWLIST=1.");
  }

  return Object.freeze({
    unrestricted,
    isAuthorized(userId) {
      return typeof userId === "string" && (unrestricted || allowedUserIds.has(userId));
    },
  });
}
