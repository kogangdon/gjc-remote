import { win32 } from "node:path";

const PROFILE_FIELDS = Object.freeze([
  "agentDir",
  "credentialPath",
  "recipient",
  "configIdentity",
  "credentialIdentity",
]);
const CAPABILITIES = Object.freeze([
  "open_sdk_profile_target",
  "sdk_profile_target_facts",
  "assert_sdk_profile_target",
  "close_sdk_profile_target",
]);
const UNSUPPORTED_ENVIRONMENT = Object.freeze([
  "GJC_CONFIG_DIR",
  "PI_CONFIG_DIR",
  "GJC_CODING_AGENT_DIR",
  "PI_CODING_AGENT_DIR",
  "GJC_AUTH_BROKER_URL",
  "GJC_AUTH_BROKER_TOKEN",
]);
const SID = /^S-1-(?:[0-9]+-)+[0-9]+$/;
const FILE_ID = /^win32:[0-9a-f]{16}:[0-9a-f]{32}:[0-9a-f]{16}$/;
const LAYOUT = "win32-gjc-sqlite-only-v1";

export class SdkProfileTargetError extends Error {
  constructor(reason, options) {
    super(`SDK profile target refused: ${reason}`, options);
    this.name = "SdkProfileTargetError";
    this.code = "ERR_SDK_PROFILE_TARGET_REFUSED";
    this.reason = reason;
  }
}

function refuse(reason) {
  throw new SdkProfileTargetError(reason);
}

function targetFailure(error, reason) {
  if (error instanceof SdkProfileTargetError) return error;
  return new SdkProfileTargetError(
    error?.code === "ERR_SDK_PROFILE_TARGET_REFUSED" && typeof error.reason === "string"
      ? error.reason
      : reason,
    { cause: error },
  );
}

function dataRecord(value, fields) {
  if (
    value === null ||
    typeof value !== "object" ||
    Object.getPrototypeOf(value) !== Object.prototype ||
    Reflect.ownKeys(value).length !== fields.length
  ) {
    refuse("invalid-target-evidence");
  }
  const descriptors = Object.getOwnPropertyDescriptors(value);
  const result = {};
  for (const field of fields) {
    const descriptor = descriptors[field];
    if (!descriptor || !Object.hasOwn(descriptor, "value")) {
      refuse("invalid-target-evidence");
    }
    result[field] = descriptor.value;
  }
  return result;
}

function canonicalLocalPath(value) {
  return (
    typeof value === "string" &&
    value.length < 248 &&
    /^[A-Za-z]:\\/.test(value) &&
    !/[\u0000-\u001f<>"|?*/]/.test(value) &&
    !value.slice(2).includes(":") &&
    win32.normalize(value) === value &&
    value.split("\\").slice(1).every(part => part && !/[. ]$/.test(part))
  );
}

function profileRecord(value) {
  const profile = dataRecord(value, PROFILE_FIELDS);
  if (
    !canonicalLocalPath(profile.agentDir) ||
    !canonicalLocalPath(profile.credentialPath) ||
    profile.credentialPath !== win32.join(profile.agentDir, "agent.db") ||
    typeof profile.recipient !== "string" ||
    !SID.test(profile.recipient) ||
    typeof profile.configIdentity !== "string" ||
    !FILE_ID.test(profile.configIdentity) ||
    typeof profile.credentialIdentity !== "string" ||
    !FILE_ID.test(profile.credentialIdentity)
  ) {
    refuse("invalid-target-evidence");
  }
  return Object.freeze(profile);
}

function targetEvidence(value) {
  const facts = dataRecord(value, [
    "layout",
    "managementHome",
    "managerIdentity",
    "profile",
  ]);
  if (
    facts.layout !== LAYOUT ||
    !canonicalLocalPath(facts.managementHome) ||
    typeof facts.managerIdentity !== "string" ||
    !SID.test(facts.managerIdentity)
  ) {
    refuse("invalid-target-evidence");
  }
  const profile = profileRecord(facts.profile);
  if (profile.agentDir !== win32.join(facts.managementHome, ".gjc", "agent")) {
    refuse("profile-outside-authenticated-home");
  }
  return profile;
}

function assertEnvironment(env) {
  // Presence, not truthiness: even an empty override is unsupported. Do not
  // inspect or copy bearer tokens, and do not consult HOME/USERPROFILE.
  const keys = Object.keys(env);
  if (keys.some(key => UNSUPPORTED_ENVIRONMENT.includes(key.toUpperCase()))) {
    refuse("sdk-storage-override");
  }
}

function localStartupAuth(profile) {
  // SDK 0.20.0's public createAgentSession startupAuthConfig option suppresses
  // implicit broker discovery. Windows getAgentDbPath(explicit agentDir) is
  // exactly agentDir/agent.db, including when that directory is the default.
  // Native qualification refuses any config.yml BEFORE opening agent.db, so
  // this does not override an existing profile's auth settings. A config.yml
  // created after the final absence check cannot redirect this snapshot.
  return Object.freeze({
    broker: null,
    credentialStoreIdentity: `local:${profile.credentialPath}`,
    credentialRankingMode: "balanced",
    credentialPins: Object.freeze({}),
    credentialPreferences: Object.freeze({}),
  });
}

// `authority` is an opaque native object issued ONLY after verifying that the
// protected installation manifest belongs to the live service. It binds the
// manifest's management SID and current recipient token. There is deliberately
// no JS authority constructor, caller-supplied home/path, or enabled boolean.
// This is a qualification candidate, not a production capability. SDK 0.20.0
// opens a writable SQLite database by pathname (and creates WAL sidecars), not
// through these pins. Denying deletion alone neither prevents in-place writes
// nor proves the SDK's actual opens/reopens use the verified original object.
// Production also requires the verified service/worker token and OS boundary
// that prevents SDK work from publishing the management decision.
export function createSdkProfileTarget({
  native,
  authority,
  platform = process.platform,
  env = process.env,
} = {}) {
  // Only failed acquisition cleanup belongs here. Returned leases keep their
  // own pins until their SDK owner confirms disposal and closes that lease.
  const pendingTargetCleanup = new Set();
  let retryingCleanup;

  function retryTargetCleanup() {
    retryingCleanup ??= Promise.resolve().then(() => {
      const failures = [];
      for (const handle of [...pendingTargetCleanup]) {
        try {
          native.close_sdk_profile_target(handle);
          pendingTargetCleanup.delete(handle);
        } catch (error) {
          failures.push(targetFailure(error, "target-close-failed"));
        }
      }
      if (failures.length) {
        throw new SdkProfileTargetError("target-cleanup-failed", {
          cause: new AggregateError(failures, "SDK profile target cleanup retry failed"),
        });
      }
    }).finally(() => { retryingCleanup = undefined; });
    return retryingCleanup;
  }

  function available() {
    if (platform !== "win32") refuse("unsupported-platform");
    assertEnvironment(env);
    if (
      authority === undefined ||
      authority === null ||
      !CAPABILITIES.every(name => typeof native?.[name] === "function")
    ) {
      refuse("verified-bootstrap-authority-unavailable");
    }
  }

  function acquire(expected) {
    let handle;
    let opened = false;
    let profile;
    let failureReason = "target-open-failed";
    try {
      available();
      handle = native.open_sdk_profile_target(authority);
      opened = true;
      failureReason = "target-verification-failed";
      profile = targetEvidence(native.sdk_profile_target_facts(handle));
      if (expected && !PROFILE_FIELDS.every(field => expected[field] === profile[field])) {
        refuse("profile-identity-changed");
      }
      native.assert_sdk_profile_target(handle);
    } catch (error) {
      const failure = targetFailure(error, failureReason);
      if (opened) {
        try {
          native.close_sdk_profile_target(handle);
        } catch (cleanupError) {
          pendingTargetCleanup.add(handle);
          throw new SdkProfileTargetError("target-verification-and-cleanup-failed", {
            cause: new AggregateError([failure, targetFailure(cleanupError, "target-close-failed")],
              "SDK profile target verification and pin cleanup failed"),
          });
        }
      }
      throw failure;
    }
    let closed = false;
    return Object.freeze({
      profile,
      startupAuthConfig: localStartupAuth(profile),
      assertCurrent() {
        if (closed) refuse("target-closed");
        try {
          available();
          native.assert_sdk_profile_target(handle);
        } catch (error) {
          throw targetFailure(error, "target-verification-failed");
        }
      },
      // Retain this lease through confirmed SDK disposal, including failed or
      // withdrawn session creation. Revocation alone must not release pins
      // while already-started SDK work may still use the original store.
      close() {
        if (closed) return;
        try {
          native.close_sdk_profile_target(handle);
        } catch (error) {
          throw targetFailure(error, "target-close-failed");
        }
        closed = true;
      },
    });
  }

  return Object.freeze({
    prepare() {
      return acquire();
    },
    reopen(profile) {
      let expected;
      try {
        expected = profileRecord(profile);
      } catch (error) {
        throw targetFailure(error, "invalid-target-evidence");
      }
      return acquire(expected);
    },
    retryTargetCleanup,
  });
}
