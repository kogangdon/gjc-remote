import { canonicalJsonHash, isHex64, parseStrictJsonBytes } from "./strict-json.js";

export const SDK_PROFILE_MANAGEMENT_CAPABILITY = "sdk_profile_management_v1";
export const SDK_PROFILE_MANAGEMENT_TYPES = Object.freeze({
  REQUEST: "sdk_profile_management",
  RESULT: "sdk_profile_management_result",
});
export const SDK_PROFILE_MANAGEMENT_LIMITS = Object.freeze({
  maxBytes: 2048,
  maxDepth: 4,
  maxNodes: 32,
});
export const SDK_PROFILE_MANAGEMENT_ERROR_CODES = Object.freeze({
  NOT_AUTHORIZED: "NOT_AUTHORIZED",
  MANAGEMENT_UNAVAILABLE: "MANAGEMENT_UNAVAILABLE",
  DECISION_CONFLICT: "DECISION_CONFLICT",
  DECISION_UNAVAILABLE: "DECISION_UNAVAILABLE",
  CANDIDATE_UNAVAILABLE: "CANDIDATE_UNAVAILABLE",
  CANDIDATE_CHANGED: "CANDIDATE_CHANGED",
  PERSISTENCE_FAILED: "PERSISTENCE_FAILED",
  INVALID_REQUEST: "INVALID_REQUEST",
  INVALID_RESPONSE: "INVALID_RESPONSE",
  UNSUPPORTED: "UNSUPPORTED",
  HOST_OFFLINE: "HOST_OFFLINE",
  CONNECTION_LOST: "CONNECTION_LOST",
  REQUEST_TIMEOUT: "REQUEST_TIMEOUT",
  SEND_FAILED: "SEND_FAILED",
  BUSY: "BUSY",
});

const operations = new Set(["status", "allow", "withdraw"]);
const errorCodes = new Set(Object.values(SDK_PROFILE_MANAGEMENT_ERROR_CODES));
const requestKeys = ["type", "version", "requestId", "operation"];
const resultKeys = [...requestKeys, "ok"];
const decisionKeys = ["version", "grantId", "allowed", "profileFingerprint"];
const plain = (value) => value !== null && typeof value === "object" &&
  Object.getPrototypeOf(value) === Object.prototype;
const exact = (value, keys) => plain(value) &&
  Reflect.ownKeys(value).length === keys.length &&
  keys.every((key) => Object.hasOwn(value, key));
const requestId = (value) => typeof value === "string" &&
  /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/.test(value);
const fail = () => { throw new TypeError("SDK_PROFILE_MANAGEMENT_INVALID"); };

/** Public, path-free projection. Withdrawal retains the last profile and grant ID. */
export function isPublicSdkProfileDecision(value) {
  return exact(value, decisionKeys) && value.version === 1 &&
    typeof value.allowed === "boolean" &&
    (value.grantId === null
      ? value.allowed === false && value.profileFingerprint === null
      : Number.isSafeInteger(value.grantId) && value.grantId > 0 &&
        isHex64(value.profileFingerprint));
}

/** CAS covers every public decision field, including withdrawal at the same grant ID. */
export function sdkProfileDecisionFingerprint(decision) {
  if (!isPublicSdkProfileDecision(decision)) fail();
  return canonicalJsonHash(decision);
}

export function isSdkProfileManagementRequest(value) {
  if (!plain(value) || value.type !== SDK_PROFILE_MANAGEMENT_TYPES.REQUEST ||
      value.version !== 1 || !requestId(value.requestId) ||
      !operations.has(value.operation)) return false;
  if (value.operation === "status") return exact(value, requestKeys);
  return exact(value, [...requestKeys, "expectedDecisionFingerprint",
    ...(value.operation === "allow" ? ["candidateId"] : [])]) &&
    isHex64(value.expectedDecisionFingerprint) &&
    (value.operation !== "allow" || isHex64(value.candidateId));
}

export function validateSdkProfileManagementRequest(value) {
  if (!isSdkProfileManagementRequest(value)) fail();
  return value;
}

export function buildSdkProfileManagementRequest(fields) {
  return validateSdkProfileManagementRequest({
    ...fields,
    type: SDK_PROFILE_MANAGEMENT_TYPES.REQUEST,
    version: 1,
  });
}

export function isSdkProfileManagementResult(value, request) {
  if (!plain(value) || value.type !== SDK_PROFILE_MANAGEMENT_TYPES.RESULT ||
      value.version !== 1 || !requestId(value.requestId) ||
      !operations.has(value.operation) || typeof value.ok !== "boolean") return false;
  if (request !== undefined && (!isSdkProfileManagementRequest(request) ||
      value.requestId !== request.requestId || value.operation !== request.operation)) return false;
  if (!value.ok) return exact(value, [...resultKeys, "code"]) && errorCodes.has(value.code);
  if (!exact(value, [...resultKeys, "decision", "decisionFingerprint",
        ...(value.operation === "status" ? ["candidateId"] : [])]) ||
      !isPublicSdkProfileDecision(value.decision) ||
      value.decisionFingerprint !== sdkProfileDecisionFingerprint(value.decision)) return false;
  if (value.operation === "status") return value.candidateId === null || isHex64(value.candidateId);
  if (value.operation === "withdraw") return value.decision.allowed === false;
  return value.decision.allowed === true &&
    (request === undefined || value.decision.profileFingerprint === request.candidateId);
}

export function validateSdkProfileManagementResult(value, request) {
  if (!isSdkProfileManagementResult(value, request)) fail();
  return value;
}

export function buildSdkProfileManagementResult(fields, request) {
  return validateSdkProfileManagementResult({
    ...fields,
    type: SDK_PROFILE_MANAGEMENT_TYPES.RESULT,
    version: 1,
  }, request);
}

export function parseSdkProfileManagementRequest(bytes) {
  return validateSdkProfileManagementRequest(
    parseStrictJsonBytes(bytes, SDK_PROFILE_MANAGEMENT_LIMITS)
  );
}

export function parseSdkProfileManagementResult(bytes, request) {
  return validateSdkProfileManagementResult(
    parseStrictJsonBytes(bytes, SDK_PROFILE_MANAGEMENT_LIMITS), request
  );
}
