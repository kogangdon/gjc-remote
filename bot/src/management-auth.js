import { randomBytes, scryptSync, timingSafeEqual } from "node:crypto";
import { isPrincipal } from "@gjc-remote/shared/identity";
import { canonicalJsonHash } from "@gjc-remote/shared/strict-json";

const KDF = Object.freeze({
  name: "scrypt",
  N: 16384,
  r: 8,
  p: 1,
  keyLength: 32,
  saltBytes: 16,
  maxmem: 32 * 1024 * 1024,
});
const requiredPrincipal = (value, name) => { if (!isPrincipal(value)) throw new TypeError(`${name.toUpperCase()}_INVALID`); return value; };
const requiredSecret = (value) => { if (typeof value !== "string" || value.length < 16 || Buffer.byteLength(value, "utf8") > 4096) throw new TypeError("AUTH_SECRET_INVALID"); return value; };
const principalKey = (value, name = "principal") => canonicalJsonHash(requiredPrincipal(value, name));
const deriveSecretHash = (secret, salt, kdf = KDF) => {
  requiredSecret(secret);
  if (
    kdf?.name !== KDF.name ||
    kdf.N !== KDF.N ||
    kdf.r !== KDF.r ||
    kdf.p !== KDF.p ||
    kdf.keyLength !== KDF.keyLength ||
    kdf.saltBytes !== KDF.saltBytes
  ) throw new Error("AUTH_KDF_INVALID");
  if (typeof salt !== "string" || !/^[0-9a-f]{32}$/.test(salt)) throw new Error("AUTH_SALT_INVALID");
  return scryptSync(secret, Buffer.from(salt, "hex"), kdf.keyLength, {
    N: kdf.N,
    r: kdf.r,
    p: kdf.p,
    maxmem: KDF.maxmem,
  }).toString("hex");
};
const newCredential = (principal, secret, epoch) => {
  const salt = randomBytes(KDF.saltBytes).toString("hex");
  return {
    version: 1,
    principal: structuredClone(principal),
    kdf: {
      name: KDF.name,
      N: KDF.N,
      r: KDF.r,
      p: KDF.p,
      keyLength: KDF.keyLength,
      saltBytes: KDF.saltBytes,
    },
    salt,
    hash: deriveSecretHash(secret, salt),
    epoch,
    revoked: false,
  };
};

export function bootstrapOwner(state, { actorPrincipal, osPrincipal, secret }) {
  const actorKey = principalKey(actorPrincipal, "actor principal");
  const osKey = principalKey(osPrincipal, "os principal");
  requiredSecret(secret);
  if (state.auth?.ownerPrincipal) throw new Error("GENESIS_OWNER_ALREADY_BOUND");
  if (actorKey !== osKey) throw new Error("GENESIS_OWNER_OS_BINDING_REQUIRED");
  state.auth = {
    version: 1,
    ownerPrincipal: structuredClone(actorPrincipal),
    ownerPrincipalKey: actorKey,
    credentials: {
      [actorKey]: newCredential(actorPrincipal, secret, 1),
    },
  };
  return state;
}

export const MANAGEMENT_AUTH_KDF = KDF;

export function authenticate(state, actorPrincipal, secret) {
  const key = principalKey(actorPrincipal, "actor principal");
  requiredSecret(secret);
  const credential = state.auth?.credentials?.[key];
  if (!credential || credential.revoked) throw new Error("AUTH_DENIED");
  if (credential.version !== 1) throw new Error("AUTH_CREDENTIAL_INVALID");
  const actual = Buffer.from(deriveSecretHash(secret, credential.salt, credential.kdf), "hex");
  const expected = typeof credential.hash === "string" && /^[0-9a-f]{64}$/.test(credential.hash)
    ? Buffer.from(credential.hash, "hex")
    : Buffer.alloc(0);
  if (actual.length !== expected.length || !timingSafeEqual(actual, expected)) throw new Error("AUTH_DENIED");
  return {
    actorPrincipal: structuredClone(actorPrincipal),
    owner: state.auth.ownerPrincipalKey === key,
    epoch: credential.epoch,
  };
}

export function requireOwner(identity) { if (!identity.owner) throw new Error("OWNER_REQUIRED"); }
export function addCredential(state, actor, targetPrincipal, secret) {
  const targetKey = principalKey(targetPrincipal, "target principal");
  requiredSecret(secret);
  requireOwner(authenticate(state, actor.actorPrincipal, actor.secret));
  if (state.auth.credentials[targetKey] && !state.auth.credentials[targetKey].revoked) {
    throw new Error("AUTH_PRINCIPAL_EXISTS");
  }
  const previous = state.auth.credentials[targetKey];
  state.auth.credentials[targetKey] = newCredential(targetPrincipal, secret, (previous?.epoch ?? 0) + 1);
  return state.auth.credentials[targetKey].epoch;
}

export function rotateCredential(state, actor, targetPrincipal, secret) {
  return addOrRotate(state, actor, targetPrincipal, secret);
}

export function revokeCredential(state, actor, targetPrincipal) {
  const targetKey = principalKey(targetPrincipal, "target principal");
  requireOwner(authenticate(state, actor.actorPrincipal, actor.secret));
  if (targetKey === state.auth.ownerPrincipalKey) throw new Error("OWNER_CANNOT_BE_REVOKED");
  const credential = state.auth.credentials[targetKey];
  if (!credential || credential.revoked) throw new Error("AUTH_PRINCIPAL_UNKNOWN");
  credential.revoked = true;
  credential.epoch += 1;
  return credential.epoch;
}

function addOrRotate(state, actor, targetPrincipal, secret) {
  const targetKey = principalKey(targetPrincipal, "target principal");
  requiredSecret(secret);
  requireOwner(authenticate(state, actor.actorPrincipal, actor.secret));
  const previous = state.auth.credentials[targetKey];
  if (!previous || previous.revoked) throw new Error("AUTH_PRINCIPAL_UNKNOWN");
  state.auth.credentials[targetKey] = newCredential(targetPrincipal, secret, previous.epoch + 1);
  return state.auth.credentials[targetKey].epoch;
}
