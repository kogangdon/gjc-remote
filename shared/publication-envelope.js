import { canonicalJsonHash, isHex64 } from "./strict-json.js";

const plain = (value) => value !== null && typeof value === "object" && !Array.isArray(value) && Object.getPrototypeOf(value) === Object.prototype;
const exact = (value, keys) => plain(value) && Object.keys(value).length === keys.length && keys.every((key) => Object.hasOwn(value, key));
const fail = (message) => { throw new TypeError(`PUBLICATION_ENVELOPE_INVALID: ${message}`); };
const hash = (record, field) => canonicalJsonHash(Object.fromEntries(Object.entries(record).filter(([key]) => key !== field)));
const id = (value) => typeof value === "string" && value.length > 0 && value.length <= 256;
const nullableHex = (value) => value === null || isHex64(value);
const nullableId = (value) => value === null || id(value);
const transactionKeys = ["version", "kind", "txId", "genesisTxId", "generation", "baselineFingerprint", "transactionFingerprint"];
const uKeys = ["version", "kind", "txId", "genesisTxId", "generation", "baselineFingerprint", "anchorFingerprint", "targetState", "attestationFingerprint", "authorityReservationFingerprint", "authorityCommitSnapshotFingerprint", "fenceBindingFingerprint", "leaseBindingFingerprint", "readerProjectionFingerprint", "readerInstanceId", "readerStartNonce", "readerVersion", "publication-uFingerprint"];
const pKeys = ["version", "kind", "txId", "genesisTxId", "generation", "uFingerprint", "stateFingerprint", "targetState", "authorityCommitSnapshotFingerprint", "fenceBindingFingerprint", "leaseBindingFingerprint", "readerInstanceId", "readerStartNonce", "readerVersion", "publication-pFingerprint"];
const sKeys = ["version", "kind", "txId", "genesisTxId", "generation", "pFingerprint", "stateFingerprint", "payloadFingerprint", "targetState", "authorityCommitSnapshotFingerprint", "fenceBindingFingerprint", "readerVersion", "publication-sFingerprint"];
const cKeys = ["version", "kind", "txId", "genesisTxId", "generation", "sFingerprint", "stateFingerprint", "payloadFingerprint", "snapshotFingerprint", "authorityCommitSnapshotFingerprint", "fenceBindingFingerprint", "readerInstanceId", "readerStartNonce", "readerVersion", "publication-cFingerprint"];
const qKeys = ["version", "kind", "txId", "genesisTxId", "generation", "cFingerprint", "baselineFingerprint", "stateFingerprint", "payloadFingerprint", "snapshotFingerprint", "authorityCommitSnapshotFingerprint", "fenceBindingFingerprint", "publication-qFingerprint"];
const zpKeys = ["version", "kind", "txId", "genesisTxId", "generation", "qFingerprint", "publicationFingerprint", "stateFingerprint", "payloadFingerprint", "snapshotFingerprint", "publication-zpFingerprint"];
const kKeys = ["version", "kind", "txId", "genesisTxId", "generation", "zpFingerprint", "publicationFingerprint", "authorityCommitSnapshotFingerprint", "checkpointFingerprint", "publication-kFingerprint"];
const yKeys = ["version", "kind", "txId", "genesisTxId", "generation", "kFingerprint", "publicationFingerprint", "targetState", "authorityCommitSnapshotFingerprint", "fenceBindingFingerprint", "targetFingerprint", "publication-yFingerprint"];
const phaseKeys = ["version", "kind", "txId", "genesisTxId", "generation", "publicationFingerprint", "phase", "publicationStateFingerprint"];
const semanticTarget = (value) => ["genesis-empty", "handshake-pending", "managed-empty", "managed", "legacy-unmigrated", "legacy-retained"].includes(value);
const reader = (record) => {
  for (const key of ["fenceBindingFingerprint", "leaseBindingFingerprint", "readerProjectionFingerprint"]) if (!nullableHex(record[key])) fail("reader fingerprint");
  if (!nullableId(record.readerInstanceId) || !nullableId(record.readerStartNonce) || (record.readerVersion !== null && record.readerVersion !== 2)) fail("reader identity");
  if (record.readerVersion === null) {
    if ([record.fenceBindingFingerprint, record.leaseBindingFingerprint, record.readerProjectionFingerprint, record.readerInstanceId, record.readerStartNonce].some((value) => value !== null)) fail("reader null branch");
  } else if (!isHex64(record.fenceBindingFingerprint) || !id(record.readerInstanceId) || !id(record.readerStartNonce) || (record.leaseBindingFingerprint === null) !== (record.readerProjectionFingerprint === null)) {
    fail("reader bound branch");
  }
};
const common = (record, kind, keys, field) => {
  if (!exact(record, keys) || record.version !== 1 || record.kind !== kind || !id(record.txId) || !id(record.genesisTxId) || !Number.isSafeInteger(record.generation) || record.generation < 1 || !isHex64(record[field]) || hash(record, field) !== record[field]) fail(`${kind} schema`);
};
const hexes = (record, keys) => { for (const key of keys) if (!isHex64(record[key])) fail(`${key} relation`); };

export function validatePublicationTransaction(record, baselineFingerprint) {
  common(record, "publication-transaction", transactionKeys, "transactionFingerprint");
  hexes(record, ["baselineFingerprint"]);
  if (baselineFingerprint !== undefined && record.baselineFingerprint !== baselineFingerprint) fail("transaction baseline relation");
  return record;
}
export function validatePublicationU(record, baselineFingerprint) {
  common(record, "publication-u", uKeys, "publication-uFingerprint");
  hexes(record, ["baselineFingerprint", "anchorFingerprint", "attestationFingerprint", "authorityReservationFingerprint", "authorityCommitSnapshotFingerprint"]);
  if (!semanticTarget(record.targetState)) fail("u target state"); reader(record);
  if (baselineFingerprint !== undefined && record.baselineFingerprint !== baselineFingerprint) fail("u baseline relation");
  return record;
}
export function validatePublicationP(record, u, stateFingerprint = undefined) {
  common(record, "publication-p", pKeys, "publication-pFingerprint"); hexes(record, ["uFingerprint", "stateFingerprint", "authorityCommitSnapshotFingerprint"]);
  if (!semanticTarget(record.targetState)) fail("p semantic relation");
  if (stateFingerprint !== undefined && record.stateFingerprint !== stateFingerprint) fail("p canonical state relation");
  if (typeof u === "string" ? record.uFingerprint !== u : u && (record.uFingerprint !== u["publication-uFingerprint"] || record.targetState !== u.targetState || record.authorityCommitSnapshotFingerprint !== u.authorityCommitSnapshotFingerprint || record.fenceBindingFingerprint !== u.fenceBindingFingerprint || record.leaseBindingFingerprint !== u.leaseBindingFingerprint || record.readerInstanceId !== u.readerInstanceId || record.readerStartNonce !== u.readerStartNonce || record.readerVersion !== u.readerVersion)) fail("p u relation");
  return record;
}
export function validatePublicationS(record, p, { stateFingerprint, payloadFingerprint } = {}) {
  common(record, "publication-s", sKeys, "publication-sFingerprint"); hexes(record, ["pFingerprint", "stateFingerprint", "payloadFingerprint", "authorityCommitSnapshotFingerprint"]);
  if (!semanticTarget(record.targetState)) fail("s semantic relation");
  if ((stateFingerprint !== undefined && record.stateFingerprint !== stateFingerprint) || (payloadFingerprint !== undefined && record.payloadFingerprint !== payloadFingerprint)) fail("s canonical projection relation");
  if (typeof p === "string" ? record.pFingerprint !== p : p && (record.pFingerprint !== p["publication-pFingerprint"] || record.stateFingerprint !== p.stateFingerprint || record.targetState !== p.targetState || record.authorityCommitSnapshotFingerprint !== p.authorityCommitSnapshotFingerprint || record.fenceBindingFingerprint !== p.fenceBindingFingerprint || record.readerVersion !== p.readerVersion)) fail("s p relation");
  return record;
}
export function validatePublicationC(record, s, { stateFingerprint, payloadFingerprint, snapshotFingerprint } = {}) {
  common(record, "publication-c", cKeys, "publication-cFingerprint"); hexes(record, ["sFingerprint", "stateFingerprint", "payloadFingerprint", "snapshotFingerprint", "authorityCommitSnapshotFingerprint"]);
  if ((stateFingerprint !== undefined && record.stateFingerprint !== stateFingerprint) || (payloadFingerprint !== undefined && record.payloadFingerprint !== payloadFingerprint) || (snapshotFingerprint !== undefined && record.snapshotFingerprint !== snapshotFingerprint)) fail("c canonical projection relation");
  if (typeof s === "string" ? record.sFingerprint !== s : s && (record.sFingerprint !== s["publication-sFingerprint"] || record.stateFingerprint !== s.stateFingerprint || record.payloadFingerprint !== s.payloadFingerprint || record.authorityCommitSnapshotFingerprint !== s.authorityCommitSnapshotFingerprint || record.fenceBindingFingerprint !== s.fenceBindingFingerprint || record.readerVersion !== s.readerVersion)) fail("c s relation");
  return record;
}
export function validatePublicationQ(record, c, { stateFingerprint, payloadFingerprint, snapshotFingerprint } = {}) {
  common(record, "publication-q", qKeys, "publication-qFingerprint"); hexes(record, ["cFingerprint", "baselineFingerprint", "stateFingerprint", "payloadFingerprint", "snapshotFingerprint", "authorityCommitSnapshotFingerprint"]);
  if ((stateFingerprint !== undefined && record.stateFingerprint !== stateFingerprint) || (payloadFingerprint !== undefined && record.payloadFingerprint !== payloadFingerprint) || (snapshotFingerprint !== undefined && record.snapshotFingerprint !== snapshotFingerprint)) fail("q canonical projection relation");
  if (typeof c === "string" ? record.cFingerprint !== c : c && (record.cFingerprint !== c["publication-cFingerprint"] || record.stateFingerprint !== c.stateFingerprint || record.payloadFingerprint !== c.payloadFingerprint || record.snapshotFingerprint !== c.snapshotFingerprint || record.authorityCommitSnapshotFingerprint !== c.authorityCommitSnapshotFingerprint || record.fenceBindingFingerprint !== c.fenceBindingFingerprint)) fail("q c relation"); return record;
}
export function validatePublicationZp(record, q, { stateFingerprint, payloadFingerprint, snapshotFingerprint, publicationFingerprint } = {}) {
  common(record, "publication-zp", zpKeys, "publication-zpFingerprint"); hexes(record, ["qFingerprint", "publicationFingerprint", "stateFingerprint", "payloadFingerprint", "snapshotFingerprint"]);
  if ((stateFingerprint !== undefined && record.stateFingerprint !== stateFingerprint) || (payloadFingerprint !== undefined && record.payloadFingerprint !== payloadFingerprint) || (snapshotFingerprint !== undefined && record.snapshotFingerprint !== snapshotFingerprint) || (publicationFingerprint !== undefined && record.publicationFingerprint !== publicationFingerprint)) fail("zp canonical projection relation");
  if (typeof q === "string" ? record.qFingerprint !== q : q && (record.qFingerprint !== q["publication-qFingerprint"] || record.stateFingerprint !== q.stateFingerprint || record.payloadFingerprint !== q.payloadFingerprint || record.snapshotFingerprint !== q.snapshotFingerprint)) fail("zp q relation");
  return record;
}
export function validatePublicationK(record, zp, { publicationFingerprint, checkpointFingerprint } = {}) {
  common(record, "publication-k", kKeys, "publication-kFingerprint"); hexes(record, ["zpFingerprint", "publicationFingerprint", "authorityCommitSnapshotFingerprint", "checkpointFingerprint"]);
  if ((publicationFingerprint !== undefined && record.publicationFingerprint !== publicationFingerprint) || (checkpointFingerprint !== undefined && record.checkpointFingerprint !== checkpointFingerprint)) fail("k canonical projection relation");
  if (typeof zp === "string" ? record.zpFingerprint !== zp : zp && (record.zpFingerprint !== zp["publication-zpFingerprint"] || record.publicationFingerprint !== zp.publicationFingerprint)) fail("k zp relation");
  return record;
}
export function validatePublicationY(record, k, targetFingerprint = undefined, publicationFingerprint = undefined) {
  common(record, "publication-y", yKeys, "publication-yFingerprint"); hexes(record, ["kFingerprint", "publicationFingerprint", "authorityCommitSnapshotFingerprint", "targetFingerprint"]);
  if (!semanticTarget(record.targetState)) fail("y target state");
  if (typeof k === "string" ? record.kFingerprint !== k : k && (record.kFingerprint !== k["publication-kFingerprint"] || record.publicationFingerprint !== k.publicationFingerprint || record.authorityCommitSnapshotFingerprint !== k.authorityCommitSnapshotFingerprint)) fail("y k relation");
  if (targetFingerprint !== undefined && record.targetFingerprint !== targetFingerprint) fail("y canonical target relation");
  if (publicationFingerprint !== undefined && record.publicationFingerprint !== publicationFingerprint) fail("y canonical publication relation");
  return record;
}
export function validatePublicationState(record, transaction) {
  common(record, "publication-state", phaseKeys, "publicationStateFingerprint");
  if (!isHex64(record.publicationFingerprint) || !["prepared", "replaced", "committed"].includes(record.phase)) fail("publication state schema");
  if (transaction && (record.txId !== transaction.txId || record.genesisTxId !== transaction.genesisTxId || record.generation !== transaction.generation)) fail("publication state transaction relation"); return record;
}
const build = (kind, input, field) => { const record = { version: 1, kind, ...input, [field]: null }; record[field] = hash(record, field); return record; };
export const buildPublicationTransaction = (input) => validatePublicationTransaction(build("publication-transaction", input, "transactionFingerprint"));
export const buildPublicationU = (input) => validatePublicationU(build("publication-u", input, "publication-uFingerprint"));
export const buildPublicationP = (input) => validatePublicationP(build("publication-p", input, "publication-pFingerprint"));
export const buildPublicationS = (input) => validatePublicationS(build("publication-s", input, "publication-sFingerprint"));
export const buildPublicationC = (input) => validatePublicationC(build("publication-c", input, "publication-cFingerprint"));
export const buildPublicationQ = (input) => validatePublicationQ(build("publication-q", input, "publication-qFingerprint"));
export const buildPublicationZp = (input) => validatePublicationZp(build("publication-zp", input, "publication-zpFingerprint"));
export const buildPublicationK = (input) => validatePublicationK(build("publication-k", input, "publication-kFingerprint"));
export const buildPublicationY = (input) => validatePublicationY(build("publication-y", input, "publication-yFingerprint"));
export const buildPublicationState = (input) => validatePublicationState(build("publication-state", input, "publicationStateFingerprint"));
export function validatePublicationGraph(records, expected = undefined) {
  if (!plain(records) || !exact(records, ["transaction", "u", "p", "s", "prepared", "replaced", "committed", "c", "q", "zp", "k", "y"])) fail("graph schema");
  const { transaction, u, p, s, prepared, replaced, committed, c, q, zp, k, y } = records;
  validatePublicationTransaction(transaction);
  validatePublicationU(u, transaction.baselineFingerprint);
  validatePublicationP(p, u);
  validatePublicationS(s, p);
  for (const state of [prepared, replaced, committed]) validatePublicationState(state, transaction);
  if (prepared.phase !== "prepared" || replaced.phase !== "replaced" || committed.phase !== "committed") fail("graph phase");
  validatePublicationC(c, s); validatePublicationQ(q, c); validatePublicationZp(zp, q);
  validatePublicationK(k, zp); validatePublicationY(y, k);
  if ([u, p, s, prepared, replaced, committed, c, q, zp, k, y].some((record) =>
    record.txId !== transaction.txId || record.genesisTxId !== transaction.genesisTxId || record.generation !== transaction.generation ||
    record.publicationFingerprint !== undefined && record.publicationFingerprint !== zp.publicationFingerprint)) fail("graph identity");
  if (expected !== undefined && canonicalJsonHash(records) !== canonicalJsonHash(expected)) fail("graph live relation");
  return records;
}
