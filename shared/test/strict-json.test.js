import assert from "node:assert/strict";
import test from "node:test";
import {
  STRICT_JSON_LIMITS,
  parseCanonicalJsonBytes,
  parseStrictJson,
  parseStrictJsonBytes,
} from "../strict-json.js";

test("strict JSON rejects negative zero at every value position", () => {
  for (const source of [
    "-0",
    "-0 ",
    "[-0]",
    '{"value":-0}',
    '{"nested":[{"value":-0}]}',
  ]) {
    assert.throws(() => parseStrictJson(source), /negative zero/, source);
    assert.throws(
      () => parseStrictJsonBytes(Buffer.from(source)),
      /negative zero/,
      source
    );
  }
});

test("strict JSON preserves ordinary zero and negative integer parsing", () => {
  assert.equal(parseStrictJson("0"), 0);
  assert.equal(Object.is(parseStrictJson("0"), -0), false);
  assert.deepEqual(parseStrictJson('{"zero":0,"negative":-1}'), {
    zero: 0,
    negative: -1,
  });
});

test("strict parsing and canonical rendering agree on negative zero", () => {
  assert.throws(
    () => parseCanonicalJsonBytes(Buffer.from("-0")),
    /negative zero/
  );
  assert.throws(() => parseStrictJson("-0"), /negative zero/);
});

test("negative zero rejection survives whitespace and reports UTF-8 byte offsets", () => {
  assert.throws(() => parseStrictJson(" \n\t-0"), /negative zero at byte 3/);
  assert.throws(
    () => parseStrictJson('{"é":-0}'),
    /negative zero at byte 6/
  );
});

test("invalid negative-zero lookalikes remain rejected", () => {
  for (const source of ["-00", "-01", "-0.0", "-0e0", "-0E+1", "-0x"]) {
    assert.throws(() => parseStrictJson(source), SyntaxError, source);
  }
});

test("safe-integer and control-code contracts remain unchanged", () => {
  assert.equal(parseStrictJson("9007199254740991"), Number.MAX_SAFE_INTEGER);
  assert.equal(parseStrictJson("-9007199254740991"), Number.MIN_SAFE_INTEGER);
  assert.throws(() => parseStrictJson("9007199254740992"), /unsafe number/);
  assert.throws(() => parseStrictJson("-9007199254740992"), /unsafe number/);

  const options = { allowedValueControlCodes: new Set([0x0a]) };
  assert.equal(
    parseStrictJson('"\\n"', STRICT_JSON_LIMITS, options),
    "\n"
  );
  assert.throws(
    () => parseStrictJson('"\\n"'),
    /forbidden control character/
  );
  assert.throws(
    () => parseStrictJson("-0", STRICT_JSON_LIMITS, options),
    /negative zero/
  );
});
