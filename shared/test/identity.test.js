import assert from "node:assert/strict";
import { test } from "node:test";
import { isCanonicalWindowsSid } from "../identity.js";

test("canonical Windows SID enforces native revision and numeric boundaries", () => {
  for (const value of [
    "S-1-0-0", "S-1-5-18", "S-1-5-21-1001",
    "S-1-281474976710655-4294967295",
    `S-1-5${"-4294967295".repeat(15)}`,
  ]) assert.equal(isCanonicalWindowsSid(value), true, value);
  for (const value of [
    null, 1, {}, "uid:1001", "S-0-5-18", "S-2-5-18", "S-1-5",
    "s-1-5-18", "S-01-5-18", "S-1-05-18", "S-1-5-018",
    "S-1-281474976710656-0", "S-1-5-4294967296",
    `S-1-5${"-1".repeat(16)}`, `S-1-5-${"9".repeat(4096)}`,
  ]) assert.equal(isCanonicalWindowsSid(value), false, String(value));
});
