import assert from "node:assert/strict";
import test from "node:test";
import {
  buildBundleInventory,
  validateBundleInventory,
} from "../deployment-envelope.js";

const payloads = (paths) => paths.map((path) => ({
  path,
  size: 1,
  sha256: "a".repeat(64),
  executablePolicy: "forbidden",
}));
const inventory = (paths, platform) => buildBundleInventory({ payloadEntries: payloads(paths) }, { platform });

for (const paths of [
  ["a", "a/child.js"],
  ["a", "a-other.js", "a/child.js"],
  ["bundle-files.json/child.js"],
]) {
  test(`inventory rejects file/directory conflict: ${paths.join(", ")}`, () => {
    for (const platform of ["linux", "win32"]) {
      assert.throws(() => inventory(paths, platform), /collision/);
    }
  });
}

for (const paths of [
  ["I.js", "ı.js"],
  ["ß.js", "ẞ.js"],
  ["Dir/a.js", "dir/b.js"],
  ["I/a.js", "ı/b.js"],
  ["BUNDLE-FILES.JSON"],
  ["BUNDLE-FILES.JSON/child.js"],
  ["A/child.js", "a"],
]) {
  test(`Windows inventory rejects caseless tree aliases: ${paths.join(", ")}`, () => {
    assert.throws(() => inventory(paths, "win32"), /collision/);
    const linuxInventory = inventory(paths, "linux");
    assert.equal(validateBundleInventory(linuxInventory, { platform: "linux" }), linuxInventory);
    assert.throws(() => validateBundleInventory(linuxInventory, { platform: "win32" }), /collision/);
  });
}

for (const path of ["a<b.js", "a>b.js", 'a"b.js', "a|b.js", "a?b.js", "a*b.js", "COM¹.txt", "LPT²", "CONIN$", "CONOUT$.txt"]) {
  test(`Windows inventory rejects unsupported path component: ${path}`, () => {
    assert.throws(() => inventory([path], "win32"), /inventory payload path/);
    const linuxInventory = inventory([path], "linux");
    assert.throws(() => validateBundleInventory(linuxInventory, { platform: "win32" }), /inventory payload path/);
  });
}

test("valid sibling trees preserve the same content fingerprint across target policies", () => {
  const paths = ["a-other.js", "a/child.js", "a/nested/one.js", "a/nested/two.js", "z/file.js"];
  const linux = inventory(paths, "linux");
  const windows = inventory(paths, "win32");
  assert.equal(windows.treeFingerprint, linux.treeFingerprint);
  assert.equal(windows.inventoryFingerprint, linux.inventoryFingerprint);
  assert.equal(validateBundleInventory(windows, { platform: "win32" }), windows);
});
