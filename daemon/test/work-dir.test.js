import assert from "node:assert/strict";
import test from "node:test";

import { isFullyQualifiedWorkDir, validateNativeWorkDir } from "../src/work-dir.js";

test("POSIX platforms accept absolute paths", () => {
  assert.equal(isFullyQualifiedWorkDir("/srv/project", "linux"), true);
  assert.equal(isFullyQualifiedWorkDir("/Users/example/project", "darwin"), true);
  assert.equal(isFullyQualifiedWorkDir("/opt/project", "other"), true);
});

test("POSIX platforms reject Windows-looking, relative, and empty paths", () => {
  assert.equal(isFullyQualifiedWorkDir("C:\\project", "linux"), false);
  assert.equal(isFullyQualifiedWorkDir("C:/project", "linux"), false);
  assert.equal(isFullyQualifiedWorkDir("project", "linux"), false);
  assert.equal(isFullyQualifiedWorkDir("", "linux"), false);
  assert.equal(isFullyQualifiedWorkDir("   ", "linux"), false);
  assert.equal(isFullyQualifiedWorkDir(" /srv/project", "linux"), false);
  assert.equal(isFullyQualifiedWorkDir("/srv/project ", "linux"), false);
  assert.equal(isFullyQualifiedWorkDir(null, "linux"), false);
});

test("win32 accepts fully-qualified drive and UNC paths", () => {
  assert.equal(isFullyQualifiedWorkDir("C:\\project", "win32"), true);
  assert.equal(isFullyQualifiedWorkDir("D:/project", "win32"), true);
  assert.equal(isFullyQualifiedWorkDir("Z:\\", "win32"), true);
  assert.equal(isFullyQualifiedWorkDir("\\\\server\\share", "win32"), true);
  assert.equal(isFullyQualifiedWorkDir("//server/share/project", "win32"), true);
  assert.equal(isFullyQualifiedWorkDir("\\/server/share\\project", "win32"), true);
});

test("win32 rejects drive-relative, root-relative, POSIX-looking, and malformed UNC paths", () => {
  assert.equal(isFullyQualifiedWorkDir("C:project", "win32"), false);
  assert.equal(isFullyQualifiedWorkDir("\\project", "win32"), false);
  assert.equal(isFullyQualifiedWorkDir("/project", "win32"), false);
  assert.equal(isFullyQualifiedWorkDir("/srv/project", "win32"), false);
  assert.equal(isFullyQualifiedWorkDir("\\\\server", "win32"), false);
  assert.equal(isFullyQualifiedWorkDir("\\\\server\\", "win32"), false);
  assert.equal(isFullyQualifiedWorkDir("\\\\\\share", "win32"), false);
  assert.equal(isFullyQualifiedWorkDir("///server/share", "win32"), false);
  assert.equal(isFullyQualifiedWorkDir("", "win32"), false);
  assert.equal(isFullyQualifiedWorkDir(" C:\\project", "win32"), false);
});

test("validateNativeWorkDir returns the original validated string", () => {
  const workDir = "C:/project/mixed\\path";

  assert.equal(validateNativeWorkDir(workDir, "win32"), workDir);
});

test("validateNativeWorkDir throws a controlled error for invalid values", () => {
  const secret = "provider-secret-value";

  assert.throws(
    () => validateNativeWorkDir(`relative/${secret}`, "linux"),
    (error) => {
      assert.equal(error instanceof TypeError, true);
      assert.match(error.message, /fully qualified native path/);
      assert.equal(error.message.includes(secret), false);
      return true;
    }
  );
  assert.throws(() => validateNativeWorkDir(undefined, "win32"), TypeError);
});
