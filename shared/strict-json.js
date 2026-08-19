import { createHash } from "node:crypto";

export const STRICT_JSON_LIMITS = Object.freeze({
  maxBytes: 1024 * 1024,
  maxDepth: 64,
  maxNodes: 10000,
});

export function utf8Compare(left, right) {
  return Buffer.compare(Buffer.from(left, "utf8"), Buffer.from(right, "utf8"));
}

export function isHex64(value) {
  return typeof value === "string" && /^[0-9a-f]{64}$/.test(value);
}

export function assertStrictText(value, name = "text", maxUtf8Bytes = Infinity) {
  if (typeof value !== "string") throw new TypeError(`${name} must be a string`);
  if (Buffer.byteLength(value, "utf8") > maxUtf8Bytes) throw new RangeError(`${name} exceeds its byte limit`);
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index);
    if ((code >= 0 && code <= 0x1f) || (code >= 0x7f && code <= 0x9f) || code === 0x2028 || code === 0x2029) {
      throw new SyntaxError(`${name} contains a forbidden control character`);
    }
    if (code >= 0xd800 && code <= 0xdfff) {
      const next = value.charCodeAt(index + 1);
      if (code <= 0xdbff && next >= 0xdc00 && next <= 0xdfff) index += 1;
      else throw new SyntaxError(`${name} contains an unpaired surrogate`);
    }
  }
  return value;
}

function assertJsonValue(value, depth, state) {
  if (depth > state.maxDepth) throw new RangeError("JSON nesting exceeds its depth limit");
  state.nodes += 1;
  if (state.nodes > state.maxNodes) throw new RangeError("JSON exceeds its node limit");
  if (value === null || typeof value === "boolean") return;
  if (typeof value === "string") return assertStrictText(value, "JSON string");
  if (typeof value === "number") {
    if (!Number.isSafeInteger(value)) throw new TypeError("JSON numbers must be safe integers");
    return;
  }
  if (Array.isArray(value)) {
    for (const item of value) assertJsonValue(item, depth + 1, state);
    return;
  }
  if (Object.getPrototypeOf(value) !== Object.prototype) throw new TypeError("JSON objects must be plain objects");
  for (const key of Object.keys(value)) {
    assertStrictText(key, "JSON object key");
    assertJsonValue(value[key], depth + 1, state);
  }
}

export function canonicalJson(value, limits = STRICT_JSON_LIMITS) {
  const state = { maxDepth: limits.maxDepth, maxNodes: limits.maxNodes, nodes: 0 };
  assertJsonValue(value, 0, state);
  const render = (item) => {
    if (item === null || typeof item === "boolean" || typeof item === "number") return JSON.stringify(item);
    if (typeof item === "string") return JSON.stringify(item);
    if (Array.isArray(item)) return `[${item.map(render).join(",")}]`;
    return `{${Object.keys(item).sort(utf8Compare).map((key) => `${JSON.stringify(key)}:${render(item[key])}`).join(",")}}`;
  };
  return render(value);
}

export function canonicalJsonBytes(value, limits) {
  return Buffer.from(canonicalJson(value, limits), "utf8");
}

export function canonicalJsonHash(value, limits) {
  return createHash("sha256").update(canonicalJsonBytes(value, limits)).digest("hex");
}

export function parseStrictJsonBytes(bytes, limits = STRICT_JSON_LIMITS, options) {
  if (!Buffer.isBuffer(bytes) && !(bytes instanceof Uint8Array)) throw new TypeError("JSON input must be bytes");
  if (bytes.byteLength > limits.maxBytes) throw new RangeError("JSON exceeds its byte limit");
  const input = Buffer.from(bytes);
  if (input.length >= 3 && input[0] === 0xef && input[1] === 0xbb && input[2] === 0xbf) throw new SyntaxError("JSON must not contain a BOM");
  let source;
  try { source = new TextDecoder("utf-8", { fatal: true }).decode(input); } catch { throw new SyntaxError("JSON is not valid UTF-8"); }
  return parseStrictJson(source, limits, options);
}
export function parseCanonicalJsonBytes(bytes, limits = STRICT_JSON_LIMITS) {
  const value = parseStrictJsonBytes(bytes, limits);
  const input = Buffer.from(bytes);
  if (!input.equals(canonicalJsonBytes(value, limits))) throw new SyntaxError("JSON is not canonically encoded");
  return value;
}

export function parseStrictJson(source, limits = STRICT_JSON_LIMITS, options = {}) {
  if (typeof source !== "string") throw new TypeError("JSON input must be a string");
  if (Buffer.byteLength(source, "utf8") > limits.maxBytes) throw new RangeError("JSON exceeds its byte limit");
  let at = 0;
  let nodes = 0;
  const fail = (message) => { throw new SyntaxError(`${message} at byte ${Buffer.byteLength(source.slice(0, at), "utf8")}`); };
  const whitespace = () => { while (/[ \t\n\r]/.test(source[at])) at += 1; };
  const string = (isKey = false) => {
    if (source[at] !== '"') fail("expected string");
    const start = at; at += 1;
    while (at < source.length) {
      const char = source[at++];
      if (char === '"') {
        let decoded;
        try { decoded = JSON.parse(source.slice(start, at)); } catch { fail("invalid string"); }
        if (isKey || !options.allowedValueControlCodes) {
          assertStrictText(decoded, "JSON string");
        } else {
          for (let index = 0; index < decoded.length; index += 1) {
            const code = decoded.charCodeAt(index);
            if (((code >= 0 && code <= 0x1f) || (code >= 0x7f && code <= 0x9f) || code === 0x2028 || code === 0x2029) &&
                !options.allowedValueControlCodes.has(code)) {
              throw new SyntaxError("JSON string contains a forbidden control character");
            }
            if (code >= 0xd800 && code <= 0xdfff) {
              const next = decoded.charCodeAt(index + 1);
              if (code <= 0xdbff && next >= 0xdc00 && next <= 0xdfff) index += 1;
              else throw new SyntaxError("JSON string contains an unpaired surrogate");
            }
          }
        }
        return decoded;
      }
      if (char === "\\") { at += 1; continue; }
      if (char.charCodeAt(0) <= 0x1f) fail("unescaped control character");
    }
    fail("unterminated string");
  };
  const value = (depth) => {
    if (depth > limits.maxDepth) throw new RangeError("JSON nesting exceeds its depth limit");
    nodes += 1; if (nodes > limits.maxNodes) throw new RangeError("JSON exceeds its node limit");
    whitespace(); const char = source[at];
    if (char === '"') return string();
    if (char === "{") {
      at += 1; whitespace(); const object = {};
      if (source[at] === "}") { at += 1; return object; }
      while (true) {
        whitespace(); const key = string(true); whitespace(); if (source[at++] !== ":") fail("expected colon");
        if (Object.hasOwn(object, key)) fail("duplicate object key");
        Object.defineProperty(object, key, { value: value(depth + 1), enumerable: true, writable: true, configurable: true }); whitespace();
        if (source[at] === "}") { at += 1; return object; }
        if (source[at++] !== ",") fail("expected comma");
      }
    }
    if (char === "[") {
      at += 1; whitespace(); const array = [];
      if (source[at] === "]") { at += 1; return array; }
      while (true) { array.push(value(depth + 1)); whitespace(); if (source[at] === "]") { at += 1; return array; } if (source[at++] !== ",") fail("expected comma"); }
    }
    const match = /^(?:-?(?:0|[1-9][0-9]*))(?![.eE0-9])/.exec(source.slice(at));
    if (match) {
      const token = match[0];
      if (token === "-0") fail("negative zero");
      at += token.length;
      const number = Number(token);
      if (!Number.isSafeInteger(number)) fail("unsafe number");
      return number;
    }
    for (const [literal, result] of [["true", true], ["false", false], ["null", null]]) if (source.startsWith(literal, at)) { at += literal.length; return result; }
    fail("expected value");
  };
  const result = value(0); whitespace(); if (at !== source.length) fail("trailing JSON data"); return result;
}
