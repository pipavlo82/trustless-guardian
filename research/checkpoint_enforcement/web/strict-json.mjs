
export const MAX_DOCUMENT_BYTES = 256 * 1024;
const forbidden = new Set(['__proto__', 'prototype', 'constructor']);
export function problem(code, message) {
  return Object.assign(new Error(message), { code });
}
function scalarString(value) {
  for (let i = 0; i < value.length; i++) {
    const n = value.charCodeAt(i);
    if (n >= 0xd800 && n <= 0xdbff) {
      const next = value.charCodeAt(++i);
      if (!(next >= 0xdc00 && next <= 0xdfff)) throw problem('INVALID_UNICODE', 'Unpaired high surrogate.');
    } else if (n >= 0xdc00 && n <= 0xdfff) throw problem('INVALID_UNICODE', 'Unpaired low surrogate.');
  }
  return value;
}
function validKey(key) {
  scalarString(key);
  if (!/^[\x20-\x7e]+$/.test(key) || forbidden.has(key)) throw problem('INVALID_JSON_KEY', 'Keys must be safe ASCII names.');
}
export function parseStrict(input) {
  if (!(typeof input === 'string')) {
    throw problem('INVALID_JSON_INPUT', 'Supply UTF-8 JSON text or bytes.');
  }
  if (typeof input === 'string') scalarString(input);
  const bytes = new TextEncoder().encode(input);
  if (bytes.length > MAX_DOCUMENT_BYTES) throw problem('INPUT_TOO_LARGE', 'JSON document exceeds 256 KiB.');
  let text;
  try { text = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes); }
  catch { throw problem('INVALID_UTF8', 'JSON must be valid UTF-8.'); }
  let at = 0;
  const error = () => { throw problem('MALFORMED_JSON', `Invalid JSON at character ${at}.`); };
  const space = () => { while (at < text.length && /[ \t\r\n]/.test(text[at])) at++; };
  const string = () => {
    if (text[at] !== '"') error();
    const start = at++;
    while (at < text.length) {
      if (text[at] === '\\') { at += 2; continue; }
      if (text[at++] === '"') {
        try { return scalarString(JSON.parse(text.slice(start, at))); }
        catch (e) { if (e.code) throw e; error(); }
      }
    }
    error();
  };
  const value = (depth) => {
    space();
    if (text[at] === '{' || text[at] === '[') {
      if (depth >= 32) throw problem('JSON_NESTING_LIMIT', 'Maximum nesting is 32 containers.');
      if (text[at++] === '{') {
        const obj = Object.create(null);
        space();
        if (text[at] === '}') { at++; return obj; }
        for (;;) {
          space();
          const key = string();
          validKey(key);
          if (Object.hasOwn(obj, key)) throw problem('DUPLICATE_JSON_KEY', `Duplicate member ${key}.`);
          space();
          if (text[at++] !== ':') error();
          obj[key] = value(depth + 1);
          space();
          const delimiter = text[at++];
          if (delimiter === '}') return obj;
          if (delimiter !== ',') error();
        }
      }
      const array = [];
      space();
      if (text[at] === ']') { at++; return array; }
      for (;;) {
        array.push(value(depth + 1));
        space();
        const delimiter = text[at++];
        if (delimiter === ']') return array;
        if (delimiter !== ',') error();
      }
    }
    if (text[at] === '"') return string();
    for (const [word, result] of [['true', true], ['false', false], ['null', null]]) {
      if (text.startsWith(word, at)) { at += word.length; return result; }
    }
    const match = /^-?(?:0|[1-9][0-9]*)/.exec(text.slice(at));
    if (match) {
      at += match[0].length;
      const n = Number(match[0]);
      if (/[.eE]/.test(text[at] ?? '') || !Number.isSafeInteger(n) || Object.is(n, -0)) {
        throw problem('UNSAFE_JSON_NUMBER', 'Only exact safe integers are admitted.');
      }
      return n;
    }
    error();
  };
  const result = value(0);
  space();
  if (at !== text.length) error();
  return result;
}
export function canonicalize(input) {
  const seen = new Set();
  const visit = (value, depth) => {
    if (value === null) return 'null';
    if (typeof value === 'string') return JSON.stringify(scalarString(value));
    if (typeof value === 'boolean') return value ? 'true' : 'false';
    if (typeof value === 'number') {
      if (!Number.isSafeInteger(value) || Object.is(value, -0)) throw problem('UNSAFE_JSON_NUMBER', 'Only exact safe integers are admitted.');
      return String(value);
    }
    if (typeof value !== 'object') throw problem('NON_JSON_VALUE', 'Value is outside the canonical JSON domain.');
    if (depth >= 32) throw problem('JSON_NESTING_LIMIT', 'Maximum nesting is 32 containers.');
    if (seen.has(value)) throw problem('CYCLIC_JSON_VALUE', 'Cycles are not JSON.');
    seen.add(value);
    let output;
    if (Array.isArray(value)) {
      if (Object.getOwnPropertyNames(value).length !== value.length + 1 || Object.keys(value).length !== value.length || Object.getOwnPropertySymbols(value).length) throw problem('NON_JSON_VALUE', 'Sparse/decorated arrays are not admitted.');
      const items = [];
      for (let i = 0; i < value.length; i++) {
        const descriptor = Object.getOwnPropertyDescriptor(value, String(i));
        if (!descriptor || !Object.hasOwn(descriptor, 'value') || !descriptor.enumerable) throw problem('NON_JSON_VALUE', 'Array accessors are not JSON.');
        items.push(visit(descriptor.value, depth + 1));
      }
      output = '[' + items.join(',') + ']';
    } else {
      if (![null, Object.prototype].includes(Object.getPrototypeOf(value)) || Object.getOwnPropertySymbols(value).length) throw problem('NON_JSON_VALUE', 'Only plain JSON objects are admitted.');
      if (Object.getOwnPropertyNames(value).length !== Object.keys(value).length) throw problem('NON_JSON_VALUE', 'Hidden object members are not JSON.');
      output = '{' + Object.keys(value).sort().map((key) => {
        validKey(key);
        const descriptor = Object.getOwnPropertyDescriptor(value, key);
        if (!Object.hasOwn(descriptor, 'value')) throw problem('NON_JSON_VALUE', 'Accessors are not JSON.');
        return JSON.stringify(key) + ':' + visit(descriptor.value, depth + 1);
      }).join(',') + '}';
    }
    seen.delete(value);
    return output;
  };
  const bytes = new TextEncoder().encode(visit(input, 0));
  if (bytes.length > MAX_DOCUMENT_BYTES) throw problem('INPUT_TOO_LARGE', 'Canonical JSON exceeds 256 KiB.');
  return bytes;
}
