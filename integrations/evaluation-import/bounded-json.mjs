// Internal parser for hostile JSON text. Never returns input in an error.
// Building null-prototype objects and rejecting duplicate/unsafe keys avoids
// ambiguous field selection and prototype mutation before format validation.
// Sized from real Promptfoo exports (2026-10-19): 65 to 70 row runs are about 1.4 MB and
// 11,000 to 12,000 nodes, and a single response.output reached 316 KB. Every bound still
// applies to discarded fields.
export const LIMITS = Object.freeze({
  maxBytes: 16_777_216,
  maxDepth: 24,
  maxNodes: 200_000,
  maxArrayItems: 1_000,
  maxObjectKeys: 256,
  maxStringBytes: 1_048_576,
  maxKeyBytes: 128,
  maxResults: 500,
});

export class ImportFailure extends Error {
  constructor(code) { super(code); this.code = code; }
}
const fail = code => { throw new ImportFailure(code); };

export function parseBoundedJson(text) {
  if (typeof text !== 'string') fail('invalid_input');
  if (text.length > LIMITS.maxBytes || Buffer.byteLength(text, 'utf8') > LIMITS.maxBytes) fail('input_limit');
  let offset = 0, nodes = 0;
  const whitespace = () => { while (offset < text.length && /[\x20\t\r\n]/.test(text[offset])) offset++; };
  const string = (maxBytes = LIMITS.maxStringBytes) => {
    if (text[offset] !== '"') fail('invalid_json');
    const start = offset++;
    while (offset < text.length) {
      const c = text[offset++];
      if (c === '\\') { offset++; continue; }
      if (c !== '"') continue;
      let value;
      try { value = JSON.parse(text.slice(start, offset)); } catch { fail('invalid_json'); }
      if (Buffer.byteLength(value, 'utf8') > maxBytes) fail('structure_limit');
      return value;
    }
    fail('invalid_json');
  };
  const value = depth => {
    if (depth > LIMITS.maxDepth || ++nodes > LIMITS.maxNodes) fail('structure_limit');
    whitespace();
    const c = text[offset];
    if (c === '"') return string();
    if (c === '{' || c === '[') {
      offset++; whitespace();
      const object = c === '{', end = object ? '}' : ']';
      const out = object ? Object.create(null) : [];
      if (text[offset] === end) { offset++; return out; }
      let count = 0;
      while (offset < text.length) {
        if (++count > (object ? LIMITS.maxObjectKeys : LIMITS.maxArrayItems)) fail('structure_limit');
        whitespace();
        if (object) {
          const key = string(LIMITS.maxKeyBytes);
          if (['__proto__', 'prototype', 'constructor'].includes(key)) fail('unsafe_key');
          if (Object.hasOwn(out, key)) fail('duplicate_key');
          whitespace();
          if (text[offset++] !== ':') fail('invalid_json');
          out[key] = value(depth + 1);
        } else out.push(value(depth + 1));
        whitespace();
        if (text[offset] === end) { offset++; return out; }
        if (text[offset++] !== ',') fail('invalid_json');
      }
      fail('invalid_json');
    }
    for (const [token, parsed] of [['true', true], ['false', false], ['null', null]]) {
      if (text.startsWith(token, offset)) { offset += token.length; return parsed; }
    }
    const number = /^-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?/.exec(text.slice(offset));
    if (!number) fail('invalid_json');
    offset += number[0].length;
    const parsed = Number(number[0]);
    if (!Number.isFinite(parsed)) fail('invalid_json');
    return parsed;
  };
  const parsed = value(0);
  whitespace();
  if (offset !== text.length) fail('invalid_json');
  return parsed;
}
