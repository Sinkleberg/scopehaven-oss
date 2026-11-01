// A small PostgreSQL tokenizer for reading migration files: identifiers (unquoted are
// case-folded in ASCII only, as PostgreSQL does; quoted keep their case), string and dollar-quoted literals, numbers,
// operators and punctuation, with line numbers. Comments are dropped. It splits
// statements on top-level semicolons and renders token runs back into a normalized
// expression text so a reformatted migration doesn't read as a changed policy.
// Unicode-escape names and strings (U&"..." and U&'...', with an optional UESCAPE) are kept
// undecoded as their own token types ("uident", "ustring") so a reader can refuse the statement:
// read as u, & and a quoted name, a policy on public.U&"docs" would be filed under a table "u"
// while PostgreSQL applies it to docs. An identifier is cut to 63 bytes, as PostgreSQL cuts it.
// An E'...' string keeps the character after each backslash, which is PostgreSQL's value only for \'
// and \\, so escapedString marks one whose value a reader must not take as a name or a setting.
const IDENT_START = /[A-Za-z_\u0080-￿]/, IDENT_PART = /[A-Za-z0-9_$\u0080-￿]/, OP_CHARS = new Set('+-*/<>=~!@#%^&|`?:');
const PUNCT = new Set('(),;.[]');

export function tokenize(text) {
  const tokens = [];
  let i = 0, line = 1;
  const push = (t, v, start, raw) => tokens.push({ t, v, line: lineAt, start, end: i, raw: raw ?? text.slice(start, i) });
  let lineAt = 1;
  const advance = to => { for (; i < to; i++) if (text[i] === '\n') line++; };
  while (i < text.length) {
    const c = text[i], start = i;
    lineAt = line;
    if (/\s/.test(c)) { advance(i + 1); continue; }
    if (c === '-' && text[i + 1] === '-') { const end = text.indexOf('\n', i); advance(end < 0 ? text.length : end); continue; }
    if (c === '/' && text[i + 1] === '*') {
      let depth = 0, j = i;
      while (j < text.length) {
        if (text[j] === '/' && text[j + 1] === '*') { depth++; j += 2; } else if (text[j] === '*' && text[j + 1] === '/') { depth--; j += 2; if (!depth) break; } else j++;
      }
      if (depth) throw new SqlSyntaxError('unterminated comment', lineAt);
      advance(j); continue;
    }
    if ((c === 'U' || c === 'u') && text[i + 1] === '&' && (text[i + 2] === '"' || text[i + 2] === "'")) { const quote = text[i + 2]; advance(i + 2); push(quote === '"' ? 'uident' : 'ustring', readQuoted(quote, false), start); continue; }
    if ((c === 'E' || c === 'e') && text[i + 1] === "'") { advance(i + 1); push('string', readQuoted("'", true), start); continue; }
    if (c === "'") { push('string', readQuoted("'", false), start); continue; }
    if (c === '"') { push('qident', truncateName(readQuoted('"', false)), start); continue; }
    if (c === '$') {
      const m = /^\$([A-Za-z_][A-Za-z0-9_]*)?\$/.exec(text.slice(i));
      if (m) {
        const tag = m[0], close = text.indexOf(tag, i + tag.length);
        if (close < 0) throw new SqlSyntaxError('unterminated dollar-quoted string', lineAt);
        const body = text.slice(i + tag.length, close);
        advance(close + tag.length); push('dollar', body, start); continue;
      }
      if (/\d/.test(text[i + 1] ?? '')) { let j = i + 1; while (/\d/.test(text[j] ?? '')) j++; advance(j); push('param', text.slice(start, j), start); continue; }
    }
    if (/\d/.test(c) || (c === '.' && /\d/.test(text[i + 1] ?? ''))) {
      const m = /^(\d+\.?\d*|\.\d+)([eE][+-]?\d+)?/.exec(text.slice(i));
      advance(i + m[0].length); push('number', m[0], start); continue;
    }
    if (IDENT_START.test(c)) { let j = i + 1; while (j < text.length && IDENT_PART.test(text[j])) j++; advance(j); push('ident', truncateName(text.slice(start, j).replace(/[A-Z]+/g, m => m.toLowerCase())), start); continue; }
    if (PUNCT.has(c)) { advance(i + 1); push('punct', c, start); continue; }
    if (OP_CHARS.has(c)) { let j = i + 1; while (j < text.length && OP_CHARS.has(text[j]) && !(text[j] === '-' && text[j + 1] === '-') && !(text[j] === '/' && text[j + 1] === '*')) j++; advance(j); push('op', text.slice(start, j), start); continue; }
    throw new SqlSyntaxError(`unexpected character ${JSON.stringify(c)}`, lineAt);
  }
  return tokens;

  function readQuoted(quote, backslash) {
    let j = i + 1, value = '';
    for (;;) {
      if (j >= text.length) throw new SqlSyntaxError(`unterminated ${quote === '"' ? 'quoted identifier' : 'string'}`, lineAt);
      const ch = text[j];
      if (backslash && ch === '\\') { value += text[j + 1] ?? ''; j += 2; continue; }
      if (ch === quote) { if (text[j + 1] === quote) { value += quote; j += 2; continue; } j++; break; }
      value += ch; j++;
    }
    advance(j);
    return value;
  }
}

// PostgreSQL cuts a name to 63 bytes (NAMEDATALEN - 1) at a character boundary, so two spellings that agree in their first
// 63 bytes name one object.
export function truncateName(name) {
  let out = '', bytes = 0;
  for (const ch of name) { bytes += Buffer.byteLength(ch); if (bytes > 63) break; out += ch; }
  return out;
}
export const escapedString = token => token?.t === 'string' && /^[Ee]'/.test(token.raw) && token.raw.includes('\\');

export class SqlSyntaxError extends Error {
  constructor(message, line) { super(`${message} (line ${line})`); this.line = line; }
}

// A function body written as BEGIN ATOMIC ... END holds its own semicolons, so it stays
// inside one statement.
export function splitStatements(tokens) {
  const statements = [];
  let current = [], depth = 0, atomic = 0, cases = 0;
  tokens.forEach((token, index) => {
    if (token.t === 'punct' && token.v === '(') depth++;
    if (token.t === 'punct' && token.v === ')') depth = Math.max(0, depth - 1);
    if (token.t === 'ident' && token.v === 'begin' && tokens[index + 1]?.t === 'ident' && tokens[index + 1].v === 'atomic') atomic++;
    // "e.case" and "1 as case" are labels, not CASE expressions.
    const label = tokens[index - 1] && ((tokens[index - 1].t === 'punct' && tokens[index - 1].v === '.') || (tokens[index - 1].t === 'ident' && tokens[index - 1].v === 'as'));
    if (atomic > 0 && token.t === 'ident' && token.v === 'case' && !label) cases++;
    if (atomic > 0 && token.t === 'ident' && token.v === 'end') { if (cases > 0) cases--; else { atomic--; current.push(token); return; } }
    if (token.t === 'punct' && token.v === ';' && depth === 0 && atomic === 0) { if (current.length) statements.push(current); current = []; return; }
    current.push(token);
  });
  if (current.length) statements.push(current);
  // A BEGIN ATOMIC body still open at the end swallowed what followed it.
  if (atomic > 0) statements.unclosed = true;
  return statements;
}

// A quoted identifier spelled like a keyword literal stays quoted, so "true" never reads as true.
const quoteIdent = v => /^[a-z_][a-z0-9_$]*$/.test(v) && !['true', 'false', 'null'].includes(v) ? v : `"${v.replaceAll('"', '""')}"`;
const quoteString = v => `'${v.replaceAll("'", "''")}'`;
const renderToken = token => token.t === 'ident' ? token.v : token.t === 'qident' ? quoteIdent(token.v)
  : token.t === 'string' ? quoteString(token.v) : token.t === 'dollar' ? quoteString(token.v) : token.t === 'uident' || token.t === 'ustring' ? token.raw : token.v;
export const unicodeEscaped = tokens => tokens.some(t => t.t === 'uident' || t.t === 'ustring');

// Normalized text of a token run: identifiers folded, literals re-quoted, single spaces
// except around . :: and inside brackets, and no space between a function name and "(".
export function render(tokens) {
  let out = '';
  tokens.forEach((token, index) => {
    const prev = tokens[index - 1], text = renderToken(token);
    const tight = !prev || (prev.t === 'punct' && ['(', '.', '['].includes(prev.v)) || (prev.t === 'op' && prev.v === '::')
      || (token.t === 'punct' && [')', ',', '.', ']'].includes(token.v)) || (token.t === 'op' && token.v === '::')
      || (token.t === 'punct' && token.v === '(' && (prev.t === 'ident' || prev.t === 'qident'));
    out += (tight ? '' : ' ') + text;
  });
  return out;
}

// Removes redundant outer parentheses: "((x))" -> "x", but not "(a) and (b)".
export function stripOuterParens(tokens) {
  let run = tokens;
  while (run.length >= 2 && run[0].t === 'punct' && run[0].v === '(' && run.at(-1).t === 'punct' && run.at(-1).v === ')') {
    let depth = 0, closesAtEnd = true;
    for (let k = 0; k < run.length; k++) {
      if (run[k].t === 'punct' && run[k].v === '(') depth++;
      if (run[k].t === 'punct' && run[k].v === ')') { depth--; if (depth === 0 && k < run.length - 1) { closesAtEnd = false; break; } }
    }
    if (!closesAtEnd) break;
    run = run.slice(1, -1);
  }
  return run;
}
