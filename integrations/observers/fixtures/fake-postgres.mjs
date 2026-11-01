// A scripted fake PostgreSQL server for tests (protocol 3.0 startup, server-side
// SCRAM-SHA-256 and md5 verification, cleartext offer, simple-query responses).
// Loopback only; no real database.
import { createServer } from 'node:net';
import { createHash, createHmac, pbkdf2Sync, randomBytes, timingSafeEqual } from 'node:crypto';
import { CATALOG_KINDS } from '../catalog.mjs';

export const USER = 'reader', PASSWORD = 'synthetic-reader-pass-7Hq2';
// Built-in types' output functions and volatility, as PostgreSQL 17 reports them (pg_type.typoutput, pg_proc.provolatile).
export const TYPE_OUTPUTS = Object.freeze({
  25: ['pg_catalog.textout', 'i'], 27: ['pg_catalog.tidout', 'i'], 28: ['pg_catalog.xidout', 'i'], 29: ['pg_catalog.cidout', 'i'], 1043: ['pg_catalog.varcharout', 'i'], 2950: ['pg_catalog.uuid_out', 'i'], 23: ['pg_catalog.int4out', 'i'], 1700: ['pg_catalog.numeric_out', 'i'], 17: ['pg_catalog.byteaout', 'i'],
  1082: ['pg_catalog.date_out', 's'], 1114: ['pg_catalog.timestamp_out', 's'], 1184: ['pg_catalog.timestamptz_out', 's'], 1186: ['pg_catalog.interval_out', 's'], 790: ['pg_catalog.cash_out', 's'],
  1033: ['pg_catalog.aclitemout', 's'], 2205: ['pg_catalog.regclassout', 's'], 4096: ['pg_catalog.regroleout', 's'], 1009: ['pg_catalog.array_out', 's'], 3904: ['pg_catalog.range_out', 's'], 4451: ['pg_catalog.multirange_out', 's'],
});
// Split a select list on its top-level commas.
const splitTop = list => { const parts = []; let depth = 0, quoted = false, from = 0;
  for (let i = 0; i < list.length; i++) { const c = list[i];
    if (c === "'") quoted = !quoted; else if (!quoted && c === '(') depth++; else if (!quoted && c === ')') depth--;
    else if (!quoted && depth === 0 && c === ',' && list[i + 1] === ' ') { parts.push(list.slice(from, i)); from = i + 2; } }
  return [...parts, list.slice(from)]; };
const int32 = n => { const b = Buffer.alloc(4); b.writeInt32BE(n); return b; };
const int16 = n => { const b = Buffer.alloc(2); b.writeInt16BE(n); return b; };
const msg = (type, body = Buffer.alloc(0)) => Buffer.concat([Buffer.from(type), int32(body.length + 4), body]);
const cstr = s => Buffer.concat([Buffer.from(s), Buffer.from([0])]);
const hmac = (k, d) => createHmac('sha256', k).update(d).digest();
const errorFrame = code => msg('E', Buffer.concat([cstr('SERROR'), cstr(`C${code}`), cstr('Mfake server message that must not leak'), Buffer.from([0])]));

// auth: 'scram' | 'scram-bad-signature' | 'md5' | 'cleartext'. onQuery(statement) -> rows ([[text|null]]) or { error: sqlstate }.
export async function fakePostgres(t, { auth = 'scram', password = PASSWORD, onQuery = () => [], startups = [] } = {}) {
  const server = createServer(socket => {
    let buf = Buffer.alloc(0), stage = 'startup', scramState = null;
    const send = b => socket.write(b);
    const ready = () => send(msg('Z', Buffer.from('I')));
    const ok = () => { send(msg('R', int32(0))); send(msg('S', Buffer.concat([cstr('server_version'), cstr('16.0')]))); ready(); stage = 'query'; };
    socket.on('data', chunk => {
      buf = Buffer.concat([buf, chunk]);
      for (;;) {
        if (stage === 'startup') {
          if (buf.length < 4 || buf.length < buf.readInt32BE(0)) return;
          // The startup parameters (name, value pairs after the protocol version), recorded for tests.
          const fields = buf.subarray(8, buf.readInt32BE(0) - 1).toString('utf8').split('\0');
          startups.push(Object.fromEntries(fields.flatMap((v, i) => i % 2 ? [] : [[v, fields[i + 1]]])));
          buf = buf.subarray(buf.readInt32BE(0));
          if (auth === 'trust') { ok(); continue; } // AuthenticationOk with no challenge
          if (auth.startsWith('scram')) { send(msg('R', Buffer.concat([int32(10), cstr('SCRAM-SHA-256'), Buffer.from([0])]))); stage = 'sasl-initial'; }
          else if (auth === 'md5') { scramState = { salt: randomBytes(4) }; send(msg('R', Buffer.concat([int32(5), scramState.salt]))); stage = 'md5'; }
          else { send(msg('R', int32(3))); stage = 'cleartext'; }
          continue;
        }
        if (buf.length < 5 || buf.length < 1 + buf.readInt32BE(1)) return;
        const type = String.fromCharCode(buf[0]), body = buf.subarray(5, 1 + buf.readInt32BE(1));
        buf = buf.subarray(1 + buf.readInt32BE(1));
        if (type === 'X') { socket.end(); return; }
        if (stage === 'sasl-initial') {
          const mechEnd = body.indexOf(0), len = body.readInt32BE(mechEnd + 1), first = body.subarray(mechEnd + 5, mechEnd + 5 + len).toString();
          const clientFirstBare = first.replace(/^n,,/, ''), clientNonce = /r=([^,]+)/.exec(clientFirstBare)[1];
          const iterations = auth === 'scram-low-iterations' ? 1 : 4096, serverNonce = auth === 'scram-echo-nonce' ? clientNonce : `${clientNonce}${randomBytes(12).toString('base64')}`;
          const salt = randomBytes(16), serverFirst = `r=${serverNonce},s=${salt.toString('base64')},i=${iterations}`;
          scramState = { clientFirstBare, serverFirst, salted: pbkdf2Sync(password, salt, iterations, 32, 'sha256') };
          send(msg('R', Buffer.concat([int32(11), Buffer.from(serverFirst)]))); stage = 'sasl-final'; continue;
        }
        if (stage === 'sasl-final') {
          const final = body.toString(), withoutProof = final.replace(/,p=[^,]+$/, ''), proof = Buffer.from(/p=([^,]+)$/.exec(final)[1], 'base64');
          const authMessage = `${scramState.clientFirstBare},${scramState.serverFirst},${withoutProof}`;
          const clientKey = hmac(scramState.salted, 'Client Key'), storedKey = createHash('sha256').update(clientKey).digest();
          const recovered = Buffer.from(proof.map((b, i) => b ^ hmac(storedKey, authMessage)[i]));
          if (!timingSafeEqual(createHash('sha256').update(recovered).digest(), storedKey)) { send(errorFrame('28P01')); socket.end(); return; }
          const signature = auth === 'scram-bad-signature' ? randomBytes(32) : hmac(hmac(scramState.salted, 'Server Key'), authMessage);
          send(msg('R', Buffer.concat([int32(12), Buffer.from(`v=${signature.toString('base64')}`)]))); ok(); continue;
        }
        if (stage === 'md5') {
          const expected = `md5${createHash('md5').update(Buffer.concat([Buffer.from(createHash('md5').update(password + USER).digest('hex')), scramState.salt])).digest('hex')}`;
          if (body.toString('utf8', 0, body.length - 1) !== expected) { send(errorFrame('28P01')); socket.end(); return; }
          ok(); continue;
        }
        if (stage === 'cleartext') { stage = 'gave-password-in-clear'; server.cleartextReceived = true; socket.end(); return; }
        if (type === 'Q') {
          const statements = body.toString('utf8', 0, body.length - 1).split('; ');
          for (const statement of statements) {
            const out = onQuery(statement);
            if (out && out.stall) return; // never answers: the client's own deadline must end the query
            // Several result sets for one statement (a statement list joined otherwise than by "; ", as pg-actor's verifySql is).
            if (out && Array.isArray(out.results)) {
              for (const rows of out.results) {
                if (rows.length) { send(msg('T', int16(0))); for (const row of rows) send(msg('D', Buffer.concat([int16(row.length), ...row.map(v => v === null ? int32(-1) : Buffer.concat([int32(Buffer.byteLength(v)), Buffer.from(v)]))]))); }
                send(msg('C', cstr(`SELECT ${rows.length}`)));
              }
              continue;
            }
            if (out && out.rawError) { send(msg('E', out.rawError)); break; } // a malformed ErrorResponse
            if (out && out.error) { send(errorFrame(out.error)); break; }
            if (Array.isArray(out) && out.length) {
              send(msg('T', int16(0)));
              for (const row of out) send(msg('D', Buffer.concat([int16(row.length), ...row.map(v => v === null ? int32(-1) : Buffer.concat([int32(Buffer.byteLength(v)), Buffer.from(v)]))])));
            }
            send(msg('C', cstr(/^select/i.test(statement) ? `SELECT ${out.length ?? 0}` : statement.split(' ')[0].toUpperCase())));
          }
          ready();
        }
      }
    });
    socket.on('error', () => {});
  });
  await new Promise(r => server.listen(0, '127.0.0.1', r));
  t.after(() => new Promise(r => server.close(r)));
  server.port = server.address().port;
  return server;
}

// The catalog fingerprint's two statements (./catalog.mjs), as a server with one unchanging catalog answers them: every
// kind empty but the public schema, and no relation versions. A state's catalog { kinds, versions } replaces either.
export const FAKE_CATALOG = Object.freeze({ kinds: CATALOG_KINDS.postgres.map(kind => [kind, kind === 'schema' ? '1' : '0', createHash('sha256').update(kind === 'schema' ? 'public' : '').digest('hex'),
  createHash('sha256').update(kind === 'schema' ? 'public:2200' : '').digest('hex')]), versions: [] });
export const catalogAnswer = (statement, catalog) => (/^\/\* sh:dbcatalog \*\//.test(statement) ? (catalog?.kinds ?? FAKE_CATALOG.kinds)
  : /^\/\* sh:dbversions \*\//.test(statement) ? (catalog?.versions ?? FAKE_CATALOG.versions) : null);

// A scripted database: per mark, the snapshot text and each table's rows [key, xmin, md5].
// beginState(mark), when given, builds each mark's state at its BEGIN (pgModel below).
// answer(statement, mark): an optional hook consulted before the rules below (after BEGIN), whose non-undefined result is the
// statement's answer: a scripted database can answer the actor capture's definition and ledger reads (../pg-actor.mjs) this way.
export function scriptedDb(t, states, log = [], { auth = 'scram', startups, beginState, answer } = {}) {
  // The catalog is read on its own session before and after each mark's transaction (../catalog.mjs): a read after a
  // COMMIT is that mark's, any other the coming mark's.
  let mark = -1, catalogOf = 'next';
  const onQuery = statement => {
    log.push(statement);
    if (/^BEGIN/.test(statement)) { mark++; if (beginState) states[mark] = beginState(mark); return []; }
    if (answer) { const out = answer(statement, mark); if (out !== undefined) return out; }
    if (statement === 'COMMIT') catalogOf = 'current';
    // Before the rules below: the catalog statements read pg_class, pg_proc and pg_attribute too.
    // A state's catalogAfter answers the read after its COMMIT (a catalog changed while the mark was read).
    const at = catalogOf === 'current' ? mark : mark + 1, st = states[at] ?? (at > mark ? states[mark] : undefined);
    const catalog = catalogAnswer(statement, catalogOf === 'current' ? st?.catalogAfter ?? st?.catalog : st?.catalog);
    if (/^\/\* sh:dbversions \*\//.test(statement) && catalogOf === 'current') catalogOf = 'next';
    if (catalog) return catalog;
    // serverStart: pg_postmaster_start_time() (a restart between marks changes it).
    if (/pg_current_snapshot/.test(statement)) return [[states[mark].snapshot, states[mark].writers ?? null, states[mark].recovery ?? 'false', states[mark].serverStart ?? '2026-10-06 00:00:00+00']];
    // Granted relation locks: this backend's (by default every listed relation; locked: [oids] overrides) and, only
    // when the statement does not filter on this backend's pid, other backends' (otherLocks: [oids]).
    if (/pg_backend_pid/.test(statement)) {
      const st = states[mark], all = Object.keys(st.tables ?? {}).flatMap(name => [...(st.relations?.[name] ?? [['16384']]).map(([o]) => o), ...(st.descendants?.[name] ?? []).map(([o]) => o)]);
      const own = /WHERE pid = pg_catalog\.pg_backend_pid\(\) AND /.test(statement);
      const oids = [...(st.locked ?? all), ...(own ? [] : st.otherLocks ?? [])];
      return [[oids.length ? `{${oids.join(',')}}` : null]];
    }
    // Each relation's key column and its type's output function: the statement is evaluated over attributes
    // (attnum, attname, atttypid, attisdropped, attgenerated?) and TYPE_OUTPUTS plus states[mark].types.
    if (/pg_catalog\.pg_proc/.test(statement)) {
      const m = /^SELECT (.+) FROM pg_catalog\.pg_attribute a JOIN pg_catalog\.pg_type ty ON ty\.oid = a\.atttypid JOIN pg_catalog\.pg_proc p ON p\.oid = ty\.typoutput JOIN pg_catalog\.pg_namespace n ON n\.oid = p\.pronamespace WHERE a\.attrelid = ANY \(ARRAY\[([^\]]*)\]::pg_catalog\.oid\[\]\)(.*) ORDER BY 1$/.exec(statement);
      if (!m || (m[3] && !m[3].startsWith(' AND '))) return { error: '42601' }; // nothing unmodelled before the first AND
      const where = m[3].split(' AND ').slice(1).map(c => { let w;
        if ((w = /^a\.attname = '(\w+)'$/.exec(c))) return a => a[1] === w[1];
        if ((w = /^a\.attnum > (\d+)$/.exec(c))) return a => Number(a[0]) > Number(w[1]);
        if (c === 'NOT a.attisdropped') return a => a[3] === 'false';
        return null; });
      const types = { ...TYPE_OUTPUTS, ...states[mark].types }, out = typid => types[typid] ?? [`unknown.${typid}`, 'v'];
      const select = splitTop(m[1]).map(e => { let w;
        if (e === 'a.attrelid::text') return oid => oid;
        if ((w = /^COALESCE\(pg_catalog\.to_jsonb\(a\) ->> '(\w+)', ''\)$/.exec(e))) return (oid, a) => (w[1] === 'attgenerated' ? a[4] : undefined) ?? '';
        if (e === 'p.provolatile::text') return (oid, a) => out(a[2])[1];
        if (e === "n.nspname::text || '.' || p.proname::text") return (oid, a) => out(a[2])[0];
        if (e === 'p.proname::text') return (oid, a) => out(a[2])[0].split('.').pop();
        return null; });
      if (where.some(f => !f) || select.some(f => !f)) return { error: '42601' };
      return [...m[2].matchAll(/'(\d+)'/g)].flatMap(([, oid]) => (states[mark].attributes?.[oid] ?? [['1', 'id', '25', 'false']]).filter(a => where.every(f => f(a))).map(a => select.map(f => f(oid, a))));
    }
    // A read-back table's columns (pg-readback): evaluated over the same attributes ([attnum, attname, atttypid, attisdropped,
    // attgenerated?]) of the named relation, with each type's [typtype, typbasetype] from states[mark].typeInfo (default base).
    if (/t\.typbasetype/.test(statement)) {
      const m = /^SELECT a\.attnum::text, a\.attname::text, a\.atttypid::text, COALESCE\(pg_catalog\.to_jsonb\(a\) ->> 'attgenerated', ''\), t\.typtype::text, t\.typbasetype::text FROM pg_catalog\.pg_attribute a JOIN pg_catalog\.pg_type t ON t\.oid = a\.atttypid WHERE a\.attrelid = \(SELECT c\.oid FROM pg_catalog\.pg_class c JOIN pg_catalog\.pg_namespace n ON n\.oid = c\.relnamespace WHERE n\.nspname = '\w+' AND c\.relname = '(\w+)'\) AND a\.attnum > 0 AND NOT a\.attisdropped ORDER BY a\.attnum$/.exec(statement);
      if (!m) return { error: '42601' };
      const st = states[mark], oid = st.relations?.[m[1]]?.[0]?.[0] ?? '16384';
      return (st.attributes?.[oid] ?? [['1', 'id', '25', 'false']]).filter(a => a[3] === 'false').map(a => [a[0], a[1], a[2], a[4] ?? '', ...(st.typeInfo?.[a[2]] ?? ['b', '0'])]);
    }
    // Column layout: the statement is evaluated over attributes { oid: [[attnum, attname, atttypid, attisdropped]] }
    // (default one text key column): its select list, its relation list and its attnum bound.
    if (/pg_catalog\.pg_attribute/.test(statement)) {
      const m = /^SELECT (.+) FROM pg_catalog\.pg_attribute WHERE attrelid = ANY \(ARRAY\[([^\]]*)\]::pg_catalog\.oid\[\]\) AND attnum > (\d+) ORDER BY 1, 2$/.exec(statement);
      const fields = { 'attrelid::text': (oid) => oid, 'attnum::text': (oid, a) => a[0], 'attname::text': (oid, a) => a[1], 'atttypid::text': (oid, a) => a[2], 'attisdropped::text': (oid, a) => a[3], "''::text": () => '' };
      const select = m?.[1].split(', ').map(e => fields[e]);
      if (!m || select.some(f => !f)) return { error: '42601' };
      return [...m[2].matchAll(/'(\d+)'/g)].flatMap(([, oid]) => (states[mark].attributes?.[oid] ?? [['1', 'id', '25', 'false']]).filter(a => Number(a[0]) > Number(m[3])).map(a => select.map(f => f(oid, a))));
    }
    // File nodes: states[mark].filenodes { oid: node } (default: the oid itself); filenodesNow: the current ones after the scan.
    const filenode = oid => states[mark].filenodes?.[oid] ?? oid;
    if (/WITH RECURSIVE/.test(statement)) { const name = /c\.relname = '(\w+)'/.exec(statement)[1]; return (states[mark].descendants?.[name] ?? []).map(row => row.length === 3 ? [...row, 'p', 'false'] : row).map(row => row.length === 5 ? [...row, filenode(row[0])] : row); } // [oid, relkind, am, relpersistence?, detach pending?, filenode?]
    if (/pg_relation_filenode/.test(statement)) return [...statement.matchAll(/'(\d+)'/g)].map(([, oid]) => [oid, states[mark].filenodesNow?.[oid] ?? filenode(oid)]);
    // [oid, relkind, am, filenode?, relpersistence?]
    if (/pg_catalog\.pg_class/.test(statement)) { const name = /c\.relname = '(\w+)'/.exec(statement)[1]; return (states[mark].relations?.[name] ?? [['16384', 'r', 'heap']]).map(row => row.length === 3 ? [...row, filenode(row[0])] : row).map(row => row.length === 4 ? [...row, 'p'] : row); }
    if (/pg_locks/.test(statement)) return [[states[mark].writersAtEnd ?? states[mark].writers ?? null]];
    const table = /FROM "\w+"\."(\w+)" AS r/.exec(statement)?.[1];
    if (table) {
      const rows = states[mark].tables[table], oid = states[mark].relations?.[table]?.[0]?.[0] ?? '16384';
      // Rows carry their tableoid (the relation they live in); a scripted row without one lives in the table itself.
      if (typeof rows === 'function') return rows(statement); // a model table evaluates the statement itself
      if (rows === 'denied') return { error: '42501' };
      if (!Array.isArray(rows ?? [])) return rows; // a scripted error, stall or raw error
      return (rows ?? []).map(row => row.length === 3 ? [...row, oid] : row);
    }
    return [];
  };
  return fakePostgres(t, { onQuery, auth, startups });
}

// A typed database model for read-back tests (pg-readback). tables: [{ table, key, keyType ('25'), columns: [{ name, type
// (an oid string), typtype?, basetype?, generated? }], rows: [{ column: text | null }] }], each value the text PostgreSQL
// prints for it. Each write is one committed transaction with a new xmin (one id counter for the database), and a mark
// reads the model as it was at its BEGIN (scriptedDb's beginState: () => model.state()). A table scan is evaluated from its own select list, so a statement the model
// does not know is answered 42601, and each column a scan selected as a value is listed in model.valuesRead.
export function pgModel(tables) {
  let txid = 1000;
  const db = tables.map((t, i) => ({ ...t, oid: String(16384 + i), keyType: t.keyType ?? '25', data: new Map(t.rows.map(r => [String(r[t.key]), { xmin: String(txid), values: { ...r } }])) }));
  const byName = name => { const t = db.find(x => x.table === name); if (!t) throw new Error(`no model table ${name}`); return t; };
  const valuesRead = [];
  const scan = (t, rows) => statement => {
    const m = /^SELECT (.+) FROM "\w+"\."\w+" AS r ORDER BY 1, r\.tableoid, r\.ctid LIMIT (\d+)$/.exec(statement);
    if (!m) return { error: '42601' };
    const names = [t.key, ...t.columns.map(c => c.name)], text = (row, cols) => JSON.stringify(cols.map(c => row.values[c] ?? null));
    const exprs = splitTop(m[1]).map(e => { let w;
      if (e === `(r."${t.key}")::text`) return row => row.key;
      if (e === 'r.xmin::text') return row => row.xmin;
      if (e === 'pg_catalog.md5(r::text)') return row => createHash('md5').update(text(row, names)).digest('hex');
      if (e === 'r.tableoid::text') return () => t.oid;
      // A value is read as text only (a cast such as ::jsonb is not modelled: 42601).
      if ((w = /^pg_catalog\.left\(\(r\."(\w+)"\)::pg_catalog\.text, (\d+)\)$/.exec(e)) && names.includes(w[1])) {
        valuesRead.push(`${t.table}.${w[1]}`);
        return row => { const v = row.values[w[1]] ?? null; return v === null ? null : [...v].slice(0, Number(w[2])).join(''); };
      }
      // sha256 of the whole row, or of a ROW of named columns (the remainder of an expected row).
      const hashed = /^pg_catalog\.encode\(pg_catalog\.sha256\(pg_catalog\.textsend\((.*)\)\), 'hex'\)$/.exec(e)?.[1];
      if (hashed === 'r::pg_catalog.text') return row => createHash('sha256').update(text(row, names)).digest('hex');
      if ((w = /^ROW\((.*)\)::pg_catalog\.text$/.exec(hashed ?? ''))) {
        const cols = w[1] ? w[1].split(', ').map(x => /^r\."((?:[^"]|"")+)"$/.exec(x)?.[1]?.replace(/""/g, '"')) : [];
        if (cols.some(c => !names.includes(c))) return null;
        return row => createHash('sha256').update(`(${text(row, cols)})`).digest('hex');
      }
      return null; });
    if (exprs.some(f => !f)) return { error: '42601' };
    return rows.slice(0, Number(m[2])).map(row => exprs.map(f => f(row)));
  };
  return {
    valuesRead,
    write(table, key, values) { const t = byName(table), k = String(key); txid++; t.data.set(k, { xmin: String(txid), values: { ...(t.data.get(k)?.values ?? { [t.key]: k }), ...values } }); },
    remove(table, key) { const t = byName(table); txid++; t.data.delete(String(key)); },
    // One mark's state: the snapshot (no transaction in progress), each table's relation, columns and frozen rows.
    state() {
      const next = String(txid + 1);
      return { snapshot: `${next}:${next}:`,
        relations: Object.fromEntries(db.map(t => [t.table, [[t.oid, 'r', 'heap']]])),
        attributes: Object.fromEntries(db.map(t => [t.oid, [['1', t.key, t.keyType, 'false', ''], ...t.columns.map((c, i) => [String(i + 2), c.name, c.type, 'false', c.generated ?? ''])]])),
        typeInfo: Object.fromEntries(db.flatMap(t => t.columns.filter(c => c.typtype).map(c => [c.type, [c.typtype, c.basetype ?? '0']]))),
        tables: Object.fromEntries(db.map(t => [t.table, scan(t, [...t.data.entries()].sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0)).map(([key, r]) => ({ key, xmin: r.xmin, values: { ...r.values } })))])) };
    },
  };
}
