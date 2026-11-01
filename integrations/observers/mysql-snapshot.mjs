// MySQL snapshot observer: reads the application's own InnoDB tables at each
// mark, in one REPEATABLE READ, READ ONLY transaction started WITH CONSISTENT
// SNAPSHOT, through the built-in client (mysql-wire.mjs). For every row it
// reads the key and MD5(JSON_ARRAY(<every column>)), computed in the server, so
// no other column values leave it except, for a table with a change column,
// that column at microsecond precision.
//
// Coverage. InnoDB exposes no row versions to a reader, so changes are the net
// difference between two marks (net-only): an insert, update or delete is an
// event, and a write undone within the window is not seen. An UPDATE that sets
// the values a row already has changes nothing and is not seen either. Absence
// is exact only for a change column the schema itself keeps current: a
// TIMESTAMP column defined DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
// (the server stamps every insert and every UPDATE that changes the row,
// write-and-revert included; TIMESTAMP is stored in UTC, so the writer's session
// time zone cannot make a fresh stamp look old, which rules out DATETIME), plus
// a recorded source check that no writer sets that column: the app's code, SQL
// the agent can run, a session that sets its own clock (SET timestamp), a
// trigger that sets it, or a foreign-key cascade (which does not stamp). Any of
// those leaves the old stamp on a changed row. As with the SQLite change
// column, a row whose column is unchanged between the marks had no committed
// update; a row stamped within maxCommitLagMs (plus one tick of the column's
// precision) of the start mark, a NULL or zero-date stamp, a row present at one
// mark only, and a selected row absent at either mark are not exact; content
// that changed under an unchanged column voids the table's exactness and
// reports none of its changes. Both the change column and the guard use the
// server's own clock (NOW(6), read before the snapshot starts), so there is no
// host-to-server skew. A write not yet committed at the end mark is not in it:
// declare settleMs of at least maxCommitLagMs.
//
// The window fails, with no events, when a table's rows cannot be identified
// across the marks: it is no longer an InnoDB base table, it was recreated or
// rebuilt (CREATE_TIME changed: ALTER TABLE rebuilds, OPTIMIZE) or its column
// names or types changed ('relation-rewritten'), it was created or rebuilt in
// the same second the start mark read it, so a second rebuild in that second
// would keep its CREATE_TIME ('relation-unverified'), or a key is NULL or
// duplicated ('duplicate-key'). CREATE_TIME has whole seconds and is the only
// identity a SELECT-only reader can see. It does not change when a table's rows
// are swapped with a partition (ALTER TABLE ... EXCHANGE PARTITION ... WITH
// TABLE, observed live on MySQL 8.4), nor when a twin created in the same second
// is renamed into its place, so either reads as the same table. With tableIds,
// each mark also compares InnoDB's table and tablespace ids, which both swaps
// change; the reader then needs the PROCESS privilege (which also shows other
// sessions' statements). TRUNCATE also gives the table new ids, so with tableIds
// it fails the window instead of reading as deletes. Partitioned tables are refused. A server with read_only set (a
// replica, usually) is refused; a replica without it is not detected. A view
// or another engine is refused. Each mark pins the session time zone (UTC) and
// sql_mode (MySQL 8.4's default), so values read the same.
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { digest } from '../../src/domain.mjs';
import { makeEffect, credentialFrom, CREDENTIAL_ENV } from './events.mjs';
import { mysqlConnect, MysqlError } from './mysql-wire.mjs';

export const MYSQL_SNAPSHOT_LIMITS = Object.freeze({ rowsPerTable: 200000, rowsPerTableBounds: [1, 200000], tables: 32, statementTimeoutMs: 10000, statementTimeoutBounds: [500, 60000], retainedMarks: 128, presentResources: 1000 });
const IDENT = /^[A-Za-z_][A-Za-z0-9_$]{0,63}$/;
const quote = name => { if (typeof name !== 'string' || !IDENT.test(name)) throw new Error(`Unsupported SQL identifier "${String(name).slice(0, 80)}".`); return `\`${name}\``; };
const literal = name => { quote(name); return `'${name}'`; };
const STAMP = /^(\d{4})-(\d{2})-(\d{2}) (\d{2}):(\d{2}):(\d{2})\.(\d{6})$/;
// A 'YYYY-MM-DD HH:MM:SS.ffffff' server time as microseconds (UTC session); null for NULL or a zero date.
const micros = text => { const m = STAMP.exec(text ?? ''); return m && +m[1] > 0 && +m[2] > 0 && +m[3] > 0 ? BigInt(Date.UTC(+m[1], +m[2] - 1, +m[3], +m[4], +m[5], +m[6])) * 1000n + BigInt(m[7]) : null; };
// The server keeps a column current only when it sets it on insert (DEFAULT CURRENT_TIMESTAMP) and on update.
const SERVER_DEFAULT = /^CURRENT_TIMESTAMP(\(\d\))?$/i, ON_UPDATE = /^DEFAULT_GENERATED on update CURRENT_TIMESTAMP(\(\d\))?$/i;
const SQL_MODE = 'ONLY_FULL_GROUP_BY,STRICT_TRANS_TABLES,NO_ZERO_IN_DATE,NO_ZERO_DATE,ERROR_FOR_DIVISION_BY_ZERO,NO_ENGINE_SUBSTITUTION';

// tables: [{ table, key, resourcePrefix?, changeColumn?: { column, audit } }]
// watchedResources: the resources the profile's effect selectors name ("table/<key>"); supplied by the connector.
export function createMysqlSnapshotObserver({ instanceId = 'mysql-snapshot-1', env = process.env, host, port, database, credentialEnv, tables, maxCommitLagMs,
  rowsPerTable = MYSQL_SNAPSHOT_LIMITS.rowsPerTable, statementTimeoutMs = MYSQL_SNAPSHOT_LIMITS.statementTimeoutMs, tableIds = false, watchedResources = [], connect = mysqlConnect }) {
  const within = (v, [min, max]) => Number.isInteger(v) && v >= min && v <= max;
  if (host !== '127.0.0.1') throw new Error('The MySQL host must be the literal loopback address 127.0.0.1.');
  if (!Number.isInteger(port) || port < 1 || port > 65535) throw new Error('Declare the MySQL port.');
  if (typeof database !== 'string' || !IDENT.test(database)) throw new Error('Declare the MySQL database name.');
  if (!within(rowsPerTable, MYSQL_SNAPSHOT_LIMITS.rowsPerTableBounds)) throw new Error('rowsPerTable must be an integer from 1 to 200000.');
  if (!within(statementTimeoutMs, MYSQL_SNAPSHOT_LIMITS.statementTimeoutBounds)) throw new Error('statementTimeoutMs must be an integer from 500 to 60000.');
  if (typeof tableIds !== 'boolean') throw new Error('tableIds is true or false.');
  if (!Array.isArray(tables) || !tables.length || tables.length > MYSQL_SNAPSHOT_LIMITS.tables) throw new Error('Declare 1 to 32 tables.');
  const declared = tables.map(t => ({ table: t.table, key: t.key, prefix: t.resourcePrefix ?? t.table, changeColumn: t.changeColumn ?? null }));
  for (const t of declared) { quote(t.table); quote(t.key); if (t.changeColumn) quote(t.changeColumn.column); }
  if (new Set(declared.map(t => t.table)).size !== declared.length) throw new Error('Each table name is declared once per observer.');
  const audits = new Map();
  for (const t of declared) if (t.changeColumn) {
    let bytes;
    try { bytes = readFileSync(t.changeColumn.audit); } catch { throw new Error('A changeColumn needs "audit": the path of its recorded source check (no writer sets the column: app code, agent SQL, SET timestamp, triggers, cascades).'); }
    audits.set(t.table, { ref: String(t.changeColumn.audit).split('/').slice(-3).join('/'), sha256: createHash('sha256').update(bytes).digest('hex') });
  }
  if (declared.some(t => t.changeColumn) && !(Number.isFinite(maxCommitLagMs) && maxCommitLagMs >= 0 && maxCommitLagMs <= 600000)) throw new Error('A changeColumn needs "maxCommitLagMs": the longest statement-to-commit delay, 0 to 600000 ms.');
  if (!Array.isArray(watchedResources) || !watchedResources.every(r => typeof r === 'string' && r.length <= 200)) throw new Error('watchedResources lists resource strings.');
  credentialFrom(env, credentialEnv, 'mysql-snapshot credential'); // validates the namespace now; the value is read at each mark
  // The server's RSA public key (PEM) for caching_sha2_password full authentication, pinned beside the credential;
  // a key the server offers is never used (mysql-wire.mjs). Without one only the fast path and native logins work.
  const keyEnv = `${credentialEnv}_RSA_PUBLIC_KEY`;
  const serverKey = () => CREDENTIAL_ENV.test(keyEnv) ? credentialFrom(env, keyEnv, 'mysql-snapshot server key') ?? null : null;
  const observer = { kind: 'mysql-snapshot-diff', instanceId };
  const snapshots = new Map();
  let seq = 0, nextIndex = 0;

  const take = async () => {
    const secret = credentialFrom(env, credentialEnv, 'mysql-snapshot credential');
    const split = typeof secret === 'string' ? secret.indexOf(':') : -1;
    if (split < 1) throw new MysqlError('credential-missing');
    const client = await connect({ host, port, database, user: secret.slice(0, split), password: secret.slice(split + 1), serverPublicKey: serverKey(), connectTimeoutMs: Math.min(5000, statementTimeoutMs) });
    const opts = { queryTimeoutMs: statementTimeoutMs + 1000 };
    try {
      for (const sql of ["SET SESSION TRANSACTION ISOLATION LEVEL REPEATABLE READ", "SET SESSION time_zone = '+00:00'", `SET SESSION sql_mode = '${SQL_MODE}'`,
        `SET SESSION max_execution_time = ${statementTimeoutMs}`]) await client.query(sql, opts);
      // The server's clock before the snapshot starts, so the guard is never later than the snapshot.
      const [[now, readOnly] = []] = (await client.query("SELECT DATE_FORMAT(NOW(6), '%Y-%m-%d %H:%i:%s.%f'), @@global.read_only", opts)).rows;
      if (readOnly !== '0') throw new MysqlError('read-only-server-refused');
      if (micros(now) === null) throw new MysqlError('unexpected-result');
      await client.query('START TRANSACTION WITH CONSISTENT SNAPSHOT, READ ONLY', opts);
      const byTable = new Map();
      for (const t of declared) {
        const [info] = (await client.query(`SELECT ENGINE, TABLE_TYPE, DATE_FORMAT(CREATE_TIME, '%Y-%m-%d %H:%i:%s'), CREATE_OPTIONS FROM information_schema.TABLES WHERE TABLE_SCHEMA = ${literal(database)} AND TABLE_NAME = ${literal(t.table)}`, opts)).rows;
        if (!info) throw new MysqlError('table-missing');
        if (info[1] !== 'BASE TABLE' || info[0] !== 'InnoDB') throw new MysqlError('relation-not-innodb-table');
        if (/partitioned/i.test(info[3] ?? '')) throw new MysqlError('relation-partitioned-refused');
        // InnoDB's own ids (PROCESS privilege): an exchanged partition or a renamed twin brings other ids. The dictionary
        // name is "<database>/<table>" with "$" written as "@0024".
        const dictionaryName = `${database}/${t.table}`.replaceAll('$', '@0024');
        // Compared byte for byte (the column's collation ignores case), and exactly one row: anything else is unreadable.
        const idRows = !tableIds ? [] : (await client.query(`SELECT TABLE_ID, SPACE FROM information_schema.INNODB_TABLES WHERE BINARY NAME = '${dictionaryName}'`, opts)).rows;
        const ids = tableIds ? idRows[0] ?? null : null;
        if (tableIds && !(idRows.length === 1 && /^\d+$/.test(ids[0] ?? '') && /^\d+$/.test(ids[1] ?? ''))) throw new MysqlError('table-ids-unreadable');
        const columns = (await client.query(`SELECT COLUMN_NAME, EXTRA, DATA_TYPE, DATETIME_PRECISION, COLUMN_DEFAULT FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = ${literal(database)} AND TABLE_NAME = ${literal(t.table)} ORDER BY ORDINAL_POSITION`, opts)).rows;
        if (!columns.length || !columns.every(([name]) => IDENT.test(name ?? '')) || !columns.some(([name]) => name === t.key)) throw new MysqlError('unexpected-columns');
        let precision = null;
        if (t.changeColumn) {
          const col = columns.find(([name]) => name === t.changeColumn.column);
          // TIMESTAMP only (stored in UTC; a DATETIME stamp is in the writer's time zone), set by the server on insert and on update.
          if (!col || col[2] !== 'timestamp' || !ON_UPDATE.test((col[1] ?? '').trim()) || !SERVER_DEFAULT.test(col[4] ?? '')) throw new MysqlError('change-column-not-server-maintained');
          precision = Number(col[3] ?? 0);
        }
        const select = `SELECT CAST(${quote(t.key)} AS CHAR), ${t.changeColumn ? `DATE_FORMAT(${quote(t.changeColumn.column)}, '%Y-%m-%d %H:%i:%s.%f')` : 'NULL'}, MD5(JSON_ARRAY(${columns.map(([name]) => quote(name)).join(', ')})) FROM ${quote(database)}.${quote(t.table)} ORDER BY 1 LIMIT ${rowsPerTable + 1}`;
        const rows = (await client.query(select, { ...opts, maxRows: rowsPerTable + 1 })).rows;
        if (rows.length > rowsPerTable) throw new MysqlError('row-limit');
        const map = new Map(rows.map(([key, change, hash]) => [key, { change, hash }]));
        map.identity = digest({ created: info[2], columns: columns.map(([name, , type]) => [name, type]), ...(ids ? { tableId: ids[0], space: ids[1] } : {}) });
        // CREATE_TIME has whole seconds: a table created or rebuilt in the second this mark reads could be rebuilt
        // again in that second without a new CREATE_TIME, so its identity cannot be followed from this mark.
        map.fresh = !info[2] || info[2] >= now.slice(0, 19);
        map.duplicateKeys = map.size !== rows.length || rows.some(([key]) => key === null);
        map.precision = precision;
        byTable.set(t.table, map);
      }
      await client.query('COMMIT', opts);
      return { now, tables: byTable };
    } finally { client.close(); }
  };
  const reasonOf = error => !(error instanceof MysqlError) ? 'read-failed'
    : error.sqlState === '42000' ? 'permission-denied' : error.sqlState === '42S02' ? 'table-missing'
    : ['row-limit', 'credential-missing', 'read-only-server-refused', 'relation-not-innodb-table', 'relation-partitioned-refused', 'table-ids-unreadable', 'table-missing', 'change-column-not-server-maintained', 'unexpected-columns'].includes(error.code) ? error.code
    : ['connection-closed', 'connect-failed'].includes(error.code) ? 'read-timeout-or-closed'
    : ['cleartext-password-refused', 'unsupported-authentication', 'authentication-failed', 'empty-password-refused', 'server-key-not-pinned', 'invalid-server-key'].includes(error.code) ? 'authentication-refused' : 'read-failed';

  return {
    kind: observer.kind, instanceId, source: 'sql-snapshot',
    scope: Object.freeze({ operations: ['insert', 'update', 'delete'], names: declared.map(t => t.table), actorAttribution: 'none', evidence: 'authoritative' }),
    async start() { await take(); },
    async mark() {
      const index = nextIndex++;
      try { snapshots.set(index, { ok: true, at: new Date().toISOString(), ...(await take()) }); }
      catch (error) { snapshots.set(index, { ok: false, at: new Date().toISOString(), reason: reasonOf(error) }); }
      snapshots.delete(index - MYSQL_SNAPSHOT_LIMITS.retainedMarks);
      return { index };
    },
    async collect(from, to) {
      const before = snapshots.get(from?.index), after = snapshots.get(to?.index);
      if (!before?.ok || !after?.ok) return { events: [], coverage: 'failed', reason: (!before?.ok ? before : after)?.reason || 'missing-snapshot' };
      if (!(to.index > from.index)) return { events: [], coverage: 'failed', reason: 'window-not-forward' };
      const identity = new Set();
      for (const t of declared) {
        const a = before.tables.get(t.table), b = after.tables.get(t.table);
        if (a.identity !== b.identity) identity.add('relation-rewritten');
        else if (a.fresh) identity.add('relation-unverified');
        if (a.duplicateKeys || b.duplicateKeys) identity.add('duplicate-key');
      }
      if (identity.size) return { events: [], coverage: 'failed', reason: [...identity].sort().join(',') };
      const events = [], exact = [];
      for (const t of declared) {
        const a = before.tables.get(t.table), b = after.tables.get(t.table), resourceOf = key => `${t.prefix}/${key}`;
        const found = [];
        const emit = (operation, key, row) => found.push(makeEffect({ source: 'sql-snapshot', observer, seq: ++seq, observedAt: after.at, actor: null,
          operation, name: t.table, resource: resourceOf(key).slice(0, 200), outcome: 'committed', content: row.hash }));
        // An update: the content changed, or the server-maintained column moved (a write and its revert inside
        // the window leave the content as it was; the column still records that a committed update happened).
        for (const [key, row] of b) if (!a.has(key)) emit('insert', key, row); else if (a.get(key).hash !== row.hash || (t.changeColumn && a.get(key).change !== row.change)) emit('update', key, row);
        for (const [key, row] of a) if (!b.has(key)) emit('delete', key, row);
        if (!t.changeColumn) { events.push(...found); continue; }
        // Same server clock at both marks: a row stamped at or after the guard could have a write in flight at the start mark.
        const tick = 10n ** BigInt(6 - Math.min(6, Math.max(0, a.precision ?? 6)));
        const guard = micros(before.now) - BigInt(Math.ceil(maxCommitLagMs)) * 1000n - tick;
        const ambiguous = new Set();
        let violated = false;
        for (const [key, row] of a) {
          const v = micros(row.change);
          if (v === null || v >= guard) ambiguous.add(resourceOf(key));
          const later = b.get(key);
          if (!later) { ambiguous.add(resourceOf(key)); continue; }
          if (later.hash !== row.hash && later.change === row.change) violated = true; // content changed but the column did not
        }
        for (const key of b.keys()) if (!a.has(key)) ambiguous.add(resourceOf(key));
        const present = [];
        for (const resource of new Set(watchedResources)) {
          if (!resource.startsWith(`${t.prefix}/`)) continue;
          const key = resource.slice(t.prefix.length + 1);
          if (a.has(key) && b.has(key)) present.push(resource);
        }
        const audit = audits.get(t.table), list = [...ambiguous];
        violated ||= list.length > 10000 || present.length > MYSQL_SNAPSHOT_LIMITS.presentResources;
        if (!violated) events.push(...found);
        exact.push({ name: t.table, auditSha256: audit.sha256, ambiguousResources: list.slice(0, 10000), presentResources: present.slice(0, MYSQL_SNAPSHOT_LIMITS.presentResources), violated,
          basis: `server-maintained change column ${t.changeColumn.column} (TIMESTAMP with DEFAULT and ON UPDATE CURRENT_TIMESTAMP in the schema; table identity: ${tableIds ? 'CREATE_TIME and InnoDB table and tablespace ids' : 'CREATE_TIME only, so an exchanged partition or a same-second renamed twin is not seen'}; source-checked that no writer sets it (app code, agent SQL, SET timestamp, triggers, cascades): ${audit.ref} sha256 ${audit.sha256.slice(0, 12)}; commit lag ${maxCommitLagMs} ms, ${list.length} ambiguous row${list.length === 1 ? '' : 's'})`.slice(0, 512) });
      }
      return { events, coverage: 'net-only', reason: 'net-change-between-snapshots', ...(exact.length ? { exact } : {}) };
    },
    async stop() {},
  };
}
