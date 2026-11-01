// Lineage of an observer's evidence, by effect source (recorded on each sealed
// window). Its own module so that src/http-effects.mjs and src/custody.mjs can
// both import it without a cycle; http-effects.mjs re-exports it unchanged for
// existing importers. Pure: no I/O.
export const LINEAGE_BY_SOURCE = Object.freeze({
  'sql-snapshot': 'application-store', 'sql-audit-table': 'application-store', 'http-audit-log': 'application-store', 'file-audit-log': 'application-store',
  'hold-proxy': 'request-path', 'http-egress': 'request-path', 'smtp-capture': 'request-path', 'otel-genai': 'target-instrumentation', 'mcp-jsonrpc': 'target-instrumentation',
  // An email provider's own signed record of what it accepted, read by the provider-feed observer (never the app's record).
  'provider-feed': 'provider-record',
  // The application's own action log (src/app-log-rules.mjs): what the application says it did. Never custody evidence.
  'app-log': 'application-report',
  // The Postgres logical-decoding observer (pg-wal, NC9 item 4; docs/PG-WAL.md): the server's own write-ahead log, read through a
  // temporary slot the observer's session holds.
  'sql-wal': 'database-log',
});
