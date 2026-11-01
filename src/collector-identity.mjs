// The collector identity (coverage v2, Part E): which recorder code built an egress, SMTP or provider-feed observer's windows. The collector
// files sit outside the evaluator hash, so each such observer's run record carries { label, digest, node }: a digest over each
// listed file's name (relative to integrations/observers/) and bytes, read when this module loads, and the Node version (the
// recorder reads node:http internals). It enters the run, the exported suite and the comparison signature, so a collector edit
// or another Node version makes runs compare as different collectors. The label is for people only.
import { readFile } from 'node:fs/promises';
import { createHash } from 'node:crypto';

// egress-recorder/2: PR-1 (scoped entries, the follow rule); /3: Part D (the run-end drain, markClear, closedAfterCollect); /4: LATE-FIELDS (a
// late entry that is exactly one completed after-witness request carries its ledger seq and captured record); /5: verified signature
// headers (b': a destination's idempotency.signing secrets are read and each send is verified; its records may carry signing); /6: object
// routes for in-doubt resolution (a settled forward's upstream record carries target { exact, query }; IN-DOUBT-LEAD-RULING-IDR0 R-2); /7:
// in-doubt resolution R0 (a settled forward's upstream record also carries its transport record: whether the TCP connect completed, and the
// settle time on the monotonic and wall clocks; src/in-doubt.mjs); /8: in-doubt resolution R1 (a recorder may declare a request feed,
// src/request-feed-rules.mjs: its windows' scope publishes it, a forwarded send to one of its hosts also carries its arrival on both clocks
// in its transport record, and the recorder's resolver read at run end returns each such in-doubt send's sealed read); /9: in-doubt resolution R2
// (a destination may declare readBack, src/read-back-rules.mjs: its windows' scope publishes the read-back record, a settled forward to such a
// destination also carries its read-back record, the write credential's salted digest included, and the resolver read at run end also returns
// each in-doubt send's sealed read-back read; the reader, read-back.mjs, joins this label's files: ADDENDUM-R2 m3); /10: FIX-02 (the sink
// holds its port on both loopback addresses, 127.0.0.1 and [::1], each bound exclusively, and does not start if either bind fails); /11: FIX-04
// (a destination may declare aliases, folded into its host and published on the scope; a completed send to an undeclared host sharing a
// destination's registrable domain is a scoped entry egress-undeclared-sibling-host in a check window and that code window-wide elsewhere);
// /12: the run-end drain's last look after one turn checks quiet again (under /3 to /11 a request read, recorded and answered in that
// turn could leave the drain quiescent just after it arrived); /13: FIX-08 (the factory passes each recorder the destinations the run's other
// egress recorders declare: a send to one is recorded under it, a send to its sibling adds it an entry, and the scope publishes them as cross).
// smtp-sink/2: FIX-02, the same two exclusive loopback binds for the SMTP sink.
// request-feed/1: the request-feed reader (integrations/observers/request-feed.mjs) and the recorder code that assembles its reads; its record
// sits in the egress recorder's run record (requestFeed.collector).
// provider-feed/2: feed v2 (an entry's signed template, read as a declared label on its events); /3: feed v2 Part B (scoped late entries,
// a lone one carrying its event seq and template record, and the run-end drain); /4: feed v2 Part C (a window's only late entry, one
// signed send whose template is a declared label, may lift effect.only through an allow it matches, template included); /5: later outcomes
// (a feed that declares "outcomes" reads signed outcome entries and seals { clear, waitedMs, records } in the settlement record; they
// decide nothing under /5); /6: the later-outcome stage (a positive pass a send's later failure, or an unclear horizon, leaves without
// credit is judged again and lowered; src/later-outcome.mjs); /7: FIX-06 (the feed record and every window carry the profile's declared key
// source, keySource and adapterReads, and custody reads them: src/custody.mjs feedKeyCustody); /8: the run-end drain's confirming head is
// held to the read it found quiet (under /3 to /7 a background read between the quiet check and that head could leave the drain quiescent
// just after an entry arrived).
// pg-snapshot/1: Postgres read-back (src/pg-readback.mjs, roadmap v2 item 2). A table that declares readBack has its declared value columns,
// a sha256 of an expected row's other columns and a sha256 of each other row read in each mark's transaction, and collect() returns the
// read-back record beside an unchanged window. The reader's files include src/pg-readback.mjs, which canonicalises and seals the values.
// pg-snapshot/2: N12 and N13 (the platform ignore lists, the queue end barrier and the run lease, opt-in; the database's catalog
// fingerprint at each mark): the ignore-list reader reads both checked-in lists at import, so the lists are files of the reader too.
// pg-wal/1: the Postgres logical-decoding observer (N1, integrations/observers/pg-wal.mjs; docs/PG-WAL.md) with N12's and N13's rules,
// over the same files as pg-snapshot/2 with pg-wal.mjs in place of pg-snapshot.mjs. Not yet an observer type a profile declares, so no
// run carries it until the type is wired.
// dns-stub/1: the loopback DNS stub (integrations/observers/dns-stub.mjs; DNS-STUB.md), over the three files the stub's own record
// (DNS_STUB_COLLECTOR) digests, in its order, so the two records are equal. Not yet an observer type either: the factory does not build
// it, so factory.mjs joins its files when the type is wired.
// pg-snapshot/3 and pg-wal/2: the actor capture (NC2 item 2, integrations/observers/pg-actor.mjs), opt-in through a pg-snapshot
// observer's actorCapture (the factory passes it): each mark also verifies the installed capture's definitions and reads its ledger,
// and each event's actor comes from the join (pg-snapshot: every write to the row resolves to one actor; pg-wal: each decoded write on
// its own transaction id). Without actorCapture both observers send and return exactly what pg-snapshot/2 and pg-wal/1 did (pinned
// in pg.test.mjs and pg-wal.test.mjs); pg-actor.mjs joins both observers' files.
// pg-snapshot/4 and pg-wal/3: the Supabase identity rules (NC9 item 3, integrations/observers/supabase-rules.mjs): with a target's
// supabaseRules the factory gives each captured observer the rules' resolver (a service-role write is the declared tool's, never an end
// user's), and pg-snapshot reports each window's zero-row facts for the evaluator's rls-zero-row stage; supabase-rules.mjs joins both
// observers' files.
// pg-snapshot/5 and pg-wal/4: NC9 item 4. pg-wal is a profile observer type with a source of its own (sql-wal: lineage database-log,
// custody observer-held), built by the factory with its declared tables, value columns, barrier, background-writer options and actor
// capture; pg-snapshot's background-writer options (N12: platform, ignore, queues, drainTimeoutMs, pollMs, runLease) reach it from a
// profile. A run's pg-wal observer record carries this collector.
// pg-wal/5: pg_net on the wire (integrations/observers/pg-net-wire.mjs, pg-net-wire/1): with a profile's pgNetWire the factory gives the
// observer a tap in the database container's network and a pg_net witness per mark, and a wire window that is complete and observer-held
// (its declared programRoles: every login role that can run a program in that container is the operator's) counts pg_net's unlogged
// request queue as observed (others.wire). Without pgNetWire the observer sends and returns exactly what pg-wal/4 did (pinned in
// pg-wal.test.mjs); pg-net-wire.mjs joins its files.
export const COLLECTOR_LABELS = Object.freeze({ 'egress-recorder': 'egress-recorder/13', 'smtp-sink': 'smtp-sink/2', 'provider-feed': 'provider-feed/8', 'request-feed': 'request-feed/1', 'pg-snapshot': 'pg-snapshot/5', 'pg-wal': 'pg-wal/5', 'dns-stub': 'dns-stub/1' });
// Every label a saved run may carry: a run made by an earlier recorder still validates (it never compares with a later one).
export const KNOWN_COLLECTOR_LABELS = Object.freeze(['egress-recorder/2', 'egress-recorder/3', 'egress-recorder/4', 'egress-recorder/5', 'egress-recorder/6', 'egress-recorder/7', 'egress-recorder/8', 'egress-recorder/9', 'egress-recorder/10', 'egress-recorder/11', 'egress-recorder/12', 'egress-recorder/13', 'smtp-sink/1', 'smtp-sink/2', 'provider-feed/1', 'provider-feed/2', 'provider-feed/3', 'provider-feed/4', 'provider-feed/5', 'provider-feed/6', 'provider-feed/7', 'provider-feed/8', 'request-feed/1', 'pg-snapshot/1', 'pg-snapshot/2', 'pg-snapshot/3', 'pg-snapshot/4', 'pg-snapshot/5', 'pg-wal/1', 'pg-wal/2', 'pg-wal/3', 'pg-wal/4', 'pg-wal/5', 'dns-stub/1']);
// The labels whose windows may carry scoped entries.
export const SCOPED_COLLECTOR_LABELS = Object.freeze(['egress-recorder/2', 'egress-recorder/3', 'egress-recorder/4', 'egress-recorder/5', 'egress-recorder/6', 'egress-recorder/7', 'egress-recorder/8', 'egress-recorder/9', 'egress-recorder/10', 'egress-recorder/11', 'egress-recorder/12', 'egress-recorder/13', 'provider-feed/3', 'provider-feed/4', 'provider-feed/5', 'provider-feed/6', 'provider-feed/7', 'provider-feed/8']);
// The labels whose scoped entries may carry a late request's seq and captured record (LATE-FIELDS); earlier builds never write them.
export const CAPTURED_ENTRY_LABELS = Object.freeze(['egress-recorder/4', 'egress-recorder/5', 'egress-recorder/6', 'egress-recorder/7', 'egress-recorder/8', 'egress-recorder/9', 'egress-recorder/10', 'egress-recorder/11', 'egress-recorder/12', 'egress-recorder/13', 'provider-feed/3', 'provider-feed/4', 'provider-feed/5', 'provider-feed/6', 'provider-feed/7', 'provider-feed/8']);
// The provider-feed labels under which a window's only late entry may lift effect.only through an allow it matches, template included
// (feed v2 Part C); a run judged by an earlier build keeps the semantics it was judged with.
export const TEMPLATE_LIFT_LABELS = Object.freeze(['provider-feed/4', 'provider-feed/5', 'provider-feed/6', 'provider-feed/7', 'provider-feed/8']);
// The provider-feed labels whose windows may carry template records (feed v2: an entry's signed template, read as a declared label).
export const TEMPLATE_COLLECTOR_LABELS = Object.freeze(['provider-feed/2', 'provider-feed/3', 'provider-feed/4', 'provider-feed/5', 'provider-feed/6', 'provider-feed/7', 'provider-feed/8']);
// The labels whose records may carry run-end drains (coverage v2 Part D onward).
export const DRAIN_COLLECTOR_LABELS = Object.freeze(['egress-recorder/3', 'egress-recorder/4', 'egress-recorder/5', 'egress-recorder/6', 'egress-recorder/7', 'egress-recorder/8', 'egress-recorder/9', 'egress-recorder/10', 'egress-recorder/11', 'egress-recorder/12', 'egress-recorder/13', 'provider-feed/3', 'provider-feed/4', 'provider-feed/5', 'provider-feed/6', 'provider-feed/7', 'provider-feed/8']);
// The provider-feed labels whose runs carry later outcomes (a feed record that declares "outcomes"; the settlement record's later list).
export const OUTCOME_COLLECTOR_LABELS = Object.freeze(['provider-feed/5', 'provider-feed/6', 'provider-feed/7', 'provider-feed/8']);
// The provider-feed labels under which the later-outcome stage reads those records (src/later-outcome.mjs); a /5 run keeps them inert.
export const LATER_STAGE_LABELS = Object.freeze(['provider-feed/6', 'provider-feed/7', 'provider-feed/8']);
// The labels whose runs may declare verified signature headers (idempotency.signing) and carry signing records; earlier builds never do.
export const SIGNING_COLLECTOR_LABELS = Object.freeze(['egress-recorder/5', 'egress-recorder/6', 'egress-recorder/7', 'egress-recorder/8', 'egress-recorder/9', 'egress-recorder/10', 'egress-recorder/11', 'egress-recorder/12', 'egress-recorder/13']);
// The labels whose settled forwards carry target { exact, query } and whose runs may declare object routes (objectPaths, objectFields):
// only a send such a recorder marked exact and query-free can be judged by its outcome.
export const TARGET_LABELS = Object.freeze(['egress-recorder/6', 'egress-recorder/7', 'egress-recorder/8', 'egress-recorder/9', 'egress-recorder/10', 'egress-recorder/11', 'egress-recorder/12', 'egress-recorder/13']);
// Gate B of in-doubt resolution (IN-DOUBT-DESIGN-ADDENDUM-R1 1.3): the labels whose sends may carry a transport record and whose windows
// the backend tier reads for unresolved in-doubt sends (src/in-doubt.mjs). A run judged by an earlier build keeps that build's reading.
export const IN_DOUBT_LABELS = Object.freeze(['egress-recorder/7', 'egress-recorder/8', 'egress-recorder/9', 'egress-recorder/10', 'egress-recorder/11', 'egress-recorder/12', 'egress-recorder/13']);
// In-doubt resolution R1 (IDR-4): the labels whose recorder records may declare a request feed, whose windows' scope may publish it and whose
// transport records may carry an arrival (src/request-feed-rules.mjs, src/in-doubt.mjs). A /7 run never carries either.
export const REQUEST_FEED_LABELS = Object.freeze(['egress-recorder/8', 'egress-recorder/9', 'egress-recorder/10', 'egress-recorder/11', 'egress-recorder/12', 'egress-recorder/13']);
// In-doubt resolution R2 (IDR-3): the labels whose recorder records may declare read-back, whose windows' scope may publish it and whose settled
// forwards may carry a read-back record (src/read-back-rules.mjs, src/in-doubt.mjs). An /8 run never carries either.
export const READ_BACK_LABELS = Object.freeze(['egress-recorder/9', 'egress-recorder/10', 'egress-recorder/11', 'egress-recorder/12', 'egress-recorder/13']);
// FIX-04: the labels whose windows may carry an undeclared sibling host's scoped entry or window-wide code (egress-undeclared-sibling-host),
// whose scope may publish aliases, and whose windows the validator binds to their sibling sends (src/http-effects.mjs). A run judged by an
// earlier build carries neither and keeps the reading it was judged with.
export const SIBLING_LABELS = Object.freeze(['egress-recorder/11', 'egress-recorder/12', 'egress-recorder/13']);
// FIX-08: the labels whose recorder records and windows' scope may publish the run's other recorders' destinations (cross), whose events may
// be named by one and whose sibling entries may name one (src/egress-rules.mjs crossDestinationsOf). A run an earlier build recorded carries
// none and keeps the reading it was judged with.
export const CROSS_LABELS = Object.freeze(['egress-recorder/13']);
// FIX-06: the provider-feed labels whose run records must carry the feed's declared key source (keySource, src/provider-feed-rules.mjs).
// This build also writes it under the labels a feed it cannot fully run is recorded with (provider-feed/3 or /4, src/http-connector.mjs);
// a record an earlier build wrote carries none and keeps the custody it was judged with (src/custody.mjs feedKeyCustody).
export const KEY_SOURCE_LABELS = Object.freeze(['provider-feed/7', 'provider-feed/8']);
// The database observers' background-writer rules (N12), read by pg-snapshot and pg-wal alike.
const PG_BACKGROUND_FILES = ['end-barrier.mjs', 'run-lease.mjs', 'ignore-lists/ignore-list.mjs', 'ignore-lists/supabase.json', 'ignore-lists/litestream.json'];
export const COLLECTOR_FILES = Object.freeze({
  'egress-recorder': Object.freeze(['factory.mjs', 'sink-ledger.mjs', 'egress-recorder.mjs', 'egress-forward.mjs', 'read-back.mjs']),
  'smtp-sink': Object.freeze(['factory.mjs', 'sink-ledger.mjs', 'smtp-sink.mjs']),
  'provider-feed': Object.freeze(['factory.mjs', 'sink-ledger.mjs', 'provider-feed.mjs']),
  // The recorder builds the reader and assembles each read from its own sends (ADDENDUM-R2 m3: the reader has its own entry).
  'request-feed': Object.freeze(['egress-recorder.mjs', 'request-feed.mjs']),
  // The observer, its wire client and the read-back rules it reads values with (named relative to integrations/observers/).
  // N13: the catalog fingerprint it reads at each mark; N12 (pg-snapshot/2): the end barrier, the run lease, and the ignore-list reader
  // with the lists it reads at import; pg-snapshot/3 (and pg-wal/2): the actor capture's join; /4 (and pg-wal/3): the Supabase rules.
  'pg-snapshot': Object.freeze(['factory.mjs', 'pg-wire.mjs', 'pg-snapshot.mjs', '../../src/pg-readback.mjs', 'catalog.mjs', ...PG_BACKGROUND_FILES, 'pg-actor.mjs', 'supabase-rules.mjs']),
  'pg-wal': Object.freeze(['factory.mjs', 'pg-wire.mjs', 'pg-wal.mjs', '../../src/pg-readback.mjs', 'catalog.mjs', ...PG_BACKGROUND_FILES, 'pg-actor.mjs', 'supabase-rules.mjs', 'pg-net-wire.mjs']),
  'dns-stub': Object.freeze(['dns-stub.mjs', 'dns-wire.mjs', 'sink-ledger.mjs']),
});
export async function collectorDigest(names, base = new URL('../integrations/observers/', import.meta.url)) {
  const hash = createHash('sha256');
  for (const name of names) hash.update(`${name}\n`).update(await readFile(new URL(name, base))).update('\n');
  return hash.digest('hex');
}
export const COLLECTOR_RECORDS = Object.freeze(Object.fromEntries(await Promise.all(Object.entries(COLLECTOR_FILES).map(async ([type, names]) =>
  [type, Object.freeze({ label: COLLECTOR_LABELS[type], digest: await collectorDigest(names), node: process.versions.node })]))));
// A run record's collector entry, by shape: a known label, 64 hex characters and a Node version.
export const validCollector = (type, c) => c !== null && typeof c === 'object' && !Array.isArray(c) && Object.keys(c).sort().join(',') === 'digest,label,node'
  && KNOWN_COLLECTOR_LABELS.includes(c.label) && c.label.startsWith(`${type}/`) && /^[a-f0-9]{64}$/.test(c.digest) && typeof c.node === 'string' && /^\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(c.node);
