// App action log reader (the "file" route of src/app-log-rules.mjs). It reads the JSON-lines file the application appends
// one line per action to, and maps each line to effect events with source "app-log". The application writes this file, so
// its windows are never custody evidence: the connector keeps them apart from every observer window and seals them beside a
// check's windows (data.appLogWindows). It sends no request, waits for nothing and holds no port: a mark is a local stat and
// a read of at most the last line and 4 KiB, and the window is read after every observer was collected, so it adds no request
// and no wait to any observer window (only those small file reads, which run inside them).
//
// Marks (the connector's order, src/http-connector.mjs): the start mark after every custody observer's start mark, right
// before the check request; the cut right after the custody end marks, before any witness request; the collect after every
// custody collect. A window is the byte range [start, cut]. Lines after the cut (a witness's side effects, a late flush) are
// never this check's.
// Consistency at marks: each mark fingerprints the 4 KiB before its position and records the file's inode. The range is read
// once, at collect, and only when both fingerprints still match and the inode is unchanged; a file that was rotated or
// truncated, or rewritten in the 4 KiB before a mark, fails the window (other rewrites of earlier lines are not detected: the
// application writes the file). A line still being written at the cut is not read, and a line already being written at the
// start mark began before the check's request, so it is skipped; either leaves the window partial. The file is opened
// non-blocking and checked on the open descriptor, so a FIFO or any other non-regular file at the path reads failed, never hangs.
// Entries before start() are never read: the file is bound at its end when the run starts.
import { fstatSync, openSync, readSync, closeSync, constants } from 'node:fs';
import { createHash } from 'node:crypto';
import { makeEffect, validateWindow } from './events.mjs';
import { readAppLogLine, appLogReason, compileAppLog, APP_LOG_BOUNDS, APP_LOG_SOURCE, APP_LOG_KIND } from '../../src/app-log-rules.mjs';

const FINGERPRINT_BYTES = 4096;
const sha = buf => createHash('sha256').update(buf).digest('hex');

// cfg: compileAppLog's configuration. clock: the wall time stamped on events without a readable "at" (tests inject one).
export function createAppLogObserver(cfg, { clock = () => Date.now() } = {}) {
  const observer = Object.freeze({ kind: APP_LOG_KIND, instanceId: cfg.instanceId });
  let boundIno = null;
  // Non-blocking, no symlink, and only a regular file (checked on the descriptor): a FIFO or device never blocks the run.
  const open = () => {
    const fd = openSync(cfg.path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
    try { const st = fstatSync(fd); if (!st.isFile()) throw new Error('app-log-not-a-file'); return { fd, st }; } catch (error) { closeSync(fd); throw error; }
  };
  const readRange = (fd, start, end) => { const buf = Buffer.alloc(end - start); if (buf.length) readSync(fd, buf, 0, buf.length, start); return buf; };
  // The end of the last complete line, a fingerprint of the bytes before it, and the file identity.
  const position = () => {
    let fd, st;
    try { ({ fd, st } = open()); } catch { return { ok: false, reason: 'app-log-file-missing' }; }
    try {
      let pos = st.size;
      if (pos > 0) {
        const tailStart = Math.max(0, pos - APP_LOG_BOUNDS.lineBytes), tail = readRange(fd, tailStart, pos), cut = tail.lastIndexOf(0x0a);
        pos = cut < 0 ? tailStart : tailStart + cut + 1;
      }
      const fpStart = Math.max(0, pos - FINGERPRINT_BYTES);
      return { ok: true, pos, size: st.size, ino: st.ino, at: clock(), partialTail: st.size > pos, fingerprint: { start: fpStart, sha256: sha(readRange(fd, fpStart, pos)) } };
    } finally { closeSync(fd); }
  };
  const stillThere = (fd, st, mark) => st.ino === mark.ino && st.size >= mark.pos && sha(readRange(fd, mark.fingerprint.start, mark.pos)) === mark.fingerprint.sha256;
  return {
    kind: observer.kind, instanceId: cfg.instanceId, source: APP_LOG_SOURCE, scope: cfg.scope,
    // Binds the file at its current end; a missing file fails start, so every window reads failed.
    async start() { const p = position(); if (!p.ok) throw new Error(p.reason); boundIno = p.ino; },
    // A mark on a file replaced since the run started is a rotation: every window it bounds fails.
    mark() { const p = position(); return p.ok ? { ...p, rotated: p.ino !== boundIno } : p; },
    // The window [from, cut]: { source, instanceId, scope, coverage, reason, events }, never thrown.
    collect(from, cut) {
      const base = { source: APP_LOG_SOURCE, instanceId: cfg.instanceId, scope: cfg.scope };
      const failed = reason => ({ ...base, coverage: 'failed', reason, events: [] });
      if (!from?.ok || !cut?.ok) return failed((from?.ok ? cut : from)?.reason ?? 'app-log-not-marked');
      if (from.rotated || cut.rotated || cut.ino !== from.ino || cut.pos < from.pos) return failed('app-log-truncated-or-rotated');
      if (cut.pos - from.pos > APP_LOG_BOUNDS.windowBytes) return { ...base, coverage: 'partial', reason: 'app-log-window-too-large', events: [] };
      let fd, bytes;
      try {
        let st;
        ({ fd, st } = open());
        if (!stillThere(fd, st, from) || !stillThere(fd, st, cut)) return failed('app-log-truncated-or-rotated');
        bytes = readRange(fd, from.pos, cut.pos);
      } catch { return failed('app-log-truncated-or-rotated'); } finally { if (fd !== undefined) closeSync(fd); }
      const problems = new Set(), events = [], ids = new Set();
      let offset = from.pos, first = true;
      for (const line of bytes.toString('utf8').split('\n')) {
        const at = offset; offset += Buffer.byteLength(line) + 1;
        // The line being written at the start mark began before the check's request: never this check's.
        if (first) { first = false; if (from.partialTail) { problems.add('app-log-line-incomplete-at-start'); continue; } }
        if (!line) continue;
        const read = readAppLogLine(line, cfg);
        read.problems.forEach(p => problems.add(p));
        if (read.kind !== 'rule') continue;
        // A repeated entry id: a replayed or duplicated line, so the window cannot be read line by line.
        if (read.entryId !== null) { if (ids.has(read.entryId)) problems.add('app-log-duplicate-id'); ids.add(read.entryId); }
        read.effects.forEach((e, i) => {
          if (events.length >= APP_LOG_BOUNDS.eventsPerWindow) { problems.add('app-log-window-too-large'); return; }
          // seq: the line's byte offset, times 128, plus the recipient index (at most 100 recipients per line).
          events.push(makeEffect({ source: APP_LOG_SOURCE, observer, seq: (at + 1) * 128 + i, observedAt: e.at ?? new Date(cut.at).toISOString(), actor: e.actor,
            operation: e.operation, name: e.name, resource: e.resource, outcome: e.outcome, correlation: e.correlation ?? {}, content: line, ...(e.captured ? { captured: e.captured } : {}) }));
        });
      }
      if (cut.partialTail) problems.add('app-log-line-incomplete-at-cut');
      const reason = appLogReason([...problems]);
      return { ...base, coverage: reason ? 'partial' : 'complete', reason, events: problems.has('app-log-window-too-large') ? [] : events };
    },
    async stop() {},
  };
}

// The connector's handle on a target's declared app logs (src/http-connector.mjs): mark() and collect() over all of them,
// in declaration order. A log that cannot start, mark or collect gives failed windows; it never stops the run, and it never
// throws into a check (a malformed window is replaced by a failed one).
export async function startAppLogs(target, options) {
  const readers = target.appLogs.map(o => createAppLogObserver(compileAppLog(o, target), options));
  const started = await Promise.all(readers.map(async r => { try { await r.start(); return true; } catch { return false; } }));
  const failed = (r, reason) => ({ source: APP_LOG_SOURCE, instanceId: r.instanceId, scope: r.scope, coverage: 'failed', reason, events: [] });
  return Object.freeze({
    mark: () => readers.map((r, i) => { if (!started[i]) return { ok: false, reason: 'app-log-not-started' }; try { return r.mark(); } catch { return { ok: false, reason: 'app-log-mark-failed' }; } }),
    collect: (starts, cuts) => readers.map((r, i) => {
      try { return validateWindow(r.collect(starts[i], cuts[i])); } catch { return failed(r, 'app-log-collect-failed'); }
    }),
    stop: () => Promise.allSettled(readers.map(r => r.stop())),
  });
}
