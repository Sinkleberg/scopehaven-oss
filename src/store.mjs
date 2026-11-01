import { constants } from 'node:fs';
import { mkdir, open, link, unlink, rename, opendir, lstat, realpath } from 'node:fs/promises';
import { join, resolve } from 'node:path';
import { randomUUID } from 'node:crypto';
import { digest } from './domain.mjs';
import { isFinalizedRun } from '../integrations/temporal-contracts/evaluator.mjs';
import { isVerifiedRun } from '../integrations/temporal-contracts/persistence.mjs';
import { idValid } from './http.mjs';

// Trusted local owner: these checks constrain accidental exposure and other-UID
// access, not malware running as this UID. Canonical-root locks coordinate this
// process only; cross-process quota transactions require stronger storage.
// The prototype assumes one writer process. Atomic note replacement can use
// one bounded file of temporary scratch beyond the retained-evidence quota.
const writers = new Map();
const defaults = { maxRuns: 1000, maxTotalBytes: 64 * 1024 * 1024, maxFileBytes: 2 * 1024 * 1024 };
class StorageError extends Error {}
const failure = (message, status = 500, code) => Object.assign(new StorageError(message), { status, ...(code ? { code } : {}) });
const uid = process.getuid();
function serial(root, operation) {
  const result = (writers.get(root) || Promise.resolve()).then(operation), settled = result.catch(() => {});
  writers.set(root, settled);
  void settled.then(() => { if (writers.get(root) === settled) writers.delete(root); });
  return result;
}
async function secureDirectory(path, create = false) {
  let stat;
  try { stat = await lstat(path); }
  catch (error) {
    if (!create || error.code !== 'ENOENT') throw failure('Storage directory is unavailable.');
    try { await mkdir(path, { recursive: true, mode: 0o700 }); stat = await lstat(path); }
    catch { throw failure('Storage directory could not be created.'); }
  }
  if (!stat.isDirectory() || stat.isSymbolicLink() || stat.uid !== uid || (stat.mode & 0o7777) !== 0o700) throw failure('Storage directories must be real, owner-controlled directories with mode 0700.');
}
function validFile(stat, maximum) {
  if (!stat.isFile() || Number(stat.uid) !== uid || (Number(stat.mode) & 0o7777 & ~0o600) !== 0 || Number(stat.size) > maximum) throw failure('Evidence file must be a bounded, private, owner-controlled regular file.');
}
const compareMetadata = (a, b) => a.mtimeNs === b.mtimeNs ? b.id.localeCompare(a.id) : a.mtimeNs > b.mtimeNs ? -1 : 1;
const cursorFor = item => Buffer.from(JSON.stringify({ v: 1, mtimeNs: item.mtimeNs.toString(), id: item.id })).toString('base64url');
function parseCursor(cursor) {
  if (cursor === undefined) return null;
  try {
    if (typeof cursor !== 'string' || cursor.length < 1 || cursor.length > 256 || !/^[A-Za-z0-9_-]+$/.test(cursor) || Buffer.from(cursor, 'base64url').toString('base64url') !== cursor) throw new Error();
    const value = JSON.parse(Buffer.from(cursor, 'base64url').toString('utf8'));
    if (!value || Object.keys(value).sort().join(',') !== 'id,mtimeNs,v' || value.v !== 1 || !idValid(value.id) || typeof value.mtimeNs !== 'string' || !/^[0-9]{1,30}$/.test(value.mtimeNs)) throw new Error();
    return { id: value.id, mtimeNs: BigInt(value.mtimeNs) };
  } catch { throw failure('Invalid history cursor.', 400); }
}

export function createStore(directory, options = {}) {
  if (typeof directory !== 'string' || !directory.length) throw failure('Invalid storage directory.', 400);
  const limits = { ...defaults, ...options };
  if (Object.keys(options).some(key => !Object.hasOwn(defaults, key)) || Object.values(limits).some(value => !Number.isSafeInteger(value) || value < 1)) throw failure('Invalid storage limits.', 400);
  const configuredRoot = resolve(directory); let root, runsDir, notesDir;
  const ready = (async () => {
    await secureDirectory(configuredRoot, true);
    try { root = await realpath(configuredRoot); } catch { throw failure('Storage directory is unavailable.'); }
    runsDir = join(root, 'runs'); notesDir = join(root, 'notes');
    await secureDirectory(runsDir, true); await secureDirectory(notesDir, true);
  })();
  void ready.catch(() => {});
  const path = (dir, id) => { if (!idValid(id)) throw failure('Invalid run identifier.', 400); return join(dir, `${id}.json`); };
  async function directories() {
    await ready; await secureDirectory(configuredRoot); await secureDirectory(root);
    await secureDirectory(runsDir); await secureDirectory(notesDir);
  }
  async function fileMetadata(file) {
    let handle;
    try {
      handle = await open(file, constants.O_RDONLY | constants.O_NOFOLLOW);
      const stat = await handle.stat({ bigint: true }); validFile(stat, limits.maxFileBytes); return stat;
    } catch (error) {
      if (error instanceof StorageError) throw error;
      throw failure(error.code === 'ENOENT' ? 'Evidence file is unavailable.' : 'Evidence file cannot be accessed safely.', 500, error.code === 'ENOENT' ? 'ENOENT' : undefined);
    } finally { await handle?.close(); }
  }
  async function readJSON(file) {
    let handle;
    try {
      handle = await open(file, constants.O_RDONLY | constants.O_NOFOLLOW); validFile(await handle.stat(), limits.maxFileBytes);
      const chunks = [], buffer = Buffer.alloc(Math.min(65536, limits.maxFileBytes + 1)); let size = 0;
      while (true) {
        const { bytesRead } = await handle.read(buffer, 0, buffer.length, size);
        if (!bytesRead) break; size += bytesRead;
        if (size > limits.maxFileBytes) throw failure('Evidence file exceeds the storage limit.');
        chunks.push(Buffer.from(buffer.subarray(0, bytesRead)));
      }
      try { return JSON.parse(Buffer.concat(chunks).toString('utf8')); } catch { throw failure('Evidence file contains invalid JSON.'); }
    } catch (error) {
      if (error instanceof StorageError) throw error;
      throw failure(error.code === 'ENOENT' ? 'Evidence file is unavailable.' : 'Evidence file cannot be accessed safely.', 500, error.code === 'ENOENT' ? 'ENOENT' : undefined);
    } finally { await handle?.close(); }
  }
  async function readRun(id, includeNotes = true) {
    let saved;
    try { saved = await readJSON(path(runsDir, id)); }
    catch (error) { if (error.code === 'ENOENT') throw failure('Run not found.', 404); throw error; }
    let valid = false;
    try { valid = saved.core?.schemaVersion === 1 && saved.core.id === id && digest(saved.core) === saved.sha256; } catch {}
    if (!valid) throw failure('Stored evidence failed its integrity check.');
    let notes = {};
    if (includeNotes) {
      try { notes = await readJSON(path(notesDir, id)); } catch (error) { if (error.code !== 'ENOENT') throw error; }
      if (!notes || typeof notes !== 'object' || Array.isArray(notes)) throw failure('Stored notes have an invalid format.');
    }
    return { ...saved.core, integrity: { algorithm: 'SHA-256', sha256: saved.sha256, scope: 'run core only; editable notes excluded' }, notes };
  }
  async function scan() {
    await directories(); const runs = [], sizes = new Map(); let totalBytes = 0;
    const entryLimit = limits.maxRuns + 1000; // Bound metadata even with abandoned temporaries.
    for (const dir of [runsDir, notesDir]) {
      let entries = 0;
      try {
        for await (const entry of await opendir(dir)) {
          if (++entries > entryLimit) throw failure('Storage metadata scan exceeds its bounded capacity.');
          const file = join(dir, entry.name), isEvidence = entry.name.endsWith('.json') && idValid(entry.name.slice(0, -5));
          if (isEvidence) {
            const stat = await fileMetadata(file); sizes.set(file, Number(stat.size)); totalBytes += Number(stat.size);
            if (dir === runsDir) runs.push({ id: entry.name.slice(0, -5), mtimeNs: stat.mtimeNs });
          } else {
            const stat = await lstat(file);
            if (!stat.isFile() || stat.isSymbolicLink() || stat.uid !== uid) throw failure('Storage contains an unsupported filesystem entry.');
            totalBytes += stat.size;
          }
        }
      } catch (error) { if (error instanceof StorageError) throw error; throw failure('Storage metadata could not be inspected safely.'); }
    }
    if (runs.length > limits.maxRuns || totalBytes > limits.maxTotalBytes) throw failure('Storage capacity is exceeded; preserve existing evidence and choose another private storage directory.', 507);
    return { runs, sizes, totalBytes };
  }
  function serialized(value) {
    let content; try { content = JSON.stringify(value, null, 2); } catch { throw failure('Evidence could not be serialized safely.', 400); }
    if (typeof content !== 'string' || Buffer.byteLength(content) > limits.maxFileBytes) throw failure('Evidence file exceeds the storage limit.', 413);
    return content;
  }
  async function publish(dir, destination, content, exclusive) {
    await directories(); const temporary = join(dir, `.${randomUUID()}.tmp`); let handle;
    try {
      handle = await open(temporary, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600);
      await handle.writeFile(content); await handle.sync(); await handle.close(); handle = null;
      await directories();
      if (exclusive) await link(temporary, destination); else await rename(temporary, destination);
    } catch (error) {
      if (error instanceof StorageError) throw error;
      throw failure(error.code === 'EEXIST' ? 'Run already exists; immutable evidence cannot be overwritten.' : 'Evidence could not be published safely.', error.code === 'EEXIST' ? 409 : 500);
    } finally { await handle?.close(); await unlink(temporary).catch(() => {}); }
  }
  async function get(id) { await directories(); return readRun(id); }
  async function save(core) {
    await ready;
    return serial(root, async () => {
      if (!core || typeof core !== 'object' || Array.isArray(core) || core.schemaVersion !== 1 || !Array.isArray(core.results)) throw failure('Invalid run evidence format.', 400);
      if(core.evidenceOrigin==='owned-refund-loopback-http' && !isFinalizedRun(core) && !isVerifiedRun(core)) throw failure('Refund evidence requires trusted evaluator finalization.',400);
      await directories(); const destination = path(runsDir, core?.id);
      let checksum; try { checksum = digest(core); } catch { throw failure('Evidence could not be serialized safely.', 400); }
      const content = serialized({ core, sha256: checksum }), usage = await scan();
      if (usage.sizes.has(destination)) throw failure('Run already exists; immutable evidence cannot be overwritten.', 409);
      if (usage.runs.length >= limits.maxRuns || usage.totalBytes + Buffer.byteLength(content) > limits.maxTotalBytes) throw failure('Storage quota prevents saving this run; existing evidence is preserved.', 507);
      await publish(runsDir, destination, content, true); return readRun(core.id);
    });
  }
  const summary = run => { const { results, notes, limitations, integrity, provenance, identityEvidence, conversationEvidence, refundAdjudication, settlement, timing, scenarioEvidence, ...rest } = run; return rest; };
  async function historyPage({ limit = 50, before } = {}) {
    if (!Number.isInteger(limit) || limit < 1 || limit > 100) throw failure('History limit must be between 1 and 100.', 400);
    const cursor = parseCursor(before); await ready;
    return serial(root, async () => {
      const usage = await scan(), ordered = usage.runs.sort(compareMetadata);
      const remaining = cursor ? ordered.filter(item => compareMetadata(item, cursor) > 0) : ordered;
      const page = remaining.slice(0, limit), runs = [];
      for (const item of page) runs.push(summary(await readRun(item.id, false)));
      return { runs, nextCursor: remaining.length > page.length ? cursorFor(page.at(-1)) : null, total: ordered.length };
    });
  }
  async function list(options) { return (await historyPage(options)).runs; }
  async function note(id, caseId, text) {
    await ready;
    return serial(root, async () => {
      await directories(); const run = await readRun(id);
      if (!Array.isArray(run.results) || !run.results.some(result => result.id === caseId)) throw failure('Unknown scenario.', 400);
      if (typeof text !== 'string' || text.length > 5000) throw failure('Notes must contain at most 5,000 characters.', 400);
      const value = { note: text, updatedAt: new Date().toISOString() }, destination = path(notesDir, id);
      const content = serialized({ ...run.notes, [caseId]: value }), usage = await scan(), replacedBytes = usage.sizes.get(destination) || 0;
      if (usage.totalBytes - replacedBytes + Buffer.byteLength(content) > limits.maxTotalBytes) throw failure('Storage quota prevents saving this note; existing evidence is preserved.', 507);
      await publish(notesDir, destination, content, false); return { caseId, ...value };
    });
  }
  return { ready, save, get, list, historyPage, note, summary };
}
