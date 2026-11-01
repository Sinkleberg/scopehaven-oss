// Read an authorization record from disk: a regular file, never through a symlink or a FIFO
// (opened without blocking, so a FIFO is refused at once), at most 256 KiB, parsed as JSON.
// A record that repeats a field name in any object is refused (authorization-duplicate-key): JSON.parse keeps
// only the last of the repeats, so the file a person reads could show one value while the check enforces, and the
// checksum covers, another. Without repeats, the parsed record is the text, and the checksum covers all of it.
// Errors never echo the path's contents.
import { open } from 'node:fs/promises';
import { constants } from 'node:fs';
import { AuthorizationError, checkAuthorization, windowGuard, authorizedRemote } from './authorization.mjs';
import { countKeyTokens } from './body-fields.mjs';

export const MAX_RECORD_BYTES = 256 * 1024;
// The member names of a parsed JSON tree, at any depth, without recursion.
const parsedKeyCount = root => {
  let keys = 0;
  for (const stack = [root]; stack.length;) {
    const value = stack.pop();
    if (value === null || typeof value !== 'object') continue;
    if (!Array.isArray(value)) keys += Object.keys(value).length;
    for (const child of Array.isArray(value) ? value : Object.values(value)) stack.push(child);
  }
  return keys;
};
export async function readAuthorizationFile(path) {
  const unreadable = () => new AuthorizationError('authorization-invalid', 'the authorization record is not a readable JSON file (a regular file, not a symlink, at most 256 KiB)');
  let handle;
  try { handle = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK); } catch { throw unreadable(); }
  try {
    if (!(await handle.stat()).isFile()) throw unreadable();
    // Read at most one byte past the limit, so an oversized (or growing) file is never read whole.
    const buffer = Buffer.alloc(MAX_RECORD_BYTES + 1);
    let length = 0;
    for (let n; length < buffer.length && (n = (await handle.read(buffer, length, buffer.length - length, length)).bytesRead) > 0;) length += n;
    if (length > MAX_RECORD_BYTES) throw unreadable();
    const text = buffer.toString('utf8', 0, length);
    let record;
    try { record = JSON.parse(text); } catch { throw unreadable(); }
    // In valid JSON a string followed by a colon is a member name, so the text's names beyond the parsed tree's are repeats.
    if (countKeyTokens(text) !== parsedKeyCount(record)) throw new AuthorizationError('authorization-duplicate-key', 'the record repeats a field name in one object; JSON keeps only the last, so the file could show one value and enforce another');
    return record;
  } finally { await handle.close(); }
}

// The step every entry point runs before it sends a request to a target the operator configured (assess, the
// gate, the dashboard's run path, sequences and conversations): no record named is authorization-missing;
// otherwise the record is read now, from a regular file, and checked against the profile the run will use.
// Returns { stamp, window, remote }: the stamp the run carries, the window guard (src/authorization.mjs windowGuard)
// the entry point checks before every request the run sends, and what a remote target's transport may dial (the
// record's non-public addresses, src/remote-target.mjs). Throws AuthorizationError (its code is the refusal reason).
export async function authorizeConfigured(profile, file, { now = new Date(), alsoContacts = [] } = {}) {
  if (typeof file !== 'string' || !file.length) throw new AuthorizationError('authorization-missing', 'a configured target needs an authorization record (--authorization <file>; see docs/RULES-OF-ENGAGEMENT.md)');
  const record = await readAuthorizationFile(file);
  return { stamp: checkAuthorization(record, profile, { now, alsoContacts }), window: windowGuard(record), remote: authorizedRemote(record) };
}
