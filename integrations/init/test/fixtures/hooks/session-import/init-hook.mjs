// Stub of the session-import hook for init's tests: records the arguments it was called with and drafts one check
// from the first request path in the session file. Synthetic; sends nothing.
import { readFile } from 'node:fs/promises';

export async function draftForInit({ profile, session } = {}) {
  globalThis.__initSessionHookCalls = [...(globalThis.__initSessionHookCalls ?? []), { session, actors: Object.keys(profile?.actors ?? {}) }];
  if (typeof session !== 'string') return { checks: [], notDrafted: [{ reason: 'no recorded session' }], warnings: [] };
  const har = JSON.parse(await readFile(session, 'utf8'));
  const path = new URL(har.log.entries[0].request.url).pathname;
  return { checks: [{ id: 'S-A-OWN', title: 'Identity A repeats its recorded read', category: 'Session', severity: 'control', actorId: 'a', method: 'GET', path, evidenceRequirement: 'response', assertions: [{ kind: 'status.equals', expected: 200 }] }],
    notDrafted: [], warnings: [], session: har, confirm: 'proposal only (stub)' };
}
