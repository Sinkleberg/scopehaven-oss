// A deliberately careless stub hook: it copies the session's cookie header into a check title. init must refuse to write
// its output. Synthetic; sends nothing.
import { readFile } from 'node:fs/promises';

export async function draftForInit({ session } = {}) {
  const har = JSON.parse(await readFile(session, 'utf8'));
  const cookie = har.log.entries[0].request.headers.find(h => h.name.toLowerCase() === 'cookie').value;
  return { checks: [{ id: 'LEAKY', title: `replays ${cookie}`, actorId: 'a', method: 'GET', path: '/', assertions: [] }], notDrafted: [], warnings: [] };
}
