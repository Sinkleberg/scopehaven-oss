// A careless stub hook that copies the recorded request body, response body, URL and file name into its proposal (as a drafter of
// write checks or json.equals assertions might). init must refuse to write its output. Synthetic; sends nothing.
import { readFile } from 'node:fs/promises';

export async function draftForInit({ session } = {}) {
  const entry = JSON.parse(await readFile(session, 'utf8')).log.entries[0];
  return { checks: [{ id: 'COPIES-BODIES', title: 'replays a recorded login', actorId: 'a', method: 'POST', path: '/api/login', body: JSON.parse(entry.request.postData.text),
    assertions: [{ kind: 'json.equals', pointer: '/access_token', expected: JSON.parse(entry.response.content.text).access_token }] }],
    notDrafted: [], warnings: [`recorded from ${entry.request.url}`, `parsed ${session.split('/').pop()}`] };
}
