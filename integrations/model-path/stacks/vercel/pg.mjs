// The Vercel copies' own Postgres: a separate container (sh-sup2-mp-pg) on 127.0.0.1:4494
// from the practice install's pinned image, data on tmpfs (gone when it stops), password
// random and kept in a 0600 file beside the copies (never printed).
//   node pg.mjs up <copy dir to migrate from> | down | url-file
import { execFileSync } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { dirname, isAbsolute, join } from 'node:path';
import { fileURLToPath } from 'node:url';

export const PG = { container: 'sh-sup2-mp-pg', port: 4494, user: 'chatbot', db: 'chatbot' };
// Machine paths come from the environment, never from a default under someone's home:
//   SCOPEHAVEN_PRACTICE_DIR       the folder holding the practice installs; copies live in <it>/sup-build-2/model-path
//   SCOPEHAVEN_PRACTICE_NODE_BIN  the Node bin folder the Vercel copy runs with (default: this Node's)
export function practiceDir() {
  const dir = process.env.SCOPEHAVEN_PRACTICE_DIR;
  if (!dir || !isAbsolute(dir)) throw new Error('set SCOPEHAVEN_PRACTICE_DIR to the absolute folder that holds the practice installs');
  return dir;
}
export const copiesDir = () => join(practiceDir(), 'sup-build-2', 'model-path');
const secretFile = () => join(copiesDir(), 'pg.secret');
export const NODE_BIN = process.env.SCOPEHAVEN_PRACTICE_NODE_BIN || dirname(process.execPath);
export const postgresUrl = () => `postgres://${PG.user}:${readFileSync(secretFile(), 'utf8').trim()}@127.0.0.1:${PG.port}/${PG.db}`;
export const psql = sql => execFileSync('docker', ['exec', PG.container, 'psql', '-U', PG.user, '-d', PG.db, '-tAc', sql], { encoding: 'utf8' }).trim();

if (fileURLToPath(import.meta.url) === process.argv[1]) {
  const [action, copyDir] = process.argv.slice(2);
  if (action === 'up') {
    // The practice install's pinned image, already pulled: never pulled here.
    const IMAGE = readFileSync(join(practiceDir(), 'vercel-chatbot', 'PG_IMAGE'), 'utf8').trim();
    const SECRET = secretFile();
    if (!existsSync(SECRET)) writeFileSync(SECRET, randomBytes(24).toString('hex'), { mode: 0o600, flag: 'wx' });
    execFileSync('docker', ['run', '-d', '--pull', 'never', '--name', PG.container, '-p', `127.0.0.1:${PG.port}:5432`, '--tmpfs', '/var/lib/postgresql/data',
      '-e', `POSTGRES_USER=${PG.user}`, '-e', `POSTGRES_DB=${PG.db}`, '-e', `POSTGRES_PASSWORD=${readFileSync(SECRET, 'utf8').trim()}`,
      '--label', 'scopehaven-practice=sup-build-2-model-path', IMAGE], { stdio: 'ignore' });
    for (let i = 0; i < 60; i++) { try { execFileSync('docker', ['exec', PG.container, 'pg_isready', '-U', PG.user, '-d', PG.db], { stdio: 'ignore' }); break; } catch { execFileSync('sleep', ['1']); } }
    // A fresh server needs a moment after pg_isready during first-boot init.
    execFileSync('sleep', ['3']);
    execFileSync(join(copyDir, 'node_modules', '.bin', 'tsx'), ['lib/db/migrate.ts'], { cwd: copyDir, stdio: 'inherit', env: { PATH: `${NODE_BIN}:/usr/bin:/bin`, HOME: homedir(), POSTGRES_URL: postgresUrl() } });
    console.log('up; tables:', psql(`SELECT string_agg(tablename, ',' ORDER BY tablename) FROM pg_tables WHERE schemaname = 'public'`));
  } else if (action === 'down') {
    execFileSync('docker', ['rm', '-f', PG.container], { stdio: 'ignore' });
    console.log('removed', PG.container);
  } else { console.error('usage: pg.mjs up <copy dir> | down'); process.exit(2); }
}
