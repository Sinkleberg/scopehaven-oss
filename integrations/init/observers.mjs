// Observer candidates from environment variable NAMES only. A name suggests where the app keeps records or sends
// effects; init never reads a value unless the operator says yes for that name, and then only in memory, to tell
// whether it points at loopback. No value, and no part of one (host, port, user, database), is written anywhere: the
// draft fragment carries placeholders the operator fills in, and the credential reference is a new SCOPEHAVEN_TARGET_
// name the operator sets themselves.
// Client-side tool settings in the operator's own shell, never an API the app calls: the container engine's daemon
// address (Docker, Podman, BuildKit) and the cluster address Kubernetes sets inside every pod.
const TOOL_NAMES = /^(DOCKER_HOST|CONTAINER_HOST|BUILDKIT_HOST|KUBERNETES_SERVICE_HOST)$/;
const RULES = [
  // A local Supabase stack: SUPABASE_URL on 127.0.0.1:54321 implies its Postgres on 127.0.0.1:54322 (supabase start).
  { test: n => /^(NEXT_PUBLIC_|VITE_|PUBLIC_)?SUPABASE_(URL|DB_URL)$/.test(n), observer: 'pg-snapshot', group: 'supabase',
    why: 'Supabase stack: a local one keeps its Postgres on 127.0.0.1:54322; read the app\'s rows with a read-only role',
    doc: 'docs/ONBOARDING.md, "Observe what the app recorded"; integrations/observers/SUPABASE-IDENTITY.md' },
  { test: n => /^(DATABASE_URL|POSTGRES_URL|POSTGRES_PRISMA_URL|PG_URL|PGURL)$/.test(n) || /^PG(HOST|DATABASE|USER|PASSWORD|PORT)$/.test(n),
    observer: 'pg-snapshot', group: 'postgres', why: 'Postgres connection: read the app\'s own rows before and after each check',
    doc: 'docs/ONBOARDING.md, "Observe what the app recorded"; integrations/observers/README.md (pg-snapshot)' },
  { test: n => /^(MYSQL_URL|MYSQL_HOST|MYSQL_DATABASE)$/.test(n), observer: 'mysql-snapshot', group: 'mysql', why: 'MySQL connection: read the app\'s rows',
    doc: 'integrations/observers/README.md (mysql-snapshot)' },
  { test: n => /^(SQLITE_PATH|SQLITE_FILE|DB_PATH|DATABASE_PATH)$/.test(n), observer: 'sqlite-snapshot', group: 'sqlite', why: 'SQLite file: read a copy of the app\'s database',
    doc: 'docs/profiles/sqlite-snapshot.example.json' },
  { test: n => /^SMTP_/.test(n) || /^(MAIL_HOST|EMAIL_HOST|EMAIL_SERVER)$/.test(n), observer: 'smtp-sink', group: 'smtp', why: 'mail host: point it at the loopback SMTP sink to see each message the app sends',
    doc: 'docs/ONBOARDING.md, "Requests and mail the app sends"' },
  { test: n => /_(BASE_URL|API_BASE|API_URL|ENDPOINT|HOST)$/.test(n) && !/^(NEXT_PUBLIC_|VITE_|PUBLIC_)/.test(n) && !/^(DATABASE|POSTGRES|MYSQL|REDIS|SMTP|MAIL|EMAIL)/.test(n) && !TOOL_NAMES.test(n),
    observer: 'egress-recorder', group: 'egress', why: 'outbound API base URL: point it at the loopback egress recorder to see each call the app makes',
    doc: 'docs/profiles/egress-recorder.example.json' },
];

export function observerCandidates(names) {
  const seen = new Map();
  for (const name of [...new Set(names)].sort()) {
    const rule = RULES.find(r => r.test(name));
    if (!rule) continue;
    const key = rule.group === 'egress' ? `egress:${name}` : rule.group;
    if (!seen.has(key)) seen.set(key, { observer: rule.observer, names: [], why: rule.why, doc: rule.doc });
    seen.get(key).names.push(name);
  }
  return [...seen.values()];
}

// Reads one value in memory, only after the operator said yes for that name. Returns only whether it names loopback.
export function pointsAtLoopback(value) {
  if (typeof value !== 'string' || !value) return null;
  try {
    const url = new URL(value.includes('://') ? value : `tcp://${value}`);
    return ['127.0.0.1', 'localhost', '[::1]'].includes(url.hostname);
  } catch { return /^(127\.0\.0\.1|localhost)(:\d+)?$/.test(value); }
}

const credentialName = (targetId, suffix) => `SCOPEHAVEN_TARGET_${targetId.toUpperCase().replace(/[^A-Z0-9]+/g, '_')}_${suffix}`.slice(0, 128);

// Draft fragments with placeholders. They are not merged into the starter profile: an observer needs choices only the
// operator can make (tables, routes, witnesses), and check-config refuses a half-filled one.
export function observerDrafts(targetId, accepted) {
  return accepted.map(c => {
    if (c.observer === 'pg-snapshot') return { from: c.names, observer: { type: 'pg-snapshot', id: 'pg-1', host: '127.0.0.1', port: c.names.some(n => /SUPABASE/.test(n)) ? '<54322 for a local Supabase stack, else the database port>' : '<port of the app database>', database: c.names.some(n => /SUPABASE/.test(n)) ? '<postgres for a local Supabase stack>' : '<database name>',
      credentialEnv: credentialName(targetId, 'PG'), tables: ['<table the app writes>'] }, set: `${credentialName(targetId, 'PG')}=<read-only user>:<password>`, doc: c.doc };
    if (c.observer === 'mysql-snapshot') return { from: c.names, observer: { type: 'mysql-snapshot', id: 'mysql-1', host: '127.0.0.1', port: '<port>', database: '<database name>',
      credentialEnv: credentialName(targetId, 'MYSQL'), tables: ['<table the app writes>'] }, set: `${credentialName(targetId, 'MYSQL')}=<read-only user>:<password>`, doc: c.doc };
    if (c.observer === 'sqlite-snapshot') return { from: c.names, observer: { type: 'sqlite-snapshot', id: 'sqlite-1', path: '<absolute path to a copy of the database>', tables: ['<table>'] }, doc: c.doc };
    if (c.observer === 'smtp-sink') return { from: c.names, observer: { type: 'smtp-sink', id: 'smtp-1', port: '<free loopback port; point the app\'s mail host here>', domains: ['<recipient domain>'] }, doc: c.doc };
    return { from: c.names, observer: { type: 'egress-recorder', id: `egress-${c.names[0].toLowerCase().replace(/[^a-z0-9]+/g, '-')}`.slice(0, 80), port: '<free loopback port; point the app\'s base URL here>',
      destinations: [{ host: '<provider host the app calls>' }] }, doc: c.doc };
  });
}
