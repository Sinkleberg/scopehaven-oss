// A throwaway test CA and a server certificate signed by it, made with the openssl command line (LibreSSL or
// OpenSSL) in a private temporary folder, for the remote HTTPS tests. Nothing is kept: the caller removes the folder.
// Returns null when openssl is not on PATH (the tests that need it skip).
import { execFileSync } from 'node:child_process';
import { readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

export function makeTestCa(dir, { dnsNames = [], ips = [] } = {}) {
  const run = args => execFileSync('openssl', args, { cwd: dir, stdio: ['ignore', 'ignore', 'pipe'] });
  try { run(['version']); } catch { return null; }
  const san = [...dnsNames.map(n => `DNS:${n}`), ...ips.map(ip => `IP:${ip}`)].join(', ');
  writeFileSync(join(dir, 'ext.cnf'), ['[req]', 'distinguished_name = dn', '[dn]', '[ca_ext]', 'basicConstraints = critical, CA:TRUE', 'keyUsage = critical, keyCertSign, cRLSign',
    '[srv_ext]', 'basicConstraints = critical, CA:FALSE', 'keyUsage = critical, digitalSignature', 'extendedKeyUsage = serverAuth', `subjectAltName = ${san}`, ''].join('\n'));
  run(['ecparam', '-name', 'prime256v1', '-genkey', '-noout', '-out', 'ca.key']);
  run(['req', '-x509', '-new', '-key', 'ca.key', '-sha256', '-days', '2', '-subj', '/CN=Scopehaven throwaway test CA', '-config', 'ext.cnf', '-extensions', 'ca_ext', '-out', 'ca.pem']);
  run(['ecparam', '-name', 'prime256v1', '-genkey', '-noout', '-out', 'server.key']);
  run(['req', '-new', '-key', 'server.key', '-subj', `/CN=${dnsNames[0] ?? ips[0]}`, '-config', 'ext.cnf', '-out', 'server.csr']);
  run(['x509', '-req', '-in', 'server.csr', '-CA', 'ca.pem', '-CAkey', 'ca.key', '-CAcreateserial', '-days', '2', '-sha256', '-extfile', 'ext.cnf', '-extensions', 'srv_ext', '-out', 'server.pem']);
  const read = name => readFileSync(join(dir, name), 'utf8');
  return { ca: read('ca.pem'), key: read('server.key'), cert: read('server.pem'), caFile: join(dir, 'ca.pem') };
}
