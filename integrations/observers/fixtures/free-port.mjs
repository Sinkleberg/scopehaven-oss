// Loopback ports for tests whose observer configuration must name its port before the sink listens (the app is
// pointed at it first, and a sink's configuration refuses port 0). A sink counts everything that reaches it, so its port
// must be one no other process is still sending to. A port the OS hands out on its own (a listen on port 0, every
// outgoing connection) can be one: under suite load the OS reissues a number another process gave up seconds earlier
// (macOS hands them out in order and, at thousands of loopback connections a second, laps its range in seconds), and a
// client of that process may still send to it; each such request lands in the sink's windows, which then run to their
// cap and read partial. So the ports come from a band below the OS automatic range, which the OS never hands out on its
// own, and under the suite's own fixed ports (40998 and up): random ports there that nothing answers on and that bind on
// 127.0.0.1, none of them handed out by this process recently. Only a host whose automatic range leaves no such band
// gets ports the OS picks. Two processes can still pick the same port, so onFreePorts runs the test body again, on
// fresh ports, when a bind loses that race: up to RETRIES times. Tests only.
import { execFileSync } from 'node:child_process';
import { randomInt } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { createServer, connect } from 'node:net';

export const RETRIES = 5;
export const QUIET_BAND = Object.freeze({ low: 16384, high: 32767 });

// The range the OS takes ports from on its own, read from the system on Linux and macOS; elsewhere, or when it cannot be
// read, the union of their defaults (32768-60999 and 49152-65535).
let automatic = null;
export function automaticPortRange() {
  if (automatic) return automatic;
  try {
    const text = process.platform === 'linux' ? readFileSync('/proc/sys/net/ipv4/ip_local_port_range', 'utf8')
      : process.platform === 'darwin' ? execFileSync('/usr/sbin/sysctl', ['-n', 'net.inet.ip.portrange.first', 'net.inet.ip.portrange.last'], { encoding: 'utf8', timeout: 5000 }) : '';
    const [first, last] = text.trim().split(/\s+/).map(Number);
    if (Number.isInteger(first) && Number.isInteger(last) && first >= 1 && first <= last && last <= 65535) return (automatic = { first, last });
  } catch {}
  return (automatic = { first: 32768, last: 65535 });
}

const answers = port => new Promise(resolve => {
  const socket = connect({ host: '127.0.0.1', port });
  const done = value => { socket.destroy(); resolve(value); };
  socket.once('connect', () => done(true)); socket.once('error', error => done(error.code !== 'ECONNREFUSED')); socket.setTimeout(1000, () => done(true));
});
const binds = port => new Promise(resolve => {
  const server = createServer();
  server.once('error', () => resolve(false)); server.listen(port, '127.0.0.1', () => server.close(() => resolve(true)));
});
// The OS's own pick: every probe listens on port 0 at once, so the ports differ, and all are closed before use.
async function osPorts(count) {
  const servers = await Promise.all(Array.from({ length: count }, () => new Promise((resolve, reject) => {
    const s = createServer(); s.once('error', reject); s.listen(0, '127.0.0.1', () => resolve(s));
  })));
  const ports = servers.map(s => s.address().port);
  await Promise.all(servers.map(s => new Promise(resolve => s.close(resolve))));
  return ports;
}
// The ports this process handed out last: one of its own sinks' old clients may still be sending to them.
const recent = [];
export async function freePorts(count) {
  const high = Math.min(QUIET_BAND.high, automaticPortRange().first - 1), span = high - QUIET_BAND.low + 1;
  if (span < 1024) return osPorts(count);
  const ports = [];
  for (let tries = 0; ports.length < count && tries < 20 * count; tries++) {
    const port = QUIET_BAND.low + randomInt(span);
    if (!ports.includes(port) && !recent.includes(port) && !(await answers(port)) && await binds(port)) ports.push(port);
  }
  if (ports.length < count) return osPorts(count);
  recent.push(...ports); recent.splice(0, Math.max(0, recent.length - 256));
  return ports;
}

// run(...ports), again on fresh ports if it threw EADDRINUSE or lostRace(result) says a bind was lost.
export async function onFreePorts(count, run, lostRace = () => false) {
  for (let attempt = 0; ; attempt++) {
    let result;
    try { result = await run(...await freePorts(count)); }
    catch (error) { if (attempt < RETRIES && error?.code === 'EADDRINUSE') continue; throw error; }
    if (attempt < RETRIES && lostRace(result)) continue;
    return result;
  }
}

// For a profile run, whose connector starts the observers itself: an observer factory wrapping build's observers so
// that a sink start that lost its port (EADDRINUSE) is noted. That is the one failure such a test retries on a fresh
// port; a window that fails for any other reason stands.
export function watchingBinds(build) {
  const state = { lostBind: false };
  const factory = (configs, options) => build(configs, options).map(o => {
    const start = o.start.bind(o);
    o.start = async () => { try { await start(); } catch (error) { if (error?.code === 'EADDRINUSE') state.lostBind = true; throw error; } };
    return o;
  });
  return { factory, state };
}
