// Run a configured target only under an authorization record that covers it now, and stamp
// the run with { schema, id, sha256 }. The check happens before any request is sent; the
// stamp is added after the run, so it never changes a verdict, a count or an identity hash.
// A check-run-stamp step for callers that want one; the proposed src/cli.mjs and gate change
// calls checkAuthorization itself, with the validated profile the run uses (README).
// The profile is copied once (accessors read once), and the check and the run get that copy.
// The window is checked again before every request (windowGuard's check as the connector's beforeRequest, on whichever
// transport it uses, a remote target's included) and when each observer call starts (guardObserverFactory), on a clock
// that starts at `now`, and once more before the run is returned: once it ends, no
// further request is sent and no further observer call starts (one already running can finish its reads), and the run
// is refused (authorization-window-ended), never returned or stamped. A custom `run` that ignores beforeRequest and the
// guarded observer factory is not guarded per request; the final check still applies to it. A remote target's transport
// dials only the non-public addresses the record names (authorizedRemote), as at the entry points.
import { runHttpAssessment } from '../../src/http-connector.mjs';
import { buildObservers } from '../observers/factory.mjs';
import { AuthorizationError, checkAuthorization, windowGuard, guardObserverFactory, windowRefusal, authorizedRemote } from './authorization.mjs';

export async function runAuthorized(profile, { record, env, now = new Date(), run = runHttpAssessment } = {}) {
  if (record === undefined || record === null) throw new AuthorizationError('authorization-missing', 'a configured target needs an authorization record (--authorization <file>)');
  let copy;
  try { copy = structuredClone(profile); } catch { throw new AuthorizationError('authorization-profile', 'the target profile is not plain data (a function, symbol or proxy in it), so it cannot be checked'); }
  const stamp = checkAuthorization(record, copy, { now });
  const started = Date.now(), window = windowGuard(record, { now: () => now.getTime() + (Date.now() - started) });
  let result;
  try { result = await run(copy, { env, beforeRequest: window.check, remote: authorizedRemote(record), observerFactory: guardObserverFactory(buildObservers, window.check) }); }
  catch (error) { throw windowRefusal(window, error); }
  // The window once more, immediately before the run is stamped and returned.
  window.check();
  return { ...result, authorization: stamp };
}
