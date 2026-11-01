import { randomBytes, timingSafeEqual } from 'node:crypto';
import { singleHeader } from './http.mjs';

const validToken = value => typeof value === 'string' && /^[A-Za-z0-9_-]{32,128}$/.test(value);
const escapeHTML = value => value.replace(/[&<>"']/g, character => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[character]);

// A short-lived capability for this local launch, not a hosted identity system.
export function createLocalAccess({ token = randomBytes(32).toString('base64url'), now = () => Date.now(), ttlMs = 8 * 60 * 60 * 1000 } = {}) {
  if (!validToken(token)) throw new Error('Local access token must contain 32 to 128 URL-safe ASCII characters.');
  if (typeof now !== 'function' || !Number.isFinite(ttlMs) || ttlMs < 0) throw new Error('Invalid local access expiry configuration.');
  const startedAt = now();
  if (!Number.isFinite(startedAt) || !Number.isFinite(startedAt + ttlMs)) throw new Error('Invalid local access clock.');
  const expiresAt = startedAt + ttlMs;
  const expected = Buffer.from(token, 'ascii');
  return {
    token,
    expiresAt,
    authorize(req) {
      try {
        const currentTime = now();
        if (!Number.isFinite(currentTime) || currentTime >= expiresAt) return false;
        const header = req ? singleHeader(req, 'authorization') : undefined;
        if (typeof header !== 'string') return false;
        const matched = /^Bearer ([A-Za-z0-9_-]{32,128})$/.exec(header);
        if (!matched) return false;
        const presented = Buffer.from(matched[1], 'ascii');
        return presented.length === expected.length && timingSafeEqual(presented, expected);
      } catch {
        return false;
      }
    },
  };
}

export function renderLaunchPage(origin, token) {
  const match = typeof origin === 'string' && /^http:\/\/127\.0\.0\.1:([1-9][0-9]{0,4})$/.exec(origin);
  if (!match || Number(match[1]) > 65535) throw new Error('Launch origin must be an exact numeric loopback HTTP origin with a valid port.');
  if (!validToken(token)) throw new Error('Invalid local launch capability.');
  const href = escapeHTML(`${origin}#access=${token}`);
  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="referrer" content="no-referrer">
  <title>Open Scopehaven locally</title>
  <style>body{font:16px/1.6 system-ui,sans-serif;max-width:600px;margin:12vh auto;padding:24px;color:#17313c;background:#f5f5ef}h1{line-height:1.2}a{display:inline-block;padding:12px 20px;background:#167568;color:white;border-radius:7px;text-decoration:none}a:focus-visible{outline:3px solid #132b36;outline-offset:4px}small{display:block;margin-top:24px;color:#54666b}</style>
</head>
<body>
  <h1>Your local Scopehaven workspace</h1>
  <p>This private launch page opens the workbench for the current server session.</p>
  <a href="${href}" rel="noreferrer" referrerpolicy="no-referrer">Open Scopehaven</a>
  <small>Keep this file private. Its link grants local access until this launch expires. Restarting the workbench creates a new capability.</small>
</body>
</html>`;
}
