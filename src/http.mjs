export function json(res, status, value) {
  const payload = Buffer.from(JSON.stringify(value) ?? '', 'utf8');
  // An explicit length lets the browser finish the body instead of logging a cancelled stream.
  res.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8', 'Content-Length': payload.length, 'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff' });
  res.end(payload);
}
export async function body(req, limit = 16384) {
  if (String(singleHeader(req, 'content-type') || '').split(';')[0].trim().toLowerCase() !== 'application/json') throw Object.assign(new Error('JSON content type required.'), { status: 415 });
  let size = 0; const chunks = [];
  for await (const chunk of req) {
    size += chunk.length;
    if (size > limit) throw Object.assign(new Error('Request is too large.'), { status: 413 });
    chunks.push(chunk);
  }
  try { return JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(Buffer.concat(chunks))); }
  catch { throw Object.assign(new Error('Invalid JSON.'), { status: 400 }); }
}
export function record(value) { return value !== null && typeof value === 'object' && !Array.isArray(value); }
export function singleHeader(req, name) {
  const lower = name.toLowerCase();
  if (Array.isArray(req.rawHeaders)) {
    let count = 0;
    for (let i = 0; i < req.rawHeaders.length; i += 2) if (String(req.rawHeaders[i]).toLowerCase() === lower) count++;
    if (count !== 1) return undefined;
  }
  const value = req.headers?.[lower];
  return typeof value === 'string' ? value : undefined;
}
export function bearer(req) { return /^Bearer ([A-Za-z0-9_-]+)$/.exec(singleHeader(req, 'authorization') || '')?.[1]; }
export function localHostAllowed(req, address) { return (!req.rawHeaders || req.rawHeaders.length <= 80) && singleHeader(req, 'host') === `127.0.0.1:${address.port}`; }
export const idValid = value => typeof value === 'string' && /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(value);
