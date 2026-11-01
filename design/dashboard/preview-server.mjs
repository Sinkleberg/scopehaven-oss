import { createServer } from 'node:http';
import { readFile } from 'node:fs/promises';
import { pathToFileURL } from 'node:url';
import { resolve } from 'node:path';

const files = new Map([
  ['/', ['preview.html','text/html']],
  ['/preview.mjs',['preview.mjs','text/javascript']], ['/dashboard.mjs',['dashboard.mjs','text/javascript']],
  ['/adapter.mjs',['adapter.mjs','text/javascript']], ['/dashboard.css',['dashboard.css','text/css']],
  ['/preview-data.json',['preview-data.json','application/json']], ['/preview.css',['preview.css','text/css']],
]);
export async function startPreviewServer({port = 4392} = {}) {
  if (!Number.isInteger(port) || port < 0 || port > 65535) throw new TypeError('Invalid preview port.');
  const server = createServer(async (req,res) => {
    res.setHeader('Content-Security-Policy', "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' data:; base-uri 'none'; frame-ancestors 'none'; form-action 'none'");
    res.setHeader('X-Content-Type-Options','nosniff'); res.setHeader('Referrer-Policy','no-referrer'); res.setHeader('Cache-Control','no-store');
    const origin = `http://127.0.0.1:${server.address().port}`;
    if (req.headers.host !== `127.0.0.1:${server.address().port}` || (req.headers.origin && req.headers.origin !== origin) || req.headers['sec-fetch-site'] === 'cross-site') { res.writeHead(403); return res.end('Preview access denied.'); }
    if (req.method !== 'GET') { res.writeHead(405); return res.end('Preview serves allowlisted assets only.'); }
    const entry = files.get(req.url);
    if (!entry) { res.writeHead(404); return res.end('Not found.'); }
    try {
      const data = await readFile(new URL(entry[0],import.meta.url));
      res.writeHead(200,{'Content-Type':`${entry[1]}; charset=utf-8`}); res.end(data);
    } catch { res.writeHead(500); res.end('Preview asset unavailable.'); }
  });
  server.requestTimeout = 10000; server.headersTimeout = 5000;
  server.maxConnections = 16; server.keepAliveTimeout = 1000;
  await new Promise((done,reject) => {server.once('error',reject); server.listen(port,'127.0.0.1',done);});
  return {origin:`http://127.0.0.1:${server.address().port}`,server,close:() => new Promise(done => {server.close(done);server.closeAllConnections();})};
}
if (process.argv[1] && pathToFileURL(resolve(process.argv[1])).href === import.meta.url) {
  const preview = await startPreviewServer();
  console.log(JSON.stringify({previewOnly:true,status:'listening',origin:preview.origin,assets:'allowlisted dashboard preview files only'}));
}
