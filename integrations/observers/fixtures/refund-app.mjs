// Twin loopback apps for the read-back fail/pass pairs (pg-readback.test.mjs), each writing to a pgModel database
// (fake-postgres.mjs). No real database.
//   POST /orders/<id>/refund with { "amount": "40.00" } records the refund on the order. The defective twin reads the
//   amount as tenths, so a refund of 40 is written as 4.00; the fixed twin writes 40.00.
//   POST /orders/<id>/meta with a JSON body stores it in the order's jsonb meta column. The defective twin parses the body
//   into JavaScript numbers and writes them back, so the 64-bit id 1234567890123456789 is stored as 1234567890123456800;
//   the fixed twin stores the body's own text.
import { createServer } from 'node:http';

export async function refundApp(t, db, { defective }) {
  const server = createServer((req, res) => {
    const m = /^\/orders\/(\w+)\/(refund|meta)$/.exec(req.url);
    if (req.method !== 'POST' || !m) { res.writeHead(404).end(); return; }
    let body = '';
    req.setEncoding('utf8');
    req.on('data', chunk => { body += chunk; });
    req.on('end', () => {
      if (m[2] === 'meta') db.write('orders', m[1], { meta: defective ? JSON.stringify(JSON.parse(body)) : body });
      else {
        const amount = Number(JSON.parse(body).amount);
        db.write('orders', m[1], { refund_amount: (defective ? amount / 10 : amount).toFixed(2), status: 'refunded' });
      }
      res.writeHead(200, { 'content-type': 'application/json' }).end('{"ok":true}');
    });
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => server.close(resolve)));
  const post = async (path, body) => (await fetch(`http://127.0.0.1:${server.address().port}${path}`, { method: 'POST', body })).json();
  return { refund: (order, amount) => post(`/orders/${order}/refund`, JSON.stringify({ amount })), meta: (order, text) => post(`/orders/${order}/meta`, text) };
}
