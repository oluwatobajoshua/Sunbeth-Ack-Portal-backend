const http = require('http');

const PORT = parseInt(process.env.PORT || process.argv[2] || '4116', 10);
const ADMIN = process.env.FORCE_SUPERADMIN_EMAILS || 'oluwatoba.ogunsakin@sunbeth.net';
const BASE = `http://localhost:${PORT}`;

function requestJson(path, headers = {}) {
  return new Promise((resolve) => {
    const opts = new URL(BASE + path);
    const req = http.request({
      hostname: opts.hostname,
      port: opts.port,
      path: opts.pathname + (opts.search || ''),
      method: 'GET',
      headers: { 'x-admin-email': ADMIN, ...headers },
    }, (res) => {
      const chunks = [];
      res.on('data', (c) => chunks.push(c));
      res.on('end', () => {
        const body = Buffer.concat(chunks).toString('utf8');
        try { resolve({ status: res.statusCode, json: JSON.parse(body) }); }
        catch { resolve({ status: res.statusCode, text: body }); }
      });
    });
    req.on('error', (e) => resolve({ error: e.message }));
    req.end();
  });
}

(async () => {
  console.log('Smoke (local) against', BASE);
  console.log('Health:');
  console.log(await requestJson('/api/health'));

  console.log('\nAdmin Settings (GET):');
  console.log(await requestJson('/api/admin/settings'));

  console.log('\nFlags Effective:');
  console.log(await requestJson('/api/flags/effective'));
})();
