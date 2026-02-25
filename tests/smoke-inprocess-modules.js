const request = require('supertest');
const { createApp } = require('../server');
const { setSetting } = require('../models/settingsModel');

async function main() {
  const app = createApp();
  const admin = process.env.FORCE_SUPERADMIN_EMAILS || 'oluwatoba.ogunsakin@sunbeth.net';
  // Seed admin role to satisfy adminGuard in in-process mode
  const { getDb } = require('../config/db');
  const db = await getDb();
  try { db.run('INSERT INTO roles (email, role) VALUES (?, ?) ON CONFLICT(email, role) DO NOTHING', [admin, 'admin']); db.persist?.(); } catch {}

  // Ensure external support feature is enabled for tests
  await setSetting('external_support_enabled', '1');
  await setSetting('frontend_base_url', 'http://localhost:5173');

  console.log('External Users: list');
  const list = await request(app)
    .get('/api/external-users')
    .set('x-admin-email', admin);
  console.log('Status:', list.statusCode, 'Body:', list.body);

  console.log('\nExternal Users: invite');
  const invite = await request(app)
    .post('/api/external-users/invite')
    .set('x-admin-email', admin)
    .send({ email: 'example.user+test@sunbeth.net', name: 'Example User' });
  console.log('Status:', invite.statusCode, 'Body:', invite.body);

  console.log('\nSettings: PUT update');
  const putSettings = await request(app)
    .put('/api/admin/settings')
    .set('x-admin-email', admin)
    .send({ settings: { external_support_enabled: true, tenant_subdomain_enabled: false, frontend_base_url: 'http://localhost:5173' } });
  console.log('Status:', putSettings.statusCode, 'Body:', putSettings.body);

  console.log('\nSettings: GET confirm');
  const getSettings = await request(app)
    .get('/api/admin/settings')
    .set('x-admin-email', admin);
  console.log('Status:', getSettings.statusCode, 'Body:', getSettings.body);

  console.log('\nFiles: upload PDF');
  const pdfBuffer = Buffer.from('%PDF-1.4\n1 0 obj\n<<>>\nendobj\ntrailer\n<<>>\n%%EOF');
  const upload = await request(app)
    .post('/api/files/upload')
    .set('x-admin-email', admin)
    .attach('file', pdfBuffer, { filename: 'test.pdf', contentType: 'application/pdf' });
  console.log('Status:', upload.statusCode, 'Body:', upload.body);

  console.log('\nLibrary: list');
  const lib = await request(app)
    .get('/api/library/list')
    .set('x-admin-email', admin);
  console.log('Status:', lib.statusCode, 'Body:', lib.body);

  if (upload.statusCode === 200 && upload.body?.id != null) {
    console.log('\nFiles: stream uploaded by id');
    const stream = await request(app)
      .get(`/api/files/${upload.body.id}`)
      .buffer(true);
    console.log('Status:', stream.statusCode, 'Content-Type:', stream.headers['content-type'], 'Length:', stream.headers['content-length']);
  }

  console.log('\nLibrary: save-graph without token (expect 401)');
  const saveGraphNoToken = await request(app)
    .post('/api/library/save-graph')
    .set('x-admin-email', admin)
    .send({ url: 'https://example.sharepoint.com/fake' });
  console.log('Status:', saveGraphNoToken.statusCode, 'Body:', saveGraphNoToken.body);

  console.log('\nAudit Logs: seed demo');
  const seed = await request(app).post('/api/audit-logs/seed-demo');
  console.log('Status:', seed.statusCode, 'Body:', seed.body);

  console.log('\nAudit Logs: get');
  const logs = await request(app).get('/api/audit-logs');
  console.log('Status:', logs.statusCode, 'Count:', Array.isArray(logs.body?.logs) ? logs.body.logs.length : 'n/a');
}

main().catch((e) => {
  console.error('Modules smoke failed:', e && e.message ? e.message : e);
  process.exit(1);
});
