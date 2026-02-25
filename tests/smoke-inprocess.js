const request = require('supertest');
const { createApp } = require('../server');

async function main() {
  const app = createApp();
  const admin = process.env.FORCE_SUPERADMIN_EMAILS || 'oluwatoba.ogunsakin@sunbeth.net';

  console.log('In-process smoke: /api/health');
  const health = await request(app).get('/api/health');
  console.log('Status:', health.statusCode, 'Body:', health.body);

  console.log('\nIn-process smoke: /api/admin/settings (GET)');
  const settings = await request(app)
    .get('/api/admin/settings')
    .set('x-admin-email', admin);
  console.log('Status:', settings.statusCode, 'Body:', settings.body);

  console.log('\nIn-process smoke: /api/flags/effective');
  const flags = await request(app)
    .get('/api/flags/effective')
    .set('x-admin-email', admin);
  console.log('Status:', flags.statusCode, 'Body:', flags.body);
}

main().catch((e) => {
  console.error('Smoke failed:', e && e.message ? e.message : e);
  process.exit(1);
});
