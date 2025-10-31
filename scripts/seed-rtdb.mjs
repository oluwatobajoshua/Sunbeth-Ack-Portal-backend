// Minimal RTDB-friendly seed script using public API endpoints
// Usage: node ./scripts/seed-rtdb.mjs http://localhost:4005

const BASE = process.argv[2] || process.env.API_BASE || 'http://localhost:4000';
const SEED_EMAIL = process.argv[3] || process.env.SEED_EMAIL || null;

async function json(req) {
  const res = await fetch(req);
  const text = await res.text();
  try { return { status: res.status, ok: res.ok, body: text ? JSON.parse(text) : null }; }
  catch { return { status: res.status, ok: res.ok, body: text }; }
}

async function post(path, body, headers = {}) {
  return json(new Request(`${BASE}${path}`, {
    method: 'POST', headers: { 'Content-Type': 'application/json', ...headers }, body: JSON.stringify(body || {})
  }));
}
async function put(path, body, headers = {}) {
  return json(new Request(`${BASE}${path}`, {
    method: 'PUT', headers: { 'Content-Type': 'application/json', ...headers }, body: JSON.stringify(body || {})
  }));
}
async function get(path, headers = {}) { return json(new Request(`${BASE}${path}`, { headers })); }

async function main() {
  console.log(`[seed] targeting ${BASE}`);

  // 1) Health
  try {
    const h = await get('/api/health');
    if (!h.ok) throw new Error(`health ${h.status}`);
    console.log('[seed] health ok');
  } catch (e) {
    console.error('[seed] server not reachable:', e.message || e);
    process.exit(2);
  }

  // 2) Create a business
  const bizName = `Seed Co ${Date.now()}`;
  const biz = await post('/api/businesses', { name: bizName, code: 'SEED', isActive: true, description: 'RTDB seed business' });
  if (!biz.ok || !biz.body?.id) {
    console.warn('[seed] business create failed or already exists:', biz.status, biz.body);
  } else {
    console.log('[seed] business id', biz.body.id);
  }

  // 3) Create a full batch with documents and recipients
  const batchBody = {
    name: `RTDB Seed Batch ${new Date().toISOString()}`,
    startDate: null,
    dueDate: null,
    status: 1,
    description: 'Seeded batch',
    documents: [
      { title: 'Handbook', url: 'https://example.com/handbook.pdf', version: 1, requiresSignature: 0 },
      { title: 'Policy', url: 'https://example.com/policy.pdf', version: 1, requiresSignature: 0 }
    ],
    recipients: [
      { email: SEED_EMAIL || `seed.user.${Date.now()}@sunbeth.net`, displayName: SEED_EMAIL ? 'Seeded User' : 'Seed User', department: 'IT', jobTitle: 'Engineer', location: 'Lagos', primaryGroup: 'Default' }
    ]
  };
  const full = await post('/api/batches/full', batchBody);
  if (!full.ok) {
    console.warn('[seed] batch create failed:', full.status, full.body);
  } else {
    console.log('[seed] batch created:', full.body);
  }

  // 4) Set notification emails (optional)
  const emails = await post('/api/notification-emails', { emails: ['ops@sunbeth.net'] });
  if (!emails.ok) console.warn('[seed] notification emails not set:', emails.status, emails.body);

  // 5) List batches
  const list = await get('/api/batches');
  console.log('[seed] batches status', list.status, 'count =', Array.isArray(list.body) ? list.body.length : 'n/a');

  console.log('[seed] done');
}

main().catch((e) => { console.error('[seed] fatal:', e); process.exit(1); });
