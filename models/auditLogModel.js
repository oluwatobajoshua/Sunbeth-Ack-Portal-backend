const { getDb } = require('../config/db');

async function ensureSchema(adapter) {
  try {
    if (adapter.driver === 'sqlite') {
      adapter.run('CREATE TABLE IF NOT EXISTS audit_logs (id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT, actor TEXT, action TEXT, target TEXT, ip TEXT, details TEXT)');
    }
  } catch {}
}

async function listAuditLogs({ limit = 50 } = {}) {
  const db = await getDb();
  await ensureSchema(db);
  try {
    if (db.driver === 'sqlite') {
      const rows = db.query('SELECT id, ts, actor, action, target, ip, details FROM audit_logs ORDER BY id DESC LIMIT ?', [limit]);
      return Array.isArray(rows) ? rows : [];
    }
    // For other drivers, use generic query interface (if implemented)
    const rows = await db.query('AUDIT_LIST', { limit });
    return Array.isArray(rows) ? rows : [];
  } catch (e) {
    return [];
  }
}

async function seedDemoAuditLogs() {
  const db = await getDb();
  await ensureSchema(db);
  const now = () => new Date().toISOString();
  const demos = [
    { ts: now(), actor: 'system', action: 'server_start', target: 'backend', ip: '127.0.0.1', details: 'Server boot' },
    { ts: now(), actor: 'admin@example.com', action: 'login', target: 'admin_panel', ip: '127.0.0.1', details: 'Successful login' },
    { ts: now(), actor: 'admin@example.com', action: 'mfa_setup', target: 'auth', ip: '127.0.0.1', details: 'MFA seed demo' },
    { ts: now(), actor: 'alice@example.com', action: 'password_reset', target: 'auth', ip: '127.0.0.1', details: 'Requested reset link' },
  ];
  try {
    if (db.driver === 'sqlite') {
      for (const r of demos) {
        db.run('INSERT INTO audit_logs (ts, actor, action, target, ip, details) VALUES (?, ?, ?, ?, ?, ?)', [r.ts, r.actor, r.action, r.target, r.ip, r.details]);
      }
      db.persist?.();
      return { inserted: demos.length };
    }
    // Generic insertion for other adapters
    for (const r of demos) await db.run('AUDIT_INSERT', r);
    return { inserted: demos.length };
  } catch (e) {
    return { inserted: 0 };
  }
}

module.exports = { listAuditLogs, seedDemoAuditLogs };
