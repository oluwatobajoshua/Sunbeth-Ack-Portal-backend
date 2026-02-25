const { getDb } = require('../config/db');

async function adminGuard(req, res, next) {
  try {
    const hdr = (req.headers['x-admin-email'] || req.headers['x-user-email'] || '').toString().trim().toLowerCase();
    const qp = (req.query && req.query.adminEmail ? String(req.query.adminEmail) : '').trim().toLowerCase();
    const email = hdr || qp || '';
    const force = String(process.env.FORCE_SUPERADMIN_EMAILS || '').toLowerCase();
    if (email && force.includes(email)) return next();
    if (!email) return res.status(401).json({ error: 'missing_admin_email' });
    const db = await getDb();
    const rows = db.query?.('SELECT role FROM roles WHERE LOWER(email)=LOWER(?)', [email]) || [];
    const roles = Array.isArray(rows) ? rows.map(r => String(r.role || '').toLowerCase()) : [];
    if (roles.includes('admin') || roles.includes('superadmin')) return next();
    return res.status(403).json({ error: 'forbidden' });
  } catch (e) {
    return res.status(500).json({ error: 'admin_guard_error', details: e.message });
  }
}

module.exports = { adminGuard };
