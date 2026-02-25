const crypto = require('crypto');
const bcrypt = require('bcrypt');
const { authenticator } = require('otplib');
const { getDb } = require('../config/db');

const BCRYPT_ROUNDS = Number(process.env.BCRYPT_ROUNDS || 10);

// In-memory stores for onboarding and simple lockouts
const onboardingTokens = new Map(); // email -> { token, expiresAt }
const failedLogins = new Map(); // email -> { count, lockUntil }

function isLocked(email) {
  const e = String(email || '').toLowerCase();
  const rec = failedLogins.get(e);
  return !!(rec && rec.lockUntil && rec.lockUntil > Date.now());
}

function recordLoginFailure(email) {
  const e = String(email || '').toLowerCase();
  const rec = failedLogins.get(e) || { count: 0, lockUntil: 0 };
  rec.count += 1;
  if (rec.count >= 5) {
    rec.lockUntil = Date.now() + 5 * 60 * 1000; // 5 minutes lock
    rec.count = 0;
  }
  failedLogins.set(e, rec);
  return rec;
}

function clearLoginFailures(email) {
  failedLogins.delete(String(email || '').toLowerCase());
}

async function ensureSchema() {
  const db = await getDb();
  try {
    db.run?.("CREATE TABLE IF NOT EXISTS external_users (id INTEGER PRIMARY KEY AUTOINCREMENT, email TEXT NOT NULL UNIQUE, name TEXT, phone TEXT, password_hash TEXT, mfa_enabled INTEGER DEFAULT 0, mfa_secret TEXT, status TEXT DEFAULT 'active', created_at TEXT DEFAULT (datetime('now')), last_login TEXT, department TEXT, business_id INTEGER)");
    db.run?.('CREATE UNIQUE INDEX IF NOT EXISTS ux_external_users_email ON external_users(LOWER(email))');
  } catch {}
  return db;
}

async function searchUsers({ q }) {
  const db = await ensureSchema();
  const term = String(q || '').trim().toLowerCase();
  const where = term
    ? "WHERE LOWER(email) LIKE ? OR LOWER(name) LIKE ? OR LOWER(phone) LIKE ? OR LOWER(department) LIKE ?"
    : '';
  const arg = term ? `%${term}%` : null;
  const rows = db.query(
    `SELECT id, email, name, phone, department, business_id, status, created_at, last_login, mfa_enabled FROM external_users ${where} ORDER BY created_at DESC LIMIT 100`,
    term ? [arg, arg, arg, arg] : []
  );
  return Array.isArray(rows) ? rows : [];
}

async function listUsers({ status, department, businessId, mfaEnabled, limit = 50, offset = 0 }) {
  const db = await ensureSchema();
  const where = [];
  const params = [];
  if (status) { where.push('status=?'); params.push(String(status)); }
  if (department) { where.push('LOWER(department)=LOWER(?)'); params.push(String(department)); }
  if (businessId != null && businessId !== '') { where.push('business_id=?'); params.push(Number(businessId)); }
  if (mfaEnabled != null) { where.push('mfa_enabled=?'); params.push(mfaEnabled ? 1 : 0); }
  const sqlWhere = where.length ? `WHERE ${where.join(' AND ')}` : '';
  const rows = db.query(
    `SELECT id, email, name, phone, department, business_id, status, mfa_enabled, created_at, last_login FROM external_users ${sqlWhere} ORDER BY created_at DESC LIMIT ${Number(limit)||50} OFFSET ${Number(offset)||0}`,
    params
  );
  return Array.isArray(rows) ? rows : [];
}

async function findUserByEmail(email) {
  const db = await ensureSchema();
  const rows = db.query('SELECT * FROM external_users WHERE LOWER(email)=LOWER(?)', [String(email).trim().toLowerCase()]);
  return rows && rows[0] ? rows[0] : null;
}

async function inviteUser({ email, name = '', phone = '', department = null, businessId = null }) {
  const db = await ensureSchema();
  const e = String(email || '').trim().toLowerCase();
  const existing = db.query('SELECT id FROM external_users WHERE LOWER(email)=LOWER(?)', [e])[0];
  const now = new Date().toISOString();
  if (existing) {
    db.run('UPDATE external_users SET name=?, phone=?, department=COALESCE(?,department), business_id=COALESCE(?,business_id), status=status WHERE id=?', [name, phone, department, businessId != null && businessId !== '' ? Number(businessId) : null, existing.id]);
  } else {
    db.run('INSERT INTO external_users (email, name, phone, department, business_id, password_hash, status, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)', [e, name, phone, department, businessId != null && businessId !== '' ? Number(businessId) : null, '', 'invited', now]);
  }
  const token = crypto.randomBytes(32).toString('hex');
  const expiresAt = Date.now() + 1000 * 60 * 60 * 48; // 48h
  onboardingTokens.set(e, { token, expiresAt });
  return { email: e, token };
}

async function resendInvite(email) {
  const db = await ensureSchema();
  const e = String(email || '').trim().toLowerCase();
  const user = db.query('SELECT id, name FROM external_users WHERE LOWER(email)=LOWER(?)', [e])[0];
  if (!user) return null;
  const token = crypto.randomBytes(32).toString('hex');
  const expiresAt = Date.now() + 1000 * 60 * 60 * 48;
  onboardingTokens.set(e, { token, expiresAt });
  return { email: e, name: user.name || '', token };
}

async function setPassword({ email, token, password, department = null, businessId = null }) {
  const db = await ensureSchema();
  const e = String(email || '').trim().toLowerCase();
  const rec = onboardingTokens.get(e);
  if (!rec || rec.token !== token || Date.now() > rec.expiresAt) return { ok: false, error: 'invalid_or_expired_token' };
  const hash = await bcrypt.hash(String(password), BCRYPT_ROUNDS);
  db.run('UPDATE external_users SET password_hash=?, status=?, department=COALESCE(?,department), business_id=COALESCE(?,business_id) WHERE LOWER(email)=LOWER(?)', [hash, 'active', department, businessId, e]);
  onboardingTokens.delete(e);
  return { ok: true };
}

async function login({ email, password }) {
  const db = await ensureSchema();
  const e = String(email || '').trim().toLowerCase();
  if (isLocked(e)) return { ok: false, error: 'account_locked_temp' };
  const user = db.query('SELECT * FROM external_users WHERE LOWER(email)=LOWER(?)', [e])[0];
  if (!user) { recordLoginFailure(e); return { ok: false, error: 'invalid_credentials' }; }
  if (!user.password_hash) return { ok: false, error: 'password_not_set', onboarding: true };
  const match = await bcrypt.compare(String(password), user.password_hash);
  if (!match) { const rec = recordLoginFailure(e); return { ok: false, error: rec?.lockUntil && rec.lockUntil > Date.now() ? 'account_locked_temp' : 'invalid_credentials' }; }
  clearLoginFailures(e);
  if (user.mfa_enabled) return { ok: true, mfaRequired: true };
  db.run('UPDATE external_users SET last_login=? WHERE id=?', [new Date().toISOString(), user.id]);
  return { ok: true, user: { email: user.email, name: user.name } };
}

async function mfaSetup(email) {
  const db = await ensureSchema();
  const e = String(email || '').trim().toLowerCase();
  const user = db.query('SELECT * FROM external_users WHERE LOWER(email)=LOWER(?)', [e])[0];
  if (!user) return null;
  const secret = authenticator.generateSecret();
  const otpauth = authenticator.keyuri(e, 'Sunbeth', secret);
  db.run('UPDATE external_users SET mfa_secret=? WHERE id=?', [secret, user.id]);
  return { secret, otpauth };
}

async function mfaVerify(email, code) {
  const db = await ensureSchema();
  const e = String(email || '').trim().toLowerCase();
  const user = db.query('SELECT * FROM external_users WHERE LOWER(email)=LOWER(?)', [e])[0];
  if (!user || !user.mfa_secret) return { ok: false, error: 'user_or_secret_not_found' };
  const valid = authenticator.check(String(code), user.mfa_secret);
  if (!valid) return { ok: false, error: 'invalid_code' };
  db.run('UPDATE external_users SET mfa_enabled=1 WHERE id=?', [user.id]);
  return { ok: true };
}

async function mfaDisable(email) {
  const db = await ensureSchema();
  const e = String(email || '').trim().toLowerCase();
  const user = db.query('SELECT * FROM external_users WHERE LOWER(email)=LOWER(?)', [e])[0];
  if (!user) return false;
  db.run('UPDATE external_users SET mfa_enabled=0, mfa_secret=NULL WHERE id=?', [user.id]);
  return true;
}

async function updateUserById(id, fields) {
  const db = await ensureSchema();
  const updates = [];
  const params = [];
  if (fields.name != null) { updates.push('name=?'); params.push(String(fields.name)); }
  if (fields.phone != null) { updates.push('phone=?'); params.push(String(fields.phone)); }
  if (fields.department !== undefined) { updates.push('department=?'); params.push(fields.department === '' ? null : fields.department); }
  if (fields.businessId !== undefined) { updates.push('business_id=?'); params.push(fields.businessId != null && fields.businessId !== '' ? Number(fields.businessId) : null); }
  if (fields.status != null) { updates.push('status=?'); params.push(String(fields.status)); }
  if (!updates.length) return false;
  params.push(Number(id));
  db.run(`UPDATE external_users SET ${updates.join(', ')} WHERE id=?`, params);
  return true;
}

async function deleteUserById(id) {
  const db = await ensureSchema();
  db.run('DELETE FROM external_users WHERE id=?', [Number(id)]);
  return true;
}

module.exports = {
  searchUsers,
  listUsers,
  findUserByEmail,
  inviteUser,
  resendInvite,
  setPassword,
  login,
  mfaSetup,
  mfaVerify,
  mfaDisable,
  updateUserById,
  deleteUserById,
  onboardingTokens,
};
