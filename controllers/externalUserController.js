const csvParse = require('csv-parse/sync');
const XLSX = (() => { try { return require('xlsx'); } catch { return null; } })();
const { getSetting } = require('../models/settingsModel');
const mailer = (() => { try { return require('../src/services/mailer'); } catch { return null; } })();
const {
  searchUsers,
  listUsers,
  inviteUser,
  resendInvite,
  setPassword,
  login,
  mfaSetup,
  mfaVerify,
  mfaDisable,
  updateUserById,
  deleteUserById,
} = require('../models/externalUserModel');

function featureEnabled() { return getSetting('external_support_enabled', '0').then(v => v === '1'); }

// Simple password reset tokens (distinct from onboarding)
const passwordResetTokens = new Map(); // email -> { token, expiresAt }

async function search(req, res) {
  if (!(await featureEnabled())) return res.status(404).json({ error: 'not_found' });
  const { q } = req.query || {};
  const rows = await searchUsers({ q });
  res.json({ results: rows });
}

async function list(req, res) {
  if (!(await featureEnabled())) return res.status(404).json({ error: 'not_found' });
  const { status, department, businessId, mfaEnabled, limit, offset } = req.query || {};
  const rows = await listUsers({ status, department, businessId, mfaEnabled: mfaEnabled == null ? undefined : ['1','true','yes'].includes(String(mfaEnabled).toLowerCase()), limit: Number(limit)||50, offset: Number(offset)||0 });
  res.json({ users: rows });
}

function computeOnboardingLink(req, email, token) {
  const base = (req.headers.origin || `${req.protocol}://${req.headers.host}`);
  const cfg = process.env.FRONTEND_BASE_URL || '';
  const setting = req.app?.locals?.frontend_base_url_override || null;
  // getSetting async can't be awaited here; controller callers pass link after fetching setting
  const baseUrl = (setting || cfg || base).replace(/\/$/, '');
  return `${baseUrl}/onboard?email=${encodeURIComponent(email)}&token=${token}`;
}

async function invite(req, res) {
  if (!(await featureEnabled())) return res.status(404).json({ error: 'not_found' });
  const { email, name = '', phone = '', department = null, businessId = null } = req.body || {};
  if (!email) return res.status(400).json({ error: 'missing_email' });
  const rec = await inviteUser({ email, name, phone, department, businessId });
  try { require('../utils/logger').info('external:invite', { reqId: req.id, email: rec.email }); } catch {}
  const baseSetting = await getSetting('frontend_base_url', process.env.FRONTEND_BASE_URL || '');
  const base = baseSetting || req.headers.origin || `${req.protocol}://${req.headers.host}`;
  const link = `${String(base).replace(/\/$/, '')}/onboard?email=${encodeURIComponent(rec.email)}&token=${rec.token}`;
  try { if (mailer?.sendOnboardingEmail) await mailer.sendOnboardingEmail(rec.email, name, link); } catch {}
  res.json({ ok: true, email: rec.email });
}

async function resend(req, res) {
  if (!(await featureEnabled())) return res.status(404).json({ error: 'not_found' });
  const { email } = req.body || {};
  if (!email) return res.status(400).json({ error: 'missing_email' });
  const rec = await resendInvite(email);
  if (!rec) return res.status(404).json({ error: 'user_not_found' });
  try { require('../utils/logger').info('external:resend', { reqId: req.id, email: rec.email }); } catch {}
  const baseSetting = await getSetting('frontend_base_url', process.env.FRONTEND_BASE_URL || '');
  const base = baseSetting || req.headers.origin || `${req.protocol}://${req.headers.host}`;
  const link = `${String(base).replace(/\/$/, '')}/onboard?email=${encodeURIComponent(rec.email)}&token=${rec.token}`;
  try { if (mailer?.sendOnboardingEmail) await mailer.sendOnboardingEmail(rec.email, rec.name, link); } catch {}
  res.json({ ok: true });
}

async function inviteBatch(req, res) {
  if (!(await featureEnabled())) return res.status(404).json({ error: 'not_found' });
  const list = Array.isArray(req.body?.users) ? req.body.users : Array.isArray(req.body) ? req.body : [];
  if (!list.length) return res.status(400).json({ error: 'no_records_found' });
  const baseSetting = await getSetting('frontend_base_url', process.env.FRONTEND_BASE_URL || '');
  const base = baseSetting || req.headers.origin || `${req.protocol}://${req.headers.host}`;
  const onboarding = [];
  let inserted = 0, updated = 0;
  for (const row of list) {
    const email = String(row.email || '').trim().toLowerCase();
    if (!email || !/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email)) continue;
    const rec = await inviteUser({ email, name: row.name || '', phone: row.phone || '', department: row.department || null, businessId: row.businessId != null && row.businessId !== '' ? Number(row.businessId) : null });
    const link = `${String(base).replace(/\/$/, '')}/onboard?email=${encodeURIComponent(rec.email)}&token=${rec.token}`;
    onboarding.push({ email: rec.email, name: row.name || '', link });
    inserted++; // treat as invites
  }
  try { require('../utils/logger').info('external:inviteBatch', { reqId: req.id, inserted, total: list.length }); } catch {}
  try { await Promise.all(onboarding.map(u => mailer?.sendOnboardingEmail ? mailer.sendOnboardingEmail(u.email, u.name, u.link) : Promise.resolve())); } catch {}
  res.json({ inserted, updated, onboarding: onboarding.map(u => ({ email: u.email, sent: true })) });
}

async function resendBatch(req, res) {
  if (!(await featureEnabled())) return res.status(404).json({ error: 'not_found' });
  const emails = Array.isArray(req.body?.emails) ? req.body.emails : [];
  if (!emails.length) return res.status(400).json({ error: 'no_emails' });
  const baseSetting = await getSetting('frontend_base_url', process.env.FRONTEND_BASE_URL || '');
  const base = baseSetting || req.headers.origin || `${req.protocol}://${req.headers.host}`;
  const results = [];
  for (const e of emails) {
    const rec = await resendInvite(e);
    if (!rec) { results.push({ email: e, sent: false }); continue; }
    const link = `${String(base).replace(/\/$/, '')}/onboard?email=${encodeURIComponent(rec.email)}&token=${rec.token}`;
    try { if (mailer?.sendOnboardingEmail) await mailer.sendOnboardingEmail(rec.email, rec.name, link); } catch {}
    results.push({ email: rec.email, sent: true });
  }
  try { require('../utils/logger').info('external:resendBatch', { reqId: req.id, total: emails.length }); } catch {}
  res.json({ results });
}

async function setPasswordHandler(req, res) {
  if (!(await featureEnabled())) return res.status(404).json({ error: 'not_found' });
  const { email, token, password, department = null, businessId = null } = req.body || {};
  if (!email || !token || !password) return res.status(400).json({ error: 'missing_fields' });
  const out = await setPassword({ email, token, password, department, businessId });
  if (!out.ok) return res.status(400).json({ error: out.error });
  res.json({ ok: true });
}

async function requestResetHandler(req, res) {
  if (!(await featureEnabled())) return res.status(404).json({ error: 'not_found' });
  const { email } = req.body || {};
  if (!email) return res.status(400).json({ error: 'missing_email' });
  const e = String(email).trim().toLowerCase();
  const token = require('crypto').randomBytes(32).toString('hex');
  const expiresAt = Date.now() + 1000 * 60 * 60 * 2; // 2 hours
  passwordResetTokens.set(e, { token, expiresAt });
  const baseSetting = await getSetting('frontend_base_url', process.env.FRONTEND_BASE_URL || '');
  const base = baseSetting || req.headers.origin || `${req.protocol}://${req.headers.host}`;
  const link = `${String(base).replace(/\/$/, '')}/reset-password?email=${encodeURIComponent(e)}&token=${token}`;
  try { if (mailer?.sendHtml) await mailer.sendHtml(e, 'Reset your password', `<p>Reset your password using this link:</p><p><a href="${link}">${link}</a></p>`); } catch {}
  res.json({ ok: true });
}

async function resetPasswordHandler(req, res) {
  if (!(await featureEnabled())) return res.status(404).json({ error: 'not_found' });
  const { email, token, password } = req.body || {};
  if (!email || !token || !password) return res.status(400).json({ error: 'missing_fields' });
  const e = String(email).trim().toLowerCase();
  const rec = passwordResetTokens.get(e);
  if (!rec || rec.token !== token || Date.now() > rec.expiresAt) return res.status(400).json({ error: 'invalid_or_expired_token' });
  const out = await setPassword({ email: e, token: rec.token, password });
  if (!out.ok) return res.status(400).json({ error: out.error });
  passwordResetTokens.delete(e);
  res.json({ ok: true });
}

async function loginHandler(req, res) {
  if (!(await featureEnabled())) return res.status(404).json({ error: 'not_found' });
  const { email, password } = req.body || {};
  if (!email || !password) return res.status(400).json({ error: 'missing_fields' });
  const out = await login({ email, password });
  try { require('../utils/logger').info('external:login', { reqId: req.id, email: String(email).toLowerCase(), ok: !!out?.ok, mfaRequired: !!out?.mfaRequired }); } catch {}
  if (!out.ok) return res.status(out.error === 'account_locked_temp' ? 429 : 401).json({ error: out.error, onboarding: out.onboarding });
  if (out.mfaRequired) return res.json({ mfaRequired: true });
  res.json({ ok: true, ...out.user });
}

async function mfaSetupHandler(req, res) {
  if (!(await featureEnabled())) return res.status(404).json({ error: 'not_found' });
  const { email } = req.body || {};
  if (!email) return res.status(400).json({ error: 'missing_email' });
  const out = await mfaSetup(email);
  if (!out) return res.status(404).json({ error: 'user_not_found' });
  try { require('../utils/logger').info('external:mfaSetup', { reqId: req.id, email }); } catch {}
  res.json(out);
}

async function mfaVerifyHandler(req, res) {
  if (!(await featureEnabled())) return res.status(404).json({ error: 'not_found' });
  const { email, code } = req.body || {};
  if (!email || !code) return res.status(400).json({ error: 'missing_fields' });
  const out = await mfaVerify(email, code);
  if (!out.ok) {
    try { require('../utils/logger').warn('external:mfaVerifyFail', { reqId: req.id, email }); } catch {}
    return res.status(out.error === 'invalid_code' ? 401 : 404).json({ error: out.error });
  }
  try { require('../utils/logger').info('external:mfaVerify', { reqId: req.id, email }); } catch {}
  res.json({ ok: true });
}

async function mfaDisableHandler(req, res) {
  if (!(await featureEnabled())) return res.status(404).json({ error: 'not_found' });
  const { email } = req.body || {};
  if (!email) return res.status(400).json({ error: 'missing_email' });
  const ok = await mfaDisable(email);
  try { require('../utils/logger').info('external:mfaDisable', { reqId: req.id, email, ok }); } catch {}
  if (!ok) return res.status(404).json({ error: 'user_not_found' });
  res.json({ ok: true });
}

async function patchUser(req, res) {
  if (!(await featureEnabled())) return res.status(404).json({ error: 'not_found' });
  const { id } = req.params || {};
  const ok = await updateUserById(id, req.body || {});
  try { require('../utils/logger').info('external:patch', { reqId: req.id, id, ok }); } catch {}
  if (!ok) return res.status(400).json({ error: 'no_updates' });
  res.json({ ok: true });
}

async function deleteUser(req, res) {
  if (!(await featureEnabled())) return res.status(404).json({ error: 'not_found' });
  const { id } = req.params || {};
  await deleteUserById(id);
  try { require('../utils/logger').info('external:delete', { reqId: req.id, id }); } catch {}
  res.json({ ok: true });
}

async function bulkUpload(req, res) {
  if (!(await featureEnabled())) return res.status(404).json({ error: 'not_found' });
  if (!req.file) return res.status(400).json({ error: 'no_file_uploaded' });
  const isExcel = /\.xlsx$|\.xls$/i.test(req.file.originalname || '') || (req.file.mimetype && /sheet|excel/i.test(req.file.mimetype));
  let records = [];
  try {
    if (isExcel && XLSX) {
      const wb = XLSX.read(req.file.buffer, { type: 'buffer' });
      const sheetName = wb.SheetNames.find((n) => /externalusers|users/i.test(n)) || wb.SheetNames[0];
      records = XLSX.utils.sheet_to_json(wb.Sheets[sheetName] || {}, { defval: '' });
    } else {
      const content = req.file.buffer.toString('utf8');
      records = csvParse.parse(content, { columns: true, skip_empty_lines: true });
    }
  } catch (e) {
    return res.status(400).json({ error: isExcel ? 'invalid_excel' : 'invalid_csv', details: e.message });
  }
  if (!Array.isArray(records) || !records.length) return res.status(400).json({ error: 'no_records_found' });
  const baseSetting = await getSetting('frontend_base_url', process.env.FRONTEND_BASE_URL || '');
  const base = baseSetting || req.headers.origin || `${req.protocol}://${req.headers.host}`;
  const onboarding = [];
  let inserted = 0, updated = 0; // we treat all as invites for simplicity
  for (const row of records) {
    const email = String(row.email || '').trim().toLowerCase();
    if (!email || !/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email)) continue;
    const rec = await inviteUser({ email, name: row.name || '', phone: row.phone || '', department: row.department || null, businessId: row.businessId != null && row.businessId !== '' ? Number(row.businessId) : null });
    const link = `${String(base).replace(/\/$/, '')}/onboard?email=${encodeURIComponent(rec.email)}&token=${rec.token}`;
    onboarding.push({ email: rec.email, name: row.name || '', link });
    inserted++;
  }
  try { await Promise.all(onboarding.map(u => mailer?.sendOnboardingEmail ? mailer.sendOnboardingEmail(u.email, u.name, u.link) : Promise.resolve())); } catch {}
  res.json({ inserted, updated, onboarding: onboarding.map(u => ({ email: u.email, sent: true })) });
}

module.exports = {
  search,
  list,
  invite,
  resend,
  inviteBatch,
  resendBatch,
  setPasswordHandler,
  requestResetHandler,
  resetPasswordHandler,
  loginHandler,
  mfaSetupHandler,
  mfaVerifyHandler,
  mfaDisableHandler,
  patchUser,
  deleteUser,
  bulkUpload,
};
