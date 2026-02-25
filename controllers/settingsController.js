const { asyncHandler } = require('../utils/helpers');
const { getDb } = require('../config/db');

const SETTINGS_WHITELIST = new Set([
  'external_support_enabled',
  'allowed_origins',
  'tenant_base_domain',
  'tenant_subdomain_enabled',
  'frontend_base_url',
  // SharePoint upload configuration
  'sharepoint_site_name',
  'sharepoint_library_name',
]);

const getAdminSettings = asyncHandler(async (_req, res) => {
  const db = await getDb();
  const rows = db.query('SELECT key, value FROM app_settings');
  const out = {};
  for (const r of rows) {
    const k = String(r.key);
    if (!SETTINGS_WHITELIST.has(k)) continue;
    let v = r.value;
    if (k.endsWith('_enabled')) v = String(v) === '1' || String(v).toLowerCase() === 'true';
    out[k] = v;
  }
  res.json({ settings: out });
});

const putAdminSettings = asyncHandler(async (req, res) => {
  const db = await getDb();
  const payload = req.body && req.body.settings ? req.body.settings : req.body;
  if (!payload || typeof payload !== 'object') return res.status(400).json({ error: 'invalid_payload' });
  db.run('BEGIN');
  try {
    const applied = {};
    for (const [k, val] of Object.entries(payload)) {
      if (!SETTINGS_WHITELIST.has(k)) continue;
      const v = k.endsWith('_enabled') ? (val ? '1' : '0') : String(val ?? '');
      db.run('INSERT INTO app_settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value', [k, v]);
      applied[k] = v;
    }
    db.run('COMMIT');
    db.persist?.();
  } catch (e) {
    try { db.run('ROLLBACK'); } catch {}
    throw e;
  }
  try { require('../utils/logger').info('settings:update', { reqId: req.id, applied }); } catch {}
  res.json({ ok: true });
});

module.exports = { getAdminSettings, putAdminSettings };
// Public: read-only sharepoint settings for UI display
const getSharePointSettingsPublic = asyncHandler(async (_req, res) => {
  const db = await getDb();
  const rows = db.query('SELECT key, value FROM app_settings WHERE key IN (?, ?)', ['sharepoint_site_name', 'sharepoint_library_name']);
  const map = {};
  for (const r of rows) map[String(r.key)] = r.value;
  res.json({ siteName: String(map['sharepoint_site_name'] || ''), libraryName: String(map['sharepoint_library_name'] || '') });
});

module.exports.getSharePointSettingsPublic = getSharePointSettingsPublic;

// Public: save sharepoint site/library into app_settings (same method as other settings)
const putSharePointSettingsPublic = asyncHandler(async (req, res) => {
  const db = await getDb();
  const siteName = req?.body?.siteName == null ? '' : String(req.body.siteName);
  const libraryName = req?.body?.libraryName == null ? '' : String(req.body.libraryName);
  db.run('BEGIN');
  try {
    db.run('INSERT INTO app_settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value', ['sharepoint_site_name', siteName]);
    db.run('INSERT INTO app_settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value', ['sharepoint_library_name', libraryName]);
    db.run('COMMIT');
    db.persist?.();
  } catch (e) {
    try { db.run('ROLLBACK'); } catch {}
    throw e;
  }
  try { require('../utils/logger').info('settings:sharepoint:update', { reqId: req.id, siteName, libraryName }); } catch {}
  res.json({ siteName, libraryName });
});

module.exports.putSharePointSettingsPublic = putSharePointSettingsPublic;
