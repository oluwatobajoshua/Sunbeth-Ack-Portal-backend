const { getDb } = require('../config/db');

async function listGlobalFlags() {
  try {
    const db = await getDb();
    const rows = db.query("SELECT key, value FROM app_settings WHERE key LIKE 'ff_%'");
    const out = {};
    for (const r of rows) {
      const v = String(r.value);
      out[r.key] = v === '1' || v.toLowerCase() === 'true';
    }
    return out;
  } catch {
    return {};
  }
}

async function getTenantSettings(tenantId) {
  try {
    const db = await getDb();
    const rows = db.query('SELECT settings_json FROM tenant_settings WHERE tenant_id=?', [String(tenantId)]);
    const r = rows[0];
    if (!r || !r.settings_json) return {};
    try { return JSON.parse(String(r.settings_json)); } catch { return {}; }
  } catch {
    return {};
  }
}

async function getEffectiveFlags(tenantId=null) {
  const global = await listGlobalFlags();
  let flags = { ...global };
  if (tenantId != null) {
    const s = await getTenantSettings(tenantId);
    if (s && s.flags && typeof s.flags === 'object') {
      flags = { ...flags, ...s.flags };
    }
  }
  return { flags };
}

module.exports = { listGlobalFlags, getTenantSettings, getEffectiveFlags };
