const { getDb } = require('../config/db');
const { getSetting } = require('./settingsModel');
const { listModules } = require('../src/modules/loader');

async function listTenants() {
  const db = await getDb();
  const rows = db.query('SELECT id, name, code, is_active as isActive, is_owner as isOwner, parent_id as parentId FROM tenants ORDER BY is_owner DESC, name ASC');
  const out = [];
  for (const r of rows) {
    let modulesEnabled = 0; let activeLicenses = 0;
    try {
      const mRows = db.query('SELECT COUNT(*) as c FROM tenant_modules WHERE tenant_id=? AND enabled=1', [r.id]);
      modulesEnabled = Number((Array.isArray(mRows) && mRows[0] && (mRows[0].c ?? mRows[0].count)) || 0);
    } catch {}
    try {
      const lRows = db.query("SELECT COUNT(*) as c FROM licenses WHERE tenant_id=? AND status='active'", [r.id]);
      activeLicenses = Number((Array.isArray(lRows) && lRows[0] && (lRows[0].c ?? lRows[0].count)) || 0);
    } catch {}
    out.push({ id: r.id, name: r.name, code: r.code, isActive: !!r.isActive, isOwner: !!r.isOwner, parentId: r.parentId || null, modulesEnabled, activeLicenses });
  }
  return out;
}

async function createTenant({ name, code, parentId=null, isActive=true, isOwner=false }) {
  if (!name || !code) throw Object.assign(new Error('name_code_required'), { status: 400 });
  const db = await getDb();
  db.run('INSERT INTO tenants (name, code, parent_id, is_active, is_owner) VALUES (?, ?, ?, ?, ?)', [String(name), String(code).toUpperCase(), parentId, isActive ? 1 : 0, isOwner ? 1 : 0]);
  const idRow = db.query('SELECT last_insert_rowid() AS id');
  const id = Array.isArray(idRow) && idRow[0] ? idRow[0].id : null;
  db.persist?.();
  return { id };
}

async function updateTenant(id, { name, code, parentId, isActive, isOwner }) {
  const db = await getDb();
  const cur = db.query('SELECT * FROM tenants WHERE id=?', [Number(id)])[0];
  if (!cur) throw Object.assign(new Error('not_found'), { status: 404 });
  const next = {
    name: name != null ? String(name) : cur.name,
    code: code != null ? String(code).toUpperCase() : cur.code,
    parent_id: parentId !== undefined ? parentId : cur.parent_id,
    is_active: isActive !== undefined ? (isActive ? 1 : 0) : cur.is_active,
    is_owner: isOwner !== undefined ? (isOwner ? 1 : 0) : cur.is_owner,
  };
  db.run('UPDATE tenants SET name=?, code=?, parent_id=?, is_active=?, is_owner=? WHERE id=?', [next.name, next.code, next.parent_id, next.is_active, next.is_owner, Number(id)]);
  db.persist?.();
  return { ok: true };
}

async function getTenantModules(tenantId) {
  const db = await getDb();
  const mods = listModules({ featureFlagGetter: (k, f) => getSetting(k, f) });
  const rows = db.query('SELECT module_name, enabled FROM tenant_modules WHERE tenant_id=?', [Number(tenantId)]);
  const byName = new Map(rows.map((r) => [r.module_name, !!r.enabled]));
  return mods.map((m) => ({ ...m, enabled: byName.has(m.name) ? Boolean(byName.get(m.name)) : false }));
}

async function setTenantModuleEnabled(tenantId, module, enabled) {
  if (!module || typeof enabled !== 'boolean') throw Object.assign(new Error('module_and_enabled_required'), { status: 400 });
  const db = await getDb();
  db.run('INSERT INTO tenant_modules (tenant_id, module_name, enabled) VALUES (?, ?, ?) ON CONFLICT(tenant_id, module_name) DO UPDATE SET enabled=excluded.enabled', [Number(tenantId), String(module), enabled ? 1 : 0]);
  db.persist?.();
  return { ok: true };
}

async function listLicenses(tenantId) {
  const db = await getDb();
  const rows = db.query('SELECT id, plan, seats, status, is_free as isFree, valid_from as validFrom, valid_to as validTo FROM licenses WHERE tenant_id=? ORDER BY created_at DESC', [Number(tenantId)]);
  return rows.map((r) => ({ id: r.id, plan: r.plan, seats: r.seats, status: r.status, isFree: !!r.isFree, validFrom: r.validFrom, validTo: r.validTo }));
}

async function createLicense(tenantId, { plan, seats=0, status='active', isFree=false, validFrom=null, validTo=null }) {
  const db = await getDb();
  db.run('INSERT INTO licenses (tenant_id, plan, seats, status, is_free, valid_from, valid_to) VALUES (?, ?, ?, ?, ?, ?, ?)', [Number(tenantId), plan || null, Number(seats) || 0, String(status), isFree ? 1 : 0, validFrom, validTo]);
  const idRow = db.query('SELECT last_insert_rowid() as id');
  const id = Array.isArray(idRow) && idRow[0] ? idRow[0].id : null;
  db.persist?.();
  return { id };
}

async function listDomains(tenantId) {
  const db = await getDb();
  const rows = db.query('SELECT id, domain, is_primary as isPrimary, verified, added_at as addedAt FROM tenant_domains WHERE tenant_id=? ORDER BY is_primary DESC, domain ASC', [Number(tenantId)]);
  return rows.map((r) => ({ id: r.id, domain: r.domain, isPrimary: !!r.isPrimary, verified: !!r.verified, addedAt: r.addedAt }));
}

async function createDomain(tenantId, { domain, isPrimary=false }) {
  if (!domain || !/^[a-z0-9.-]+$/i.test(String(domain))) throw Object.assign(new Error('invalid_domain'), { status: 400 });
  const db = await getDb();
  const now = new Date().toISOString();
  db.run('INSERT INTO tenant_domains (tenant_id, domain, is_primary, verified, added_at) VALUES (?, ?, ?, 0, ?)', [Number(tenantId), String(domain).toLowerCase(), isPrimary ? 1 : 0, now]);
  if (isPrimary) db.run('UPDATE tenant_domains SET is_primary=0 WHERE tenant_id=? AND LOWER(domain)<>LOWER(?)', [Number(tenantId), String(domain).toLowerCase()]);
  const idRow = db.query('SELECT last_insert_rowid() as id');
  const id = Array.isArray(idRow) && idRow[0] ? idRow[0].id : null;
  db.persist?.();
  return { id };
}

async function deleteDomain(tenantId, domainId) {
  const db = await getDb();
  db.run('DELETE FROM tenant_domains WHERE tenant_id=? AND id=?', [Number(tenantId), Number(domainId)]);
  db.persist?.();
  return { ok: true };
}

async function getTenantTheme(tenantId) {
  const db = await getDb();
  const rows = db.query('SELECT theme_json FROM tenant_settings WHERE tenant_id=?', [Number(tenantId)]);
  const r = rows[0];
  const theme = r?.theme_json ? (function(){ try { return JSON.parse(String(r.theme_json)); } catch { return null; } })() : null;
  return { theme };
}

async function putTenantTheme(tenantId, theme) {
  const db = await getDb();
  const json = JSON.stringify(theme || {});
  db.run('INSERT INTO tenant_settings (tenant_id, theme_json) VALUES (?, ?) ON CONFLICT(tenant_id) DO UPDATE SET theme_json=excluded.theme_json', [Number(tenantId), json]);
  db.persist?.();
  return { ok: true };
}

module.exports = {
  listTenants,
  createTenant,
  updateTenant,
  getTenantModules,
  setTenantModuleEnabled,
  listLicenses,
  createLicense,
  listDomains,
  createDomain,
  deleteDomain,
  getTenantTheme,
  putTenantTheme,
};

module.exports = { listTenants, createTenant, updateTenant, getTenantModules, setTenantModuleEnabled, listLicenses, createLicense, listDomains, createDomain, deleteDomain, getTenantTheme, putTenantTheme };
