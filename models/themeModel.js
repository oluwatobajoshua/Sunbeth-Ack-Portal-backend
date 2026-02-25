const { getDb } = require('../config/db');

function safeParse(json) { try { return json ? JSON.parse(String(json)) : null; } catch { return null; } }
function deepMerge(a, b) {
  if (!a) return b; if (!b) return a;
  const out = Array.isArray(a) ? [...a] : { ...a };
  for (const [k, v] of Object.entries(b)) {
    if (v && typeof v === 'object' && !Array.isArray(v)) out[k] = deepMerge(out[k] || {}, v);
    else out[k] = v;
  }
  return out;
}
function defaultLight() { return { cssVars: { '--primary': '#0c5343','--accent': '#f64500','--bg': '#f7f8fa','--bg-elevated': '#ffffff','--card': '#ffffff','--muted': '#6b6b6b' } }; }
function defaultDark() { return { cssVars: { '--bg': '#111a17','--bg-elevated': '#16211d','--card': '#182520','--muted': '#a5b2ad' }, darkMode: true }; }

async function listThemes() {
  const db = await getDb();
  const rows = db.query('SELECT id, name, description, base_theme_id as baseThemeId, is_system as isSystem, created_at as createdAt, updated_at as updatedAt FROM themes ORDER BY is_system DESC, name ASC');
  return rows.map((r) => ({ id: r.id, name: r.name, description: r.description, baseThemeId: r.baseThemeId, isSystem: !!r.isSystem, createdAt: r.createdAt, updatedAt: r.updatedAt }));
}

async function createTheme({ name, description=null, light=null, dark=null, baseThemeId=null }) {
  const db = await getDb();
  const n = String(name || '').trim(); if (!n) throw Object.assign(new Error('name_required'), { status: 400 });
  const now = new Date().toISOString();
  db.run('INSERT INTO themes (name, description, light_json, dark_json, base_theme_id, is_system, created_at, updated_at) VALUES (?, ?, ?, ?, ?, 0, ?, ?)', [n, description, light ? JSON.stringify(light) : null, dark ? JSON.stringify(dark) : null, baseThemeId, now, now]);
  const idRow = db.query('SELECT last_insert_rowid() as id');
  const id = Array.isArray(idRow) && idRow[0] ? idRow[0].id : null;
  db.persist?.();
  return { id };
}

async function getTheme(id) {
  const db = await getDb();
  const rows = db.query('SELECT id, name, description, light_json, dark_json, base_theme_id as baseThemeId, is_system as isSystem, created_at as createdAt, updated_at as updatedAt FROM themes WHERE id=?', [Number(id)]);
  const r = rows[0]; if (!r) return null;
  return { id: r.id, name: r.name, description: r.description, baseThemeId: r.baseThemeId, isSystem: !!r.isSystem, createdAt: r.createdAt, updatedAt: r.updatedAt, light: safeParse(r.light_json), dark: safeParse(r.dark_json) };
}

async function updateTheme(id, { name, description, light, dark }) {
  const db = await getDb();
  const cur = db.query('SELECT id FROM themes WHERE id=?', [Number(id)])[0];
  if (!cur) throw Object.assign(new Error('not_found'), { status: 404 });
  const now = new Date().toISOString();
  db.run('UPDATE themes SET name=COALESCE(?, name), description=COALESCE(?, description), light_json=COALESCE(?, light_json), dark_json=COALESCE(?, dark_json), updated_at=? WHERE id=?', [name || null, description || null, light ? JSON.stringify(light) : null, dark ? JSON.stringify(dark) : null, now, Number(id)]);
  db.persist?.();
  return { ok: true };
}

async function deleteTheme(id) {
  const db = await getDb();
  db.run('DELETE FROM themes WHERE id=? AND is_system=0', [Number(id)]);
  db.persist?.();
  return { ok: true };
}

async function cloneTheme(id, name) {
  const db = await getDb();
  const src = db.query('SELECT name, description, light_json, dark_json FROM themes WHERE id=?', [Number(id)])[0];
  if (!src) throw Object.assign(new Error('not_found'), { status: 404 });
  const n = String(name || `${src.name} Copy`).trim();
  const now = new Date().toISOString();
  db.run('INSERT INTO themes (name, description, light_json, dark_json, base_theme_id, is_system, created_at, updated_at) VALUES (?, ?, ?, ?, ?, 0, ?, ?)', [n, src.description, src.light_json, src.dark_json, Number(id), now, now]);
  const idRow = db.query('SELECT last_insert_rowid() as id');
  const newId = Array.isArray(idRow) && idRow[0] ? idRow[0].id : null;
  db.persist?.();
  return { id: newId };
}

async function listAssignments({ targetType, targetId }) {
  const db = await getDb();
  let rows;
  if (targetType) {
    rows = db.query('SELECT ta.id, ta.theme_id as themeId, ta.target_type as targetType, ta.target_id as targetId, ta.enabled, t.name as themeName FROM theme_assignments ta JOIN themes t ON t.id=ta.theme_id WHERE ta.target_type=? AND (ta.target_id IS ? OR ta.target_id=?)', [String(targetType), targetId != null ? String(targetId) : null, targetId != null ? String(targetId) : null]);
  } else {
    rows = db.query('SELECT ta.id, ta.theme_id as themeId, ta.target_type as targetType, ta.target_id as targetId, ta.enabled, t.name as themeName FROM theme_assignments ta JOIN themes t ON t.id=ta.theme_id ORDER BY ta.id DESC');
  }
  return rows.map((r) => ({ id: r.id, themeId: r.themeId, themeName: r.themeName, targetType: r.targetType, targetId: r.targetId, enabled: !!r.enabled }));
}

async function resolveEffectiveTheme({ tenantId=null, module='', plugin='' }) {
  const db = await getDb();
  let light = defaultLight();
  let dark = defaultDark();
  const overlayThemeById = (themeId) => {
    if (themeId == null) return;
    const thr = db.query('SELECT light_json, dark_json FROM themes WHERE id=?', [Number(themeId)])[0];
    const l = safeParse(thr?.light_json); const d = safeParse(thr?.dark_json);
    if (l) light = deepMerge(light, l); if (d) dark = deepMerge(dark, d);
  };
  const rowsGlobal = db.query('SELECT theme_id FROM theme_assignments WHERE target_type=? AND (target_id IS NULL OR target_id="") AND enabled=1', ['global']);
  for (const r of rowsGlobal) overlayThemeById(r.theme_id);
  if (tenantId != null) {
    const tenantRows = db.query('SELECT theme_id FROM theme_assignments WHERE target_type=? AND target_id=? AND enabled=1', ['tenant', String(tenantId)]);
    if (tenantRows.length > 0) {
      for (const r of tenantRows) overlayThemeById(r.theme_id);
    } else {
      const ts = db.query('SELECT theme_json FROM tenant_settings WHERE tenant_id=?', [String(tenantId)])[0];
      const t = safeParse(ts?.theme_json); if (t) light = deepMerge(light, t);
    }
  }
  if (plugin) {
    const rowsPlugin = db.query('SELECT theme_id FROM theme_assignments WHERE target_type=? AND target_id=? AND enabled=1', ['plugin', String(plugin)]);
    for (const r of rowsPlugin) overlayThemeById(r.theme_id);
  }
  if (module) {
    const rowsModule = db.query('SELECT theme_id FROM theme_assignments WHERE target_type=? AND target_id=? AND enabled=1', ['module', String(module)]);
    for (const r of rowsModule) overlayThemeById(r.theme_id);
  }
  return { theme: { light, dark } };
}

module.exports = { listThemes, createTheme, getTheme, updateTheme, deleteTheme, cloneTheme, listAssignments, resolveEffectiveTheme };
