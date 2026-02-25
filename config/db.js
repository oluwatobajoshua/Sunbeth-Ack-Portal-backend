const path = require('path');
const { getEnv } = require('./env');
// Reuse existing adapter from src/db/adapter.js
const { createDbAdapter } = require('../src/db/adapter');

let cached;

async function getDb() {
  if (cached) return cached;
  const env = getEnv();
  const dataDir = env.DATA_DIR || path.join(process.cwd(), 'data');
  const dbPath = env.DB_PATH || path.join(dataDir, 'app.sqlite');

  const { adapter } = await createDbAdapter({
    driver: env.DB_DRIVER,
    dataDir,
    dbPath,
    bootstrapSchema: (db) => {
      try {
        // Minimal schema to support core modules when using sqlite
        db.run?.('CREATE TABLE IF NOT EXISTS audit_logs (id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT, actor TEXT, action TEXT, target TEXT, ip TEXT, details TEXT)');
        db.run?.('CREATE TABLE IF NOT EXISTS themes (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, description TEXT, light_json TEXT, dark_json TEXT, base_theme_id INTEGER, is_system INTEGER DEFAULT 0, created_at TEXT, updated_at TEXT)');
        db.run?.('CREATE TABLE IF NOT EXISTS theme_assignments (id INTEGER PRIMARY KEY AUTOINCREMENT, theme_id INTEGER NOT NULL, target_type TEXT NOT NULL, target_id TEXT, enabled INTEGER DEFAULT 1)');
        db.run?.("CREATE TABLE IF NOT EXISTS tenants (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, code TEXT NOT NULL UNIQUE, parent_id INTEGER, is_active INTEGER DEFAULT 1, is_owner INTEGER DEFAULT 0, created_at TEXT DEFAULT (datetime('now'))) ");
        db.run?.('CREATE TABLE IF NOT EXISTS roles (email TEXT NOT NULL, role TEXT NOT NULL, createdAt TEXT, UNIQUE(email, role))');
        db.run?.('CREATE TABLE IF NOT EXISTS app_settings (key TEXT PRIMARY KEY, value TEXT)');
        db.run?.('CREATE TABLE IF NOT EXISTS tenant_settings (tenant_id TEXT PRIMARY KEY, theme_json TEXT, settings_json TEXT)');
        db.run?.('CREATE TABLE IF NOT EXISTS tenant_modules (tenant_id INTEGER NOT NULL, module_name TEXT NOT NULL, enabled INTEGER NOT NULL DEFAULT 0, PRIMARY KEY (tenant_id, module_name))');
        db.run?.("CREATE TABLE IF NOT EXISTS licenses (id INTEGER PRIMARY KEY AUTOINCREMENT, tenant_id INTEGER NOT NULL, plan TEXT, seats INTEGER, status TEXT DEFAULT 'active', is_free INTEGER DEFAULT 0, valid_from TEXT, valid_to TEXT, created_at TEXT DEFAULT (datetime('now'))) ");
        db.run?.("CREATE TABLE IF NOT EXISTS tenant_domains (id INTEGER PRIMARY KEY AUTOINCREMENT, tenant_id INTEGER NOT NULL, domain TEXT NOT NULL UNIQUE, is_primary INTEGER DEFAULT 0, verified INTEGER DEFAULT 0, added_at TEXT DEFAULT (datetime('now'))) ");
        db.run?.("CREATE TABLE IF NOT EXISTS external_users (id INTEGER PRIMARY KEY AUTOINCREMENT, email TEXT NOT NULL UNIQUE, name TEXT, phone TEXT, password_hash TEXT, mfa_enabled INTEGER DEFAULT 0, mfa_secret TEXT, status TEXT DEFAULT 'active', created_at TEXT DEFAULT (datetime('now')), last_login TEXT, department TEXT, business_id INTEGER)");
        db.run?.('CREATE UNIQUE INDEX IF NOT EXISTS ux_external_users_email ON external_users(LOWER(email))');
        db.run?.("CREATE TABLE IF NOT EXISTS uploaded_files (id INTEGER PRIMARY KEY AUTOINCREMENT, original_name TEXT, stored_name TEXT, rel_path TEXT NOT NULL, size INTEGER, mime TEXT, sha256 TEXT, uploaded_at TEXT, uploaded_by TEXT, source_type TEXT, source_url TEXT, driveId TEXT, itemId TEXT)");
        db.run?.('CREATE UNIQUE INDEX IF NOT EXISTS ux_uploaded_files_sha ON uploaded_files(sha256)');
      } catch {}
    },
    migrateSchema: (db) => {
      // Ensure required tables exist even on existing DBs
      try {
        db.run?.('PRAGMA foreign_keys = ON');
        db.run?.('CREATE TABLE IF NOT EXISTS audit_logs (id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT, actor TEXT, action TEXT, target TEXT, ip TEXT, details TEXT)');
        db.run?.('CREATE TABLE IF NOT EXISTS themes (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, description TEXT, light_json TEXT, dark_json TEXT, base_theme_id INTEGER, is_system INTEGER DEFAULT 0, created_at TEXT, updated_at TEXT)');
        db.run?.('CREATE TABLE IF NOT EXISTS theme_assignments (id INTEGER PRIMARY KEY AUTOINCREMENT, theme_id INTEGER NOT NULL, target_type TEXT NOT NULL, target_id TEXT, enabled INTEGER DEFAULT 1)');
        db.run?.("CREATE TABLE IF NOT EXISTS tenants (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, code TEXT NOT NULL UNIQUE, parent_id INTEGER, is_active INTEGER DEFAULT 1, is_owner INTEGER DEFAULT 0, created_at TEXT DEFAULT (datetime('now'))) ");
        db.run?.('CREATE TABLE IF NOT EXISTS roles (email TEXT NOT NULL, role TEXT NOT NULL, createdAt TEXT, UNIQUE(email, role))');
        db.run?.('CREATE TABLE IF NOT EXISTS app_settings (key TEXT PRIMARY KEY, value TEXT)');
        db.run?.('CREATE TABLE IF NOT EXISTS tenant_settings (tenant_id TEXT PRIMARY KEY, theme_json TEXT, settings_json TEXT)');
        db.run?.('CREATE TABLE IF NOT EXISTS tenant_modules (tenant_id INTEGER NOT NULL, module_name TEXT NOT NULL, enabled INTEGER NOT NULL DEFAULT 0, PRIMARY KEY (tenant_id, module_name))');
        db.run?.("CREATE TABLE IF NOT EXISTS licenses (id INTEGER PRIMARY KEY AUTOINCREMENT, tenant_id INTEGER NOT NULL, plan TEXT, seats INTEGER, status TEXT DEFAULT 'active', is_free INTEGER DEFAULT 0, valid_from TEXT, valid_to TEXT, created_at TEXT DEFAULT (datetime('now'))) ");
        db.run?.("CREATE TABLE IF NOT EXISTS tenant_domains (id INTEGER PRIMARY KEY AUTOINCREMENT, tenant_id INTEGER NOT NULL, domain TEXT NOT NULL UNIQUE, is_primary INTEGER DEFAULT 0, verified INTEGER DEFAULT 0, added_at TEXT DEFAULT (datetime('now'))) ");
        db.run?.("CREATE TABLE IF NOT EXISTS external_users (id INTEGER PRIMARY KEY AUTOINCREMENT, email TEXT NOT NULL UNIQUE, name TEXT, phone TEXT, password_hash TEXT, mfa_enabled INTEGER DEFAULT 0, mfa_secret TEXT, status TEXT DEFAULT 'active', created_at TEXT DEFAULT (datetime('now')), last_login TEXT, department TEXT, business_id INTEGER)");
        db.run?.('CREATE UNIQUE INDEX IF NOT EXISTS ux_external_users_email ON external_users(LOWER(email))');
        db.run?.("CREATE TABLE IF NOT EXISTS uploaded_files (id INTEGER PRIMARY KEY AUTOINCREMENT, original_name TEXT, stored_name TEXT, rel_path TEXT NOT NULL, size INTEGER, mime TEXT, sha256 TEXT, uploaded_at TEXT, uploaded_by TEXT)");
        db.run?.('CREATE UNIQUE INDEX IF NOT EXISTS ux_uploaded_files_sha ON uploaded_files(sha256)');
        try { db.run?.('ALTER TABLE uploaded_files ADD COLUMN source_type TEXT'); } catch {}
        try { db.run?.('ALTER TABLE uploaded_files ADD COLUMN source_url TEXT'); } catch {}
        try { db.run?.('ALTER TABLE uploaded_files ADD COLUMN driveId TEXT'); } catch {}
        try { db.run?.('ALTER TABLE uploaded_files ADD COLUMN itemId TEXT'); } catch {}
      } catch {}
    }
  });
  cached = adapter;
  return cached;
}

module.exports = { getDb };
