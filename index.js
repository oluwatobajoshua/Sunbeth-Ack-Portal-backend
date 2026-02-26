/*
  Minimal SQLite API using sql.js (pure WASM, no native build).
  - DB file: ./data/sunbeth.db (created if missing)
  - Endpoints cover app features: batches, documents, recipients, acks, progress, businesses.
*/
// Load environment variables early
try {
  require('dotenv').config();
} catch {
  /* ignore if dotenv not available */
}
const path = require('path');
const fs = require('fs');
const express = require('express');
const cors = require('cors');
const initSqlJs = require('sql.js');
const http = require('http');
const https = require('https');
// Optional outbound proxy support (for corporate networks)
let HttpsProxyAgent = null;
try {
  HttpsProxyAgent = require('https-proxy-agent');
} catch {}

// Helper: determine if hostname matches NO_PROXY list
function shouldBypassProxy(host, noProxyRaw) {
  try {
    if (!noProxyRaw) return false;
    const hostLc = String(host || '').toLowerCase();
    const parts = String(noProxyRaw)
      .split(',')
      .map((s) => s.trim().toLowerCase())
      .filter(Boolean);
    for (const p of parts) {
      if (p === '*') return true;
      if (hostLc === p) return true;
      if (p.startsWith('.') && (hostLc.endsWith(p) || hostLc === p.slice(1))) return true;
      // simple suffix match
      if (hostLc.endsWith(p)) return true;
    }
  } catch {}
  return false;
}

// Helper: get an Agent for outbound HTTP(S) based on env HTTPS_PROXY/HTTP_PROXY/NO_PROXY
function getProxyAgent(urlObj) {
  try {
    const proto = String(urlObj?.protocol || '').toLowerCase();
    const host = String(urlObj?.hostname || '').toLowerCase();
    const httpsProxy = process.env.HTTPS_PROXY || process.env.https_proxy || '';
    const httpProxy = process.env.HTTP_PROXY || process.env.http_proxy || '';
    const noProxy = process.env.NO_PROXY || process.env.no_proxy || '';
    if (shouldBypassProxy(host, noProxy)) return null;
    const proxyUrl = proto === 'https:' ? httpsProxy || httpProxy : httpProxy || httpsProxy;
    if (!proxyUrl) return null;
    if (!HttpsProxyAgent) return null; // dependency not installed; fail open
    return new HttpsProxyAgent(proxyUrl);
  } catch {
    return null;
  }
}

// Permission catalog for RBAC matrix (extendable)
const PERMISSIONS = [
  {
    key: 'viewAdmin',
    label: 'View Admin Panel',
    description: 'Access the Admin route and dashboards',
    category: 'General',
  },
  {
    key: 'manageSettings',
    label: 'Manage Settings',
    description: 'Change system settings in Admin',
    category: 'General',
  },
  {
    key: 'viewDebugLogs',
    label: 'View Debug Logs',
    description: 'Access troubleshooting console and logs',
    category: 'General',
  },
  {
    key: 'exportAnalytics',
    label: 'Export Analytics',
    description: 'Export analytics to Excel/CSV',
    category: 'Analytics',
  },
  {
    key: 'viewAnalytics',
    label: 'View Analytics',
    description: 'Access analytics dashboards',
    category: 'Analytics',
  },
  {
    key: 'createBatch',
    label: 'Create Batch',
    description: 'Create acknowledgement batches',
    category: 'Batches',
  },
  {
    key: 'editBatch',
    label: 'Edit Batch',
    description: 'Update batch metadata and content',
    category: 'Batches',
  },
  {
    key: 'deleteBatch',
    label: 'Delete Batch',
    description: 'Remove batches and related records',
    category: 'Batches',
  },
  {
    key: 'manageRecipients',
    label: 'Manage Recipients',
    description: 'Add/remove batch recipients',
    category: 'Batches',
  },
  {
    key: 'manageDocuments',
    label: 'Manage Documents',
    description: 'Add/remove documents in a batch',
    category: 'Batches',
  },
  {
    key: 'sendNotifications',
    label: 'Send Notifications',
    description: 'Send email notifications via Graph',
    category: 'Communications',
  },
  {
    key: 'uploadDocuments',
    label: 'Upload Documents',
    description: 'Upload to SharePoint libraries',
    category: 'Content',
  },
  {
    key: 'manageBusinesses',
    label: 'Manage Businesses',
    description: 'Create/edit/delete businesses',
    category: 'Data',
  },
  {
    key: 'manageRoles',
    label: 'Manage Roles',
    description: 'Add/remove Admins and Managers',
    category: 'Security',
  },
  {
    key: 'managePermissions',
    label: 'Manage Permissions',
    description: 'Edit RBAC matrix (role/user overrides)',
    category: 'Security',
  },
  {
    key: 'managePolicyOwners',
    label: 'Manage Policy Owners',
    description: 'Create/edit owners, scopes, and subscriptions for policies',
    category: 'Policies',
  },
  {
    key: 'viewOwnerDash',
    label: 'View Owner Dashboard',
    description: 'Access the policy owner dashboard and insights',
    category: 'Policies',
  },
  {
    key: 'notifyPolicyOwners',
    label: 'Notify Policy Owners',
    description: 'Send or schedule notifications to policy owners/subscribers',
    category: 'Policies',
  },
  {
    key: 'approvePolicies',
    label: 'Approve Policies',
    description: 'Approve or reject policy submissions before rollout',
    category: 'Policies',
  },
];

// Enhanced logging utility for batch operations
const createLogger = (requestId) => {
  const log = (level, operation, message, data = null) => {
    const timestamp = new Date().toISOString();
    const logEntry = {
      timestamp,
      level,
      operation,
      message,
      requestId,
      data,
    };

    const logMessage = `[${timestamp}] [${level.toUpperCase()}] [${requestId}] ${operation}: ${message}`;

    switch (level) {
      case 'error':
        console.error(logMessage, data || '');
        break;
      case 'warn':
        console.warn(logMessage, data || '');
        break;
      case 'debug':
        console.debug(logMessage, data || '');
        break;
      default:
        console.log(logMessage, data || '');
    }

    return logEntry;
  };

  return {
    info: (operation, message, data) => log('info', operation, message, data),
    warn: (operation, message, data) => log('warn', operation, message, data),
    error: (operation, message, data) => log('error', operation, message, data),
    debug: (operation, message, data) => log('debug', operation, message, data),
  };
};

// Generate unique request ID
const generateRequestId = () => {
  return Math.random().toString(36).substr(2, 9) + Date.now().toString(36);
};

const IS_SERVERLESS = !!(
  process.env.VERCEL ||
  process.env.NOW_REGION ||
  process.env.AWS_LAMBDA_FUNCTION_NAME
);
const DATA_DIR = IS_SERVERLESS ? process.env.DATA_DIR || '/tmp' : path.join(__dirname, 'data');
// In serverless, default to ephemeral file storage under /tmp for better reuse across warm invocations
// Set DB_PATH="" to force pure in-memory, or set DB_DRIVER to another provider to change persistence mode
const DB_PATH = IS_SERVERLESS
  ? (process.env.DB_PATH ?? path.join(DATA_DIR, 'sunbeth.db'))
  : path.join(DATA_DIR, 'sunbeth.db');

const PORT = process.env.PORT || 4000;
// Google Identity (frontend) ID token verification
let OAuth2Client = null;
try {
  ({ OAuth2Client } = require('google-auth-library'));
} catch {}

async function start() {
  // --- External User Auth: Password Hashing ---
  let bcrypt;
  try {
    bcrypt = require('bcrypt');
  } catch {
    try {
      bcrypt = require('bcryptjs');
    } catch {
      bcrypt = null;
    }
  }
  const BCRYPT_ROUNDS = 12;
  // --- Password Reset for External Users ---
  // In-memory store for reset tokens (for demo; use DB in production)
  const passwordResetTokens = new Map(); // email -> { token, expiresAt }
  // --- MFA (TOTP) for External Users ---
  const { authenticator } = require('otplib');
  // In-memory store for onboarding tokens (for demo; use DB in production)
  // --- Basic auth hardening helpers (rate limiting, lockouts, audit) ---
  // Per-identifier fixed-window rate limiter (simple, in-memory)
  const makeRateLimiter = (limit, windowMs) => {
    const store = new Map(); // key -> { count, windowStart }
    return {
      allow(key) {
        const k = String(key || '');
        const now = Date.now();
        const rec = store.get(k) || { count: 0, windowStart: now };
        if (now - rec.windowStart >= windowMs) {
          rec.count = 0;
          rec.windowStart = now;
        }
        rec.count += 1;
        store.set(k, rec);
        return rec.count <= limit;
      },
      getRemaining(key) {
        const rec = store.get(String(key || ''));
        return rec ? Math.max(0, limit - rec.count) : limit;
      },
    };
  };
  const limiters = {
    loginByEmail: makeRateLimiter(20, 15 * 60 * 1000), // 20 per 15m per email
    loginByIp: makeRateLimiter(100, 15 * 60 * 1000), // 100 per 15m per IP
    resetByEmail: makeRateLimiter(5, 60 * 1000), // 5 per minute per email
    resetByIp: makeRateLimiter(30, 60 * 1000), // 30 per minute per IP
    mfaByEmail: makeRateLimiter(10, 5 * 60 * 1000), // 10 per 5m per email
    mfaByIp: makeRateLimiter(60, 5 * 60 * 1000), // 60 per 5m per IP
  };
  // Simple login failure tracker for temporary lockouts
  const failedLogins = new Map(); // email -> { count, lockUntil, windowStart }
  const LOGIN_FAIL_LIMIT = 5;
  const LOGIN_FAIL_WINDOW = 15 * 60 * 1000; // 15 minutes
  const LOCKOUT_MS = 15 * 60 * 1000;
  function isLocked(email) {
    const e = String(email || '').toLowerCase();
    const rec = failedLogins.get(e);
    return !!(rec && rec.lockUntil && rec.lockUntil > Date.now());
  }
  function recordLoginFailure(email) {
    const e = String(email || '').toLowerCase();
    const now = Date.now();
    const rec = failedLogins.get(e) || { count: 0, windowStart: now, lockUntil: 0 };
    if (now - rec.windowStart >= LOGIN_FAIL_WINDOW) {
      rec.count = 0;
      rec.windowStart = now;
    }
    rec.count += 1;
    if (rec.count >= LOGIN_FAIL_LIMIT) {
      rec.lockUntil = now + LOCKOUT_MS;
    }
    failedLogins.set(e, rec);
    return rec;
  }
  function clearLoginFailures(email) {
    try {
      failedLogins.delete(String(email || '').toLowerCase());
    } catch {}
  }

  // Placeholder for moved external user routes (now relocated after app init)
  if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
  // If running on Vercel, optionally seed /tmp DB from packaged data/sunbeth.db on first cold start
  try {
    if (IS_SERVERLESS && DB_PATH) {
      const SEED_DB_PATH = path.join(__dirname, 'data', 'sunbeth.db');
      if (!fs.existsSync(DB_PATH) && fs.existsSync(SEED_DB_PATH)) {
        fs.copyFileSync(SEED_DB_PATH, DB_PATH);
      }
    }
  } catch (e) {
    try {
      console.warn('DB seed copy failed (non-fatal):', e?.message || e);
    } catch {}
  }
  // Initialize database adapter (driver-agnostic). Default: sqlite (sql.js)
  const { createDbAdapter } = require('./src/db/adapter');
  const { adapter: db } = await createDbAdapter({
    driver: process.env.DB_DRIVER || 'sqlite',
    dataDir: DATA_DIR,
    dbPath: DB_PATH,
    bootstrapSchema,
    migrateSchema,
  });

  // Ensure optional columns for Google auth exist
  try {
    const cols = allQuiet("PRAGMA table_info('external_users')", []);
    const colNames = Array.isArray(cols) ? cols.map((c) => String(c.name || c.Name || '')).filter(Boolean) : [];
    if (!colNames.includes('google_sub')) {
      try { db.run("ALTER TABLE external_users ADD COLUMN google_sub TEXT"); persist(db); } catch {}
    }
    if (!colNames.includes('provider')) {
      try { db.run("ALTER TABLE external_users ADD COLUMN provider TEXT"); persist(db); } catch {}
    }
  } catch {}

  // Utilities (move up so 'one' and 'all' are defined before use)
  const exec = (sql, params = []) => {
    try {
      db.run(sql, params);
      persist(db);
      return true;
    } catch (e) {
      console.error(e);
      return false;
    }
  };
  const all = (sql, params = []) => {
    try {
      return db.query(sql, params) || [];
    } catch (e) {
      console.error(e);
      return [];
    }
  };
  // Quiet variant that suppresses console noise for expected/optional tables
  const allQuiet = (sql, params = []) => {
    try {
      return db.query(sql, params) || [];
    } catch {
      return [];
    }
  };
  const one = (sql, params = []) => {
    const res = all(sql, params);
    if (res && typeof res.then === 'function') {
      return res.then((rows) => (Array.isArray(rows) && rows.length > 0 ? rows[0] : null));
    }
    return Array.isArray(res) && res.length > 0 ? res[0] : null;
  };

  // Precompute daily trends to avoid RTDB-wide scans
  const rebuildTrendsCache = async (windowDays = 30) => {
    const daysCount = Math.max(1, Math.min(Number(windowDays) || 30, 90));
    const dayStrings = Array.from({ length: daysCount }, (_, i) =>
      new Date(Date.now() - (daysCount - 1 - i) * 24 * 60 * 60 * 1000).toISOString().slice(0, 10)
    );
    const since = dayStrings[0];
    const completionsMap = new Map(dayStrings.map((d) => [d, 0]));
    const activeMap = new Map(dayStrings.map((d) => [d, new Set()]));
    const newBatchMap = new Map(dayStrings.map((d) => [d, 0]));

    const [acksMaybe, batchesMaybe] = [
      all('SELECT ackDate as date, email FROM acks'),
      all('SELECT startDate as date FROM batches'),
    ];
    const acks = (acksMaybe && typeof acksMaybe.then === 'function') ? await acksMaybe : acksMaybe || [];
    const batches = (batchesMaybe && typeof batchesMaybe.then === 'function') ? await batchesMaybe : batchesMaybe || [];

    for (const a of acks) {
      const dateStr = String(a.date || a.ackDate || '').slice(0, 10);
      if (!dateStr || dateStr < since) continue;
      if (!completionsMap.has(dateStr)) continue;
      completionsMap.set(dateStr, (completionsMap.get(dateStr) || 0) + 1);
      const em = String(a.email || '').toLowerCase();
      activeMap.get(dateStr)?.add(em);
    }
    for (const b of batches) {
      const dateStr = String(b.date || b.startDate || '').slice(0, 10);
      if (!dateStr || dateStr < since) continue;
      if (!newBatchMap.has(dateStr)) continue;
      newBatchMap.set(dateStr, (newBatchMap.get(dateStr) || 0) + 1);
    }

    try { db.run('DELETE FROM trends_daily WHERE date>=?', [since]); } catch {}
    for (const d of dayStrings) {
      const comps = completionsMap.get(d) || 0;
      const news = newBatchMap.get(d) || 0;
      const act = activeMap.get(d)?.size || 0;
      try { db.run('INSERT INTO trends_daily (date, completions, newBatches, activeUsers) VALUES (?, ?, ?, ?)', [d, comps, news, act]); } catch {}
    }
    return dayStrings.length;
  };

  // Simple JSON cache helpers for stats/compliance/doc-stats
  const readJsonCache = (table) => {
    try {
      const row = one(`SELECT payload FROM ${table} WHERE id=1`);
      if (row && row.payload) return JSON.parse(String(row.payload));
    } catch {}
    return null;
  };
  const writeJsonCache = (table, data) => {
    try {
      const payload = JSON.stringify(data || {});
      db.run(
        `INSERT INTO ${table} (id, payload, updatedAt) VALUES (1, ?, datetime('now'))
         ON CONFLICT(id) DO UPDATE SET payload=excluded.payload, updatedAt=excluded.updatedAt`,
        [payload]
      );
    } catch {}
  };

  // Settings helpers (simple key/value via app_settings) - defined early for use in downstream middleware/routes
  const getSetting = (k, fallback = null) => {
    try {
      const isFirebase = db && (db.driver === 'firebase' || db.driver === 'rtdb');
      const sql = isFirebase
        ? 'SELECT value FROM app_settings WHERE key=? ORDER BY updatedAt DESC LIMIT 1'
        : 'SELECT value FROM app_settings WHERE key=?';
      const r = one(sql, [String(k)]);
      return r ? r.value : fallback;
    } catch {
      return fallback;
    }
  };
  const setSetting = (k, v) => {
    try {
      db.run(
        'INSERT INTO app_settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value',
        [String(k), String(v)]
      );
      persist(db);
      return true;
    } catch {
      return false;
    }
  };
  const setSettingAsync = async (k, v) => {
    try {
      const isFirebase = db && (db.driver === 'firebase' || db.driver === 'rtdb');
      if (isFirebase) {
        try {
          await db.run('DELETE FROM app_settings WHERE key=?', [String(k)]);
        } catch { void 0; }
        await db.run('INSERT INTO app_settings (key, value) VALUES (?, ?)', [String(k), String(v)]);
        persist(db);
        return true;
      } else {
        db.run(
          'INSERT INTO app_settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value',
          [String(k), String(v)]
        );
        persist(db);
        return true;
      }
    } catch (e) {
      return false;
    }
  };
  const getSettingAsync = async (k, fallback = null) => {
    try {
      const isFirebase = db && (db.driver === 'firebase' || db.driver === 'rtdb');
      const sql = isFirebase
        ? 'SELECT value FROM app_settings WHERE key=? ORDER BY updatedAt DESC LIMIT 1'
        : 'SELECT value FROM app_settings WHERE key=?';
      const r = await one(sql, [String(k)]);
      return r ? r.value : fallback;
    } catch {
      return fallback;
    }
  };
  const isExternalSupportEnabled = () => {
    try {
      const raw = getSetting(
        'external_support_enabled',
        process.env.EXTERNAL_SUPPORT_ENABLED || '0'
      );
      const v = String(raw || '0');
      return v === '1' || v.toLowerCase() === 'true';
    } catch {
      const v = String(process.env.EXTERNAL_SUPPORT_ENABLED || '0');
      return v === '1' || v.toLowerCase() === 'true';
    }
  };
  const isExternalSupportEnabledAsync = async () => {
    try {
      const raw = await getSettingAsync(
        'external_support_enabled',
        process.env.EXTERNAL_SUPPORT_ENABLED || '0'
      );
      const v = String(raw || '0');
      return v === '1' || v.toLowerCase() === 'true';
    } catch {
      const v = String(process.env.EXTERNAL_SUPPORT_ENABLED || '0');
      return v === '1' || v.toLowerCase() === 'true';
    }
  };
  const logExternalEvent = (type, details) => {
    try {
      const fs = require('fs');
      const logPath = require('path').join(__dirname, 'backend.log.err');
      const payload = JSON.stringify(details ?? {});
      fs.appendFileSync(
        logPath,
        `\n[${new Date().toISOString()}] [EXTERNAL_${type}] ${payload}\n`
      );
    } catch {}
  };
  const parseJson = (s, d = null) => {
    try {
      return s ? JSON.parse(String(s)) : d == null ? {} : d;
    } catch {
      return d == null ? {} : d;
    }
  };
  const getTenantSettings = (tenantId) => {
    try {
      const r = one('SELECT settings_json FROM tenant_settings WHERE tenant_id=?', [tenantId]);
      return parseJson(r?.settings_json, {});
    } catch {
      return {};
    }
  };
  const setTenantSettings = (tenantId, obj) => {
    try {
      const json = JSON.stringify(obj || {});
      db.run(
        'INSERT INTO tenant_settings (tenant_id, settings_json) VALUES (?, ?) ON CONFLICT(tenant_id) DO UPDATE SET settings_json=excluded.settings_json',
        [tenantId, json]
      );
      persist(db);
      return true;
    } catch {
      return false;
    }
  };
  const listGlobalFlags = () => {
    try {
      const rows = all("SELECT key, value FROM app_settings WHERE key LIKE 'ff_%'");
      const out = {};
      for (const r of rows) {
        const v = String(r.value);
        out[r.key] = v === '1' || v.toLowerCase() === 'true';
      }
      return out;
    } catch {
      return {};
    }
  };
  const saveGlobalFlags = (flags) => {
    try {
      db.run('BEGIN');
      try {
        for (const [k, val] of Object.entries(flags || {})) {
          if (!/^ff_[a-z0-9._-]+$/i.test(k)) continue;
          const v = val ? '1' : '0';
          db.run(
            'INSERT INTO app_settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value',
            [k, v]
          );
        }
        db.run('COMMIT');
        persist(db);
        return true;
      } catch (e) {
        try {
          db.run('ROLLBACK');
        } catch {}
        return false;
      }
    } catch {
      return false;
    }
  };

  // --- Microsoft Graph (app-only) helper ---
  async function getAppGraphToken() {
    const tenantId = process.env.GRAPH_TENANT_ID || process.env.AZURE_TENANT_ID || '';
    const clientId = process.env.GRAPH_CLIENT_ID || process.env.AZURE_CLIENT_ID || '';
    const clientSecret = process.env.GRAPH_CLIENT_SECRET || process.env.AZURE_CLIENT_SECRET || '';
    if (!(tenantId && clientId && clientSecret)) {
      throw new Error('graph_creds_missing');
    }
    const tokenUrl = `https://login.microsoftonline.com/${encodeURIComponent(tenantId)}/oauth2/v2.0/token`;
    const body = new URLSearchParams();
    body.append('client_id', clientId);
    body.append('client_secret', clientSecret);
    body.append('grant_type', 'client_credentials');
    body.append('scope', 'https://graph.microsoft.com/.default');
    const agent = getProxyAgent(new URL(tokenUrl));
    const resp = await fetch(tokenUrl, { method: 'POST', body, agent });
    if (!resp.ok) throw new Error('graph_token_failed');
    return resp.json();
  }

  // --- Audit helper ---
  function audit(req, event, email, result, details) {
    try {
      const ts = new Date().toISOString();
      const ip =
        req && (req.ip || req.headers['x-forwarded-for'])
          ? String(req.ip || req.headers['x-forwarded-for'])
          : '';
      const ua = req && req.get ? String(req.get('User-Agent') || '') : '';
      const info = details ? JSON.stringify(details).slice(0, 2000) : null;
      db.run(
        'INSERT INTO audit_logs (ts, event, email, ip, ua, result, details) VALUES (?, ?, ?, ?, ?, ?, ?)',
        [ts, String(event), String(email || '').toLowerCase(), ip, ua, String(result), info]
      );
    } catch (e) {
      // non-fatal
    }
  }

  // Seed DB roles from environment (.env) for Admins/Managers (idempotent)
  try {
    const parseList = (s) =>
      String(s || '')
        .split(',')
        .map((x) => String(x).trim().toLowerCase())
        .filter((x) => x && x.includes('@'));
    const admins = parseList(process.env.REACT_APP_ADMINS);
    const managers = parseList(process.env.REACT_APP_MANAGERS);
    if (admins.length + managers.length > 0) {
      db.run('BEGIN');
      const now = new Date().toISOString();
      try {
        for (const e of admins) {
          db.run('INSERT OR IGNORE INTO roles (email, role, createdAt) VALUES (?, ?, ?)', [
            e,
            'Admin',
            now,
          ]);
        }
        for (const e of managers) {
          db.run('INSERT OR IGNORE INTO roles (email, role, createdAt) VALUES (?, ?, ?)', [
            e,
            'Manager',
            now,
          ]);
        }
        db.run('COMMIT');
        persist(db);
      } catch (e) {
        try {
          db.run('ROLLBACK');
        } catch {}
        console.warn('Env roles seed failed (non-fatal):', e?.message || e);
      }
    }
  } catch (e) {
    console.warn('Env roles parse failed (non-fatal):', e?.message || e);
  }

  // Seed default role permissions if none exist
  try {
    const has = one('SELECT COUNT(*) as c FROM role_permissions')?.c || 0;
    if (has === 0) {
      const allowAll = (keys) => Object.fromEntries(keys.map((k) => [k, 1]));
      const denyAll = (keys) => Object.fromEntries(keys.map((k) => [k, 0]));
      const keys = PERMISSIONS.map((p) => p.key);
      const adminDefaults = allowAll(keys);
      // Manager defaults: allow most, restrict destructive and security
      const managerDefaults = allowAll(keys);
      for (const k of [
        'deleteBatch',
        'manageRoles',
        'managePermissions',
        'manageSettings',
        'viewDebugLogs',
        'manageBusinesses',
      ])
        managerDefaults[k] = 0;
      const employeeDefaults = denyAll(keys);
      // Owner roles: defaults scoped for owner features
      const ownerAdminDefaults = denyAll(keys);
      ownerAdminDefaults['viewOwnerDash'] = 1;
      ownerAdminDefaults['managePolicyOwners'] = 1;
      ownerAdminDefaults['notifyPolicyOwners'] = 1;
      // HR/Admin approve
      adminDefaults['approvePolicies'] = 1;
      ownerAdminDefaults['approvePolicies'] = 0;
      managerDefaults['approvePolicies'] = 0;
      const ownerManagerDefaults = denyAll(keys);
      ownerManagerDefaults['viewOwnerDash'] = 1;
      ownerManagerDefaults['notifyPolicyOwners'] = 1;
      const seedRole = (role, mapping) => {
        for (const k of keys) {
          const v = mapping[k] ? 1 : 0;
          db.run('INSERT OR IGNORE INTO role_permissions (role, permKey, value) VALUES (?, ?, ?)', [
            role,
            k,
            v,
          ]);
        }
      };
      db.run('BEGIN');
      try {
        seedRole('Admin', adminDefaults);
        seedRole('Manager', managerDefaults);
        seedRole('Employee', employeeDefaults);
        seedRole('OwnerAdmin', ownerAdminDefaults);
        seedRole('OwnerManager', ownerManagerDefaults);
        db.run('COMMIT');
        persist(db);
      } catch (e) {
        try {
          db.run('ROLLBACK');
        } catch {}
      }
    }
    // Ensure owner roles exist in role_permissions if table already had data
    else {
      const keys = PERMISSIONS.map((p) => p.key);
      const denyAll = (ks) => Object.fromEntries(ks.map((k) => [k, 0]));
      const ownerAdminDefaults = denyAll(keys);
      ownerAdminDefaults['viewOwnerDash'] = 1;
      ownerAdminDefaults['managePolicyOwners'] = 1;
      ownerAdminDefaults['notifyPolicyOwners'] = 1;
      const ownerManagerDefaults = denyAll(keys);
      ownerManagerDefaults['viewOwnerDash'] = 1;
      ownerManagerDefaults['notifyPolicyOwners'] = 1;
      const ensureRole = (role, mapping) => {
        try {
          const cnt = one('SELECT COUNT(*) as c FROM role_permissions WHERE LOWER(role)=LOWER(?)', [
            role,
          ])?.c;
          if (Number(cnt || 0) === 0) {
            for (const k of keys) {
              const v = mapping[k] ? 1 : 0;
              db.run(
                'INSERT OR IGNORE INTO role_permissions (role, permKey, value) VALUES (?, ?, ?)',
                [role, k, v]
              );
            }
            persist(db);
          }
        } catch {}
      };
      ensureRole('OwnerAdmin', ownerAdminDefaults);
      ensureRole('OwnerManager', ownerManagerDefaults);
    }
  } catch (e) {
    console.warn('Default role-permissions seed failed (non-fatal):', e?.message || e);
  }

  const app = express();
  // Security headers (CSP, HSTS, Referrer-Policy, etc.)
  try {
    const helmet = require('helmet');
    app.use(
      helmet({
        contentSecurityPolicy: {
          useDefaults: true,
          directives: {
            ...helmet.contentSecurityPolicy.getDefaultDirectives(),
            // Adjust as needed for fonts/images; keep strict by default
            'default-src': ["'self'"],
            'img-src': ["'self'", 'data:'],
            'script-src': ["'self'"],
            'style-src': ["'self'", "'unsafe-inline'"],
            'connect-src': ["'self'"],
            'frame-ancestors': ["'none'"],
            'object-src': ["'none'"],
            'base-uri': ["'self'"],
          },
        },
        referrerPolicy: { policy: 'no-referrer' },
        crossOriginEmbedderPolicy: false, // loosen if needed for PDFs/workers
        crossOriginResourcePolicy: { policy: 'same-site' },
        hidePoweredBy: true,
        hsts: { maxAge: 31536000, includeSubDomains: true, preload: false },
      })
    );
  } catch {}
  // Gzip compression
  try {
    app.use(require('compression')());
  } catch {}
  // Strict CORS (allow-list via settings or env ALLOWED_ORIGINS = comma-separated origins)
  try {
    app.use(
      cors({
        origin: (origin, cb) => {
          try {
            const raw = String(
              getSetting('allowed_origins', process.env.ALLOWED_ORIGINS || '') || ''
            ).trim();
            const list = raw
              ? raw
                  .split(',')
                  .map((s) => s.trim())
                  .filter(Boolean)
              : [];
            if (!origin || list.length === 0) return cb(null, true); // allow same-origin or if no list set
            return cb(null, list.includes(origin));
          } catch {
            return cb(null, true);
          }
        },
        credentials: true,
        methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
        allowedHeaders: [
          'Content-Type',
          'Authorization',
          'X-Requested-With',
          'X-Admin-Email',
          'X-User-Email',
        ],
      })
    );
  } catch {
    app.use(cors());
  }
  // JSON parsing with sane limit
  app.use(express.json({ limit: '2mb' }));

  // SharePoint proxy for app-based PDF access
  try {
    const sharepointProxy = require('./api/sharepoint-proxy');
    app.use('/api/sharepoint-proxy', sharepointProxy);
  } catch (e) {
    console.error('Failed to load sharepoint-proxy:', e);
  }

  // --- External Users: Request/Response Logging Middleware ---
  // Console-log all external user requests/responses with sensitive fields redacted.
  const sanitizeExternalBody = (body) => {
    try {
      if (!body || typeof body !== 'object') return body;
      const clone = Array.isArray(body) ? [] : {};
      const sensitive = new Set([
        'password',
        'newPassword',
        'token',
        'idToken',
        'code',
        'mfaCode',
        'secret',
        'mfa_secret',
      ]);
      for (const [k, v] of Object.entries(body)) {
        if (sensitive.has(k)) {
          clone[k] = v != null ? '[REDACTED]' : v;
          continue;
        }
        if (typeof v === 'string' && v.length > 500) {
          clone[k] = `${v.slice(0, 500)}...[truncated]`;
          continue;
        }
        clone[k] = v;
      }
      return clone;
    } catch {
      return body;
    }
  };

  const externalUsersLogger = (req, res, next) => {
    try {
      const pathStr = String(req.originalUrl || req.url || '');
      if (!pathStr.startsWith('/api/external-users')) return next();
      const start = Date.now();
      const safeBody = sanitizeExternalBody(req.body || {});
      // eslint-disable-next-line no-console
      console.log('[EXTERNAL_REQ]', {
        method: req.method,
        url: req.originalUrl || req.url,
        ip: req.ip,
        query: req.query || {},
        body: safeBody,
      });
      res.on('finish', () => {
        const durationMs = Date.now() - start;
        // eslint-disable-next-line no-console
        console.log('[EXTERNAL_RES]', {
          method: req.method,
          url: req.originalUrl || req.url,
          status: res.statusCode,
          durationMs,
        });
      });
    } catch (e) {
      try {
        // eslint-disable-next-line no-console
        console.warn('externalUsersLogger failed', e?.message || e);
      } catch {}
    }
    return next();
  };

  app.use(externalUsersLogger);
  // Lightweight JSON schema validator using Ajv (per-route)
  let ajv = null;
  try {
    const Ajv = require('ajv');
    const addFormats = require('ajv-formats');
    ajv = new Ajv({ allErrors: true, removeAdditional: true, coerceTypes: true });
    try {
      addFormats(ajv);
    } catch {}
  } catch {}
  const validate =
    (schema, source = 'body') =>
    (req, res, next) => {
      try {
        if (!ajv || !schema) return next();
        const v = ajv.compile(schema);
        const data = source === 'query' ? req.query : source === 'params' ? req.params : req.body;
        if (v(data || {})) return next();
        return res
          .status(400)
          .json({ error: 'invalid_request', details: (v.errors || []).slice(0, 3) });
      } catch {
        return next();
      }
    };
  // Basic API rate limiting (custom endpoints may implement their own as well)
  try {
    const rateLimit = require('express-rate-limit');
    const limiter = rateLimit({
      windowMs: 15 * 60 * 1000,
      max: 1000,
      standardHeaders: true,
      legacyHeaders: false,
    });
    app.use('/api/', limiter);
  } catch {}

  // Request logging middleware
  app.use((req, res, next) => {
    req.requestId = generateRequestId();
    req.logger = createLogger(req.requestId);
    res.setHeader('X-Request-Id', req.requestId);

    const startTime = Date.now();
    req.logger.info('request', `${req.method} ${req.url}`, {
      ip: req.ip,
      userAgent: req.get('User-Agent'),
      contentType: req.get('Content-Type'),
    });

    // Override res.json to log responses
    const originalJson = res.json.bind(res);
    res.json = function (data) {
      const duration = Date.now() - startTime;
      req.logger.info('response', `${req.method} ${req.url} - ${res.statusCode}`, {
        duration: `${duration}ms`,
        status: res.statusCode,
        dataSize: JSON.stringify(data).length,
      });
      return originalJson(data);
    };

    // Override res.status for error logging
    const originalStatus = res.status.bind(res);
    res.status = function (code) {
      if (code >= 400) {
        const duration = Date.now() - startTime;
        req.logger.error('response', `${req.method} ${req.url} - ${code}`, {
          duration: `${duration}ms`,
          status: code,
        });
      }
      return originalStatus(code);
    };
    next();
  });

  // Tenant resolver middleware: resolve tenant by custom domain or fallback to owner
  app.use((req, _res, next) => {
    try {
      // Allow overriding host via header for proxies/tests
      const rawHost = (req.headers['x-tenant-domain'] || req.headers.host || '').toString();
      const host = rawHost.replace(/:\d+$/, '').toLowerCase();
      // 1) Match explicit custom domain
      let tenant = null;
      if (host) {
        tenant = one(
          `SELECT t.id, t.name, t.code, t.parent_id as parentId, t.is_active as isActive, t.is_owner as isOwner
           FROM tenants t
           JOIN tenant_domains d ON d.tenant_id=t.id
           WHERE LOWER(d.domain)=LOWER(?)
           LIMIT 1`,
          [host]
        );
      }
      // 2) Optional: subdomain pattern like CODE.example.com (behind a flag)
      if (!tenant) {
        const enableSubdomain = getSetting('tenant_subdomain_enabled', '0') === '1';
        const baseDomain = getSetting('tenant_base_domain', '');
        if (
          enableSubdomain &&
          host &&
          baseDomain &&
          host.endsWith(`.${baseDomain.toLowerCase()}`)
        ) {
          const sub = host.slice(0, -(baseDomain.length + 1));
          if (sub && /^[a-z0-9-_.]+$/.test(sub)) {
            tenant = one(
              `SELECT id, name, code, parent_id as parentId, is_active as isActive, is_owner as isOwner
               FROM tenants WHERE UPPER(code)=UPPER(?) LIMIT 1`,
              [sub]
            );
          }
        }
      }
      // 3) Fallback to owner tenant
      if (!tenant) {
        tenant = one(
          `SELECT id, name, code, parent_id as parentId, is_active as isActive, is_owner as isOwner FROM tenants WHERE is_owner=1 LIMIT 1`
        );
      }
      // Attach tenant + theme
      let theme = null;
      try {
        const r = one(`SELECT theme_json FROM tenant_settings WHERE tenant_id=?`, [
          tenant?.id || -1,
        ]);
        if (r && r.theme_json) {
          try {
            theme = JSON.parse(String(r.theme_json));
          } catch {
            theme = null;
          }
        }
      } catch { void 0; }
      req.tenant = tenant
        ? { ...tenant, isActive: !!tenant.isActive, isOwner: !!tenant.isOwner, domain: host, theme }
        : null;
    } catch (e) {
      req.tenant = null;
    }
    next();
  });

  // Auto-mount module routers discovered under src/modules/* if present
  let listModules = (_opts) => [];
  let _mountModules = null;
  try {
    const mod = require('./src/modules/loader');
    listModules = mod.listModules || listModules;
    _mountModules = mod.loadAndMountModules || null;
  } catch (e) {
    console.warn('[modules] loader missing:', e?.message || e);
  }
  try {
    if (_mountModules) _mountModules(app, { featureFlagGetter: getSetting });
  } catch (e) {
    console.warn('[modules] auto-mount skipped:', e?.message || e);
  }
  // Ensure owner tenant has all discovered modules enabled by default (commercially exempt)
  try {
    const owner = one('SELECT id FROM tenants WHERE is_owner=1 LIMIT 1');
    if (owner?.id) {
      const modsAtBoot = listModules({ featureFlagGetter: getSetting });
      for (const m of modsAtBoot) {
        try {
          db.run(
            'INSERT INTO tenant_modules (tenant_id, module_name, enabled) VALUES (?, ?, 1) ON CONFLICT(tenant_id, module_name) DO NOTHING',
            [owner.id, m.name]
          );
        } catch {}
      }
      persist(db);
    }
  } catch {}
  // Expose modules catalog for UI
  app.get('/api/modules', (_req, res) => {
    const mods = listModules({ featureFlagGetter: getSetting });
    res.json({ modules: mods });
  });
  // Tenant-aware modules: intersect feature flags with tenant entitlements
  app.get('/api/tenant/modules', (req, res) => {
    try {
      const mods = listModules({ featureFlagGetter: getSetting });
      const tenantId = req?.tenant?.id || null;
      if (!tenantId) return res.json({ modules: [] });
      const rows = all('SELECT module_name FROM tenant_modules WHERE tenant_id=? AND enabled=1', [
        tenantId,
      ]);
      const allowed = new Set(rows.map((r) => String(r.module_name)));
      const visible = mods.filter((m) => allowed.has(m.name)).map((m) => ({ ...m, enabled: true }));
      res.json({ modules: visible });
    } catch (e) {
      res.status(500).json({ error: 'list_failed' });
    }
  });
  // Current tenant info
  app.get('/api/tenant', (req, res) => {
    const t = req.tenant;
    if (!t) return res.status(404).json({ error: 'tenant_not_found' });
    res.json({ tenant: t });
  });
  // Super Admin Guard for /api/admin/* endpoints
  function adminGuard(req, res, next) {
    try {
      const hdr = (req.headers['x-user-email'] || req.headers['x-admin-email'] || '')
        .toString()
        .trim()
        .toLowerCase();
      const qp = (req.query && req.query.adminEmail ? String(req.query.adminEmail) : '')
        .trim()
        .toLowerCase();
      const email = hdr || qp || '';
      // Dev override: FORCE_SUPERADMIN_EMAILS allows bypass in non-prod
      try {
        const env = String(process.env.NODE_ENV || '').toLowerCase();
        if (env !== 'production') {
          const force = String(process.env.FORCE_SUPERADMIN_EMAILS || '')
            .split(',')
            .map((x) => String(x).trim().toLowerCase())
            .filter(Boolean);
          if (email && force.includes(email)) return next();
        }
      } catch {}
      const roles = resolveUserRoles(email, db);
      if (roles.includes('SuperAdmin')) return next();
      return res.status(403).json({ error: 'forbidden', reason: 'superadmin_required' });
    } catch (e) {
      return res.status(403).json({ error: 'forbidden' });
    }
  }
  app.use('/api/admin', adminGuard);

  // Super Admin: Tenants & Licensing
  app.get('/api/admin/tenants', async (_req, res) => {
    try {
      const maybeTenants = all(
        `SELECT id, name, code, is_active as isActive, is_owner as isOwner, parent_id as parentId
         FROM tenants
         ORDER BY is_owner DESC, name ASC`
      );
      const baseRows = maybeTenants && typeof maybeTenants.then === 'function' ? await maybeTenants : maybeTenants || [];
      const tenants = Array.isArray(baseRows) ? baseRows : [];

      const out = [];
      for (const r of tenants) {
        let modulesEnabled = 0;
        let activeLicenses = 0;
        try {
          const maybeM = all('SELECT COUNT(*) as c FROM tenant_modules WHERE tenant_id=? AND enabled=1', [r.id]);
          const mRows = maybeM && typeof maybeM.then === 'function' ? await maybeM : maybeM || [];
          modulesEnabled = Number((Array.isArray(mRows) && mRows[0] && (mRows[0].c ?? mRows[0].count)) || 0);
        } catch {}
        try {
          const maybeL = all("SELECT COUNT(*) as c FROM licenses WHERE tenant_id=? AND status='active'", [r.id]);
          const lRows = maybeL && typeof maybeL.then === 'function' ? await maybeL : maybeL || [];
          activeLicenses = Number((Array.isArray(lRows) && lRows[0] && (lRows[0].c ?? lRows[0].count)) || 0);
        } catch {}
        out.push({
          id: r.id,
          name: r.name,
          code: r.code,
          isActive: !!r.isActive,
          isOwner: !!r.isOwner,
          parentId: r.parentId || null,
          modulesEnabled,
          activeLicenses,
        });
      }
      res.json({ tenants: out });
    } catch (e) {
      res.status(500).json({ error: 'list_failed', details: e?.message || String(e) });
    }
  });
  app.post('/api/admin/tenants', (req, res) => {
    const { name, code, parentId = null, isActive = true, isOwner = false } = req.body || {};
    if (!name || !code) return res.status(400).json({ error: 'name_code_required' });
    try {
      db.run(
        'INSERT INTO tenants (name, code, parent_id, is_active, is_owner) VALUES (?, ?, ?, ?, ?)',
        [String(name), String(code).toUpperCase(), parentId, isActive ? 1 : 0, isOwner ? 1 : 0]
      );
      const id = one('SELECT last_insert_rowid() AS id')?.id;
      persist(db);
      res.json({ id });
    } catch (e) {
      res.status(500).json({ error: 'create_failed' });
    }
  });
  app.put('/api/admin/tenants/:id', (req, res) => {
    const id = Number(req.params.id);
    const { name, code, parentId, isActive, isOwner } = req.body || {};
    try {
      const cur = one('SELECT * FROM tenants WHERE id=?', [id]);
      if (!cur) return res.status(404).json({ error: 'not_found' });
      const next = {
        name: name != null ? String(name) : cur.name,
        code: code != null ? String(code).toUpperCase() : cur.code,
        parent_id: parentId !== undefined ? parentId : cur.parent_id,
        is_active: isActive !== undefined ? (isActive ? 1 : 0) : cur.is_active,
        is_owner: isOwner !== undefined ? (isOwner ? 1 : 0) : cur.is_owner,
      };
      db.run('UPDATE tenants SET name=?, code=?, parent_id=?, is_active=?, is_owner=? WHERE id=?', [
        next.name,
        next.code,
        next.parent_id,
        next.is_active,
        next.is_owner,
        id,
      ]);
      persist(db);
      res.json({ ok: true });
    } catch (e) {
      res.status(500).json({ error: 'update_failed' });
    }
  });
  // Tenant module entitlements
  app.get('/api/admin/tenants/:id/modules', (req, res) => {
    try {
      const tenantId = Number(req.params.id);
      const mods = listModules({ featureFlagGetter: getSetting });
      const rows = all('SELECT module_name, enabled FROM tenant_modules WHERE tenant_id=?', [
        tenantId,
      ]);
      const byName = new Map(rows.map((r) => [r.module_name, !!r.enabled]));
      const merged = mods.map((m) => ({
        ...m,
        enabled: byName.has(m.name) ? Boolean(byName.get(m.name)) : false,
      }));
      res.json({ modules: merged });
    } catch (e) {
      res.status(500).json({ error: 'list_failed' });
    }
  });
  app.put('/api/admin/tenants/:id/modules', (req, res) => {
    try {
      const tenantId = Number(req.params.id);
      const { module, enabled } = req.body || {};
      if (!module || typeof enabled !== 'boolean')
        return res.status(400).json({ error: 'module_and_enabled_required' });
      db.run(
        'INSERT INTO tenant_modules (tenant_id, module_name, enabled) VALUES (?, ?, ?) ON CONFLICT(tenant_id, module_name) DO UPDATE SET enabled=excluded.enabled',
        [tenantId, String(module), enabled ? 1 : 0]
      );
      persist(db);
      res.json({ ok: true });
    } catch (e) {
      res.status(500).json({ error: 'save_failed' });
    }
  });
  // Tenant licenses
  app.get('/api/admin/tenants/:id/licenses', (req, res) => {
    try {
      const tenantId = Number(req.params.id);
      const rows = all(
        'SELECT id, plan, seats, status, is_free as isFree, valid_from as validFrom, valid_to as validTo FROM licenses WHERE tenant_id=? ORDER BY created_at DESC',
        [tenantId]
      );
      res.json({
        licenses: rows.map((r) => ({
          id: r.id,
          plan: r.plan,
          seats: r.seats,
          status: r.status,
          isFree: !!r.isFree,
          validFrom: r.validFrom,
          validTo: r.validTo,
        })),
      });
    } catch (e) {
      res.status(500).json({ error: 'list_failed' });
    }
  });
  app.post('/api/admin/tenants/:id/licenses', (req, res) => {
    try {
      const tenantId = Number(req.params.id);
      const {
        plan,
        seats = 0,
        status = 'active',
        isFree = false,
        validFrom = null,
        validTo = null,
      } = req.body || {};
      db.run(
        'INSERT INTO licenses (tenant_id, plan, seats, status, is_free, valid_from, valid_to) VALUES (?, ?, ?, ?, ?, ?, ?)',
        [
          tenantId,
          plan || null,
          Number(seats) || 0,
          String(status),
          isFree ? 1 : 0,
          validFrom,
          validTo,
        ]
      );
      const id = one('SELECT last_insert_rowid() as id')?.id;
      persist(db);
      res.json({ id });
    } catch (e) {
      res.status(500).json({ error: 'create_failed' });
    }
  });
  // Theme catalog admin
  const parseTheme = (obj) => {
    const safe = (x) => (x && typeof x === 'object' ? x : {});
    return { light: safe(obj?.light), dark: safe(obj?.dark) };
  };
  app.get('/api/admin/themes', (_req, res) => {
    try {
      const rows = all(
        'SELECT id, name, description, base_theme_id as baseThemeId, is_system as isSystem, created_at as createdAt, updated_at as updatedAt FROM themes ORDER BY is_system DESC, name ASC'
      );
      res.json({
        themes: rows.map((r) => ({
          id: r.id,
          name: r.name,
          description: r.description,
          baseThemeId: r.baseThemeId,
          isSystem: !!r.isSystem,
          createdAt: r.createdAt,
          updatedAt: r.updatedAt,
        })),
      });
    } catch {
      res.status(500).json({ error: 'list_failed' });
    }
  });
  app.post('/api/admin/themes', (req, res) => {
    try {
      const {
        name,
        description = null,
        light = null,
        dark = null,
        baseThemeId = null,
      } = req.body || {};
      const n = String(name || '').trim();
      if (!n) return res.status(400).json({ error: 'name_required' });
      const now = new Date().toISOString();
      db.run(
        'INSERT INTO themes (name, description, light_json, dark_json, base_theme_id, is_system, created_at, updated_at) VALUES (?, ?, ?, ?, ?, 0, ?, ?)',
        [
          n,
          description,
          light ? JSON.stringify(light) : null,
          dark ? JSON.stringify(dark) : null,
          baseThemeId,
          now,
          now,
        ]
      );
      const id = one('SELECT last_insert_rowid() as id')?.id;
      persist(db);
      res.json({ id });
    } catch {
      res.status(500).json({ error: 'create_failed' });
    }
  });
  app.get('/api/admin/themes/:id', (req, res) => {
    try {
      const id = Number(req.params.id);
      const r = one(
        'SELECT id, name, description, light_json, dark_json, base_theme_id as baseThemeId, is_system as isSystem, created_at as createdAt, updated_at as updatedAt FROM themes WHERE id=?',
        [id]
      );
      if (!r) return res.status(404).json({ error: 'not_found' });
      res.json({
        id: r.id,
        name: r.name,
        description: r.description,
        baseThemeId: r.baseThemeId,
        isSystem: !!r.isSystem,
        createdAt: r.createdAt,
        updatedAt: r.updatedAt,
        light: r.light_json ? JSON.parse(r.light_json) : null,
        dark: r.dark_json ? JSON.parse(r.dark_json) : null,
      });
    } catch {
      res.status(500).json({ error: 'load_failed' });
    }
  });
  app.put('/api/admin/themes/:id', (req, res) => {
    try {
      const id = Number(req.params.id);
      const { name, description, light, dark } = req.body || {};
      const cur = one('SELECT id FROM themes WHERE id=?', [id]);
      if (!cur) return res.status(404).json({ error: 'not_found' });
      const now = new Date().toISOString();
      db.run(
        'UPDATE themes SET name=COALESCE(?, name), description=COALESCE(?, description), light_json=COALESCE(?, light_json), dark_json=COALESCE(?, dark_json), updated_at=? WHERE id=?',
        [
          name || null,
          description || null,
          light ? JSON.stringify(light) : null,
          dark ? JSON.stringify(dark) : null,
          now,
          id,
        ]
      );
      persist(db);
      res.json({ ok: true });
    } catch {
      res.status(500).json({ error: 'update_failed' });
    }
  });
  app.delete('/api/admin/themes/:id', (req, res) => {
    try {
      const id = Number(req.params.id);
      db.run('DELETE FROM themes WHERE id=? AND is_system=0', [id]);
      persist(db);
      res.json({ ok: true });
    } catch {
      res.status(500).json({ error: 'delete_failed' });
    }
  });
  app.post('/api/admin/themes/:id/clone', (req, res) => {
    try {
      const id = Number(req.params.id);
      const src = one('SELECT name, description, light_json, dark_json FROM themes WHERE id=?', [
        id,
      ]);
      if (!src) return res.status(404).json({ error: 'not_found' });
      const name = String(req.body?.name || `${src.name} Copy`).trim();
      const now = new Date().toISOString();
      db.run(
        'INSERT INTO themes (name, description, light_json, dark_json, base_theme_id, is_system, created_at, updated_at) VALUES (?, ?, ?, ?, ?, 0, ?, ?)',
        [name, src.description, src.light_json, src.dark_json, id, now, now]
      );
      const newId = one('SELECT last_insert_rowid() as id')?.id;
      persist(db);
      res.json({ id: newId });
    } catch {
      res.status(500).json({ error: 'clone_failed' });
    }
  });
  // Theme assignments admin
  app.get('/api/admin/theme-assignments', (req, res) => {
    try {
      const targetType = String(req.query.targetType || '').trim();
      const targetId = req.query.targetId != null ? String(req.query.targetId) : null;
      const rows = targetType
        ? all(
            'SELECT ta.id, ta.theme_id as themeId, ta.target_type as targetType, ta.target_id as targetId, ta.enabled, t.name as themeName FROM theme_assignments ta JOIN themes t ON t.id=ta.theme_id WHERE ta.target_type=? AND (ta.target_id IS ? OR ta.target_id=?)',
            [targetType, targetId, targetId]
          )
        : all(
            'SELECT ta.id, ta.theme_id as themeId, ta.target_type as targetType, ta.target_id as targetId, ta.enabled, t.name as themeName FROM theme_assignments ta JOIN themes t ON t.id=ta.theme_id ORDER BY ta.id DESC'
          );
      res.json({
        assignments: rows.map((r) => ({
          id: r.id,
          themeId: r.themeId,
          themeName: r.themeName,
          targetType: r.targetType,
          targetId: r.targetId,
          enabled: !!r.enabled,
        })),
      });
    } catch {
      res.status(500).json({ error: 'list_failed' });
    }
  });
  app.get('/api/theme/effective', async (req, res) => {
    try {
      const tenantId = req?.tenant?.id || null;
      const module = String(req.query.module || '').trim();
      const plugin = String(req.query.plugin || '').trim();
      let light = defaultLight();
      let dark = defaultDark();
      const dev = String(process.env.NODE_ENV || '').toLowerCase() !== 'production';

      // Helper: await-if-promise and normalize to array
      const toRows = async (maybe) => {
        try {
          const v = maybe && typeof maybe.then === 'function' ? await maybe : maybe;
          return Array.isArray(v) ? v : [];
        } catch {
          return [];
        }
      };
      const overlayThemeById = (themeId) => {
        try {
          if (themeId == null) return;
          const thr = one('SELECT light_json, dark_json FROM themes WHERE id=?', [themeId]);
          const l = safeParse(thr?.light_json);
          const d = safeParse(thr?.dark_json);
          if (l) light = deepMerge(light, l);
          if (d) dark = deepMerge(dark, d);
        } catch (e) {
          try {
            req.logger && req.logger.warn('theme_effective.overlay_error', String(e?.message || e));
          } catch {}
        }
      };

      // 1) Global
      const rowsGlobal = await toRows(
        all(
          'SELECT theme_id FROM theme_assignments WHERE target_type=? AND (target_id IS NULL OR target_id="") AND enabled=1',
          ['global']
        )
      );
      for (const r of rowsGlobal) overlayThemeById(r.theme_id);

      // 2) Tenant (or fallback legacy tenant_settings if no explicit tenant assignment)
      if (tenantId != null) {
        const tenantRows = await toRows(
          all(
            'SELECT theme_id FROM theme_assignments WHERE target_type=? AND target_id=? AND enabled=1',
            ['tenant', String(tenantId)]
          )
        );
        if (tenantRows.length > 0) {
          for (const r of tenantRows) overlayThemeById(r.theme_id);
        } else {
          // Fallback to legacy tenant theme JSON if no explicit assignment exists
          const ts = one('SELECT theme_json FROM tenant_settings WHERE tenant_id=?', [tenantId]);
          const t = safeParse(ts?.theme_json);
          if (t) {
            light = deepMerge(light, t);
          }
        }
      }

      // 3) Plugin
      if (plugin) {
        const rowsPlugin = await toRows(
          all(
            'SELECT theme_id FROM theme_assignments WHERE target_type=? AND target_id=? AND enabled=1',
            ['plugin', plugin]
          )
        );
        for (const r of rowsPlugin) overlayThemeById(r.theme_id);
      }

      // 4) Module (highest precedence)
      if (module) {
        const rowsModule = await toRows(
          all(
            'SELECT theme_id FROM theme_assignments WHERE target_type=? AND target_id=? AND enabled=1',
            ['module', module]
          )
        );
        for (const r of rowsModule) overlayThemeById(r.theme_id);
      }

      return res.json({ theme: { light, dark } });
    } catch (e) {
      try {
        req.logger && req.logger.error('theme_effective.error', String(e?.message || e));
      } catch {}
      const dev = String(process.env.NODE_ENV || '').toLowerCase() !== 'production';
      res
        .status(500)
        .json({ error: 'resolve_failed', message: dev ? String(e?.message || e) : undefined });
    }
  });

  app.get('/api/admin/roles', (req, res) => {
    try {
      const rows = all('SELECT email, role FROM roles ORDER BY email, role');
      const map = new Map();
      for (const r of rows) {
        const e = String(r.email || '')
          .trim()
          .toLowerCase();
        if (!e) continue;
        if (!map.has(e)) map.set(e, { email: e, roles: [] });
        map.get(e).roles.push(r.role);
      }
      res.json({ users: Array.from(map.values()) });
    } catch (e) {
      res.status(500).json({ error: 'list_failed' });
    }
  });
  app.post('/api/admin/roles', (req, res) => {
    try {
      const { email, role } = req.body || {};
      const e = String(email || '')
        .trim()
        .toLowerCase();
      const r = String(role || '').trim();
      if (!e || !e.includes('@') || !r) return res.status(400).json({ error: 'invalid_payload' });
      const now = new Date().toISOString();
      db.run('INSERT OR IGNORE INTO roles (email, role, createdAt) VALUES (?, ?, ?)', [e, r, now]);
      persist(db);
      res.json({ ok: true });
    } catch (e) {
      res.status(500).json({ error: 'save_failed' });
    }
  });
  app.delete('/api/admin/roles', (req, res) => {
    try {
      const e = String(req.query.email || req.body?.email || '')
        .trim()
        .toLowerCase();
      const r = String(req.query.role || req.body?.role || '').trim();
      if (!e || !e.includes('@') || !r) return res.status(400).json({ error: 'invalid_payload' });
      db.run('DELETE FROM roles WHERE LOWER(email)=LOWER(?) AND role=?', [e, r]);
      persist(db);
      res.json({ ok: true });
    } catch (e) {
      res.status(500).json({ error: 'delete_failed' });
    }
  });

  // Super Admin: Global settings management (safe, non-secret)
  const SETTINGS_WHITELIST = new Set([
    'external_support_enabled',
    'allowed_origins',
    'tenant_base_domain',
    'tenant_subdomain_enabled',
    'frontend_base_url',
    // SharePoint settings (admin-configured)
    'sharepoint_site_name',
    'sharepoint_library_name',
  ]);
  app.get('/api/admin/settings', (_req, res) => {
    try {
      const rows = all('SELECT key, value FROM app_settings');
      const out = {};
      for (const r of rows) {
        const k = String(r.key);
        if (!SETTINGS_WHITELIST.has(k)) continue;
        let v = r.value;
        if (k.endsWith('_enabled')) v = String(v) === '1' || String(v).toLowerCase() === 'true';
        out[k] = v;
      }
      res.json({ settings: out });
    } catch (e) {
      res.status(500).json({ error: 'list_failed' });
    }
  });
  app.put('/api/admin/settings', (req, res) => {
    try {
      const payload = req.body && req.body.settings ? req.body.settings : req.body;
      if (!payload || typeof payload !== 'object')
        return res.status(400).json({ error: 'invalid_payload' });
      db.run('BEGIN');
      try {
        for (const [k, val] of Object.entries(payload)) {
          if (!SETTINGS_WHITELIST.has(k)) continue;
          const v = k.endsWith('_enabled') ? (val ? '1' : '0') : String(val ?? '');
          db.run(
            'INSERT INTO app_settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value',
            [k, v]
          );
        }
        db.run('COMMIT');
        persist(db);
      } catch (e) {
        try {
          db.run('ROLLBACK');
        } catch {}
        throw e;
      }
      res.json({ ok: true });
    } catch (e) {
      res.status(500).json({ error: 'save_failed' });
    }
  });

  // Effective theme resolution
  function deepMerge(a, b) {
    if (!a) return b;
    if (!b) return a;
    const out = Array.isArray(a) ? [...a] : { ...a };
    for (const [k, v] of Object.entries(b)) {
      if (v && typeof v === 'object' && !Array.isArray(v)) {
        out[k] = deepMerge(out[k] || {}, v);
      } else {
        out[k] = v;
      }
    }
    return out;
  }
  function safeParse(json) {
    try {
      return json ? JSON.parse(String(json)) : null;
    } catch {
      return null;
    }
  }
  function defaultLight() {
    return {
      cssVars: {
        '--primary': '#0c5343',
        '--accent': '#f64500',
        '--bg': '#f7f8fa',
        '--bg-elevated': '#ffffff',
        '--card': '#ffffff',
        '--muted': '#6b6b6b',
      },
    };
  }
  function defaultDark() {
    return {
      cssVars: {
        '--bg': '#111a17',
        '--bg-elevated': '#16211d',
        '--card': '#182520',
        '--muted': '#a5b2ad',
      },
      darkMode: true,
    };
  }
  app.get('/api/theme/effective', (req, res) => {
    try {
      const tenantId = req?.tenant?.id || null;
      const module = String(req.query.module || '').trim();
      const plugin = String(req.query.plugin || '').trim();
      let light = defaultLight();
      let dark = defaultDark();
      // Intended precedence: module > plugin > tenant > global
      // Implementation note: later overlays win, so apply in reverse order: global -> tenant -> plugin -> module
      const overlayThemeById = (themeId) => {
        const thr = one('SELECT light_json, dark_json FROM themes WHERE id=?', [themeId]);
        const l = safeParse(thr?.light_json);
        const d = safeParse(thr?.dark_json);
        if (l) light = deepMerge(light, l);
        if (d) dark = deepMerge(dark, d);
      };

      // 1) Global
      const rowsGlobal = all(
        'SELECT theme_id FROM theme_assignments WHERE target_type=? AND (target_id IS NULL OR target_id="") AND enabled=1',
        ['global']
      );
      for (const r of rowsGlobal) overlayThemeById(r.theme_id);

      // 2) Tenant (or fallback legacy tenant_settings if no explicit tenant assignment)
      if (tenantId != null) {
        const tenantRows = all(
          'SELECT theme_id FROM theme_assignments WHERE target_type=? AND target_id=? AND enabled=1',
          ['tenant', String(tenantId)]
        );
        if (tenantRows.length > 0) {
          for (const r of tenantRows) overlayThemeById(r.theme_id);
        } else {
          // Fallback to legacy tenant theme JSON if no explicit assignment exists
          const ts = one('SELECT theme_json FROM tenant_settings WHERE tenant_id=?', [tenantId]);
          const t = safeParse(ts?.theme_json);
          if (t) {
            light = deepMerge(light, t);
          }
        }
      }

      // 3) Plugin
      if (plugin) {
        const rowsPlugin = all(
          'SELECT theme_id FROM theme_assignments WHERE target_type=? AND target_id=? AND enabled=1',
          ['plugin', plugin]
        );
        for (const r of rowsPlugin) overlayThemeById(r.theme_id);
      }

      // 4) Module (highest precedence)
      if (module) {
        const rowsModule = all(
          'SELECT theme_id FROM theme_assignments WHERE target_type=? AND target_id=? AND enabled=1',
          ['module', module]
        );
        for (const r of rowsModule) overlayThemeById(r.theme_id);
      }

      return res.json({ theme: { light, dark } });
    } catch (e) {
      res.status(500).json({ error: 'resolve_failed' });
    }
  });
  // Effective flags for current tenant
  app.get('/api/flags/effective', (req, res) => {
    try {
      const tenantId = req?.tenant?.id || null;
      const globalFlags = listGlobalFlags();
      let flags = { ...globalFlags };
      if (tenantId != null) {
        const s = getTenantSettings(tenantId);
        if (s && s.flags && typeof s.flags === 'object') {
          flags = { ...flags, ...s.flags };
        }
      }
      res.json({ flags });
    } catch {
      res.status(500).json({ error: 'resolve_failed' });
    }
  });
  // Tenant domains admin
  app.get('/api/admin/tenants/:id/domains', (req, res) => {
    try {
      const tenantId = Number(req.params.id);
      const rows = all(
        'SELECT id, domain, is_primary as isPrimary, verified, added_at as addedAt FROM tenant_domains WHERE tenant_id=? ORDER BY is_primary DESC, domain ASC',
        [tenantId]
      );
      res.json({
        domains: rows.map((r) => ({
          id: r.id,
          domain: r.domain,
          isPrimary: !!r.isPrimary,
          verified: !!r.verified,
          addedAt: r.addedAt,
        })),
      });
    } catch {
      res.status(500).json({ error: 'list_failed' });
    }
  });
  app.post('/api/admin/tenants/:id/domains', (req, res) => {
    try {
      const tenantId = Number(req.params.id);
      const { domain, isPrimary = false } = req.body || {};
      if (!domain || !/^[a-z0-9.-]+$/i.test(String(domain)))
        return res.status(400).json({ error: 'invalid_domain' });
      const now = new Date().toISOString();
      db.run(
        'INSERT INTO tenant_domains (tenant_id, domain, is_primary, verified, added_at) VALUES (?, ?, ?, 0, ?)',
        [tenantId, String(domain).toLowerCase(), isPrimary ? 1 : 0, now]
      );
      // Ensure only one primary
      if (isPrimary)
        db.run(
          'UPDATE tenant_domains SET is_primary=0 WHERE tenant_id=? AND LOWER(domain)<>LOWER(?)',
          [tenantId, String(domain).toLowerCase()]
        );
      const id = one('SELECT last_insert_rowid() as id')?.id;
      persist(db);
      res.json({ id });
    } catch (e) {
      res.status(500).json({ error: 'create_failed' });
    }
  });
  app.delete('/api/admin/tenants/:id/domains/:domainId', (req, res) => {
    try {
      const tenantId = Number(req.params.id);
      const domainId = Number(req.params.domainId);
      db.run('DELETE FROM tenant_domains WHERE tenant_id=? AND id=?', [tenantId, domainId]);
      persist(db);
      res.json({ ok: true });
    } catch {
      res.status(500).json({ error: 'delete_failed' });
    }
  });
  // Tenant theme admin
  app.get('/api/admin/tenants/:id/theme', (req, res) => {
    try {
      const tenantId = Number(req.params.id);
      const r = one('SELECT theme_json FROM tenant_settings WHERE tenant_id=?', [tenantId]);
      const theme = r?.theme_json
        ? (function () {
            try {
              return JSON.parse(String(r.theme_json));
            } catch {
              return null;
            }
          })()
        : null;
      res.json({ theme });
    } catch {
      res.status(500).json({ error: 'load_failed' });
    }
  });
  app.put('/api/admin/tenants/:id/theme', (req, res) => {
    try {
      const tenantId = Number(req.params.id);
      const theme = req.body?.theme || req.body || {};
      const json = JSON.stringify(theme || {});
      db.run(
        'INSERT INTO tenant_settings (tenant_id, theme_json) VALUES (?, ?) ON CONFLICT(tenant_id) DO UPDATE SET theme_json=excluded.theme_json',
        [tenantId, json]
      );
      persist(db);
      res.json({ ok: true });
    } catch {
      res.status(500).json({ error: 'save_failed' });
    }
  });
  // (end modules section)

  // --- External User Helpers & Routes ---
  const multer = require('multer');
  const upload = multer({ storage: multer.memoryStorage() });
  const csvParse = require('csv-parse/sync');
  const crypto = require('crypto');
  const mime = require('mime-types');
  // In-memory store for onboarding tokens (for demo; use DB in production)
  const onboardingTokens = new Map(); // email -> { token, expiresAt }
  // Onboarding email helper (via Nodemailer if configured)
  const mailer = (function () {
    try {
      return require('./src/services/mailer');
    } catch {
      return null;
    }
  })();
  async function sendOnboardingEmail(email, name, link) {
    try {
      try {
        const fs = require('fs');
        const logPath = require('path').join(__dirname, 'backend.log.err');
        fs.appendFileSync(
          logPath,
          `\n[${new Date().toISOString()}] [EXTERNAL_EMAIL_ATTEMPT] to=${String(
            email || ''
          )} name=${String(name || '')} link=${String(link || '')}\n`
        );
      } catch {}
      if (mailer && typeof mailer.sendOnboardingEmail === 'function') {
        await mailer.sendOnboardingEmail(email, name, link);
      } else {
        // eslint-disable-next-line no-console
        console.log(`[ONBOARDING EMAIL:FALLBACK] To: ${email}, Name: ${name}, Link: ${link}`);
      }
    } catch (e) {
      // eslint-disable-next-line no-console
      console.warn('sendOnboardingEmail failed; falling back to log', e?.message || e);
      try {
        const fs = require('fs');
        const logPath = require('path').join(__dirname, 'backend.log.err');
        fs.appendFileSync(
          logPath,
          `\n[${new Date().toISOString()}] [EXTERNAL_EMAIL_ERROR] to=${String(
            email || ''
          )} reason=${String(e?.message || e)}\n`
        );
      } catch {}
      // eslint-disable-next-line no-console
      console.log(`[ONBOARDING EMAIL:FALLBACK] To: ${email}, Name: ${name}, Link: ${link}`);
    }
  }

  app.get('/api/external-users/search', async (req, res) => {
    if (!(await isExternalSupportEnabledAsync()))
      return res.status(404).json({ error: 'not_found' });
    try {
      const q = (req.query.q || '').toString().trim().toLowerCase();
      let sql =
        'SELECT id, email, name, phone, department, business_id, status, created_at, last_login, mfa_enabled FROM external_users';
      let params = [];
      if (q) {
        sql += ' WHERE LOWER(email) LIKE ? OR LOWER(name) LIKE ? OR LOWER(phone) LIKE ?';
        params = [`%${q}%`, `%${q}%`, `%${q}%`];
      }
      sql += ' ORDER BY created_at DESC LIMIT 100';
      const rows = all(sql, params);
      res.json({ users: rows });
    } catch (e) {
      res.status(500).json({ error: 'search_failed', details: e.message });
    }
  });

  app.post('/api/external-users/request-reset', async (req, res) => {
    if (!(await isExternalSupportEnabledAsync()))
      return res.status(404).json({ error: 'not_found' });
    try {
      const { email } = req.body || {};
      if (!email) return res.status(400).json({ error: 'missing_email' });
      // Rate limiting by email and IP
      const ip = req.ip;
      if (
        !limiters.resetByEmail.allow(String(email).toLowerCase()) ||
        !limiters.resetByIp.allow(ip)
      ) {
        audit(req, 'password_reset_request', email, 'rate_limited', null);
        return res.status(429).json({ error: 'rate_limited' });
      }
      const user = one('SELECT * FROM external_users WHERE LOWER(email)=LOWER(?)', [
        String(email).trim().toLowerCase(),
      ]);
      if (!user) {
        audit(req, 'password_reset_request', email, 'not_found', null);
        return res.status(404).json({ error: 'user_not_found' });
      }
      const token = crypto.randomBytes(32).toString('hex');
      const expiresAt = Date.now() + 1000 * 60 * 60; // 1 hour
      passwordResetTokens.set(String(email).trim().toLowerCase(), { token, expiresAt });
      const baseUrl =
        getSetting('frontend_base_url', process.env.FRONTEND_BASE_URL || '') ||
        (req.headers.origin && String(req.headers.origin)) ||
        'http://localhost:3000';
      const link = `${String(baseUrl).replace(/\/$/, '')}/reset-password?email=${encodeURIComponent(
        email
      )}&token=${token}`;
      await sendOnboardingEmail(email, user.name || '', link);
      audit(req, 'password_reset_request', email, 'sent', null);
      return res.json({ ok: true });
    } catch (e) {
      try {
        audit(req, 'password_reset_request', req?.body?.email, 'error', { message: e.message });
      } catch {}
      res.status(500).json({ error: 'request_reset_failed', details: e.message });
    }
  });

  app.post('/api/external-users/reset-password', async (req, res) => {
    if (!(await isExternalSupportEnabledAsync()))
      return res.status(404).json({ error: 'not_found' });
    try {
      const { email, token, password } = req.body || {};
      if (!email || !token || !password) return res.status(400).json({ error: 'missing_fields' });
      const rec = passwordResetTokens.get(String(email).trim().toLowerCase());
      if (!rec || rec.token !== token || Date.now() > rec.expiresAt) {
        audit(req, 'password_reset', email, 'invalid_or_expired', null);
        return res.status(400).json({ error: 'invalid_or_expired_token' });
      }
      if (!/^.{8,}$/.test(password) || !/[A-Za-z]/.test(password) || !/\d/.test(password)) {
        audit(req, 'password_reset', email, 'weak_password', null);
        return res.status(400).json({ error: 'weak_password' });
      }
      const hash = await bcrypt.hash(password, BCRYPT_ROUNDS);
      db.run('UPDATE external_users SET password_hash=?, status=? WHERE LOWER(email)=LOWER(?)', [
        hash,
        'active',
        email,
      ]);
      passwordResetTokens.delete(String(email).trim().toLowerCase());
      audit(req, 'password_reset', email, 'ok', null);
      return res.json({ ok: true });
    } catch (e) {
      try {
        audit(req, 'password_reset', req?.body?.email, 'error', { message: e.message });
      } catch {}
      res.status(500).json({ error: 'reset_password_failed', details: e.message });
    }
  });

  app.post('/api/external-users/mfa/setup', async (req, res) => {
    if (!(await isExternalSupportEnabledAsync()))
      return res.status(404).json({ error: 'not_found' });
    const { email } = req.body || {};
    if (!email) return res.status(400).json({ error: 'missing_email' });
    const user = one('SELECT * FROM external_users WHERE LOWER(email)=LOWER(?)', [
      String(email).trim().toLowerCase(),
    ]);
    if (!user) {
      audit(req, 'mfa_setup', email, 'user_not_found', null);
      return res.status(404).json({ error: 'user_not_found' });
    }
    const secret = authenticator.generateSecret();
    const otpauth = authenticator.keyuri(email, 'Sunbeth', secret);
    db.run('UPDATE external_users SET mfa_secret=? WHERE id=?', [secret, user.id]);
    audit(req, 'mfa_setup', email, 'ok', null);
    return res.json({ secret, otpauth });
  });

  app.post('/api/external-users/mfa/verify', async (req, res) => {
    if (!(await isExternalSupportEnabledAsync()))
      return res.status(404).json({ error: 'not_found' });
    const { email, code } = req.body || {};
    if (!email || !code) return res.status(400).json({ error: 'missing_fields' });
    const ip = req.ip;
    if (!limiters.mfaByEmail.allow(String(email).toLowerCase()) || !limiters.mfaByIp.allow(ip)) {
      return res.status(429).json({ error: 'rate_limited' });
    }
    const user = one('SELECT * FROM external_users WHERE LOWER(email)=LOWER(?)', [
      String(email).trim().toLowerCase(),
    ]);
    if (!user || !user.mfa_secret) {
      audit(req, 'mfa_verify', email, 'user_or_secret_not_found', null);
      return res.status(404).json({ error: 'user_or_secret_not_found' });
    }
    const valid = authenticator.check(code, user.mfa_secret);
    if (!valid) {
      audit(req, 'mfa_verify', email, 'invalid_code', null);
      return res.status(401).json({ error: 'invalid_code' });
    }
    db.run('UPDATE external_users SET mfa_enabled=1 WHERE id=?', [user.id]);
    audit(req, 'mfa_verify', email, 'ok', null);
    return res.json({ ok: true });
  });

  app.post('/api/external-users/mfa/disable', async (req, res) => {
    if (!(await isExternalSupportEnabledAsync()))
      return res.status(404).json({ error: 'not_found' });
    const { email } = req.body || {};
    if (!email) return res.status(400).json({ error: 'missing_email' });
    const user = one('SELECT * FROM external_users WHERE LOWER(email)=LOWER(?)', [
      String(email).trim().toLowerCase(),
    ]);
    if (!user) {
      audit(req, 'mfa_disable', email, 'user_not_found', null);
      return res.status(404).json({ error: 'user_not_found' });
    }
    db.run('UPDATE external_users SET mfa_enabled=0, mfa_secret=NULL WHERE id=?', [user.id]);
    audit(req, 'mfa_disable', email, 'ok', null);
    return res.json({ ok: true });
  });

  app.post('/api/external-users/login', async (req, res) => {
    // Validate request
    try {
      const Ajv = require('ajv');
      const addFormats = require('ajv-formats');
      const ajv = new Ajv({ allErrors: true, removeAdditional: true });
      addFormats(ajv);
      const schema = {
        type: 'object',
        required: ['email', 'password'],
        additionalProperties: false,
        properties: {
          email: { type: 'string', format: 'email' },
          password: { type: 'string', minLength: 8 },
        },
      };
      const valid = ajv.validate(schema, req.body || {});
      if (!valid) return res.status(400).json({ error: 'invalid_request', details: ajv.errors });
    } catch {}
    if (!(await isExternalSupportEnabledAsync()))
      return res.status(404).json({ error: 'not_found' });
    try {
      const { email, password } = req.body || {};
      if (!email || !password) return res.status(400).json({ error: 'missing_fields' });
      const ip = req.ip;
      // Lockout check
      if (isLocked(email)) {
        audit(req, 'login', email, 'locked', null);
        return res.status(429).json({ error: 'account_locked_temp' });
      }
      // Rate limit by email and IP
      if (
        !limiters.loginByEmail.allow(String(email).toLowerCase()) ||
        !limiters.loginByIp.allow(ip)
      ) {
        audit(req, 'login', email, 'rate_limited', null);
        return res.status(429).json({ error: 'rate_limited' });
      }
      const user = one('SELECT * FROM external_users WHERE LOWER(email)=LOWER(?)', [
        String(email).trim().toLowerCase(),
      ]);
      if (!user) {
        recordLoginFailure(email);
        audit(req, 'login', email, 'invalid_user', null);
        return res.status(401).json({ error: 'invalid_credentials' });
      }
      if (!user.password_hash)
        return res.status(403).json({ error: 'password_not_set', onboarding: true });
      const match = await bcrypt.compare(password, user.password_hash);
      if (!match) {
        const rec = recordLoginFailure(email);
        audit(
          req,
          'login',
          email,
          rec?.lockUntil && rec.lockUntil > Date.now() ? 'locked' : 'invalid_password',
          null
        );
        return res.status(401).json({ error: 'invalid_credentials' });
      }
      // Success: clear failures
      clearLoginFailures(email);
      if (user.mfa_enabled) {
        audit(req, 'login', email, 'mfa_required', null);
        return res.json({ mfaRequired: true });
      }
      db.run('UPDATE external_users SET last_login=? WHERE id=?', [
        new Date().toISOString(),
        user.id,
      ]);
      audit(req, 'login', email, 'ok', null);
      return res.json({ ok: true, email: user.email, name: user.name });
    } catch (e) {
      try {
        audit(req, 'login', req?.body?.email, 'error', { message: e.message });
      } catch {}
      res.status(500).json({ error: 'login_failed', details: e.message });
    }
  });

  // Google-based external user login (passwordless)
  app.post('/api/external-users/google-login', async (req, res) => {
    try {
      // Allow Google login regardless of the external_support flag (to simplify onboarding).
      const primaryClientId = process.env.GOOGLE_CLIENT_ID || process.env.REACT_APP_GOOGLE_CLIENT_ID || '';
      const audiences = [primaryClientId].map((v) => String(v || '').trim()).filter(Boolean);
      if (!OAuth2Client || audiences.length === 0)
        return res.status(500).json({ error: 'google_not_configured' });
      const { idToken } = req.body || {};
      if (!idToken) return res.status(400).json({ error: 'missing_id_token' });
      try {
        const logPath = path.join(__dirname, 'backend.log.err');
        const meta = {
          ip: req.ip,
          origin: req.headers.origin || null,
          userAgent: req.headers['user-agent'] || null,
          primaryClientId,
          audiences,
          tokenPrefix: String(idToken).slice(0, 24),
        };
        try {
          const partsRaw = String(idToken).split('.');
          if (partsRaw.length >= 2) {
            const b64Raw = partsRaw[1].replace(/-/g, '+').replace(/_/g, '/');
            const jsonRaw = Buffer.from(b64Raw, 'base64').toString('utf8');
            const decodedRaw = JSON.parse(jsonRaw);
            meta.rawAud = decodedRaw && decodedRaw.aud ? decodedRaw.aud : null;
            meta.rawIss = decodedRaw && decodedRaw.iss ? decodedRaw.iss : null;
          }
        } catch {}
        fs.appendFileSync(
          logPath,
          `\n[${new Date().toISOString()}] [GOOGLE_LOGIN_REQUEST] ${JSON.stringify(meta)}\n`,
        );
      } catch {}
      const client = new OAuth2Client(primaryClientId || audiences[0]);
      let payload;
      try {
        const ticket = await client.verifyIdToken({
          idToken,
          audience: audiences.length === 1 ? audiences[0] : audiences,
        });
        payload = ticket.getPayload();
      } catch (verifyErr) {
        const env = String(process.env.NODE_ENV || '').toLowerCase();
        const devBypass = String(process.env.GOOGLE_DEV_TRUST_UNVERIFIED || '').toLowerCase() === '1';
        const code = (verifyErr && (verifyErr.code || verifyErr.errno)) || '';
        const msg = String(verifyErr && (verifyErr.message || verifyErr.toString() || ''));
        const isNetwork = /ENOTFOUND|EAI_AGAIN|ECONNREFUSED|ENETUNREACH|getaddrinfo/i.test(msg) ||
          /ENOTFOUND|EAI_AGAIN|ECONNREFUSED|ENETUNREACH|getaddrinfo/i.test(String(code));
        const isAudienceMismatch = /Wrong recipient, payload audience != requiredAudience/i.test(msg);
        if (!(devBypass && env !== 'production' && (isNetwork || isAudienceMismatch))) throw verifyErr;
        try {
          const parts = String(idToken).split('.');
          if (parts.length < 2) throw new Error('invalid_id_token');
          const b64 = parts[1].replace(/-/g, '+').replace(/_/g, '/');
          const json = Buffer.from(b64, 'base64').toString('utf8');
          const decoded = JSON.parse(json);
          const tokenAud = String(decoded && decoded.aud ? decoded.aud : '');
          const okAud = audiences.includes(tokenAud);
          if (!decoded || !okAud) throw new Error('aud_mismatch_offline');
          payload = decoded;
        } catch (offlineErr) {
          throw verifyErr;
        }
      }
      try {
        const logPath = path.join(__dirname, 'backend.log.err');
        const metaOk = {
          email: payload && payload.email ? String(payload.email).toLowerCase() : null,
          aud: payload && payload.aud ? payload.aud : null,
          sub: payload && payload.sub ? payload.sub : null,
          emailVerified: !!(payload && payload.email_verified),
        };
        fs.appendFileSync(
          logPath,
          `\n[${new Date().toISOString()}] [GOOGLE_LOGIN_VERIFIED] ${JSON.stringify(metaOk)}\n`,
        );
      } catch {}
      const email = String(payload?.email || '').toLowerCase();
      const emailVerified = !!payload?.email_verified;
      const name = String(payload?.name || `${payload?.given_name || ''} ${payload?.family_name || ''}`.trim()).trim() || null;
      const googleSub = String(payload?.sub || '');
      if (!email || !emailVerified) return res.status(401).json({ error: 'email_not_verified' });
      // Upsert external user
      let user = one('SELECT * FROM external_users WHERE LOWER(email)=LOWER(?)', [email]);
      if (!user) {
        db.run('INSERT INTO external_users (email, name, status, google_sub, provider, created_at, last_login) VALUES (?,?,?,?,?,?,?)', [
          email,
          name,
          'active',
          googleSub,
          'google',
          new Date().toISOString(),
          new Date().toISOString(),
        ]);
        persist(db);
        user = one('SELECT * FROM external_users WHERE LOWER(email)=LOWER(?)', [email]);
      } else {
        db.run('UPDATE external_users SET name=COALESCE(?,name), google_sub=COALESCE(?,google_sub), provider=COALESCE(?,provider), last_login=? WHERE id=?', [
          name,
          googleSub,
          'google',
          new Date().toISOString(),
          user.id,
        ]);
        persist(db);
      }
      try { audit(req, 'login_google', email, 'ok', { sub: googleSub }); } catch {}
      return res.json({ ok: true, email, name });
    } catch (e) {
      // Log full error details for troubleshooting
      const errMsg = e && e.stack ? e.stack : (e?.message || String(e));
      try {
        const fs = require('fs');
        const logPath = require('path').join(__dirname, 'backend.log.err');
        fs.appendFileSync(logPath, `\n[${new Date().toISOString()}] [GOOGLE_LOGIN_ERROR] ${errMsg}\n`);
      } catch (logErr) {
        console.error('Failed to write to backend.log.err:', logErr);
      }
      console.error('Google login error:', errMsg);
      try { audit(req, 'login_google', req?.body?.email, 'error', { message: errMsg }); } catch {}
      return res.status(500).json({ error: 'google_login_failed', details: errMsg });
    }
  });

  app.post('/api/external-users/set-password', async (req, res) => {
    if (!(await isExternalSupportEnabledAsync()))
      return res.status(404).json({ error: 'not_found' });
    // Validate request
    try {
      const Ajv = require('ajv');
      const addFormats = require('ajv-formats');
      const ajv = new Ajv({ allErrors: true, removeAdditional: false });
      addFormats(ajv);
      const schema = {
        type: 'object',
        required: ['email', 'token', 'password'],
        additionalProperties: true,
        properties: {
          email: { type: 'string', format: 'email' },
          token: { type: 'string', minLength: 6 },
          password: { type: 'string', minLength: 8 },
          department: { type: 'string', nullable: true },
          businessId: { anyOf: [ { type: 'integer' }, { type: 'string' } ], nullable: true }
        },
      };
      const valid = ajv.validate(schema, req.body || {});
      if (!valid) return res.status(400).json({ error: 'invalid_request', details: ajv.errors });
    } catch {}
    try {
      const { email, token, password, department = null, businessId = null } = req.body || {};
      if (!email || !token || !password) return res.status(400).json({ error: 'missing_fields' });
      const rec = onboardingTokens.get(String(email).trim().toLowerCase());
      if (!rec || rec.token !== token || Date.now() > rec.expiresAt) {
        audit(req, 'onboard_set_password', email, 'invalid_or_expired', null);
        return res.status(400).json({ error: 'invalid_or_expired_token' });
      }
      if (!/^.{8,}$/.test(password) || !/[A-Za-z]/.test(password) || !/\d/.test(password)) {
        audit(req, 'onboard_set_password', email, 'weak_password', null);
        return res.status(400).json({ error: 'weak_password' });
      }
      const hash = await bcrypt.hash(password, BCRYPT_ROUNDS);
      db.run('UPDATE external_users SET password_hash=?, status=?, department=COALESCE(?,department), business_id=COALESCE(?,business_id) WHERE LOWER(email)=LOWER(?)', [
        hash,
        'active',
        department,
        businessId,
        email,
      ]);
      onboardingTokens.delete(String(email).trim().toLowerCase());
      audit(req, 'onboard_set_password', email, 'ok', null);
      return res.json({ ok: true });
    } catch (e) {
      try {
        audit(req, 'onboard_set_password', req?.body?.email, 'error', { message: e.message });
      } catch {}
      res.status(500).json({ error: 'set_password_failed', details: e.message });
    }
  });

  app.post('/api/external-users/bulk-upload', upload.single('file'), async (req, res) => {
    if (!(await isExternalSupportEnabledAsync()))
      return res.status(404).json({ error: 'not_found' });
    try {
      if (!req.file) return res.status(400).json({ error: 'no_file_uploaded' });
      const isExcel =
        /\.xlsx$|\.xls$/i.test(req.file.originalname || '') ||
        (req.file.mimetype && /sheet|excel/i.test(req.file.mimetype));
      let records;
      if (isExcel) {
        try {
          const XLSX = require('xlsx');
          const wb = XLSX.read(req.file.buffer, { type: 'buffer' });
          const sheetName =
            wb.SheetNames.find((n) => /externalusers|users/i.test(n)) || wb.SheetNames[0];
          const data = XLSX.utils.sheet_to_json(wb.Sheets[sheetName] || {}, { defval: '' });
          records = Array.isArray(data) ? data : [];
        } catch (e) {
          return res.status(400).json({ error: 'invalid_excel', details: e.message });
        }
      } else {
        try {
          const content = req.file.buffer.toString('utf8');
          records = csvParse.parse(content, { columns: true, skip_empty_lines: true });
        } catch (e) {
          return res.status(400).json({ error: 'invalid_csv', details: e.message });
        }
      }
      if (!Array.isArray(records) || records.length === 0)
        return res.status(400).json({ error: 'no_records_found' });
      let inserted = 0,
        updated = 0,
        errors = [],
        onboarding = [];
      db.run('BEGIN');
      try {
        for (const row of records) {
          const email = String(row.email || '')
            .trim()
            .toLowerCase();
          if (!email || !/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email)) {
            errors.push({ row, error: 'invalid_email' });
            continue;
          }
          const existing = one('SELECT id FROM external_users WHERE LOWER(email)=LOWER(?)', [
            email,
          ]);
          const now = new Date().toISOString();
          if (existing) {
            db.run(
              'UPDATE external_users SET name=?, phone=?, department=COALESCE(?,department), business_id=COALESCE(?,business_id), status=?, last_login=last_login WHERE id=?',
              [
                row.name || '',
                row.phone || '',
                row.department || null,
                row.businessId != null && row.businessId !== '' ? Number(row.businessId) : null,
                row.status || 'active',
                existing.id,
              ]
            );
            updated++;
          } else {
            db.run(
              'INSERT INTO external_users (email, name, phone, department, business_id, password_hash, status, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
              [
                email,
                row.name || '',
                row.phone || '',
                row.department || null,
                row.businessId != null && row.businessId !== '' ? Number(row.businessId) : null,
                '',
                row.status || 'invited',
                now,
              ]
            );
            inserted++;
            const token = crypto.randomBytes(32).toString('hex');
            const expiresAt = Date.now() + 1000 * 60 * 60 * 48; // 48 hours
            onboardingTokens.set(email, { token, expiresAt });
            const baseUrl =
              getSetting('frontend_base_url', process.env.FRONTEND_BASE_URL || '') ||
              req.headers.origin ||
              `${req.protocol}://${req.headers.host}`;
            const link = `${String(baseUrl).replace(/\/$/, '')}/onboard?email=${encodeURIComponent(email)}&token=${token}`;
            onboarding.push({ email, name: row.name || '', link });
          }
        }
        db.run('COMMIT');
      } catch (e) {
        db.run('ROLLBACK');
        return res.status(500).json({ error: 'db_error', details: e.message });
      }
      try {
        await Promise.all(onboarding.map((u) => sendOnboardingEmail(u.email, u.name, u.link)));
      } catch (e) {
        console.error('Onboarding email send failed', e);
      }
      res.json({
        inserted,
        updated,
        errors,
        onboarding: onboarding.map((u) => ({ email: u.email, sent: true })),
      });
    } catch (e) {
      res.status(500).json({ error: 'bulk_upload_failed', details: e.message });
    }
  });

  // --- Local File Uploads (PDF backup path) ---
  // Table: uploaded_files
  // Endpoint: POST /api/files/upload (multipart/form-data, field: file)
  // Returns: { id, name, size, mime, sha256, url }
  app.post('/api/files/upload', upload.single('file'), async (req, res) => {
    try {
      if (!req.file) return res.status(400).json({ error: 'no_file_uploaded' });
      const MAX_SIZE = Number(process.env.LOCAL_UPLOAD_MAX_BYTES || 100 * 1024 * 1024); // 100MB default
      if (req.file.size > MAX_SIZE)
        return res.status(400).json({ error: 'file_too_large', max: MAX_SIZE });

      // Only allow PDFs by default (can be expanded later)
      const origName = req.file.originalname || 'file';
      const guessed = req.file.mimetype || mime.lookup(origName) || 'application/octet-stream';
      const isPdf = /pdf/i.test(guessed) || /\.pdf$/i.test(origName || '');
      if (!isPdf)
        return res.status(400).json({ error: 'unsupported_type', allowed: 'application/pdf' });

      // Compute sha256 for dedupe/trace
      const sha256 = crypto.createHash('sha256').update(req.file.buffer).digest('hex');

      // (Deduplication disabled for reliability; always insert a new record)

      // Prepare storage path
      const uploadsDir = path.join(DATA_DIR, 'uploads');
      if (!fs.existsSync(uploadsDir)) fs.mkdirSync(uploadsDir, { recursive: true });
      const y = new Date().getUTCFullYear();
      const m = String(new Date().getUTCMonth() + 1).padStart(2, '0');
      const subDir = path.join(uploadsDir, String(y), String(m));
      if (!fs.existsSync(subDir)) fs.mkdirSync(subDir, { recursive: true });

      // Random filename to avoid collisions; preserve .pdf extension
      const rid = crypto.randomBytes(8).toString('hex');
      const storedName = `${rid}.pdf`;
      const fullPath = path.join(subDir, storedName);
      fs.writeFileSync(fullPath, req.file.buffer);

      // Persist metadata
      const now = new Date().toISOString();
      const uploadedBy =
        String(req.headers['x-user-email'] || req.headers['x-admin-email'] || '').toLowerCase() ||
        null;
      const relPath = path.relative(DATA_DIR, fullPath).replace(/\\/g, '/');
      const urlPath = `/api/files/by-path/${encodeURIComponent(relPath)}`; // internal convenience
      // Insert into uploaded_files table
      try {
        await db.run(
          'INSERT INTO uploaded_files (original_name, stored_name, rel_path, size, mime, sha256, uploaded_at, uploaded_by) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
          [origName, storedName, relPath, req.file.size, guessed, sha256, now, uploadedBy]
        );
      } catch (e) {
        // Ensure table exists (older DBs)
        try {
          await db.run(`CREATE TABLE IF NOT EXISTS uploaded_files (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            original_name TEXT,
            stored_name TEXT,
            rel_path TEXT NOT NULL,
            size INTEGER,
            mime TEXT,
            sha256 TEXT,
            uploaded_at TEXT,
            uploaded_by TEXT
          );`);
          await db.run(
            'INSERT INTO uploaded_files (original_name, stored_name, rel_path, size, mime, sha256, uploaded_at, uploaded_by) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
            [origName, storedName, relPath, req.file.size, guessed, sha256, now, uploadedBy]
          );
        } catch (ee) {
          return res.status(500).json({ error: 'db_error', details: ee?.message || String(ee) });
        }
      }
      let id = null;
      try {
        // SQLite/async-safe path
        const row = await one('SELECT last_insert_rowid() as id');
        id = row?.id ?? null;
      } catch (e) {
        /* noop */
      }
      if (id == null) {
        // Firebase/RTDB path: find by sha256 (async-safe)
        try {
          const probe = await one('SELECT id FROM uploaded_files WHERE sha256=? LIMIT 1', [sha256]);
          if (probe && probe.id != null) id = probe.id;
        } catch (e) {
          /* noop */
        }
      }
      persist(db);
      const apiUrl = id != null ? `/api/files/${id}` : null;
      return res.json({
        id,
        name: origName,
        size: req.file.size,
        mime: guessed,
        sha256,
        url: apiUrl,
      });
    } catch (e) {
      res.status(500).json({ error: 'upload_failed', details: e?.message || String(e) });
    }
  });

  // Import and save a SharePoint/Graph file to the server library (deduped by sha256)
  // Body: { driveId, itemId, url?, name? }
  // Auth: Bearer <Graph token> header or token query param
  app.post('/api/library/save-graph', express.json({ limit: '1mb' }), async (req, res) => {
    try {
      const driveId = String(req.body?.driveId || '') || '';
      const itemId = String(req.body?.itemId || '') || '';
      const rawUrl = String(req.body?.url || '');
      const nameHint = String(req.body?.name || 'document.pdf');
      const qToken = (req.query?.token || '').toString();
      const hdrAuth = (req.headers['authorization'] || '').toString();
      const bearer = qToken
        ? `Bearer ${qToken}`
        : hdrAuth && /^Bearer\s+/i.test(hdrAuth)
          ? hdrAuth
          : '';
      if (!bearer) return res.status(401).json({ error: 'token_required' });

      let target;
      if (driveId && itemId) {
        target = new URL(
          `https://graph.microsoft.com/v1.0/drives/${encodeURIComponent(driveId)}/items/${encodeURIComponent(itemId)}/content`
        );
      } else if (rawUrl) {
        const b64 = Buffer.from(rawUrl, 'utf8')
          .toString('base64')
          .replace(/=/g, '')
          .replace(/\+/g, '-')
          .replace(/\//g, '_');
        const shareId = `u!${b64}`;
        target = new URL(`https://graph.microsoft.com/v1.0/shares/${shareId}/driveItem/content`);
      } else {
        return res.status(400).json({ error: 'missing_ids_or_url' });
      }

      const TIMEOUT_MS = Number(process.env.PROXY_TIMEOUT_MS || 15000);
      const fetchBlob = () =>
        new Promise((resolve, reject) => {
          const opts = {
            method: 'GET',
            headers: { Authorization: bearer, 'User-Agent': 'Sunbeth-Graph-Importer/1.0' },
            agent: getProxyAgent(target),
          };
          const r = https.request(target, opts, (up) => {
            if (up.statusCode >= 300 && up.statusCode < 400 && up.headers.location) {
              try {
                const next = new URL(up.headers.location, target);
                const client = next.protocol === 'https:' ? https : http;
                const r2 = client.request(
                  next,
                  {
                    method: 'GET',
                    headers: { 'User-Agent': 'Sunbeth-Graph-Importer/1.0' },
                    agent: getProxyAgent(next),
                  },
                  (up2) => {
                    const chunks = [];
                    up2.on('data', (c) => chunks.push(c));
                    up2.on('end', () =>
                      resolve({
                        buffer: Buffer.concat(chunks),
                        contentType: up2.headers['content-type'] || 'application/octet-stream',
                      })
                    );
                    up2.on('error', reject);
                  }
                );
                r2.setTimeout(TIMEOUT_MS, () => {
                  try {
                    r2.destroy(new Error('timeout'));
                  } catch {}
                });
                r2.on('error', reject);
                r2.end();
                return;
              } catch (e) {
                return reject(e);
              }
            }
            const chunks = [];
            up.on('data', (c) => chunks.push(c));
            up.on('end', () =>
              resolve({
                buffer: Buffer.concat(chunks),
                contentType: up.headers['content-type'] || 'application/octet-stream',
              })
            );
            up.on('error', reject);
          });
          r.setTimeout(TIMEOUT_MS, () => {
            try {
              r.destroy(new Error('timeout'));
            } catch {}
          });
          r.on('error', reject);
          r.end();
        });

      const { buffer, contentType } = await fetchBlob();
      const sha256 = crypto.createHash('sha256').update(buffer).digest('hex');
      // Check existing
      const exist = one(
        'SELECT id, original_name, rel_path, mime, size FROM uploaded_files WHERE sha256=? LIMIT 1',
        [sha256]
      );
      if (exist) {
        return res.json({
          id: exist.id,
          name: exist.original_name,
          url: `/api/files/${exist.id}`,
          mime: exist.mime,
          size: exist.size,
          sha256,
          deduped: true,
        });
      }
      // Store new
      const uploadsDir = path.join(DATA_DIR, 'uploads');
      if (!fs.existsSync(uploadsDir)) fs.mkdirSync(uploadsDir, { recursive: true });
      const y = new Date().getUTCFullYear();
      const m = String(new Date().getUTCMonth() + 1).padStart(2, '0');
      const subDir = path.join(uploadsDir, String(y), String(m));
      if (!fs.existsSync(subDir)) fs.mkdirSync(subDir, { recursive: true });
      const rid = crypto.randomBytes(8).toString('hex');
      // Derive a stable extension and mime; prefer inferred type when contentType is generic
      const ext = mime.extension(contentType)
        ? `.${mime.extension(contentType)}`
        : mime.extension(mime.lookup(nameHint) || '')
          ? `.${mime.extension(mime.lookup(nameHint) || '')}`
          : '.pdf';
      const storedName = `${rid}${ext}`;
      const fullPath = path.join(subDir, storedName);
      fs.writeFileSync(fullPath, buffer);
      const now = new Date().toISOString();
      const uploadedBy =
        String(req.headers['x-user-email'] || req.headers['x-admin-email'] || '').toLowerCase() ||
        null;
      const relPath = path.relative(DATA_DIR, fullPath).replace(/\\/g, '/');
      // Pick a better mime if upstream returned octet-stream
      let saveMime = contentType || '';
      if (!saveMime || /octet-stream/i.test(saveMime)) {
        saveMime = mime.lookup(nameHint) || mime.lookup(storedName) || 'application/pdf';
      }
      try {
        db.run(
          'INSERT INTO uploaded_files (original_name, stored_name, rel_path, size, mime, sha256, uploaded_at, uploaded_by, source_type, source_url, driveId, itemId) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
          [
            nameHint,
            storedName,
            relPath,
            buffer.length,
            saveMime,
            sha256,
            now,
            uploadedBy,
            'sharepoint',
            rawUrl || null,
            driveId || null,
            itemId || null,
          ]
        );
      } catch (e) {
        // Ensure columns exist
        try {
          try {
            db.run('ALTER TABLE uploaded_files ADD COLUMN source_type TEXT');
          } catch {}
          try {
            db.run('ALTER TABLE uploaded_files ADD COLUMN source_url TEXT');
          } catch {}
          try {
            db.run('ALTER TABLE uploaded_files ADD COLUMN driveId TEXT');
          } catch {}
          try {
            db.run('ALTER TABLE uploaded_files ADD COLUMN itemId TEXT');
          } catch {}
          db.run(
            'INSERT INTO uploaded_files (original_name, stored_name, rel_path, size, mime, sha256, uploaded_at, uploaded_by, source_type, source_url, driveId, itemId) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
            [
              nameHint,
              storedName,
              relPath,
              buffer.length,
              saveMime,
              sha256,
              now,
              uploadedBy,
              'sharepoint',
              rawUrl || null,
              driveId || null,
              itemId || null,
            ]
          );
        } catch (ee) {
          return res.status(500).json({ error: 'db_error', details: ee?.message || String(ee) });
        }
      }
      const id = one('SELECT last_insert_rowid() as id')?.id;
      persist(db);
      return res.json({
        id,
        name: nameHint,
        url: `/api/files/${id}`,
        mime: contentType || 'application/octet-stream',
        size: buffer.length,
        sha256,
      });
    } catch (e) {
      res.status(500).json({ error: 'save_graph_failed', details: e?.message || String(e) });
    }
  });

  // Upload a file to SharePoint using a delegated Graph token (mirrors save-graph pattern)
  // Body: { driveId, folderItemId, fileName, contentBytes, contentType? }
  // Auth: Bearer <Graph token> header or token query param (requires Files.ReadWrite.All)
  app.post('/api/sharepoint/upload-graph', express.json({ limit: '10mb' }), async (req, res) => {
    try {
      const driveId = String(req.body?.driveId || '') || '';
      const folderItemId = String(req.body?.folderItemId || '') || '';
      const fileName = String(req.body?.fileName || 'document.pdf');
      const contentType = String(req.body?.contentType || 'application/pdf');
      const base64 = String(req.body?.contentBytes || '');
      const qToken = (req.query?.token || '').toString();
      const hdrAuth = (req.headers['authorization'] || '').toString();
      const bearer = qToken
        ? `Bearer ${qToken}`
        : hdrAuth && /^Bearer\s+/i.test(hdrAuth)
          ? hdrAuth
          : '';
      if (!bearer) return res.status(401).json({ error: 'token_required' });
      if (!driveId || !folderItemId || !base64) return res.status(400).json({ error: 'missing_params' });

      let buffer;
      try {
        buffer = Buffer.from(base64, 'base64');
      } catch (e) {
        return res.status(400).json({ error: 'invalid_base64', details: e?.message || String(e) });
      }

      const target = new URL(
        `https://graph.microsoft.com/v1.0/drives/${encodeURIComponent(driveId)}/items/${encodeURIComponent(folderItemId)}:/${encodeURIComponent(fileName)}:/content`
      );
      const TIMEOUT_MS = Number(process.env.PROXY_TIMEOUT_MS || 20000);
      const doPut = () =>
        new Promise((resolve, reject) => {
          const opts = {
            method: 'PUT',
            headers: { Authorization: bearer, 'Content-Type': contentType, 'User-Agent': 'Sunbeth-Graph-Upload/1.0' },
            agent: getProxyAgent(target),
          };
          const r = https.request(target, opts, (up) => {
            const chunks = [];
            up.on('data', (c) => chunks.push(c));
            up.on('end', () => {
              const body = Buffer.concat(chunks).toString('utf8');
              if (up.statusCode >= 200 && up.statusCode < 300) {
                try {
                  const j = JSON.parse(body);
                  return resolve(j);
                } catch {
                  return resolve({ ok: true, status: up.statusCode });
                }
              }
              return reject(new Error(`upload_failed:${up.statusCode}:${body}`));
            });
            up.on('error', reject);
          });
          r.setTimeout(TIMEOUT_MS, () => {
            try { r.destroy(new Error('timeout')); } catch {}
          });
          r.on('error', reject);
          r.write(buffer);
          r.end();
        });

      const uploaded = await doPut();
      // Return common fields from Graph driveItem
      return res.json({
        ok: true,
        id: uploaded?.id,
        name: uploaded?.name || fileName,
        webUrl: uploaded?.webUrl,
        size: uploaded?.size || buffer.length,
        driveId,
        parentId: uploaded?.parentReference?.id || folderItemId,
      });
    } catch (e) {
      res.status(500).json({ error: 'upload_graph_failed', details: e?.message || String(e) });
    }
  });

  // List server library files (most recent first)
  app.get('/api/library/list', async (req, res) => {
    try {
      const q = String(req.query.q || '')
        .trim()
        .toLowerCase();
      const limit = Math.max(1, Math.min(200, Number(req.query.limit || 100)));
      let rows;
      // Firestore/RTDB adapters don't parse "LIMIT ?"; fetch then slice client-side
      if (db && (db.driver === 'firebase' || db.driver === 'rtdb')) {
        rows = await all(
          'SELECT id, original_name, size, mime, uploaded_at, sha256 FROM uploaded_files ORDER BY id DESC'
        );
      } else {
        rows = all(
          'SELECT id, original_name, size, mime, uploaded_at, sha256 FROM uploaded_files ORDER BY id DESC LIMIT ?',
          [limit]
        );
      }
      if (q) {
        rows = rows.filter(
          (r) =>
            String(r.original_name || '')
              .toLowerCase()
              .includes(q) ||
            String(r.mime || '')
              .toLowerCase()
              .includes(q)
        );
      }
      if (db && (db.driver === 'firebase' || db.driver === 'rtdb')) {
        rows = rows.slice(0, limit);
      }
      res.json({
        files: rows.map((r) => ({
          id: r.id,
          name: r.original_name,
          size: r.size,
          mime: r.mime,
          uploadedAt: r.uploaded_at,
          sha256: r.sha256,
          url: `/api/files/${r.id}`,
        })),
      });
    } catch (e) {
      res.status(500).json({ error: 'list_failed', details: e?.message || String(e) });
    }
  });

  // GET /api/files/:id -> stream file inline (or as attachment if download=1); supports diag=1
  app.get('/api/files/:id', async (req, res) => {
    try {
      const isFirebase = db && (db.driver === 'firebase' || db.driver === 'rtdb');
      const id = isFirebase ? String(req.params.id) : Number(req.params.id);
      if (!isFirebase && !Number.isInteger(id))
        return res.status(400).json({ error: 'invalid_id' });
      const row = isFirebase
        ? await one(
            'SELECT id, original_name, stored_name, rel_path, size, mime, sha256, uploaded_at FROM uploaded_files WHERE id=?',
            [id]
          )
        : one(
            'SELECT id, original_name, stored_name, rel_path, size, mime, sha256, uploaded_at FROM uploaded_files WHERE id=?',
            [id]
          );
      if (!row) return res.status(404).json({ error: 'not_found' });
      const isDiag =
        String(req.query.diag || '').toLowerCase() === '1' ||
        String(req.query.diag || '').toLowerCase() === 'true';
      const dl = String(req.query.download || '') === '1';
      const absPath = path.join(DATA_DIR, String(row.rel_path || ''));
      if (!fs.existsSync(absPath)) return res.status(404).json({ error: 'file_missing' });
      // Prefer a specific content-type; if DB mime is generic, infer from filename
      let ct = row.mime || '';
      if (!ct || /octet-stream/i.test(String(ct))) {
        ct = mime.lookup(row.original_name || row.stored_name || '') || 'application/octet-stream';
      }
      if (isDiag) {
        return res.json({
          ok: true,
          id: row.id,
          name: row.original_name,
          size: row.size,
          mime: ct,
          sha256: row.sha256,
          path: row.rel_path,
        });
      }
      res.setHeader('Content-Type', String(ct));
      res.setHeader('Cache-Control', 'no-store');
      if (dl) {
        res.setHeader(
          'Content-Disposition',
          `attachment; filename="${encodeURIComponent(row.original_name || 'file')}"`
        );
      } else {
        res.setHeader('Content-Disposition', 'inline');
      }
      const stream = fs.createReadStream(absPath);
      stream.on('error', () => {
        try {
          res.destroy();
        } catch {}
      });
      stream.pipe(res);
    } catch (e) {
      res.status(500).json({ error: 'serve_failed', details: e?.message || String(e) });
    }
  });

  // Internal convenience for path-based fetch (not exposed in UI)
  app.get('/api/files/by-path/:relPath', (req, res) => {
    try {
      const relPath = decodeURIComponent(req.params.relPath || '');
      const abs = path.join(DATA_DIR, relPath);
      if (!abs.startsWith(DATA_DIR)) return res.status(400).json({ error: 'invalid_path' });
      if (!fs.existsSync(abs)) return res.status(404).json({ error: 'not_found' });
      const ct = mime.lookup(abs) || 'application/octet-stream';
      res.setHeader('Content-Type', String(ct));
      res.setHeader('Cache-Control', 'no-store');
      fs.createReadStream(abs).pipe(res);
    } catch (e) {
      res.status(500).json({ error: 'serve_failed' });
    }
  });

  // Bulk upload Businesses (CSV or Excel)
  app.post('/api/businesses/bulk-upload', upload.single('file'), async (req, res) => {
    try {
      if (!req.file) return res.status(400).json({ error: 'no_file_uploaded' });
      const isExcel =
        /\.xlsx$|\.xls$/i.test(req.file.originalname || '') ||
        (req.file.mimetype && /sheet|excel/i.test(req.file.mimetype));
      let records;
      if (isExcel) {
        try {
          const XLSX = require('xlsx');
          const wb = XLSX.read(req.file.buffer, { type: 'buffer' });
          const sheetName = wb.SheetNames.find((n) => /business/i.test(n)) || wb.SheetNames[0];
          const data = XLSX.utils.sheet_to_json(wb.Sheets[sheetName] || {}, { defval: '' });
          records = Array.isArray(data) ? data : [];
        } catch (e) {
          return res.status(400).json({ error: 'invalid_excel', details: e.message });
        }
      } else {
        try {
          const content = req.file.buffer.toString('utf8');
          records = csvParse.parse(content, { columns: true, skip_empty_lines: true });
        } catch (e) {
          return res.status(400).json({ error: 'invalid_csv', details: e.message });
        }
      }
      if (!Array.isArray(records) || records.length === 0)
        return res.status(400).json({ error: 'no_records_found' });
      let inserted = 0,
        updated = 0,
        errors = [];
      db.run('BEGIN');
      try {
        for (const row of records) {
          let name = String(row.name || row.Name || '').trim();
          let code = (row.code != null ? String(row.code) : '').trim();
          if (!name && !code) {
            errors.push({ row, error: 'name_or_code_required' });
            continue;
          }
          const description =
            (row.description != null ? String(row.description) : '').trim() || null;
          let isActiveRaw = row.isActive;
          const isActive =
            String(isActiveRaw).toLowerCase() === 'true' || String(isActiveRaw) === '1'
              ? 1
              : String(isActiveRaw).toLowerCase() === 'false' || String(isActiveRaw) === '0'
                ? 0
                : 1;
          // Upsert by code if provided, else by name
          let existing = null;
          if (code) existing = one('SELECT id FROM businesses WHERE code=?', [code]);
          if (!existing && name)
            existing = one('SELECT id FROM businesses WHERE LOWER(name)=LOWER(?)', [name]);
          if (existing) {
            db.run('UPDATE businesses SET name=?, code=?, isActive=?, description=? WHERE id=?', [
              name || existing.name || '',
              code || null,
              isActive,
              description,
              existing.id,
            ]);
            updated++;
          } else {
            if (!name) name = code;
            db.run(
              'INSERT INTO businesses (name, code, isActive, description) VALUES (?, ?, ?, ?)',
              [name, code || null, isActive, description]
            );
            inserted++;
          }
        }
        db.run('COMMIT');
      } catch (e) {
        db.run('ROLLBACK');
        return res.status(500).json({ error: 'db_error', details: e.message });
      }
      persist(db);
      res.json({ inserted, updated, errors });
    } catch (e) {
      res.status(500).json({ error: 'bulk_upload_failed', details: e.message });
    }
  });

  // --- Audit Logs Endpoint ---
  // List audit logs with optional filters
  app.get('/api/audit-logs', async (req, res) => {
    try {
      const q = String(req.query.q || '')
        .trim()
        .toLowerCase();
      const event = String(req.query.event || '')
        .trim()
        .toLowerCase();
      const email = String(req.query.email || '')
        .trim()
        .toLowerCase();
      const result = String(req.query.result || '')
        .trim()
        .toLowerCase();
      const ip = String(req.query.ip || '')
        .trim()
        .toLowerCase();
      const since = String(req.query.since || '').trim(); // ISO date
      const until = String(req.query.until || '').trim(); // ISO date
      const limit = Math.max(0, Math.min(500, Number(req.query.limit || 100)));
      const offset = Math.max(0, Number(req.query.offset || 0));

      const conds = [];
      const params = [];
      if (q) {
        conds.push(
          '(LOWER(event) LIKE ? OR LOWER(email) LIKE ? OR LOWER(result) LIKE ? OR LOWER(ip) LIKE ? OR LOWER(ua) LIKE ? OR LOWER(details) LIKE ?)'
        );
        params.push(`%${q}%`, `%${q}%`, `%${q}%`, `%${q}%`, `%${q}%`, `%${q}%`);
      }
      if (event) {
        conds.push('LOWER(event)=?');
        params.push(event);
      }
      if (email) {
        conds.push('LOWER(email)=?');
        params.push(email);
      }
      if (result) {
        conds.push('LOWER(result)=?');
        params.push(result);
      }
      if (ip) {
        conds.push('LOWER(ip)=?');
        params.push(ip);
      }
      if (since) {
        conds.push('ts>=?');
        params.push(since);
      }
      if (until) {
        conds.push('ts<=?');
        params.push(until);
      }
      const where = conds.length ? 'WHERE ' + conds.join(' AND ') : '';
      const rowsMaybe = all(
        `SELECT id, ts, event, email, ip, ua, result, details FROM audit_logs ${where} ORDER BY id DESC LIMIT ${limit} OFFSET ${offset}`,
        params
      );
      const rowsResolved = (rowsMaybe && typeof rowsMaybe.then === 'function') ? await rowsMaybe : (rowsMaybe || []);
      const rows = Array.isArray(rowsResolved)
        ? rowsResolved
        : (rowsResolved && typeof rowsResolved === 'object')
          ? Object.values(rowsResolved)
          : [];
      res.json({ logs: rows });
    } catch (e) {
      res.status(500).json({ error: 'list_audit_failed', details: e?.message || String(e) });
    }
  });

  // Seed a handful of demo audit events (for troubleshooting the diagnostics panel)
  app.post('/api/audit-logs/seed-demo', (req, res) => {
    try {
      const now = Date.now();
      const emails = ['guest1@example.com','guest2@example.com','guest3@example.com'];
      const events = [
        { event: 'login', result: 'ok' },
        { event: 'login', result: 'invalid_user' },
        { event: 'password_reset_request', result: 'sent' },
        { event: 'mfa_verify', result: 'invalid_code' },
        { event: 'onboard_set_password', result: 'ok' },
      ];
      for (let i = 0; i < events.length; i++) {
        const ts = new Date(now - i * 60_000).toISOString();
        const ev = events[i];
        const email = emails[i % emails.length];
        const ip = `127.0.0.${i+1}`;
        const ua = 'DemoAgent/1.0';
        const details = JSON.stringify({ note: 'demo seed' });
        try {
          db.run(
            'INSERT INTO audit_logs (ts, event, email, ip, ua, result, details) VALUES (?, ?, ?, ?, ?, ?, ?)',
            [ts, ev.event, email, ip, ua, ev.result, details]
          );
        } catch {}
      }
      persist(db);
      res.json({ ok: true, inserted: events.length });
    } catch (e) {
      res.status(500).json({ error: 'seed_failed', details: e?.message || String(e) });
    }
  });

  // --- Admin: External Users Management ---
  // List external users with optional filters
  app.get('/api/external-users', async (req, res) => {
    if (!(await isExternalSupportEnabledAsync()))
      return res.status(404).json({ error: 'not_found' });
    try {
      const q = String(req.query.q || '')
        .trim()
        .toLowerCase();
      const status = String(req.query.status || '')
        .trim()
        .toLowerCase();
      const limit = Math.max(0, Math.min(200, Number(req.query.limit || 50)));
      const offset = Math.max(0, Number(req.query.offset || 0));
      const conds = [];
      const params = [];
      if (q) {
        conds.push('(LOWER(email) LIKE ? OR LOWER(name) LIKE ? OR LOWER(phone) LIKE ?)');
        params.push(`%${q}%`, `%${q}%`, `%${q}%`);
      }
      if (status) {
        conds.push('LOWER(status)=?');
        params.push(status);
      }
      const where = conds.length ? 'WHERE ' + conds.join(' AND ') : '';
      const rows = all(
        `SELECT id, email, name, phone, department, business_id, status, mfa_enabled, created_at, last_login FROM external_users ${where} ORDER BY created_at DESC LIMIT ${limit} OFFSET ${offset}`,
        params
      );
      logExternalEvent('LIST', { q, status, limit, offset, count: Array.isArray(rows) ? rows.length : 0 });
      res.json({ users: rows });
    } catch (e) {
      logExternalEvent('LIST_ERROR', { message: e?.message || String(e) });
      res.status(500).json({ error: 'list_failed', details: e?.message || String(e) });
    }
  });

  // Invite a single external user (upsert) and send onboarding email
  app.post('/api/external-users/invite', async (req, res) => {
    if (!(await isExternalSupportEnabledAsync()))
      return res.status(404).json({ error: 'not_found' });
    try {
      const { email, name = '', phone = '', department = null, businessId = null } = req.body || {};
      const e = String(email || '')
        .trim()
        .toLowerCase();
      if (!e || !e.includes('@')) return res.status(400).json({ error: 'invalid_email' });
      const existing = one('SELECT id, status FROM external_users WHERE LOWER(email)=LOWER(?)', [
        e,
      ]);
      const now = new Date().toISOString();
      if (existing) {
        // Update basic fields, keep password hash
        db.run('UPDATE external_users SET name=?, phone=?, department=COALESCE(?,department), business_id=COALESCE(?,business_id), status=status WHERE id=?', [
          name,
          phone,
          department,
          businessId,
          existing.id,
        ]);
      } else {
        db.run(
          'INSERT INTO external_users (email, name, phone, department, business_id, password_hash, status, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
          [e, name, phone, department, businessId, '', 'invited', now]
        );
      }
      // Generate onboarding token and send email
      const token = crypto.randomBytes(32).toString('hex');
      const expiresAt = Date.now() + 1000 * 60 * 60 * 48; // 48 hours
      onboardingTokens.set(e, { token, expiresAt });
      const baseUrl =
        getSetting('frontend_base_url', process.env.FRONTEND_BASE_URL || '') ||
        req.headers.origin ||
        `${req.protocol}://${req.headers.host}`;
      const link = `${String(baseUrl).replace(/\/$/, '')}/onboard?email=${encodeURIComponent(e)}&token=${token}`;
      await sendOnboardingEmail(e, name || '', link);
      logExternalEvent('INVITE_SINGLE_OK', { email: e, existing: !!existing });
      res.json({ ok: true });
    } catch (e) {
      logExternalEvent('INVITE_SINGLE_ERROR', { email: req?.body?.email || null, message: e?.message || String(e) });
      res.status(500).json({ error: 'invite_failed', details: e?.message || String(e) });
    }
  });

  // Resend onboarding invite (regenerate token)
  app.post('/api/external-users/resend', async (req, res) => {
    if (!(await isExternalSupportEnabledAsync()))
      return res.status(404).json({ error: 'not_found' });
    try {
      const { email } = req.body || {};
      const e = String(email || '')
        .trim()
        .toLowerCase();
      if (!e || !e.includes('@')) return res.status(400).json({ error: 'invalid_email' });
      const user = one('SELECT * FROM external_users WHERE LOWER(email)=LOWER(?)', [e]);
      if (!user) return res.status(404).json({ error: 'user_not_found' });
      const token = crypto.randomBytes(32).toString('hex');
      const expiresAt = Date.now() + 1000 * 60 * 60 * 48; // 48 hours
      onboardingTokens.set(e, { token, expiresAt });
      const baseUrl =
        getSetting('frontend_base_url', process.env.FRONTEND_BASE_URL || '') ||
        req.headers.origin ||
        `${req.protocol}://${req.headers.host}`;
      const link = `${String(baseUrl).replace(/\/$/, '')}/onboard?email=${encodeURIComponent(e)}&token=${token}`;
      await sendOnboardingEmail(e, user.name || '', link);
      logExternalEvent('INVITE_RESEND_OK', { email: e });
      res.json({ ok: true });
    } catch (e) {
      logExternalEvent('INVITE_RESEND_ERROR', { email: req?.body?.email || null, message: e?.message || String(e) });
      res.status(500).json({ error: 'resend_failed', details: e?.message || String(e) });
    }
  });

  // Batch invite (create or update) multiple external users and send onboarding emails
  // POST /api/external-users/invite-batch
  // Body: { users: [ { email, name?, phone?, department?, businessId? } ], updateExisting?: boolean }
  // Returns: { invited, updated, errors: [ { email, error } ], results: [ { email, created, invited } ] }
  app.post('/api/external-users/invite-batch', express.json({ limit: '1mb' }), async (req, res) => {
    if (!(await isExternalSupportEnabledAsync()))
      return res.status(404).json({ error: 'not_found' });
    try {
      const list = Array.isArray(req.body?.users) ? req.body.users : [];
      const updateExisting = req.body?.updateExisting !== false; // default true
      if (!list.length) return res.status(400).json({ error: 'no_users' });
      const MAX = 500;
      if (list.length > MAX) return res.status(400).json({ error: 'too_many', max: MAX });
      let invited = 0,
        updated = 0;
      const errors = [];
      const results = [];
      const emailJobs = [];
      const baseUrl =
        getSetting('frontend_base_url', process.env.FRONTEND_BASE_URL || '') ||
        req.headers.origin ||
        `${req.protocol}://${req.headers.host}`;
      const nowIso = new Date().toISOString();
      db.run('BEGIN');
      try {
        for (const raw of list) {
          const email = String(raw?.email || '')
            .trim()
            .toLowerCase();
          if (!email || !/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email)) {
            errors.push({ email, error: 'invalid_email' });
            continue;
          }
          const name = String(raw?.name || '');
          const phone = String(raw?.phone || '');
          const department = raw?.department != null ? String(raw.department || '') : undefined;
          const businessId = raw?.businessId != null && raw.businessId !== '' ? Number(raw.businessId) : undefined;
          let existing = one(
            'SELECT id, name, phone, department, business_id, status FROM external_users WHERE LOWER(email)=LOWER(?)',
            [email]
          );
          const created = !existing;
          if (existing) {
            if (updateExisting) {
              // Only update provided fields (avoid blanking existing unless blank explicitly passed)
              const newName = raw.hasOwnProperty('name') ? name : existing.name;
              const newPhone = raw.hasOwnProperty('phone') ? phone : existing.phone;
              const newDept = raw.hasOwnProperty('department') ? department : existing.department;
              const newBiz = raw.hasOwnProperty('businessId') ? businessId : existing.business_id;
              db.run('UPDATE external_users SET name=?, phone=?, department=?, business_id=? WHERE id=?', [
                newName,
                newPhone,
                newDept ?? null,
                newBiz ?? null,
                existing.id,
              ]);
              updated++;
            }
          } else {
            db.run(
              'INSERT INTO external_users (email, name, phone, department, business_id, password_hash, status, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
              [email, name, phone, department ?? null, businessId ?? null, '', 'invited', nowIso]
            );
            invited++; // count new user as invited
          }
          // Always (re)generate onboarding token + email send
          const token = crypto.randomBytes(32).toString('hex');
          const expiresAt = Date.now() + 1000 * 60 * 60 * 48; // 48 hours
          onboardingTokens.set(email, { token, expiresAt });
          const link = `${String(baseUrl).replace(/\/$/, '')}/onboard?email=${encodeURIComponent(email)}&token=${token}`;
          emailJobs.push({ email, name, link, created });
          results.push({ email, created, invited: true });
        }
        db.run('COMMIT');
      } catch (e) {
        try {
          db.run('ROLLBACK');
        } catch {}
        return res.status(500).json({ error: 'db_error', details: e?.message || String(e) });
      }
      // Send emails (best-effort)
      const concurrency = 10;
      let idx = 0;
      const sendErrors = [];
      const workers = Array.from({ length: concurrency }).map(async () => {
        while (idx < emailJobs.length) {
          const jobIndex = idx++;
          const job = emailJobs[jobIndex];
          try {
            await sendOnboardingEmail(job.email, job.name || '', job.link);
            try {
              audit(req, 'invite_batch', job.email, 'ok', { created: job.created });
            } catch {}
          } catch (e) {
            sendErrors.push({
              email: job.email,
              error: 'send_failed',
              details: e?.message || String(e),
            });
            try {
              audit(req, 'invite_batch', job.email, 'error', {
                created: job.created,
                message: e?.message || String(e),
              });
            } catch {}
          }
        }
      });
      try {
        await Promise.all(workers);
      } catch {}
      const allErrors = errors.concat(sendErrors);
      logExternalEvent('INVITE_BATCH_DONE', {
        invited,
        updated,
        requested: list.length,
        errorCount: allErrors.length,
      });
      res.json({ invited, updated, errors: allErrors, results });
    } catch (e) {
      logExternalEvent('INVITE_BATCH_ERROR', { message: e?.message || String(e) });
      res.status(500).json({ error: 'invite_batch_failed', details: e?.message || String(e) });
    }
  });

  // Batch resend onboarding invites (regenerate tokens and email)
  // POST /api/external-users/resend-batch
  // Body: { emails: ["a@example.com", ...] }
  // Returns: { processed, errors: [ { email, error } ], results: [ { email, invited } ] }
  app.post(
    '/api/external-users/resend-batch',
    express.json({ limit: '512kb' }),
    async (req, res) => {
      if (!(await isExternalSupportEnabledAsync()))
        return res.status(404).json({ error: 'not_found' });
      try {
        const emails = Array.isArray(req.body?.emails) ? req.body.emails : [];
        if (!emails.length) return res.status(400).json({ error: 'no_emails' });
        const MAX = 1000;
        if (emails.length > MAX) return res.status(400).json({ error: 'too_many', max: MAX });
        const baseUrl =
          getSetting('frontend_base_url', process.env.FRONTEND_BASE_URL || '') ||
          req.headers.origin ||
          `${req.protocol}://${req.headers.host}`;
        const results = [];
        const errors = [];
        for (const raw of emails) {
          const email = String(raw || '')
            .trim()
            .toLowerCase();
          if (!email || !/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email)) {
            errors.push({ email, error: 'invalid_email' });
            continue;
          }
          const user = one('SELECT id, name FROM external_users WHERE LOWER(email)=LOWER(?)', [
            email,
          ]);
          if (!user) {
            errors.push({ email, error: 'user_not_found' });
            continue;
          }
          try {
            const token = crypto.randomBytes(32).toString('hex');
            const expiresAt = Date.now() + 1000 * 60 * 60 * 48; // 48 hours
            onboardingTokens.set(email, { token, expiresAt });
            const link = `${String(baseUrl).replace(/\/$/, '')}/onboard?email=${encodeURIComponent(email)}&token=${token}`;
            await sendOnboardingEmail(email, user.name || '', link);
            results.push({ email, invited: true });
            try {
              audit(req, 'resend_batch', email, 'ok', null);
            } catch {}
          } catch (e) {
            errors.push({ email, error: 'send_failed', details: e?.message || String(e) });
            try {
              audit(req, 'resend_batch', email, 'error', { message: e?.message || String(e) });
            } catch {}
          }
        }
        logExternalEvent('RESEND_BATCH_DONE', {
          processed: results.length,
          requested: emails.length,
          errorCount: errors.length,
        });
        res.json({ processed: results.length, errors, results });
      } catch (e) {
        logExternalEvent('RESEND_BATCH_ERROR', { message: e?.message || String(e) });
        res.status(500).json({ error: 'resend_batch_failed', details: e?.message || String(e) });
      }
    }
  );

  // Update a user's basic fields (admin)
  app.patch('/api/external-users/:id', async (req, res) => {
    if (!(await isExternalSupportEnabledAsync()))
      return res.status(404).json({ error: 'not_found' });
    try {
      const id = Number(req.params.id);
      if (!Number.isFinite(id)) return res.status(400).json({ error: 'invalid_id' });
      const allowed = ['name', 'phone', 'department', 'business_id', 'status', 'mfa_enabled'];
      const updates = [];
      const params = [];
      for (const k of allowed) {
        if (Object.prototype.hasOwnProperty.call(req.body || {}, k)) {
          updates.push(`${k}=?`);
          params.push(k === 'mfa_enabled' ? (req.body[k] ? 1 : 0) : req.body[k]);
        }
      }
      if (updates.length === 0) return res.json({ ok: true, updated: 0 });
      params.push(id);
      db.run(`UPDATE external_users SET ${updates.join(', ')} WHERE id=?`, params);
      res.json({ ok: true, updated: 1 });
    } catch (e) {
      res.status(500).json({ error: 'update_failed', details: e?.message || String(e) });
    }
  });

  // Delete an external user (admin)
  app.delete('/api/external-users/:id', async (req, res) => {
    if (!(await isExternalSupportEnabledAsync()))
      return res.status(404).json({ error: 'not_found' });
    try {
      const id = Number(req.params.id);
      if (!Number.isFinite(id)) return res.status(400).json({ error: 'invalid_id' });
      db.run('DELETE FROM external_users WHERE id=?', [id]);
      res.json({ ok: true });
    } catch (e) {
      res.status(500).json({ error: 'delete_failed', details: e?.message || String(e) });
    }
  });

  // Notification Emails API (supports merging per-business admins when batch/email provided)
  app.get('/api/notification-emails', async (req, res) => {
    try {
      // 1) Base global recipients
      const globalsMaybe = all('SELECT email FROM notification_emails ORDER BY email ASC');
      const globalRows = globalsMaybe && typeof globalsMaybe.then === 'function' ? await globalsMaybe : globalsMaybe || [];
      const globals = (Array.isArray(globalRows) ? globalRows : []).map((r) => String(r.email || '')).filter(Boolean);

      // 2) Optionally resolve business admins for the provided context
      const batchIdRaw = req.query.batchId;
      const emailRaw = (req.query.email || '').toString().trim().toLowerCase();
      let businessAdmins = [];
      try {
        if (batchIdRaw && emailRaw) {
          const isFirebase = db && (db.driver === 'firebase' || db.driver === 'rtdb');
          const batchId = isFirebase ? String(batchIdRaw) : Number(batchIdRaw);
          // Resolve businessId from recipients first
          const recRowMaybe = one('SELECT businessId FROM recipients WHERE batchId=? AND LOWER(email)=LOWER(?)', [batchId, emailRaw]);
          const recRow = recRowMaybe && typeof recRowMaybe.then === 'function' ? await recRowMaybe : recRowMaybe;
          let bizId = recRow ? recRow.businessId : null;
          if (!bizId) {
            const ubRowMaybe = one('SELECT businessId FROM user_businesses WHERE LOWER(email)=LOWER(?) ORDER BY assignedAt DESC LIMIT 1', [emailRaw]);
            const ubRow = ubRowMaybe && typeof ubRowMaybe.then === 'function' ? await ubRowMaybe : ubRowMaybe;
            bizId = ubRow ? ubRow.businessId : null;
          }
          // As a convenience: if still not found, treat provided email as an admin and resolve its business
          if (!bizId) {
            const admRowMaybe = one('SELECT businessId FROM business_admins WHERE LOWER(email)=LOWER(?) LIMIT 1', [emailRaw]);
            const admRow = admRowMaybe && typeof admRowMaybe.then === 'function' ? await admRowMaybe : admRowMaybe;
            bizId = admRow ? admRow.businessId : null;
          }
          if (bizId != null) {
            const adminsRowsMaybe = all('SELECT email FROM business_admins WHERE businessId=? ORDER BY email ASC', [bizId]);
            const adminsRows = adminsRowsMaybe && typeof adminsRowsMaybe.then === 'function' ? await adminsRowsMaybe : adminsRowsMaybe || [];
            businessAdmins = (Array.isArray(adminsRows) ? adminsRows : []).map((r) => String(r.email || '')).filter(Boolean);
          }
        }
      } catch {}

      // 3) Merge unique (lowercased) and return
      const merged = Array.from(new Set([...globals, ...businessAdmins].map((e) => String(e).trim().toLowerCase()).filter(Boolean)));
      res.json({ emails: merged });
    } catch (e) {
      res.status(500).json({ error: 'Failed to load notification emails', details: e?.message || e });
    }
  });

  // --- Settings: External Support (simple on/off) ---
  // GET /api/settings/external-support -> { enabled: boolean }
  app.get('/api/settings/external-support', async (req, res) => {
    try {
      const v = String(
        (await getSettingAsync(
          'external_support_enabled',
          process.env.EXTERNAL_SUPPORT_ENABLED || '0'
        )) || '0'
      );
      res.json({ enabled: v === '1' || v.toLowerCase() === 'true' });
    } catch (e) {
      res.status(500).json({ error: 'load_failed' });
    }
  });
  // PUT /api/settings/external-support { enabled: boolean }
  app.put('/api/settings/external-support', async (req, res) => {
    try {
      const enabled = !!(
        req.body &&
        (req.body.enabled === true || String(req.body.enabled) === '1')
      );
      const ok = await setSettingAsync('external_support_enabled', enabled ? '1' : '0');
      if (!ok) return res.status(500).json({ error: 'save_failed' });
      res.json({ enabled });
    } catch (e) {
      res.status(500).json({ error: 'save_failed' });
    }
  });

  // --- Settings: Legal Consent Document ---
  // Persist just the file id (points to uploaded_files), derive url/name on read
  // GET /api/settings/legal-consent -> { fileId, url, name }
  app.get('/api/settings/legal-consent', async (req, res) => {
    try {
      const isFirebase = db && (db.driver === 'firebase' || db.driver === 'rtdb');
      let stored = '';
      if (isFirebase) {
        const r = await one(
          'SELECT value FROM app_settings WHERE key=? ORDER BY updatedAt DESC LIMIT 1',
          ['legal_consent_file_id']
        );
        stored = String(r?.value || '').trim();
      } else {
        stored = String(getSetting('legal_consent_file_id', '') || '').trim();
      }
      const allowPreviewRaw = await getSettingAsync('legal_consent_allow_preview', '0');
      const allowDenyRaw = await getSettingAsync('legal_consent_allow_deny', '0');
      const uploadCompletionPdfRaw = await getSettingAsync('upload_completion_pdf', '0');
      const allowPreview = String(allowPreviewRaw || '0').toLowerCase() === 'true' || String(allowPreviewRaw || '0') === '1';
      const allowDeny = String(allowDenyRaw || '0').toLowerCase() === 'true' || String(allowDenyRaw || '0') === '1';
      const uploadCompletionPdf = String(uploadCompletionPdfRaw || '0').toLowerCase() === 'true' || String(uploadCompletionPdfRaw || '0') === '1';

      if (!stored) return res.json({ fileId: null, url: null, name: null, allowPreview, allowDeny, uploadCompletionPdf });
      const id = isFirebase ? stored : Number(stored);
      const row = isFirebase
        ? await one('SELECT id, original_name FROM uploaded_files WHERE id=?', [id])
        : one('SELECT id, original_name FROM uploaded_files WHERE id=?', [id]);
      if (!row) return res.json({ fileId: null, url: null, name: null, allowPreview, allowDeny, uploadCompletionPdf });
      return res.json({
        fileId: row.id,
        url: `/api/files/${row.id}`,
        name: row.original_name || 'document.pdf',
        allowPreview,
        allowDeny,
        uploadCompletionPdf,
      });
    } catch (e) {
      res.status(500).json({ error: 'load_failed' });
    }
  });

  // --- Settings: Reminders (enable + frequency days) ---
  const getReminderSettings = async () => {
    const enabledRaw = await getSettingAsync('reminder_auto', process.env.REMINDER_AUTO ?? '1');
    const daysRaw = await getSettingAsync('reminder_days', process.env.REMINDER_DAYS ?? '3');
    const enabled = String(enabledRaw ?? '1').toLowerCase() === 'true' || String(enabledRaw ?? '1') === '1';
    const days = Number.isFinite(Number(daysRaw)) ? Math.max(1, Number(daysRaw)) : 3;
    return { enabled, days };
  };

  app.get('/api/settings/reminders', async (_req, res) => {
    try {
      const s = await getReminderSettings();
      res.json({ autoReminder: s.enabled, reminderDays: s.days });
    } catch (e) {
      res.status(500).json({ error: 'load_failed' });
    }
  });

  app.put('/api/settings/reminders', async (req, res) => {
    try {
      const autoReminder = !!(
        req.body && (req.body.autoReminder === true || String(req.body.autoReminder) === '1')
      );
      const daysRaw = req.body?.reminderDays;
      const days = Number.isFinite(Number(daysRaw)) ? Math.max(1, Number(daysRaw)) : 3;
      const ok1 = await setSettingAsync('reminder_auto', autoReminder ? '1' : '0');
      const ok2 = await setSettingAsync('reminder_days', String(days));
      if (!ok1 || !ok2) return res.status(500).json({ error: 'save_failed' });
      res.json({ autoReminder, reminderDays: days });
    } catch (e) {
      res.status(500).json({ error: 'save_failed' });
    }
  });
  // PUT /api/settings/legal-consent { fileId: number|null, allowPreview?: boolean, allowDeny?: boolean }
  app.put('/api/settings/legal-consent', async (req, res) => {
    try {
      // allowPreview/allowDeny persisted in settings table for admin control
      const allowPreviewRaw = req.body?.allowPreview;
      const allowDenyRaw = req.body?.allowDeny;
      const uploadCompletionPdfRaw = req.body?.uploadCompletionPdf;
      const currentAllowPreviewRaw = await getSettingAsync('legal_consent_allow_preview', '0');
      const currentAllowDenyRaw = await getSettingAsync('legal_consent_allow_deny', '0');
      const currentUploadCompletionPdfRaw = await getSettingAsync('upload_completion_pdf', '0');
      const allowPreview = allowPreviewRaw === undefined
        ? (String(currentAllowPreviewRaw || '0').toLowerCase() === 'true' || String(currentAllowPreviewRaw || '0') === '1')
        : (allowPreviewRaw === true || String(allowPreviewRaw) === '1');
      const allowDeny = allowDenyRaw === undefined
        ? (String(currentAllowDenyRaw || '0').toLowerCase() === 'true' || String(currentAllowDenyRaw || '0') === '1')
        : (allowDenyRaw === true || String(allowDenyRaw) === '1');
      const uploadCompletionPdf = uploadCompletionPdfRaw === undefined
        ? (String(currentUploadCompletionPdfRaw || '0').toLowerCase() === 'true' || String(currentUploadCompletionPdfRaw || '0') === '1')
        : (uploadCompletionPdfRaw === true || String(uploadCompletionPdfRaw) === '1');

      const raw = req.body && req.body.fileId !== undefined ? req.body.fileId : null;
      if (raw == null || raw === '') {
        const isFirebase = db && (db.driver === 'firebase' || db.driver === 'rtdb');
        if (isFirebase) {
          try {
            await db.run('DELETE FROM app_settings WHERE key=?', ['legal_consent_file_id']);
          } catch {}
        } else {
          const ok0 = setSetting('legal_consent_file_id', '');
          if (!ok0) return res.status(500).json({ error: 'save_failed' });
        }
        const okPrev = await setSettingAsync('legal_consent_allow_preview', allowPreview ? '1' : '0');
        const okDeny = await setSettingAsync('legal_consent_allow_deny', allowDeny ? '1' : '0');
        const okUpload = await setSettingAsync('upload_completion_pdf', uploadCompletionPdf ? '1' : '0');
        if (!okPrev || !okDeny || !okUpload) return res.status(500).json({ error: 'save_failed' });
        return res.json({ fileId: null, url: null, name: null, allowPreview, allowDeny, uploadCompletionPdf });
      }
      const isFirebase = db && (db.driver === 'firebase' || db.driver === 'rtdb');
      const id = isFirebase ? String(raw) : Number(raw);
      if (!isFirebase && !Number.isFinite(id))
        return res.status(400).json({ error: 'invalid_file_id' });
      const row = isFirebase
        ? await one('SELECT id, original_name FROM uploaded_files WHERE id=?', [id])
        : one('SELECT id, original_name FROM uploaded_files WHERE id=?', [id]);
      if (!row) return res.status(404).json({ error: 'file_not_found' });
      const ok = await setSettingAsync('legal_consent_file_id', String(row.id));
      const okPrev = await setSettingAsync('legal_consent_allow_preview', allowPreview ? '1' : '0');
      const okDeny = await setSettingAsync('legal_consent_allow_deny', allowDeny ? '1' : '0');
      const okUpload = await setSettingAsync('upload_completion_pdf', uploadCompletionPdf ? '1' : '0');
      if (!ok || !okPrev || !okDeny || !okUpload) return res.status(500).json({ error: 'save_failed' });
      res.json({
        fileId: row.id,
        url: `/api/files/${row.id}`,
        name: row.original_name || 'document.pdf',
        allowPreview,
        allowDeny,
        uploadCompletionPdf,
      });
    } catch (e) {
      res.status(500).json({ error: 'save_failed' });
    }
  });

  // Customization Requests
  app.post('/api/customization-requests', (req, res) => {
    try {
      const tenantId = req?.tenant?.id || null;
      if (!tenantId) return res.status(400).json({ error: 'tenant_unresolved' });
      const {
        contactName = null,
        contactEmail = null,
        contactPhone = null,
        description = null,
        scope = null,
        priority = 'normal',
      } = req.body || {};
      if (!description || String(description).trim().length < 5)
        return res.status(400).json({ error: 'description_required' });
      db.run(
        `INSERT INTO customization_requests (tenant_id, contact_name, contact_email, contact_phone, description, scope, priority, status)
              VALUES (?, ?, ?, ?, ?, ?, ?, 'open')`,
        [
          tenantId,
          contactName,
          contactEmail,
          contactPhone,
          String(description).trim(),
          scope,
          priority,
        ]
      );
      const id = one('SELECT last_insert_rowid() as id')?.id;
      persist(db);
      res.json({ id });
    } catch (e) {
      res.status(500).json({ error: 'create_failed' });
    }
  });
  app.get('/api/admin/customization-requests', (req, res) => {
    try {
      const tenantId = req.query.tenantId ? Number(req.query.tenantId) : null;
      const where = tenantId ? 'WHERE cr.tenant_id=?' : '';
      const params = tenantId ? [tenantId] : [];
      const rows = all(
        `SELECT cr.id, cr.tenant_id as tenantId, t.name as tenantName, cr.contact_name as contactName, cr.contact_email as contactEmail,
                cr.contact_phone as contactPhone, cr.description, cr.scope, cr.priority, cr.status, cr.created_at as createdAt
         FROM customization_requests cr
         JOIN tenants t ON t.id=cr.tenant_id
         ${where}
         ORDER BY cr.id DESC`,
        params
      );
      res.json({ requests: rows });
    } catch (e) {
      res.status(500).json({ error: 'list_failed' });
    }
  });

  app.post('/api/notification-emails', (req, res) => {
    const emails = Array.isArray(req.body.emails) ? req.body.emails : [];
    try {
      db.run('BEGIN');
      db.run('DELETE FROM notification_emails');
      for (const email of emails) {
        if (typeof email === 'string' && email.includes('@')) {
          db.run('INSERT OR IGNORE INTO notification_emails (email) VALUES (?)', [
            email.trim().toLowerCase(),
          ]);
        }
      }
      db.run('COMMIT');
      persist(db);
      res.json({ success: true });
    } catch (e) {
      try {
        db.run('ROLLBACK');
      } catch {}
      res
        .status(500)
        .json({ error: 'Failed to save notification emails', details: e?.message || e });
    }
  });

  // Optional: seed a default business only when explicitly enabled
  try {
    if (String(process.env.AUTO_SEED_DEFAULT_BUSINESS || '').trim() === '1') {
      const cnt = one('SELECT COUNT(*) as c FROM businesses')?.c || 0;
      if (cnt === 0) {
        db.run('INSERT INTO businesses (name, code, isActive, description) VALUES (?, ?, ?, ?)', [
          'Default Business',
          'DEF',
          1,
          'Auto-created',
        ]);
        persist(db);
      }
    }
  } catch (e) {
    console.warn('Business seed check failed (non-fatal):', e);
  }

  // Routes
  // OpenAPI schema endpoint and Swagger UI (read-only; no auth required)
  try {
    const YAML = require('yamljs');
    const swaggerUi = require('swagger-ui-express');
    const spec = YAML.load(path.join(__dirname, 'openapi.yaml'));
    app.get('/api/openapi.json', (_req, res) => res.json(spec));
    app.use('/api/docs', swaggerUi.serve, swaggerUi.setup(spec));
  } catch {}
  // RBAC: permissions catalog
  app.get('/api/rbac/permissions', (_req, res) => {
    res.json(PERMISSIONS);
  });
  // RBAC: role permissions (get)
  app.get('/api/rbac/role-permissions', async (req, res) => {
    try {
      const role = (req.query.role || '').toString();
      const maybe = role
        ? all('SELECT role, permKey, value FROM role_permissions WHERE role=?', [role])
        : all('SELECT role, permKey, value FROM role_permissions');
      const rows = maybe && typeof maybe.then === 'function' ? await maybe : maybe || [];
      res.json(
        (Array.isArray(rows) ? rows : []).map((r) => ({
          role: r.role,
          permKey: r.permKey,
          value: !!r.value,
        }))
      );
    } catch (e) {
      res.status(500).json({ error: 'list_failed', details: e?.message || String(e) });
    }
  });
  // RBAC: role permissions (set mapping for a role)
  app.put('/api/rbac/role-permissions', (req, res) => {
    try {
      // Require SuperAdmin via header/query for modifying RBAC
      try {
        const hdr = (req.headers['x-user-email'] || req.headers['x-admin-email'] || '')
          .toString()
          .trim()
          .toLowerCase();
        const qp = (req.query && req.query.adminEmail ? String(req.query.adminEmail) : '')
          .trim()
          .toLowerCase();
        const email = hdr || qp || '';
        const roles = resolveUserRoles(email, db);
        if (!roles.includes('SuperAdmin'))
          return res.status(403).json({ error: 'forbidden', reason: 'superadmin_required' });
      } catch {}
      const { role, mapping } = req.body || {};
      if (!role || typeof mapping !== 'object')
        return res.status(400).json({ error: 'invalid_payload' });
      db.run('BEGIN');
      try {
        // Upsert each perm
        for (const p of PERMISSIONS) {
          if (!(p.key in mapping)) continue;
          const val = mapping[p.key] ? 1 : 0;
          db.run(
            'INSERT INTO role_permissions (role, permKey, value) VALUES (?, ?, ?) ON CONFLICT(LOWER(role), permKey) DO UPDATE SET value=excluded.value',
            [role, p.key, val]
          );
        }
        db.run('COMMIT');
        persist(db);
        res.json({ ok: true });
      } catch (e) {
        try {
          db.run('ROLLBACK');
        } catch {}
        throw e;
      }
    } catch (e) {
      console.error('role-permissions update failed', e);
      res.status(500).json({ error: 'update_failed' });
    }
  });
  // RBAC: user permissions (get)
  app.get('/api/rbac/user-permissions', (req, res) => {
    const email = (req.query.email || '').toString().trim().toLowerCase();
    const rows = email
      ? all('SELECT email, permKey, value FROM user_permissions WHERE LOWER(email)=LOWER(?)', [
          email,
        ])
      : all('SELECT email, permKey, value FROM user_permissions');
    res.json(
      rows.map((r) => ({
        email: (r.email || '').toLowerCase(),
        permKey: r.permKey,
        value: !!r.value,
      }))
    );
  });
  // RBAC: user permissions (set mapping for a user)
  app.put('/api/rbac/user-permissions', (req, res) => {
    try {
      // Require SuperAdmin via header/query for modifying RBAC
      try {
        const hdr = (req.headers['x-user-email'] || req.headers['x-admin-email'] || '')
          .toString()
          .trim()
          .toLowerCase();
        const qp = (req.query && req.query.adminEmail ? String(req.query.adminEmail) : '')
          .trim()
          .toLowerCase();
        const email = hdr || qp || '';
        const roles = resolveUserRoles(email, db);
        if (!roles.includes('SuperAdmin'))
          return res.status(403).json({ error: 'forbidden', reason: 'superadmin_required' });
      } catch {}
      const { email, mapping } = req.body || {};
      const e = String(email || '')
        .trim()
        .toLowerCase();
      if (!e || !e.includes('@') || typeof mapping !== 'object')
        return res.status(400).json({ error: 'invalid_payload' });
      db.run('BEGIN');
      try {
        for (const p of PERMISSIONS) {
          if (!(p.key in mapping)) continue;
          const val = mapping[p.key] ? 1 : 0;
          db.run(
            'INSERT INTO user_permissions (email, permKey, value) VALUES (?, ?, ?) ON CONFLICT(LOWER(email), permKey) DO UPDATE SET value=excluded.value',
            [e, p.key, val]
          );
        }
        db.run('COMMIT');
        persist(db);
        res.json({ ok: true });
      } catch (e) {
        try {
          db.run('ROLLBACK');
        } catch {}
        throw e;
      }
    } catch (e) {
      console.error('user-permissions update failed', e);
      res.status(500).json({ error: 'update_failed' });
    }
  });
  // RBAC: effective permissions for a user (email required)
  app.get('/api/rbac/effective', async (req, res) => {
    try {
      const email = (req.query.email || '').toString().trim().toLowerCase();
      if (!email || !email.includes('@')) return res.status(400).json({ error: 'email_required' });
      const roles = resolveUserRoles(email, db) || ['Employee'];
      // SuperAdmin shortcut: everything true
      const effective = {};
      for (const p of PERMISSIONS) effective[p.key] = false;
      if (roles.includes('SuperAdmin')) {
        for (const p of PERMISSIONS) effective[p.key] = true;
        return res.json({ roles, permissions: effective });
      }
      // Apply role defaults/mapping
      let roleRows = [];
      try {
        if (Array.isArray(roles) && roles.length > 0) {
          const maybe = all(
            'SELECT role, permKey, value FROM role_permissions WHERE LOWER(role) IN (' +
              roles.map(() => 'LOWER(?)').join(',') +
              ')',
            roles
          );
          roleRows = (maybe && typeof maybe.then === 'function') ? await maybe : (maybe || []);
        }
      } catch {}
      for (const r of roleRows) {
        effective[r.permKey] = effective[r.permKey] || !!r.value; // OR semantics across roles
      }
      // Apply user overrides (can set true/false explicitly)
      let userRows = [];
      try {
        const maybe = all(
          'SELECT permKey, value FROM user_permissions WHERE LOWER(email)=LOWER(?)',
          [email]
        );
        userRows = (maybe && typeof maybe.then === 'function') ? await maybe : (maybe || []);
      } catch {}
      for (const u of userRows) {
        effective[u.permKey] = !!u.value;
      }
      res.json({ roles, permissions: effective });
    } catch (e) {
      console.error('effective perms failed', e);
      const env = String(process.env.NODE_ENV || '').toLowerCase();
      const payload = env === 'production' ? { error: 'failed' } : { error: 'failed', details: e?.message || String(e) };
      res.status(500).json(payload);
    }
  });
  // Diagnostics: expose current DB driver (sqlite, firebase, libsql, etc.)
  app.get('/api/diag/db', async (_req, res) => {
    try {
      const driver = db && db.driver ? String(db.driver) : 'unknown';
      // simple canary query to ensure adapter responds (non-fatal if it fails)
      let canary = null;
      try {
        if (db && typeof db.query === 'function') {
          const maybe = db.query('SELECT 1 as ok');
          const rs = maybe && typeof maybe.then === 'function' ? await maybe : maybe;
          if (Array.isArray(rs) && rs.length > 0) canary = rs[0];
        }
      } catch {}
      res.json({ driver, canary });
    } catch {
      res.json({ driver: 'unknown' });
    }
  });
  app.get('/api/diag/routes', (_req, res) => {
    try {
      const out = [];
      const stack = app && app._router && Array.isArray(app._router.stack) ? app._router.stack : [];
      for (const layer of stack) {
        if (layer && layer.route && layer.route.path) {
          const methods = Object.keys(layer.route.methods || {}).map((m) => m.toUpperCase());
          out.push({ methods, path: layer.route.path });
        }
      }
      res.json({ routes: out });
    } catch (e) {
      res.status(500).json({ error: 'failed' });
    }
  });

  // Dev-only: grant SuperAdmin to a user by email (local use only)
  app.post('/api/dev/grant-superadmin', (req, res) => {
    try {
      const env = String(process.env.NODE_ENV || '').toLowerCase();
      if (env === 'production') return res.status(403).json({ error: 'forbidden' });
      const email = (req.body?.email || req.query?.email || '')
        .toString()
        .trim()
        .toLowerCase();
      if (!email || !email.includes('@')) return res.status(400).json({ error: 'email_required' });
      try {
        db.run(
          'INSERT INTO roles (email, role) VALUES (?, ?) ',
          [email, 'SuperAdmin']
        );
      } catch (e) {
        try {
          db.run('CREATE TABLE IF NOT EXISTS roles (id INTEGER PRIMARY KEY AUTOINCREMENT, email TEXT, role TEXT)');
          db.run('INSERT INTO roles (email, role) VALUES (?, ?)', [email, 'SuperAdmin']);
        } catch (ee) {
          return res.status(500).json({ error: 'grant_failed', details: ee?.message || String(ee) });
        }
      }
      persist(db);
      return res.json({ ok: true, email, role: 'SuperAdmin' });
    } catch (e) {
      return res.status(500).json({ error: 'failed' });
    }
  });

  // Admin: trigger digest notifications (daily/weekly) for policy subscribers
  app.post('/api/admin/notifications/digest', async (req, res) => {
    try {
      // Requires SuperAdmin via adminGuard on /api/admin
      const freq = String(req.query.freq || req.body?.frequency || 'daily').toLowerCase();
      const lookbackDays = freq === 'weekly' ? 7 : 1;
      // Policies with any subscriptions of the requested frequency
      const subsMaybe = all(
        `SELECT DISTINCT policy_rule_id as policyId FROM notification_subscriptions WHERE enabled=1 AND LOWER(frequency)=LOWER(?)`,
        [freq]
      );
      const subPolicies = subsMaybe && typeof subsMaybe.then === 'function' ? await subsMaybe : subsMaybe || [];
      if (!Array.isArray(subPolicies) || subPolicies.length === 0) return res.json({ sent: 0 });
      const policyIds = subPolicies.map((r) => r.policyId);
      const placeholders = policyIds.map(() => '?').join(',');
      // For each policy, compute acks in lookback window
      const nowIso = new Date().toISOString();
      const sinceExpr = `datetime('now','-${lookbackDays} day')`;
      const ackRows = all(
        `SELECT pr.id as policyId, COUNT(DISTINCT a.email || ':' || d.localFileId) as cnt
         FROM policy_rules pr
         LEFT JOIN policy_rule_files prf ON prf.policy_rule_id=pr.id
         JOIN documents d ON (d.localFileId = pr.file_id OR d.localFileId = prf.file_id)
         JOIN acks a ON a.documentId=d.id AND a.acknowledged=1 AND a.ackDate >= ${sinceExpr}
         WHERE pr.id IN (${placeholders})
         GROUP BY pr.id`,
        policyIds
      );
      const counts = ackRows && typeof ackRows.then === 'function' ? await ackRows : ackRows || [];
      const byPolicy = new Map(counts.map((r) => [String(r.policyId), Number(r.cnt || 0)]));
      const subsRows = all(
        `SELECT policy_rule_id as policyId, target_type as targetType, target
         FROM notification_subscriptions
         WHERE enabled=1 AND LOWER(frequency)=LOWER(?) AND policy_rule_id IN (${placeholders})`,
        [freq, ...policyIds]
      );
      const subs = subsRows && typeof subsRows.then === 'function' ? await subsRows : subsRows || [];
      const mailer = (function () { try { return require('./src/services/mailer'); } catch { return null; } })();
      let sent = 0;
      for (const s of subs) {
        const pid = s.policyId;
        const count = byPolicy.get(String(pid)) || 0;
        if (String(s.targetType).toLowerCase() === 'email') {
          try {
            const subject = `[${freq.toUpperCase()}] Policy #${pid} acknowledgements: ${count}`;
            const html = `<div style="font-family:Segoe UI,Tahoma,Arial,sans-serif"><h3>${freq.toUpperCase()} Digest</h3><p>Policy <b>#${pid}</b> received <b>${count}</b> acknowledgements in the last ${lookbackDays} day(s).</p><p>Generated at ${nowIso}</p></div>`;
            const text = `Policy #${pid} received ${count} acknowledgements in the last ${lookbackDays} day(s). Generated at ${nowIso}.`;
            if (mailer && typeof mailer.sendHtml === 'function') await mailer.sendHtml(String(s.target), subject, html, text);
            else console.log(`[POLICY:DIGEST:FALLBACK] To: ${s.target} :: ${text}`);
            sent += 1;
          } catch {}
        } else if (String(s.targetType).toLowerCase() === 'webhook') {
          try {
            const targetUrl = new URL(String(s.target));
            const client = targetUrl.protocol === 'https:' ? require('https') : require('http');
            const payload = JSON.stringify({ event: 'policy_digest', frequency: freq, policyId: pid, count, generatedAt: nowIso });
            await new Promise((resolve) => {
              const req2 = client.request(targetUrl, { method: 'POST', headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(payload) } }, (up) => { up.on('data', () => {}); up.on('end', resolve); });
              req2.on('error', () => resolve());
              req2.write(payload);
              req2.end();
            });
            sent += 1;
          } catch {}
        }
      }
      res.json({ sent, policies: policyIds.length, frequency: freq });
    } catch (e) {
      res.status(500).json({ error: 'digest_failed' });
    }
  });

  // Admin: seed a small demo for owners/HR/batch subscriptions
  app.post('/api/admin/seed/demo', async (req, res) => {
    try {
      const tenantId = req?.tenant?.id || null;
      const ownerEmail = String(req.body?.ownerEmail || 'owner@company.com').toLowerCase();
      const hrEmail = String(req.body?.hrEmail || 'hr.admin@company.com').toLowerCase();
      const now = new Date().toISOString();

      // 1) Add a demo uploaded file
      await db.run(
        `INSERT INTO uploaded_files (original_name, stored_name, rel_path, size, mime, sha256, uploaded_at, uploaded_by, source_type)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        ['Demo Policy.pdf', 'demo-policy.pdf', 'uploads/demo-policy.pdf', 12345, 'application/pdf', 'demo-sha256', now, ownerEmail, 'local']
      );
      const fileId = (await db.query('SELECT last_insert_rowid() as id'))[0].id;

      // 2) Create a demo policy rule + mapping
      await db.run(
        `INSERT INTO policy_rules (tenant_id, name, description, frequency, required, file_id, sha256, active, start_on, due_in_days, grace_days, created_at, updated_at)
         VALUES (?, ?, ?, 'annual', 1, ?, ?, 1, ?, 30, 7, ?, ?)`,
        [tenantId, 'Demo Policy', 'Seeded for demo', fileId, 'demo-sha256', now.slice(0,10), now, now]
      );
      const policyId = (await db.query('SELECT last_insert_rowid() as id'))[0].id;
      await db.run('INSERT OR IGNORE INTO policy_rule_files (policy_rule_id, file_id, sha256) VALUES (?, ?, ?)', [policyId, fileId, 'demo-sha256']);

      // 3) Owner + scope + policy subscriptions
      await db.run(
        'INSERT OR IGNORE INTO policy_owners (policy_rule_id, owner_email, owner_name, role, created_at) VALUES (?, ?, ?, ?, ?)',
        [policyId, ownerEmail, 'Demo Owner', 'OwnerAdmin', now]
      );
      const ownerRow = one('SELECT id FROM policy_owners WHERE policy_rule_id=? AND LOWER(owner_email)=LOWER(?)', [policyId, ownerEmail]);
      if (ownerRow?.id) {
        await db.run('INSERT INTO policy_owner_scopes (policy_owner_id, scope_type, scope_value) VALUES (?, ?, ?)', [ownerRow.id, 'department', 'HR']);
      }
      await db.run(
        'INSERT INTO notification_subscriptions (policy_rule_id, target_type, target, frequency, enabled) VALUES (?, ?, ?, ?, 1)',
        [policyId, 'email', hrEmail, 'instant']
      );

      // 4) Create a demo batch with the demo file as a document
      await db.run(
        'INSERT INTO batches (name, startDate, dueDate, status, description) VALUES (?, ?, NULL, 1, ?)',
        ['Demo Batch', now.slice(0,10), 'Seeded batch']
      );
      const batchId = (await db.query('SELECT last_insert_rowid() as id'))[0].id;
      const localUrl = `/api/files/${fileId}`;
      await db.run(
        'INSERT INTO documents (batchId, title, url, version, requiresSignature, source, localFileId, localUrl) VALUES (?, ?, ?, 1, 0, ?, ?, ?)',
        [batchId, 'Demo Policy Document', localUrl, 'local', fileId, localUrl]
      );
      // Recipients
      await db.run(
        'INSERT INTO recipients (batchId, businessId, user, email, displayName, department, jobTitle, location, primaryGroup) VALUES (?, NULL, ?, ?, ?, ?, ?, ?, ?)',
        [batchId, 'user1@example.com', 'user1@example.com', 'User One', 'HR', 'Analyst', 'NY', 'HR-Global']
      );
      await db.run(
        'INSERT INTO recipients (batchId, businessId, user, email, displayName, department, jobTitle, location, primaryGroup) VALUES (?, NULL, ?, ?, ?, ?, ?, ?, ?)',
        [batchId, 'user2@example.com', 'user2@example.com', 'User Two', 'HR', 'Manager', 'LDN', 'HR-Global']
      );
      // Batch subscriptions
      await db.run(
        'INSERT INTO batch_subscriptions (batch_id, target_type, target, frequency, enabled) VALUES (?, ?, ?, ?, 1)',
        [batchId, 'email', hrEmail, 'instant']
      );
      await db.run(
        'INSERT INTO batch_subscriptions (batch_id, target_type, target, frequency, enabled) VALUES (?, ?, ?, ?, 1)',
        [batchId, 'email', ownerEmail, 'instant']
      );

      // 5) Seed an approved submission to drive Create Batch UI
      await db.run(
        `INSERT INTO policy_submissions (tenant_id, title, description, source_type, file_id, status, owner_email, submitted_by, submitted_at, reviewed_by, reviewed_at)
         VALUES (?, ?, ?, 'upload', ?, 'approved', ?, ?, ?, ?, ?)`,
        [tenantId, 'Approved Demo Policy', 'Approved for batch', fileId, ownerEmail, ownerEmail, now, hrEmail, now]
      );

      persist(db);
      res.json({ ok: true, fileId, policyId, batchId, ownerEmail, hrEmail });
    } catch (e) {
      res.status(500).json({ error: 'seed_failed', details: e?.message || String(e) });
    }
  });
  // Health
  app.get('/api/health', (_req, res) => res.json({ ok: true }));
  // UI runtime settings (placeholder for branding/theme overrides)
  app.get('/api/ui/settings', (_req, res) => res.json({}));
  // Root helper
  app.get('/', (_req, res) => {
    res
      .type('text/plain')
      .send(
        'Sunbeth SQLite API is running.\n' +
          'Try GET /api/health or call the app at http://localhost:3000.\n' +
          'Available endpoints: /api/batches, /api/batches/:id/documents, /api/batches/:id/acks, /api/batches/:id/progress, /api/ack, /api/seed'
      );
  });

  // Ensure user_businesses table exists (id, email, businessId, assignedAt)
  try {
    db.run(
      'CREATE TABLE IF NOT EXISTS user_businesses (\n' +
        '  id INTEGER PRIMARY KEY AUTOINCREMENT,\n' +
        '  email TEXT NOT NULL,\n' +
        '  businessId INTEGER NOT NULL,\n' +
        "  assignedAt TEXT NOT NULL DEFAULT (datetime('now'))\n" +
      ')'
    );
    // index for lookups
    try { db.run('CREATE INDEX IF NOT EXISTS idx_user_businesses_email ON user_businesses(LOWER(email))'); } catch {}
    try { db.run('CREATE INDEX IF NOT EXISTS idx_user_businesses_business ON user_businesses(businessId)'); } catch {}
    persist(db);
  } catch {}

  // Public: list active businesses for user selection
  app.get('/api/businesses/active', async (req, res) => {
    try {
      const maybeRows = all('SELECT id, name FROM businesses WHERE COALESCE(isActive,1)=1 ORDER BY name ASC');
      const rows = (maybeRows && typeof maybeRows.then === 'function') ? await maybeRows : (maybeRows || []);
      res.json({ businesses: (rows || []).map(r => ({ id: r.id, name: r.name })) });
    } catch (e) {
      res.status(500).json({ error: 'list_failed' });
    }
  });

  // Persist user -> business selection (best-effort, idempotent by latest write)
  app.put('/api/users/:email/business', async (req, res) => {
    try {
      const emailRaw = String(req.params.email || '').trim().toLowerCase();
      const businessIdRaw = req.body?.businessId;
      const businessIdNum = Number(businessIdRaw);
      const businessId = Number.isNaN(businessIdNum) ? String(businessIdRaw) : businessIdNum;
      if (!emailRaw || !emailRaw.includes('@')) return res.status(400).json({ error: 'email_invalid' });
      if (businessId == null || (typeof businessId === 'number' && (!businessId || Number.isNaN(businessId)))) return res.status(400).json({ error: 'businessId_invalid' });

      const maybeExists = one('SELECT id FROM businesses WHERE id=? AND COALESCE(isActive,1)=1', [businessId]);
      const exists = (maybeExists && typeof maybeExists.then === 'function') ? await maybeExists : maybeExists;
      if (!exists) return res.status(404).json({ error: 'business_not_found' });
      // upsert semantics: keep only latest mapping for the email; support async adapters
      try {
        const delMaybe = db.run('DELETE FROM user_businesses WHERE LOWER(email)=LOWER(?)', [emailRaw]);
        if (delMaybe && typeof delMaybe.then === 'function') await delMaybe;
      } catch {}
      const insMaybe = db.run('INSERT INTO user_businesses (email, businessId, assignedAt) VALUES (?, ?, datetime("now"))', [emailRaw, businessId]);
      if (insMaybe && typeof insMaybe.then === 'function') await insMaybe;
      persist(db);
      res.json({ ok: true });
    } catch (e) {
      res.status(500).json({ error: 'save_failed' });
    }
  });

  // Stats for dashboards/overview (supports filters via query: businessId, department, primaryGroup)
  app.get('/api/stats', async (req, res) => {
    const filters = [];
    const params = [];
    // Guardrails for RTDB: defaults capped
    const limitTrend = Math.max(1, Math.min(Number(req.query.limit || 30), 60));
    const windowDays = Math.max(1, Math.min(Number(req.query.windowDays || 30), 90));
    const hasFilters = () => filters.length > 0;
    if (req.query.businessId) {
      filters.push('r.businessId = ?');
      params.push(String(req.query.businessId));
    }
    if (req.query.department) {
      filters.push('LOWER(r.department) = ?');
      params.push(String(req.query.department).toLowerCase());
    }
    if (req.query.primaryGroup) {
      filters.push('LOWER(r.primaryGroup) = ?');
      params.push(String(req.query.primaryGroup).toLowerCase());
    }
    const where = hasFilters() ? `WHERE ${filters.join(' AND ')}` : '';
    const isFirebase = db && (db.driver === 'firebase' || db.driver === 'rtdb');

    if (isFirebase) {
      if (!hasFilters()) {
        const cached = readJsonCache('stats_cache');
        if (cached) return res.json(cached);
      }
      // Fetch tables and compute in JS
      const [recRowsMaybe, ackRowsMaybe, batchRowsMaybe, docsRowsMaybe] = [
        all('SELECT id, batchId, businessId, email, department, primaryGroup FROM recipients'),
        all('SELECT batchId, email, acknowledged, documentId FROM acks'),
        all('SELECT id, status FROM batches'),
        all('SELECT id, batchId FROM documents'),
      ];
      const recRows =
        recRowsMaybe && typeof recRowsMaybe.then === 'function'
          ? await recRowsMaybe
          : recRowsMaybe || [];
      const ackRows =
        ackRowsMaybe && typeof ackRowsMaybe.then === 'function'
          ? await ackRowsMaybe
          : ackRowsMaybe || [];
      const batchRows =
        batchRowsMaybe && typeof batchRowsMaybe.then === 'function'
          ? await batchRowsMaybe
          : batchRowsMaybe || [];
      const docRows =
        docsRowsMaybe && typeof docsRowsMaybe.then === 'function'
          ? await docsRowsMaybe
          : docsRowsMaybe || [];

      const matchFilters = (r) => {
        if (req.query.businessId && String(r.businessId) !== String(req.query.businessId))
          return false;
        if (
          req.query.department &&
          String(r.department || '').toLowerCase() !== String(req.query.department).toLowerCase()
        )
          return false;
        if (
          req.query.primaryGroup &&
          String(r.primaryGroup || '').toLowerCase() !==
            String(req.query.primaryGroup).toLowerCase()
        )
          return false;
        return true;
      };
      const recipients = recRows.filter(matchFilters);
      const totalRecipients = recipients.length;
      // Assignment-based completion: denominator = total assignments (recipients x docs per batch), numerator = acknowledged acks matching those assignments
      const docsPerBatch = new Map();
      for (const d of docRows) {
        const k = String(d.batchId);
        docsPerBatch.set(k, (docsPerBatch.get(k) || 0) + 1);
      }
      const recsPerBatch = new Map();
      for (const r of recipients) {
        const k = String(r.batchId);
        recsPerBatch.set(k, (recsPerBatch.get(k) || 0) + 1);
      }
      let totalAssignments = 0;
      for (const [batchId, rc] of recsPerBatch.entries()) {
        const dc = Number(docsPerBatch.get(String(batchId)) || 0);
        totalAssignments += rc * dc;
      }
      const ackTrueAssignments = ackRows
        .filter((a) => a.acknowledged)
        .filter((a) =>
          recipients.some(
            (r) =>
              String(r.batchId) === String(a.batchId) &&
              String(r.email || '').toLowerCase() === String(a.email || '').toLowerCase()
          )
        ).length;
      const completionRate =
        totalAssignments > 0 ? Math.round((ackTrueAssignments / totalAssignments) * 1000) / 10 : 0;
      const totalBatches = new Set(recipients.map((r) => String(r.batchId))).size;
      const activeBatchIds = new Set(
        batchRows.filter((b) => Number(b.status) === 1).map((b) => String(b.id))
      );
      const activeBatches = new Set(
        recipients.map((r) => String(r.batchId)).filter((id) => activeBatchIds.has(id))
      ).size;
      const payload = {
        totalBatches,
        activeBatches,
        totalUsers: totalRecipients,
        totalAssignments,
        completionRate,
        overdueBatches: 0,
        avgCompletionTime: 0,
      };
      if (!hasFilters()) writeJsonCache('stats_cache', payload);
      return res.json(payload);
    }

    // Default (SQL) path
    let totalRecipients = 0;
    const maybeTR0 = hasFilters()
      ? one(`SELECT COUNT(*) as c FROM recipients r ${where}`, params)
      : one('SELECT COUNT(*) as c FROM recipients');
    const tr0 = maybeTR0 && typeof maybeTR0.then === 'function' ? await maybeTR0 : maybeTR0;
    totalRecipients = tr0?.c || 0;

    // Assignment-based totals (recipients x docs per batch)
    let totalAssignments = 0;
    if (hasFilters()) {
      const maybeTA = one(
        `SELECT COUNT(*) as c
         FROM recipients r
         JOIN documents d ON d.batchId = r.batchId
         ${where}`,
        params
      );
      const ta = maybeTA && typeof maybeTA.then === 'function' ? await maybeTA : maybeTA;
      totalAssignments = ta?.c || 0;
    } else {
      const maybeTA2 = one(
        'SELECT COUNT(*) as c FROM recipients r JOIN documents d ON d.batchId = r.batchId'
      );
      const ta2 = maybeTA2 && typeof maybeTA2.then === 'function' ? await maybeTA2 : maybeTA2;
      totalAssignments = ta2?.c || 0;
    }

    // Completed assignments = acknowledged acks that match a recipient
    const maybeA = hasFilters()
      ? one(
          `SELECT COUNT(*) as c FROM acks a
           JOIN recipients r ON r.batchId=a.batchId AND LOWER(r.email)=LOWER(a.email)
           ${where} AND a.acknowledged=1`,
          params
        )
      : one(
          `SELECT COUNT(*) as c FROM acks a JOIN recipients r ON r.batchId=a.batchId AND LOWER(r.email)=LOWER(a.email) WHERE a.acknowledged=1`
        );
    const a = maybeA && typeof maybeA.then === 'function' ? await maybeA : maybeA;
    const ackTrueAssignments = a?.c || 0;

    const completionRate =
      totalAssignments > 0 ? Math.round((ackTrueAssignments / totalAssignments) * 1000) / 10 : 0;

    let totalBatches = 0;
    let activeBatches = 0;
    if (hasFilters()) {
      const maybeTB = one(
        `SELECT COUNT(DISTINCT r.batchId) as c FROM recipients r ${where}`,
        params
      );
      const tb = maybeTB && typeof maybeTB.then === 'function' ? await maybeTB : maybeTB;
      totalBatches = tb?.c || 0;
      const maybeAB = one(
        `SELECT COUNT(DISTINCT r.batchId) as c FROM recipients r JOIN batches b ON b.id=r.batchId ${where} AND b.status=1`,
        params
      );
      const ab = maybeAB && typeof maybeAB.then === 'function' ? await maybeAB : maybeAB;
      activeBatches = ab?.c || 0;
    } else {
      const maybeTB2 = one('SELECT COUNT(*) as c FROM batches');
      const tb2 = maybeTB2 && typeof maybeTB2.then === 'function' ? await maybeTB2 : maybeTB2;
      totalBatches = tb2?.c || 0;
      const maybeAB2 = one('SELECT COUNT(*) as c FROM batches WHERE status=1');
      const ab2 = maybeAB2 && typeof maybeAB2.then === 'function' ? await maybeAB2 : maybeAB2;
      activeBatches = ab2?.c || totalBatches;
    }

    res.json({
      totalBatches,
      activeBatches,
      totalUsers: totalRecipients,
      totalAssignments,
      completionRate,
      overdueBatches: 0,
      avgCompletionTime: 0,
    });
  });

  // Generate a PDF completion certificate (returns base64 in JSON)
  app.post('/api/certificates/pdf', express.json({ limit: '1mb' }), async (req, res) => {
    try {
      const {
        batchName,
        userEmail,
        userName,
        completedOn,
        documents,
        department,
        jobTitle,
        location,
        businessName,
        primaryGroup,
        brandName,
        brandLogoUrl,
        brandPrimaryColor,
      } = req.body || {};
      // Optional: HTML+CSS path (only if explicitly requested via useHtml flag)
      try {
        if (!(req.body && req.body.useHtml === true)) throw new Error('skip_html');
        const puppeteer = require('puppeteer');
        const QRCode = require('qrcode');
        const htmlFromClient = (req.body && typeof req.body.htmlBody === 'string') ? String(req.body.htmlBody) : '';
        const isQuarter = (() => {
          const s = String((req.body && (req.body.pageSize || req.body.size)) || '').toLowerCase();
          return s.includes('quarter');
        })();
        const brand = String(brandName || 'Sunbeth');
        const primary = String(brandPrimaryColor || '#0a3d33');
        const displayName = String(userName || userEmail || 'User');
        const batch = String(batchName || 'Batch');
        const dt = new Date(completedOn || new Date().toISOString());
        const verifyUrl = (req.body && req.body.verifyUrl) ? String(req.body.verifyUrl) : '';
        const certificateId = (req.body && req.body.certificateId) ? String(req.body.certificateId) : '';
        const docs = Array.isArray(documents) ? documents.map((t) => String(t)).filter(Boolean) : [];
        const colCount = isQuarter ? 2 : 3;
        const maxRows = isQuarter ? 24 : 30; // approximate per-page fit
        const capacity = colCount * maxRows;
        const shownDocs = docs.slice(0, capacity);
        const leftover = Math.max(0, docs.length - shownDocs.length);

        const toDataUrl = async (src) => {
          try {
            if (!src) return '';
            const fs = require('fs'); const http = require('http'); const https = require('https');
            let buf = null; let ct = 'image/png';
            if (/^https?:\/\//i.test(src)) {
              const client = /^https:/i.test(src) ? https : http;
              buf = await new Promise((resolve) => {
                client.get(src, (resp) => { const parts = []; resp.on('data', (d) => parts.push(d)); resp.on('end', () => resolve(Buffer.concat(parts))); }).on('error', () => resolve(null));
              });
            } else if (fs.existsSync(src)) {
              buf = fs.readFileSync(src);
            }
            if (!buf) return '';
            try { if (/\.svg$/i.test(String(src))) ct = 'image/svg+xml'; } catch {}
            return 'data:' + ct + ';base64,' + buf.toString('base64');
          } catch { return ''; }
        };
        const logoDataUrl = await toDataUrl(String(brandLogoUrl || ''));
        const qrDataUrl = verifyUrl ? await QRCode.toDataURL(verifyUrl, { width: 240, margin: 1 }) : '';
        const itemsHtml = shownDocs.map((t, i) => '<div class="item">' + (i + 1) + '. ' + t.replace(/</g,'&lt;').replace(/>/g,'&gt;') + '</div>').join('');
        const tailHtml = '<div class="tail">… and ' + leftover + ' more</div>';
        // Page 1 (certificate) — based on provided prototype with fixed A4 box
        const html1 = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <title>Certificate</title>
  <style>
    @page { size: A4; margin: 0; }
    body { margin: 0; background: #ffffff; font-family: Inter, Arial, Helvetica, sans-serif; }
    .certificate { position: relative; width: 210mm; height: 297mm; margin: 0 auto; background: #ffffff; }
    .frame-outer { position: absolute; inset: 10mm; border: 4px solid #0f4c81; border-radius: 14px; }
    .frame-inner { position: absolute; inset: 16mm; border: 1px solid #0f172a; border-radius: 10px; }
    .watermark { position: absolute; inset: 0; display: flex; justify-content: center; align-items: center; font-size: 120px; font-weight: 700; color: #0f4c81; opacity: 0.04; transform: rotate(-30deg); pointer-events: none; }
    .header { position: absolute; top: 30mm; width: 100%; text-align: center; }
    .logo { max-height: 18mm; margin-bottom: 4mm; }
    .header h1 { margin: 0; font-size: 24px; color: #0f4c81; }
    .identity { position: absolute; top: 78mm; width: 100%; text-align: center; }
    .identity .name { font-size: 24px; font-weight: 700; color: #0f172a; }
    .identity .subtitle { margin-top: 4mm; font-size: 12px; font-style: italic; color: #475569; }
    .identity .batch { margin-top: 3mm; font-size: 18px; font-weight: 700; color: #0f4c81; }
    .identity .date { margin-top: 2mm; font-size: 11px; color: #64748b; }
    .grid { position: absolute; top: 135mm; left: 30mm; right: 30mm; display: grid; grid-template-columns: 40mm 1fr; row-gap: 4mm; }
    .grid span:first-child { font-weight: 600; color: #0f172a; }
    .grid span:last-child { color: #334155; }
    .email { word-break: break-word; }
    .footer { position: absolute; bottom: 45mm; left: 30mm; right: 30mm; display: grid; grid-template-columns: 1fr 1fr 1fr; align-items: center; }
    .qr img { width: 24mm; }
    .qr-text { font-size: 9px; color: #475569; }
    .seal { text-align: center; font-size: 14px; font-weight: 700; color: #0f4c81; border: 2px solid #0f4c81; padding: 8mm; border-radius: 50%; width: 32mm; height: 32mm; margin: auto; display: flex; align-items: center; justify-content: center; }
    .signature { text-align: center; font-size: 10px; color: #475569; }
    .signature .brand { font-weight: 600; }
    .cert-id { position: absolute; bottom: 20mm; width: 100%; text-align: center; font-size: 10px; color: #64748b; }
  </style>
</head>
<body>
  <div class="certificate">
    <div class="watermark">ACKNOWLEDGED</div>
    <div class="frame-outer"></div>
    <div class="frame-inner"></div>
    <header class="header">
      ${logoDataUrl ? '<img class="logo" src="' + logoDataUrl + '" alt="Logo" />' : ''}
      <h1>Certificate of Completion</h1>
    </header>
    <section class="identity">
      <div class="name">${displayName}</div>
      <div class="subtitle">has completed all required acknowledgements for</div>
      <div class="batch">${batch}</div>
      <div class="date">Completed on ${dt.toLocaleString()}</div>
    </section>
    <section class="grid">
      ${businessName ? '<div class="row"><span>Business</span><span>' + businessName + '</span></div>' : ''}
      ${department ? '<div class="row"><span>Department</span><span>' + department + '</span></div>' : ''}
      ${jobTitle ? '<div class="row"><span>Job Title</span><span>' + jobTitle + '</span></div>' : ''}
      ${location ? '<div class="row"><span>Location</span><span>' + location + '</span></div>' : ''}
      ${primaryGroup ? '<div class="row"><span>Primary Group</span><span>' + primaryGroup + '</span></div>' : ''}
      ${userEmail ? '<div class="row"><span>Email</span><span class="email">' + userEmail + '</span></div>' : ''}
    </section>
    <footer class="footer">
      <div class="qr">
        ${qrDataUrl ? '<img src="' + qrDataUrl + '" />' : ''}
        <div class="qr-text">Scan to verify</div>
      </div>
      <div class="seal">CERTIFIED</div>
      <div class="signature">
        <div class="brand">${brand}</div>
        <div class="sig-date">${dt.toLocaleDateString()}</div>
      </div>
    </footer>
    ${certificateId ? '<div class="cert-id">Certificate ID: ' + certificateId + '</div>' : ''}
  </div>
</body>
</html>`;
        // Page 2 (documents) — only when we have docs
        const html2 = shownDocs.length > 0 ? `<!doctype html>
<html>
<head>
  <meta charset="utf-8" />
  <title>Documents Acknowledged</title>
  <style>
    :root { --primary: ${primary}; --ink: #0f172a; --muted: #475569; }
    @page { size: ${isQuarter ? '105mm 148.5mm' : 'A4'}; margin: 0; }
    body { margin: 0; background: #fff; font-family: -apple-system, Segoe UI, Roboto, Helvetica, Arial, sans-serif; color: var(--ink); }
    .page { width: ${isQuarter ? '105mm' : '210mm'}; height: ${isQuarter ? '148.5mm' : '297mm'}; margin: 0 auto; overflow: hidden; }
    .listwrap { box-sizing: border-box; padding: ${isQuarter ? '10mm' : '16mm'}; height: 100%; }
    .listwrap h2 { margin: 0 0 ${isQuarter ? '4mm' : '8mm'} 0; font-size: ${isQuarter ? '14px' : '18px'}; color: var(--ink); text-align: left; }
    .cols { column-count: ${colCount}; column-gap: ${isQuarter ? '6mm' : '10mm'}; font-size: ${isQuarter ? '10px' : '12px'}; line-height: ${isQuarter ? '14px' : '16px'}; height: calc(100% - ${isQuarter ? '14mm' : '24mm'}); overflow: hidden; }
    .item { break-inside: avoid; margin: 0 0 ${isQuarter ? '2mm' : '3mm'} 0; color: #0f172a; }
    .tail { color: #64748b; font-size: ${isQuarter ? '10px' : '12px'}; margin-top: ${isQuarter ? '2mm' : '3mm'}; }
  </style>
  </head>
  <body>
    <div class="page">
      <div class="listwrap">
        <h2>Documents Acknowledged</h2>
        <div class="cols">${itemsHtml}${leftover > 0 ? tailHtml : ''}</div>
      </div>
    </div>
  </body>
  </html>` : '';
        const browser = await puppeteer.launch({ headless: 'new' });
        const page = await browser.newPage();
        try { await page.emulateMediaType('print'); } catch {}
        // Render page 1
        await page.setContent(html1, { waitUntil: 'networkidle0' });
        const pdfOpts1 = isQuarter
          ? { width: '105mm', height: '148.5mm', printBackground: true, preferCSSPageSize: true, margin: { top: '0mm', right: '0mm', bottom: '0mm', left: '0mm' }, pageRanges: '1' }
          : { format: 'A4', printBackground: true, preferCSSPageSize: true, margin: { top: '0mm', right: '0mm', bottom: '0mm', left: '0mm' }, pageRanges: '1' };
        const buf1 = await page.pdf(pdfOpts1);
        // Render page 2 when present
        let buf2 = null;
        if (html2) {
          await page.setContent(html2, { waitUntil: 'networkidle0' });
          const pdfOpts2 = pdfOpts1; // same size/margins
          buf2 = await page.pdf(pdfOpts2);
        }
        await browser.close();
        if (buf1 && Buffer.isBuffer(buf1)) {
          // Merge to a single 2-page PDF deterministically
          const { PDFDocument } = require('pdf-lib');
          const out = await PDFDocument.create();
          const one = await PDFDocument.load(buf1);
          const [p1] = await out.copyPages(one, [0]);
          out.addPage(p1);
          if (buf2 && Buffer.isBuffer(buf2)) {
            const two = await PDFDocument.load(buf2);
            const [p2] = await out.copyPages(two, [0]);
            out.addPage(p2);
          }
          const merged = await out.save();
          return res.json({
            contentBytes: Buffer.from(merged).toString('base64'),
            contentType: 'application/pdf',
            name: `${(batchName || 'certificate').toString().replace(/[^a-z0-9\-_. ]/gi,'_')}-${(userEmail || 'user').toString().replace(/[^a-z0-9\-_. ]/gi,'_')}.pdf`
          });
        }
      } catch { /* fall back to PDFKit below */ }
      const PDFDocument = require('pdfkit');
      const http = require('http');
      const https = require('https');
      const fs = require('fs');
      const QRCode = require('qrcode');
      const { randomUUID } = require('crypto');

      // Support quarter A4 if requested
      let pageSize = 'A4';
      try {
        const reqSize = (req.body && (req.body.pageSize || req.body.size || '')).toString().toLowerCase();
        if (reqSize === 'quarter' || reqSize === 'a4-quarter' || reqSize === 'quarter-a4') pageSize = [595.28/2, 841.89/2];
      } catch {}
      const doc = new PDFDocument({ size: pageSize, margin: 36 });
      const chunks = [];
      doc.on('data', (c) => chunks.push(c));
      doc.on('end', () => {
        const buff = Buffer.concat(chunks);
        res.json({
          contentBytes: buff.toString('base64'),
          contentType: 'application/pdf',
          name: `${(batchName || 'certificate').toString().replace(/[^a-z0-9\-_. ]/gi,'_')}-${(userEmail || 'user').toString().replace(/[^a-z0-9\-_. ]/gi,'_')}.pdf`
        });
      });
      const brand = String(brandName || 'Sunbeth');
      const primary = String(brandPrimaryColor || '#C9A227'); // gold accent default
      const displayName = String(userName || userEmail || 'User');
      const batch = String(batchName || 'Batch');
      const dt = new Date(completedOn || new Date().toISOString());
      const verifyUrl = (req.body && req.body.verifyUrl) ? String(req.body.verifyUrl) : '';
      const certificateId = (req.body && req.body.certificateId) ? String(req.body.certificateId) : randomUUID();

      const page = { width: doc.page.width, height: doc.page.height, margin: 36 };
      const isCompact = page.height < 500;

      // Framed border
      const outer = { x: 16, y: 16, w: page.width - 32, h: page.height - 32 };
      doc.save();
      doc.lineJoin('round')
        .lineWidth(4).strokeColor(primary).roundedRect(outer.x, outer.y, outer.w, outer.h, 12).stroke();
      const inner = { x: outer.x + 12, y: outer.y + 12, w: outer.w - 24, h: outer.h - 24 };
      doc.lineWidth(1.1).strokeColor('#0f172a').roundedRect(inner.x, inner.y, inner.w, inner.h, 10).stroke();
      doc.restore();

      // Watermark (rotated, per HTML reference)
      doc.save();
      const wmText = 'TEST';
      doc.fillColor('#0f4c81').opacity(0.05);
      doc.font('Helvetica-Bold').fontSize(isCompact ? 100 : 140);
      const wmW = doc.widthOfString(wmText);
      const wmX = (page.width - wmW) / 2;
      const wmY = page.height / 2 - (isCompact ? 20 : 40);
      doc.rotate(-30, { origin: [page.width / 2, page.height / 2] });
      doc.text(wmText, wmX, wmY, { lineBreak: false });
      doc.restore();

      // Logo and heading block
      const headerTop = inner.y + (isCompact ? 10 : 18);
      const placeLogo = async () => new Promise((resolve) => {
        try {
          const url = String(brandLogoUrl || '').trim();
          if (!/^https?:\/\//i.test(url)) return resolve();
          const client = /^https:\/\//i.test(url) ? https : http;
          client.get(url, (resp) => {
            const data = [];
            resp.on('data', (d) => data.push(d));
            resp.on('end', () => {
              try {
                const buf = Buffer.concat(data);
                const maxW = isCompact ? 110 : 150;
                const maxH = isCompact ? 46 : 64;
                const x = (page.width - maxW) / 2;
                doc.image(buf, x, headerTop, { width: maxW, height: maxH, align: 'center' });
              } catch {}
              resolve();
            });
          }).on('error', () => resolve());
        } catch { resolve(); }
      });
      await placeLogo();

      doc.fillColor('#0f172a');
      doc.font('Helvetica').fontSize(isCompact ? 12 : 16).text(brand, { align: 'center' });
      doc.moveDown(0.1);
      doc.font('Helvetica-Bold').fontSize(isCompact ? 22 : 32).fillColor(primary).text('Certificate of Completion', { align: 'center' });
      const decoY = doc.y + 6;
      const decoHalf = page.width < 400 ? 70 : 120;
      doc.moveTo(page.width / 2 - decoHalf, decoY).lineTo(page.width / 2 + decoHalf, decoY).lineWidth(2).strokeColor(primary).stroke();
      // Switch to absolute positioning to avoid auto page breaks
      const contentTop = decoY + (isCompact ? 18 : 24);

      // Recipient and batch (premium layout)
      doc.fillColor('#334155').font('Helvetica-Oblique').fontSize(isCompact ? 10 : 12).text('This certifies that', inner.x, contentTop, { align: 'center', width: inner.w });
      doc.fillColor('#0f172a').font('Helvetica-Bold').fontSize(isCompact ? 24 : 34).text(displayName, inner.x, contentTop + (isCompact ? 16 : 20), { align: 'center', width: inner.w });
      doc.fillColor('#334155').font('Helvetica-Oblique').fontSize(isCompact ? 10 : 12).text('has successfully completed all required acknowledgements for', inner.x, contentTop + (isCompact ? 36 : 44), { align: 'center', width: inner.w });
      doc.fillColor(primary).font('Helvetica-Bold').fontSize(isCompact ? 20 : 26).text(batch, inner.x, contentTop + (isCompact ? 52 : 64), { align: 'center', width: inner.w });

      // Compliance statement
      const statement = `I ${displayName} have read, understood, and agree to comply with the terms of this document`;
      doc.fillColor('#0f172a').font('Helvetica').fontSize(isCompact ? 11 : 13).text(statement, inner.x, contentTop + (isCompact ? 74 : 88), { align: 'center', width: inner.w });

      // Completed on (centered) and info bar with Department | Business | Year
      doc.fillColor('#475569').font('Helvetica').fontSize(isCompact ? 10 : 12).text(`Completed on: ${dt.toLocaleString()}`, inner.x, contentTop + (isCompact ? 92 : 112), { align: 'center', width: inner.w });
      const year = dt.getFullYear();
      const infoPieces = [];
      if (department) infoPieces.push(`Department: ${department}`);
      if (businessName) infoPieces.push(`Business: ${businessName}`);
      infoPieces.push(`Year: ${year}`);
      const infoLine = infoPieces.join('  •  ');
      doc.fillColor('#64748b').font('Helvetica-Oblique').fontSize(isCompact ? 9 : 11).text(infoLine, inner.x, contentTop + (isCompact ? 106 : 130), { align: 'center', width: inner.w });

      // Email forced single-line with ellipsis if needed
      try {
        const maxW = Math.max(inner.w - 80, page.width * 0.6);
        let fs = isCompact ? 10 : 12;
        doc.font('Helvetica');
        while (doc.widthOfString(String(userEmail || '')) > maxW && fs > 8) {
          fs -= 0.5; doc.fontSize(fs);
        }
        doc.fillColor('#0f172a').fontSize(fs).text(`Email: ${String(userEmail || '')}`, (page.width - maxW) / 2, contentTop + (isCompact ? 122 : 150), {
          width: maxW,
          align: 'center',
          lineBreak: false
        });
      } catch {}

      // Info grid stays aligned
      const infoRows = [
        ['Department', department],
        ['Job title', jobTitle],
        ['Location', location],
        ['Business', businessName],
        ['Primary group', primaryGroup],
        ['Email', userEmail],
      ].filter((row) => row[1]);
      if (infoRows.length > 0) {
        const gridTop = doc.y + (isCompact ? 10 : 14);
        const colW = (inner.w - 48) / 2;
        const rowH = isCompact ? 16 : 20;
        infoRows.forEach(([k, v], idx) => {
          const col = idx % 2;
          const row = Math.floor(idx / 2);
          const x = inner.x + 24 + col * (colW + 24);
          const y = gridTop + row * rowH;
          doc.fillColor('#64748b').font('Times-Roman').fontSize(isCompact ? 9 : 11).text(String(k) + ':', x, y, { width: colW });
          doc.fillColor('#0f172a').font('Times-Bold').fontSize(isCompact ? 10 : 12).text(String(v), x, y + (isCompact ? 9 : 11), { width: colW });
        });
        const rowsHigh = Math.ceil(infoRows.length / 2) * rowH;
        doc.y = gridTop + rowsHigh + (isCompact ? 6 : 10);
      }

      // Reserve bottom band for QR, seal, signatures
      const bandTop = page.height - (isCompact ? 160 : 200);

      // QR block (anchored to the right)
      if (verifyUrl) {
        try {
          const qrSize = isCompact ? 82 : 110;
          const qrPng = await QRCode.toBuffer(verifyUrl, { width: qrSize, margin: 1 });
          const qrX = inner.x + inner.w - 22 - qrSize;
          const qrY = bandTop + (isCompact ? 6 : 10);
          doc.image(qrPng, qrX, qrY, { width: qrSize, height: qrSize });
          doc.fillColor('#64748b').font('Times-Roman').fontSize(isCompact ? 8 : 9)
            .text('Verify', qrX, qrY + qrSize + 4, { width: qrSize, align: 'center' });
        } catch {}
      }

      // Seal centered
      const cx = page.width / 2; const cy = bandTop + (isCompact ? 72 : 94);
      doc.save();
      const r1 = isCompact ? 34 : 44;
      const r2 = isCompact ? 26 : 34;
      const sealW = isCompact ? 64 : 80;
      doc.circle(cx, cy, r1).lineWidth(3).strokeColor(primary).stroke();
      doc.circle(cx, cy, r2).lineWidth(1).strokeColor('#0f172a').stroke();
      doc.fillColor(primary).font('Times-Bold').fontSize(isCompact ? 12 : 14).text('CERTIFIED', cx - (sealW / 2), cy - (isCompact ? 7 : 8), { width: sealW, align: 'center' });
      doc.restore();

      // Signatures anchored to the band
      const signY = bandTop + (isCompact ? 120 : 150);
      const col1 = inner.x + 40;
      const col2 = inner.x + inner.w - 240;
      doc.strokeColor('#94a3b8').lineWidth(1)
        .moveTo(col1, signY).lineTo(col1 + 200, signY).stroke()
        .moveTo(col2, signY).lineTo(col2 + 200, signY).stroke();
      doc.fillColor('#64748b').font('Times-Roman').fontSize(isCompact ? 8 : 10)
        .text('Authorized Signature', col1, signY + 6, { width: 200, align: 'center' })
        .text('Date', col2, signY + 6, { width: 200, align: 'center' });

      // Certificate ID stays centered at the bottom
      doc.fillColor('#64748b').font('Times-Roman').fontSize(isCompact ? 9 : 11)
        .text(`Certificate ID: ${certificateId}`, inner.x, page.height - (isCompact ? 44 : 56), { width: inner.w, align: 'center' });

      // Optional documents list — force to exactly one page using columns and dynamic sizing
      try {
        const docTitles = Array.isArray(documents) ? documents.filter(Boolean).map((t) => String(t)) : [];
        if (docTitles.length > 0) {
          doc.addPage({ size: 'A4', margin: 50 });
          const pageW = doc.page.width - doc.page.margins.left - doc.page.margins.right;
          const pageH = doc.page.height - doc.page.margins.top - doc.page.margins.bottom;

          // Title
          const titleY = doc.y;
          doc.font('Times-Bold').fontSize(18).fillColor('#0f172a').text('Documents Acknowledged', { align: 'left' });
          let topY = doc.y + 8;

          // Available area for list
          const listX = doc.page.margins.left;
          const listY = topY;
          const listW = pageW;
          const listH = pageH - (titleY + 28);

          // Decide columns and font size to fit items into a single page
          let cols = 2; let fs = 12; let lineGap = 2; const minFs = 7; const maxCols = 4;
          function capacityFor(currentFs, currentCols) {
            doc.font('Times-Roman').fontSize(currentFs);
            const lineH = currentFs + lineGap + 1; // approximate line height
            const rowsPerCol = Math.max(1, Math.floor(listH / lineH));
            return { rowsPerCol, total: rowsPerCol * currentCols };
          }
          // Increase cols then decrease font size until items fit
          while (true) {
            const { total } = capacityFor(fs, cols);
            if (total >= docTitles.length) break;
            if (cols < maxCols) { cols += 1; continue; }
            if (fs > minFs) { fs -= 1; continue; }
            break; // cannot fit; will truncate with a tail marker
          }

          // Draw within a clipping rectangle so we never spill to extra pages
          doc.save();
          doc.rect(listX, listY, listW, listH).clip();
          doc.font('Times-Roman').fontSize(fs).fillColor('#0f172a');

          const colGap = 18;
          const colW = (listW - (colGap * (cols - 1))) / cols;
          const lineH = fs + lineGap + 1;
          const rowsPerCol = Math.max(1, Math.floor(listH / lineH));
          let idx = 0;
          for (let c = 0; c < cols && idx < docTitles.length; c++) {
            const x = doc.page.margins.left + c * (colW + colGap);
            let y = listY;
            for (let r = 0; r < rowsPerCol && idx < docTitles.length; r++) {
              const label = `${idx + 1}. ${docTitles[idx]}`;
              doc.text(label, x, y, { width: colW, height: lineH, lineBreak: false });
              y += lineH;
              idx++;
            }
          }
          // If items didn't fit, add a tail marker in the last line
          if (idx < docTitles.length) {
            const remaining = docTitles.length - idx;
            const x = doc.page.margins.left + (cols - 1) * (colW + colGap);
            const y = listY + (rowsPerCol - 1) * lineH;
            doc.fillColor('#64748b').text(`… and ${remaining} more`, x, y, { width: colW, lineBreak: false });
          }
          doc.restore();
        }
      } catch {}

      doc.end();
    } catch (e) {
      res.status(500).json({ error: 'certificate_failed' });
    }
  });

  // Generate a PDF copy of the admin completion email (returns base64 in JSON)
  app.post('/api/emails/admin-completion-pdf', express.json({ limit: '1mb' }), async (req, res) => {
    try {
      // If the client provided full HTML body, prefer rendering HTML to PDF for exact mirroring
      const htmlBody = (req.body && typeof req.body.htmlBody === 'string') ? req.body.htmlBody : '';
      if (htmlBody && htmlBody.length > 20) {
        try {
          let buffer = null;
          try {
            const puppeteer = require('puppeteer');
            const browser = await puppeteer.launch({ headless: 'new' });
            const page = await browser.newPage();
            await page.setContent(htmlBody, { waitUntil: 'networkidle0' });
            buffer = await page.pdf({ format: 'A4', margin: { top: '20mm', right: '15mm', bottom: '20mm', left: '15mm' } });
            await browser.close();
          } catch {}
          if (buffer && Buffer.isBuffer(buffer)) {
            return res.json({
              contentBytes: buffer.toString('base64'),
              contentType: 'application/pdf',
              name: `${(req.body?.batchName || 'acknowledgement').toString().replace(/[^a-z0-9\-_. ]/gi,'_')}-${(req.body?.userEmail || 'user').toString().replace(/[^a-z0-9\-_. ]/gi,'_')}.pdf`
            });
          }
        } catch {}
      }

      const {
        batchName,
        userEmail,
        userName,
        completedOn,
        totalDocuments,
        documents,
        department,
        jobTitle,
        location,
        businessName,
        primaryGroup,
        brandName,
        brandLogoUrl,
        brandPrimaryColor,
      } = req.body || {};
      const PDFDocument = require('pdfkit');
      const http = require('http');
      const https = require('https');
      const doc = new PDFDocument({ size: 'A4', margin: 36 });
      const chunks = [];
      doc.on('data', (c) => chunks.push(c));
      doc.on('end', () => {
        const buff = Buffer.concat(chunks);
        const emailStr = (userEmail || 'user').toString();
        const localPart = (() => {
          const m = emailStr.match(/^([a-z0-9._%-]+)@/i);
          const raw = m && m[1] ? m[1] : emailStr;
          return raw.replace(/[^a-z0-9._-]/gi, '').replace(/\.+/g, '.');
        })();
        const now = new Date();
        const month = now.toLocaleString('en-US', { month: 'short' }).toLowerCase();
        const year = now.getFullYear();
        const fileName = `${localPart}-document-ack-${month}-${year}.pdf`;
        res.json({
          contentBytes: buff.toString('base64'),
          contentType: 'application/pdf',
          name: fileName
        });
      });

      const brand = String(brandName || 'Sunbeth');
      const primary = String(brandPrimaryColor || '#0a3d33');
      const displayName = String(userName || userEmail || 'User');
      const batch = String(batchName || 'Batch');
      const dt = new Date(completedOn || new Date().toISOString());

      // Header with logo
      const placeLogo = async () => new Promise((resolve) => {
        try {
          const url = String(brandLogoUrl || '').trim();
          if (!url) return resolve();
          if (/^https?:\/\//i.test(url)) {
            const client = /^https:\/\//i.test(url) ? https : http;
            client.get(url, (resp) => {
              const data = [];
              resp.on('data', (d) => data.push(d));
              resp.on('end', () => {
                try {
                  const buf = Buffer.concat(data);
                  doc.image(buf, doc.page.width - 180, 30, { width: 120 });
                } catch { /* ignore */ }
                resolve();
              });
            }).on('error', () => resolve());
          } else {
            try {
              if (fs.existsSync(url)) {
                const buf = fs.readFileSync(url);
                doc.image(buf, doc.page.width - 180, 30, { width: 120 });
              }
            } catch { /* ignore */ }
            resolve();
          }
        } catch { resolve(); }
      });

      await placeLogo();

      doc.fillColor(primary).font('Helvetica-Bold').fontSize(18).text('Acknowledgement Completed', 36, 36);
      doc.moveDown(0.5);
      doc.fillColor('#111').font('Helvetica').fontSize(12).text(`Batch: ${batch}`);
      doc.text(`Completed by: ${displayName} (${userEmail || 'n/a'})`);
      doc.text(`Completed on: ${dt.toLocaleString()}`);
      if (typeof totalDocuments === 'number') doc.text(`Documents: ${totalDocuments}`);

      const meta = [
        ['Department', department],
        ['Business', businessName],
        ['Job title', jobTitle],
        ['Location', location],
        ['Primary group', primaryGroup],
      ].filter((row) => row[1]);
      if (meta.length > 0) {
        doc.moveDown(0.6);
        doc.fillColor('#111').font('Helvetica-Bold').text('Details');
        doc.moveDown(0.2);
        meta.forEach(([k, v]) => {
          doc.fillColor('#475467').font('Helvetica').text(`${k}:`, { continued: true });
          doc.fillColor('#111').text(` ${v}`);
        });
      }

      // Compliance statement block
      const statement = `I ${displayName} have read, understood, and agree to comply with the terms of this document`;
      doc.moveDown(0.8);
      doc.fillColor('#111').font('Helvetica-Bold').text('Compliance Statement');
      doc.moveDown(0.2);
      doc.fillColor('#111').font('Helvetica').text(statement);

      const docs = Array.isArray(documents) ? documents : [];
      if (docs.length > 0) {
        doc.moveDown(0.8);
        doc.fillColor('#111').font('Helvetica-Bold').text('Documents Acknowledged');
        doc.moveDown(0.2);
        doc.fillColor('#111').font('Helvetica');
        docs.forEach((d, idx) => {
          doc.text(`${idx + 1}. ${d}`);
        });
      }

      doc.moveDown(1.2);
      doc.fillColor('#475467').font('Helvetica').fontSize(10)
        .text('This PDF mirrors the completion email and can be uploaded as evidence.');

      doc.end();
    } catch (e) {
      res.status(500).json({ error: 'pdf_failed' });
    }
  });

  // Generate a PDF copy of the user completion email (returns base64 in JSON)
  app.post('/api/emails/user-completion-pdf', express.json({ limit: '1mb' }), async (req, res) => {
    try {
      // Prefer exact HTML mirror if provided by client
      const htmlBody = (req.body && typeof req.body.htmlBody === 'string') ? req.body.htmlBody : '';
      if (htmlBody && htmlBody.length > 20) {
        try {
          let buffer = null;
          try {
            const puppeteer = require('puppeteer');
            const browser = await puppeteer.launch({ headless: 'new' });
            const page = await browser.newPage();
            await page.setContent(htmlBody, { waitUntil: 'networkidle0' });
            buffer = await page.pdf({ format: 'A4', margin: { top: '20mm', right: '15mm', bottom: '20mm', left: '15mm' } });
            await browser.close();
          } catch {}
          if (buffer && Buffer.isBuffer(buffer)) {
            return res.json({
              contentBytes: buffer.toString('base64'),
              contentType: 'application/pdf',
              // Build filename: firstname.lastname-document-ack-jan-2026.pdf
              name: (() => {
                const email = (req.body?.userEmail || 'user').toString();
                let base = 'user';
                const match = email.match(/^([a-z0-9._%-]+)@/i);
                if (match && match[1]) {
                  // Try to extract firstname.lastname from email
                  base = match[1].replace(/[^a-z0-9._-]/gi, '').replace(/\.+/g, '.');
                }
                // Format: firstname.lastname-document-ack-jan-2026
                const now = new Date();
                const month = now.toLocaleString('en-US', { month: 'short' }).toLowerCase();
                const year = now.getFullYear();
                return `${base}-document-ack-${month}-${year}.pdf`;
              })(),
            });
          }
        } catch {}
      }

      const {
        batchName,
        userEmail,
        userName,
        completedOn,
        documents,
        department,
        jobTitle,
        location,
        businessName,
        primaryGroup,
        brandName,
        brandLogoUrl,
        brandPrimaryColor,
      } = req.body || {};
      const PDFDocument = require('pdfkit');
      const http = require('http');
      const https = require('https');
      const doc = new PDFDocument({ size: 'A4', margin: 36 });
      const chunks = [];
      doc.on('data', (c) => chunks.push(c));
      doc.on('end', () => {
        const buff = Buffer.concat(chunks);
        const emailStr = (userEmail || 'user').toString();
        const localPart = (() => {
          const m = emailStr.match(/^([a-z0-9._%-]+)@/i);
          const raw = m && m[1] ? m[1] : emailStr;
          return raw.replace(/[^a-z0-9._-]/gi, '').replace(/\.+/g, '.');
        })();
        const now = new Date();
        const month = now.toLocaleString('en-US', { month: 'short' }).toLowerCase();
        const year = now.getFullYear();
        const fileName = `${localPart}-document-ack-${month}-${year}.pdf`;
        res.json({
          contentBytes: buff.toString('base64'),
          contentType: 'application/pdf',
          name: fileName
        });
      });

      const brand = String(brandName || 'Sunbeth');
      const primary = String(brandPrimaryColor || '#0a3d33');
      const displayName = String(userName || userEmail || 'User');
      const batch = String(batchName || 'Batch');
      const dt = new Date(completedOn || new Date().toISOString());

      const placeLogo = async () => new Promise((resolve) => {
        try {
          const url = String(brandLogoUrl || '').trim();
          if (!/^https?:\/\//i.test(url)) return resolve();
          const client = /^https:\/\//i.test(url) ? https : http;
          client.get(url, (resp) => {
            const data = [];
            resp.on('data', (d) => data.push(d));
            resp.on('end', () => {
              try {
                const buf = Buffer.concat(data);
                doc.image(buf, doc.page.width - 180, 30, { width: 120 });
              } catch { /* ignore */ }
              resolve();
            });
          }).on('error', () => resolve());
        } catch { resolve(); }
      });

      await placeLogo();

      doc.fillColor(primary).font('Helvetica-Bold').fontSize(18).text('Acknowledgement Completed', 36, 36);
      doc.moveDown(0.5);
      doc.fillColor('#111').font('Helvetica').fontSize(12).text(`Hi ${displayName},`);
      doc.moveDown(0.2);
      doc.text(`You have completed all required acknowledgements for ${batch}.`);
      doc.text(`Completed on: ${dt.toLocaleString()}`);

      const meta = [
        ['Department', department],
        ['Business', businessName],
        ['Job title', jobTitle],
        ['Location', location],
        ['Primary group', primaryGroup],
        ['Email', userEmail],
      ].filter((row) => row[1]);
      if (meta.length > 0) {
        doc.moveDown(0.6);
        doc.fillColor('#111').font('Helvetica-Bold').text('Details');
        doc.moveDown(0.2);
        meta.forEach(([k, v]) => {
          doc.fillColor('#475467').font('Helvetica').text(`${k}:`, { continued: true });
          doc.fillColor('#111').text(` ${v}`);
        });
      }

      // Compliance statement block
      const statement = `I ${displayName} have read, understood, and agree to comply with the terms of this document`;
      doc.moveDown(0.8);
      doc.fillColor('#111').font('Helvetica-Bold').text('Compliance Statement');
      doc.moveDown(0.2);
      doc.fillColor('#111').font('Helvetica').text(statement);

      const docs = Array.isArray(documents) ? documents : [];
      if (docs.length > 0) {
        doc.moveDown(0.8);
        doc.fillColor('#111').font('Helvetica-Bold').text('Documents Acknowledged');
        doc.moveDown(0.2);
        doc.fillColor('#111').font('Helvetica');
        docs.forEach((d, idx) => {
          doc.text(`${idx + 1}. ${d}`);
        });
      }

      doc.moveDown(1.2);
      doc.fillColor('#475467').font('Helvetica').fontSize(10)
        .text('This PDF mirrors the completion email and can be uploaded as evidence.');

      doc.end();
    } catch (e) {
      res.status(500).json({ error: 'pdf_failed' });
    }
  });

  // Upload a completion PDF to SharePoint: finds user folder by Employee Email
  app.post(
    '/api/sharepoint/upload-completion-pdf',
    validate({
      type: 'object',
      required: ['businessName', 'department', 'userEmail', 'contentBytes'],
      additionalProperties: true,
      properties: {
        businessName: { type: 'string' },
        department: { type: 'string' },
        userEmail: { type: 'string', format: 'email' },
        contentBytes: { type: 'string' }, // base64
        fileName: { type: 'string' },
        batchId: { type: ['string','number'] },
      },
    }),
    async (req, res) => {
      const logger = createLogger(req.id);
      try {
        const siteName = String(getSetting('sharepoint_site_name', '') || '').trim();
        const libraryName = String(getSetting('sharepoint_library_name', '') || '').trim();
        if (!siteName || !libraryName) {
          return res.status(400).json({ error: 'sharepoint_settings_missing' });
        }

        const { businessName, department, userEmail } = req.body;
        const batchId = req.body?.batchId === undefined ? null : Number(req.body.batchId);
        const fileName = String(req.body?.fileName || 'document-ack.pdf').replace(/[^a-z0-9._ -]/gi, '_');
        const contentBytes = String(req.body?.contentBytes || '');
        if (!contentBytes || contentBytes.length < 20) return res.status(400).json({ error: 'invalid_content' });
        const buffer = Buffer.from(contentBytes, 'base64');

        // Idempotency: if batchId is provided and already recorded, short-circuit
        if (batchId && one) {
          try {
            const existing = one('SELECT id, fileName, driveId, itemId, webUrl FROM completion_uploads WHERE batchId=? AND LOWER(email)=LOWER(?) LIMIT 1', [batchId, userEmail]);
            if (existing && existing.itemId) {
              return res.json({ ok: true, alreadyUploaded: true, name: existing.fileName, driveId: existing.driveId, itemId: existing.itemId, webUrl: existing.webUrl });
            }
          } catch {}
        }

        // Acquire app token
        const token = await getAppGraphToken();
        const bearer = `Bearer ${token.access_token}`;
        const headers = { Authorization: bearer, 'User-Agent': 'Sunbeth-SharePoint-Upload/1.0' };

        // 1) Resolve Site by display name
        const siteSearchUrl = `https://graph.microsoft.com/v1.0/sites?search=${encodeURIComponent(siteName)}`;
        const siteSearchResp = await fetch(siteSearchUrl, { headers, agent: getProxyAgent(new URL(siteSearchUrl)) });
        if (!siteSearchResp.ok) return res.status(502).json({ error: 'site_search_failed', status: siteSearchResp.status });
        const siteSearchJson = await siteSearchResp.json();
        const siteObj = (Array.isArray(siteSearchJson?.value) ? siteSearchJson.value : []).find((s) => String(s?.displayName || '').toLowerCase() === siteName.toLowerCase()) || (siteSearchJson?.value?.[0]);
        if (!siteObj || !siteObj.id) return res.status(404).json({ error: 'site_not_found' });

        // 2) Find Drive (document library) by name
        const drivesUrl = `https://graph.microsoft.com/v1.0/sites/${encodeURIComponent(siteObj.id)}/drives`;
        const drivesResp = await fetch(drivesUrl, { headers, agent: getProxyAgent(new URL(drivesUrl)) });
        if (!drivesResp.ok) return res.status(502).json({ error: 'drives_failed', status: drivesResp.status });
        const drivesJson = await drivesResp.json();
        const drive = (Array.isArray(drivesJson?.value) ? drivesJson.value : []).find((d) => String(d?.name || '').toLowerCase() === libraryName.toLowerCase());
        if (!drive || !drive.id) return res.status(404).json({ error: 'library_not_found' });

        // 3) Resolve List (to query fields like Employee Email)
        const listsUrl = `https://graph.microsoft.com/v1.0/sites/${encodeURIComponent(siteObj.id)}/lists`;
        const listsResp = await fetch(listsUrl, { headers, agent: getProxyAgent(new URL(listsUrl)) });
        if (!listsResp.ok) return res.status(502).json({ error: 'lists_failed', status: listsResp.status });
        const listsJson = await listsResp.json();
        const list = (Array.isArray(listsJson?.value) ? listsJson.value : []).find((l) => String(l?.displayName || '').toLowerCase() === libraryName.toLowerCase()) || (listsJson?.value?.[0]);
        if (!list || !list.id) return res.status(404).json({ error: 'list_not_found' });

        // 4) Find internal column name for "Employee Email"
        const colsUrl = `https://graph.microsoft.com/v1.0/sites/${encodeURIComponent(siteObj.id)}/lists/${encodeURIComponent(list.id)}/columns`;
        const colsResp = await fetch(colsUrl, { headers, agent: getProxyAgent(new URL(colsUrl)) });
        if (!colsResp.ok) return res.status(502).json({ error: 'columns_failed', status: colsResp.status });
        const colsJson = await colsResp.json();
        const emailCol = (Array.isArray(colsJson?.value) ? colsJson.value : []).find((c) => String(c?.displayName || '').toLowerCase() === 'employee email');
        const emailFieldName = String(emailCol?.name || 'Employee_x0020_Email');

        // 5) Query list items by Employee Email == userEmail
        const filterEmail = encodeURIComponent(`${emailFieldName} eq '${userEmail.replace(/'/g, "''")}'`);
        const itemsUrl = `https://graph.microsoft.com/v1.0/sites/${encodeURIComponent(siteObj.id)}/lists/${encodeURIComponent(list.id)}/items?$expand=fields&$filter=fields/${filterEmail}`;
        const itemsResp = await fetch(itemsUrl, { headers, agent: getProxyAgent(new URL(itemsUrl)) });
        if (!itemsResp.ok) return res.status(502).json({ error: 'items_failed', status: itemsResp.status });
        const itemsJson = await itemsResp.json();
        const item = (Array.isArray(itemsJson?.value) ? itemsJson.value : [])[0];
        if (!item || !item.id) return res.status(404).json({ error: 'user_folder_item_not_found' });

        // 6) Resolve the driveItem (folder) for the list item
        const diUrl = `https://graph.microsoft.com/v1.0/sites/${encodeURIComponent(siteObj.id)}/lists/${encodeURIComponent(list.id)}/items/${encodeURIComponent(item.id)}/driveItem`;
        const diResp = await fetch(diUrl, { headers, agent: getProxyAgent(new URL(diUrl)) });
        if (!diResp.ok) return res.status(502).json({ error: 'driveitem_failed', status: diResp.status });
        const driveItem = await diResp.json();
        if (!driveItem || !driveItem.id) return res.status(404).json({ error: 'user_folder_not_found' });

        // Optional: verify business/department in parent path
        try {
          const p = String(driveItem?.parentReference?.path || '').toLowerCase();
          const mustContain = `/${String(businessName).toLowerCase()}/${String(department).toLowerCase()}`;
          if (p && !p.includes(mustContain)) {
            logger.warn('sharepoint:path_mismatch', `Folder path mismatch; continuing upload`, { path: p, expect: mustContain });
          }
        } catch {}

        // 7) Idempotency: check if a file with the same name already exists in folder; if yes, record and return
        if (batchId) {
          try {
            const childrenUrl = `https://graph.microsoft.com/v1.0/drives/${encodeURIComponent(drive.id)}/items/${encodeURIComponent(driveItem.id)}/children?$select=id,name,webUrl&$top=200`;
            const childrenResp = await fetch(childrenUrl, { headers, agent: getProxyAgent(new URL(childrenUrl)) });
            if (childrenResp.ok) {
              const childrenJson = await childrenResp.json();
              const match = (Array.isArray(childrenJson?.value) ? childrenJson.value : []).find((it) => String(it?.name || '').toLowerCase() === fileName.toLowerCase());
              if (match && match.id) {
                try {
                  exec('INSERT INTO completion_uploads (batchId, email, fileName, driveId, itemId, webUrl, uploadedAt) VALUES (?, ?, ?, ?, ?, ?, datetime(\'now\'))', [batchId, userEmail, fileName, drive.id, match.id, match.webUrl || null]);
                } catch {}
                try { logger.info('sharepoint:uploaded:existing', 'Found existing completion PDF', { userEmail, fileName, driveId: drive.id, itemId: match.id, webUrl: match.webUrl }); } catch {}
                return res.json({ ok: true, alreadyUploaded: true, name: fileName, driveId: drive.id, folderId: driveItem.id, itemId: match.id, webUrl: match.webUrl });
              }
            }
          } catch {}
        }

        // 8) Upload into the user's folder
        const putUrl = `https://graph.microsoft.com/v1.0/drives/${encodeURIComponent(drive.id)}/items/${encodeURIComponent(driveItem.id)}:/${encodeURIComponent(fileName)}:/content`;
        const putResp = await fetch(putUrl, {
          method: 'PUT',
          headers: { ...headers, 'Content-Type': 'application/pdf' },
          agent: getProxyAgent(new URL(putUrl)),
          body: buffer,
        });
        if (!putResp.ok) return res.status(502).json({ error: 'upload_failed', status: putResp.status });
        const uploaded = await putResp.json();

        // Record idempotency in DB if batchId provided
        if (batchId) {
          try {
            exec('INSERT OR REPLACE INTO completion_uploads (batchId, email, fileName, driveId, itemId, webUrl, uploadedAt) VALUES (?, ?, ?, ?, ?, ?, datetime(\'now\'))', [batchId, userEmail, fileName, drive.id, uploaded?.id || null, uploaded?.webUrl || null]);
          } catch {}
        }

        try { logger.info('sharepoint:uploaded', 'Completion PDF uploaded', { userEmail, fileName, size: buffer.length, driveId: drive.id, itemId: uploaded?.id, webUrl: uploaded?.webUrl }); } catch {}
        return res.json({ ok: true, size: buffer.length, name: fileName, driveId: drive.id, folderId: driveItem.id, itemId: uploaded?.id, webUrl: uploaded?.webUrl });
      } catch (e) {
        try { logger.error('sharepoint:error', e?.message || String(e)); } catch {}
        return res.status(500).json({ error: 'sharepoint_upload_error', details: e?.message || String(e) });
      }
    }
  );

  // Upload status for a user's completion PDF (per batch)
  app.get('/api/sharepoint/upload-status', async (req, res) => {
    try {
      const batchIdRaw = req.query?.batchId;
      const emailRaw = req.query?.email;
      const batchId = batchIdRaw === undefined ? null : Number(batchIdRaw);
      const email = String(emailRaw || '').trim();
      if (!batchId || !email) return res.status(400).json({ error: 'batchId_email_required' });
      const row = one('SELECT fileName, driveId, itemId, webUrl, uploadedAt FROM completion_uploads WHERE batchId=? AND LOWER(email)=LOWER(?) LIMIT 1', [batchId, email]);
      if (row) return res.json({ uploaded: true, fileName: row.fileName, driveId: row.driveId, itemId: row.itemId, webUrl: row.webUrl, uploadedAt: row.uploadedAt });
      return res.json({ uploaded: false });
    } catch (e) {
      return res.status(500).json({ error: 'status_error', details: e?.message || String(e) });
    }
  });

  // Generate a PNG completion certificate (returns base64 in JSON)
  app.post('/api/certificates/png', express.json({ limit: '1mb' }), async (req, res) => {
    try {
      const PImage = require('pureimage');
      const QRCode = require('qrcode');
      const { Readable } = require('stream');
      const { PassThrough } = require('stream');
      const { randomUUID } = require('crypto');
      const {
        batchName,
        userEmail,
        userName,
        completedOn,
        department,
        jobTitle,
        location,
        businessName,
        primaryGroup,
        brandName,
        brandPrimaryColor,
        verifyUrl,
        pageSize,
        certificateId: reqCertId,
      } = req.body || {};
      const brand = String(brandName || 'Sunbeth');
      const primary = String(brandPrimaryColor || '#C9A227');
      const displayName = String(userName || userEmail || 'User');
      const batch = String(batchName || 'Batch');
      const dt = new Date(completedOn || new Date().toISOString());

      // Quarter A4 base dimensions (points ~ px at 72dpi); upscale 2x for clarity
      const baseW = (pageSize && /quarter/i.test(String(pageSize))) ? 298 : 595;
      const baseH = (pageSize && /quarter/i.test(String(pageSize))) ? 420 : 842;
      const scale = 2;
      const W = Math.round(baseW * scale);
      const H = Math.round(baseH * scale);
      const img = PImage.make(W, H);
      const ctx = img.getContext('2d');

      const px = (v) => Math.round(v * scale);

      // Background
      ctx.fillStyle = '#ffffff'; ctx.fillRect(0, 0, W, H);

      // Borders
      const outer = { x: px(8), y: px(8), w: W - px(16), h: H - px(16) };
      ctx.strokeStyle = primary; ctx.lineWidth = px(3);
      ctx.beginPath(); ctx.roundRect(outer.x, outer.y, outer.w, outer.h, px(10)); ctx.stroke();
      const inner = { x: outer.x + px(8), y: outer.y + px(8), w: outer.w - px(16), h: outer.h - px(16) };
      ctx.strokeStyle = '#0f172a'; ctx.lineWidth = px(1);
      ctx.beginPath(); ctx.roundRect(inner.x, inner.y, inner.w, inner.h, px(8)); ctx.stroke();

      // Watermark
      ctx.save();
      ctx.globalAlpha = 0.05; ctx.fillStyle = '#0f172a';
      const wmText = brand.toUpperCase();
      ctx.font = `${px(60)}px serif`;
      const wmW = ctx.measureText(wmText).width;
      ctx.fillText(wmText, (W - wmW) / 2, H / 2);
      ctx.restore();

      // Title area
      const headerTop = inner.y + px(16);
      ctx.fillStyle = '#0f172a';
      ctx.font = `${px(H < px(1000) ? 12 : 14)}px serif`;
      const brandW = ctx.measureText(brand).width; ctx.fillText(brand, (W - brandW) / 2, headerTop + px(12));
      ctx.fillStyle = primary; ctx.font = `${px(H < px(1000) ? 20 : 26)}px serif`;
      const title = 'Certificate of Completion';
      const tW = ctx.measureText(title).width; ctx.fillText(title, (W - tW) / 2, headerTop + px(42));
      // Decorative rule
      ctx.strokeStyle = primary; ctx.lineWidth = px(2);
      const dHalf = W < px(800) ? px(80) : px(160);
      const dY = headerTop + px(50);
      ctx.beginPath(); ctx.moveTo(W / 2 - dHalf, dY); ctx.lineTo(W / 2 + dHalf, dY); ctx.stroke();

      // Recipient block
      ctx.fillStyle = '#334155'; ctx.font = `${px(H < px(1000) ? 10 : 12)}px serif`;
      const sub1 = 'This is to certify that';
      let x = (W - ctx.measureText(sub1).width) / 2; let y = dY + px(20); ctx.fillText(sub1, x, y);
      ctx.fillStyle = '#0f172a'; ctx.font = `${px(H < px(1000) ? 18 : 24)}px serif`;
      y += px(18); x = (W - ctx.measureText(displayName).width) / 2; ctx.fillText(displayName, x, y);
      ctx.fillStyle = '#334155'; ctx.font = `${px(H < px(1000) ? 10 : 12)}px serif`;
      const sub2 = 'has successfully completed all required acknowledgements for';
      y += px(16); x = (W - ctx.measureText(sub2).width) / 2; ctx.fillText(sub2, x, y);
      ctx.fillStyle = '#0f172a'; ctx.font = `${px(H < px(1000) ? 14 : 18)}px serif`;
      y += px(16); x = (W - ctx.measureText(batch).width) / 2; ctx.fillText(batch, x, y);
      ctx.fillStyle = '#475569'; ctx.font = `${px(H < px(1000) ? 10 : 12)}px serif`;
      const dateText = `Completed on: ${dt.toLocaleString()}`; y += px(18);
      x = (W - ctx.measureText(dateText).width) / 2; ctx.fillText(dateText, x, y);

      // Meta rows
      const meta = [
        ['Department', department], ['Job title', jobTitle], ['Location', location], ['Business', businessName], ['Primary group', primaryGroup], ['Email', userEmail]
      ].filter(r => r[1]);
      if (meta.length > 0) {
        let my = y + px(14); const mx = inner.x + px(20);
        meta.forEach(([k, v]) => {
          ctx.fillStyle = '#64748b'; ctx.font = `${px(10)}px serif`; ctx.fillText(`${k}:`, mx, my);
          ctx.fillStyle = '#0f172a'; ctx.font = `${px(11)}px serif`; ctx.fillText(String(v), mx + px(110), my);
          my += px(14);
        });
      }

      // Seal
      const cx = W / 2; const cy = H - px(100);
      ctx.strokeStyle = primary; ctx.lineWidth = px(3);
      ctx.beginPath(); ctx.arc(cx, cy, px(26), 0, Math.PI * 2); ctx.stroke();
      ctx.strokeStyle = '#0f172a'; ctx.lineWidth = px(1);
      ctx.beginPath(); ctx.arc(cx, cy, px(20), 0, Math.PI * 2); ctx.stroke();
      ctx.fillStyle = primary; ctx.font = `${px(10)}px serif`;
      const seal = 'CERTIFIED'; const sW = ctx.measureText(seal).width; ctx.fillText(seal, cx - sW / 2, cy + px(3));

      // QR code (if provided)
      if (verifyUrl) {
        try {
          const qrSize = px(90);
          const buf = await QRCode.toBuffer(verifyUrl, { width: qrSize, margin: 1 });
          const readable = new Readable(); readable._read = () => {}; readable.push(buf); readable.push(null);
          const qr = await PImage.decodePNGFromStream(readable);
          const qx = inner.x + px(20); const qy = H - px(170);
          ctx.drawImage(qr, qx, qy);
          ctx.fillStyle = '#64748b'; ctx.font = `${px(9)}px serif`; const qw = ctx.measureText('Verify').width; ctx.fillText('Verify', qx + (qrSize - qw) / 2, qy + qrSize + px(12));
        } catch {}
      }

      // Certificate ID text (bottom center)
      try {
        const certId = String(reqCertId || randomUUID());
        ctx.fillStyle = '#64748b'; ctx.font = `${px(9)}px serif`;
        const idText = `Certificate ID: ${certId}`;
        const idW = ctx.measureText(idText).width;
        ctx.fillText(idText, (W - idW) / 2, H - px(50));
      } catch {}
      // Encode PNG to buffer and return JSON (contentBytes, contentType, name)
      const out = new PassThrough();
      const chunks = [];
      out.on('data', (c) => chunks.push(c));
      out.on('end', () => {
        try {
          const buff = Buffer.concat(chunks);
          const safeBatch = String(batchName || 'certificate').replace(/[^a-z0-9\-_. ]/gi,'_');
          const safeUser = String(userEmail || 'user').replace(/[^a-z0-9\-_. ]/gi,'_');
          res.json({ contentBytes: buff.toString('base64'), contentType: 'image/png', name: `${safeBatch}-${safeUser}.png` });
        } catch (err) {
          res.status(500).json({ error: 'certificate_png_failed' });
        }
      });
      await PImage.encodePNGToStream(img, out);
    } catch (e) {
      try {
        const PImage = require('pureimage');
        const img = PImage.make(10,10); const ctx = img.getContext('2d'); ctx.fillStyle='#fff'; ctx.fillRect(0,0,10,10);
        const chunks = [];
        const { PassThrough } = require('stream'); const out = new PassThrough();
        out.on('data', (c)=>chunks.push(c)); out.on('end', ()=>{
          const buff = Buffer.concat(chunks);
          res.json({ contentBytes: buff.toString('base64'), contentType: 'image/png', name: 'certificate.png' });
        });
        PImage.encodePNGToStream(img, out);
      } catch {
        res.status(500).json({ error: 'certificate_png_failed' });
      }
    }
  });

  // Record a certificate issuance for verification
  app.post('/api/certificates/record', express.json({ limit: '512kb' }), async (req, res) => {
    try {
      const body = req.body || {};
      const id = String(body.certificateId || body.id || '').trim();
      if (!id) return res.status(400).json({ ok: false, error: 'missing_id' });
      const email = String(body.userEmail || body.email || '').trim();
      const userName = String(body.userName || body.displayName || '') || null;
      const batchIdRaw = body.batchId;
      const batchIdNum = Number(batchIdRaw);
      const batchId = batchIdRaw != null && Number.isFinite(batchIdNum) ? batchIdNum : null;
      const completedOn = String(body.completedOn || '') || null;
      const department = body.department != null ? String(body.department) : null;
      const jobTitle = body.jobTitle != null ? String(body.jobTitle) : null;
      const location = body.location != null ? String(body.location) : null;
      const businessName = body.businessName != null ? String(body.businessName) : null;
      const primaryGroup = body.primaryGroup != null ? String(body.primaryGroup) : null;
      const documents = Array.isArray(body.documents) ? body.documents.filter(Boolean).map(String) : [];
      const docTitles = JSON.stringify(documents);
      db.run(
        `INSERT INTO certificates (id, email, user_name, batch_id, completed_on, doc_titles, department, jobTitle, location, businessName, primaryGroup, status)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'issued')
         ON CONFLICT(id) DO UPDATE SET email=excluded.email, user_name=excluded.user_name, batch_id=excluded.batch_id, completed_on=excluded.completed_on, doc_titles=excluded.doc_titles, department=excluded.department, jobTitle=excluded.jobTitle, location=excluded.location, businessName=excluded.businessName, primaryGroup=excluded.primaryGroup`,
        [id, email, userName, batchId, completedOn, docTitles, department, jobTitle, location, businessName, primaryGroup]
      );
      persist(db);
      // Also write a lightweight JSON file for robust verification in all adapters
      try {
        const certDir = path.join(DATA_DIR, 'certificates');
        if (!fs.existsSync(certDir)) fs.mkdirSync(certDir, { recursive: true });
        const payload = {
          id,
          email,
          userName,
          batchId,
          completedOn,
          documents,
          department,
          jobTitle,
          location,
          businessName,
          primaryGroup,
          status: 'issued',
          issuedAt: new Date().toISOString(),
        };
        fs.writeFileSync(path.join(certDir, `${id}.json`), JSON.stringify(payload));
      } catch {}
      res.json({ ok: true, id });
    } catch (e) {
      res.status(500).json({ ok: false, error: 'record_failed' });
    }
  });

  // Verify a certificate by ID
  app.get('/api/certificates/verify/:id', async (req, res) => {
    try {
      const id = String(req.params.id || '').trim();
      if (!id) return res.status(400).json({ valid: false, error: 'missing_id' });
      const maybeRow = one(
        `SELECT id, email, user_name as userName, batch_id as batchId, completed_on as completedOn, issued_at as issuedAt,
                doc_titles as docTitles, department, jobTitle, location, businessName, primaryGroup, status
         FROM certificates WHERE id=? LIMIT 1`,
        [id]
      );
      const row = (maybeRow && typeof maybeRow.then === 'function') ? await maybeRow : maybeRow;
      if (!row) {
        // Fallback: check JSON file store
        try {
          const certPath = path.join(DATA_DIR, 'certificates', `${id}.json`);
          if (fs.existsSync(certPath)) {
            const raw = JSON.parse(fs.readFileSync(certPath, 'utf8'));
            return res.json({ valid: true, ...raw });
          }
        } catch {}
        return res.json({ valid: false, message: 'Not found' });
      }
      let documents = [];
      try { documents = JSON.parse(String(row.docTitles || '[]')); } catch { documents = []; }
      res.json({
        valid: true,
        id: row.id || id,
        email: row.email ?? null,
        userName: row.userName ?? null,
        batchId: row.batchId ?? null,
        completedOn: row.completedOn ?? null,
        issuedAt: row.issuedAt ?? null,
        documents,
        department: row.department ?? null,
        jobTitle: row.jobTitle ?? null,
        location: row.location ?? null,
        businessName: row.businessName ?? null,
        primaryGroup: row.primaryGroup ?? null,
        status: row.status || 'issued'
      });
    } catch (e) {
      res.status(500).json({ valid: false, error: 'verify_failed' });
    }
  });

  // Compliance breakdown by department (supports filters)
  app.get('/api/compliance', async (req, res) => {
    // Guardrails for RTDB: default to modest page size
    const limitComp = Math.max(1, Math.min(Number(req.query.limit || 100), 500));
    const offsetComp = Math.max(0, Number(req.query.offset || 0));
    const filters = [];
    const params = [];
    const hasFilters = () => filters.length > 0;
    const bizExpr = 'COALESCE(r.businessId, ub.businessId)';
    if (req.query.businessId) {
      filters.push(`${bizExpr} = ?`);
      params.push(String(req.query.businessId));
    }
    if (req.query.department) {
      filters.push('LOWER(r.department) = ?');
      params.push(String(req.query.department).toLowerCase());
    }
    if (req.query.primaryGroup) {
      filters.push('LOWER(r.primaryGroup) = ?');
      params.push(String(req.query.primaryGroup).toLowerCase());
    }
    const where = filters.length ? `WHERE ${filters.join(' AND ')}` : '';
    const isFirebase = db && (db.driver === 'firebase' || db.driver === 'rtdb');
    if (isFirebase) {
      if (!hasFilters()) {
        const cached = readJsonCache('compliance_cache');
        if (cached) return res.json(cached.slice(offsetComp, offsetComp + limitComp));
      }
      const [recRowsMaybe, ackRowsMaybe, docsRowsMaybe, bizRowsMaybe, userBizMaybe] = [
        all('SELECT department, businessId, email, batchId FROM recipients'),
        all('SELECT batchId, email, acknowledged, documentId FROM acks'),
        all('SELECT id, batchId FROM documents'),
        all('SELECT id, name FROM businesses'),
        all('SELECT email, businessId FROM user_businesses'),
      ];
      const recRows =
        recRowsMaybe && typeof recRowsMaybe.then === 'function'
          ? await recRowsMaybe
          : recRowsMaybe || [];
      const ackRows =
        ackRowsMaybe && typeof ackRowsMaybe.then === 'function'
          ? await ackRowsMaybe
          : ackRowsMaybe || [];
      const docRows =
        docsRowsMaybe && typeof docsRowsMaybe.then === 'function'
          ? await docsRowsMaybe
          : docsRowsMaybe || [];
      const bizRows =
        bizRowsMaybe && typeof bizRowsMaybe.then === 'function' ? await bizRowsMaybe : bizRowsMaybe || [];
      const userBizRows =
        userBizMaybe && typeof userBizMaybe.then === 'function' ? await userBizMaybe : userBizMaybe || [];
      const bizMap = new Map(
        bizRows.map((b) => [String(b.id), String(b.name || '').trim()]).filter(([id]) => id)
      );
      const userBizMap = new Map(
        userBizRows.map((b) => [String(b.email || '').toLowerCase(), String(b.businessId || '')])
      );

      const matchFilters = (r) => {
        const resolvedBizId = String(r.businessId || userBizMap.get(String(r.email || '').toLowerCase()) || '');
        if (req.query.businessId && resolvedBizId !== String(req.query.businessId))
          return false;
        if (
          req.query.department &&
          String(r.department || '').toLowerCase() !== String(req.query.department).toLowerCase()
        )
          return false;
        if (
          req.query.primaryGroup &&
          String(r.primaryGroup || '').toLowerCase() !==
            String(req.query.primaryGroup).toLowerCase()
        )
          return false;
        return true;
      };
      const recipients = recRows.filter(matchFilters);
      const recipientsByKey = new Map();
      for (const r of recipients) {
        const key = `${String(r.batchId)}|||${String(r.email || '').toLowerCase()}`;
        recipientsByKey.set(key, r);
      }
      const docsPerBatch = new Map();
      for (const d of docRows) {
        const k = String(d.batchId);
        docsPerBatch.set(k, (docsPerBatch.get(k) || 0) + 1);
      }
      // Build business+department -> { perBatchRecipients: Map(batchId -> count), completedAssignments }
      const grouped = new Map();
      for (const r of recipients) {
        const dep = String(r.department || 'Unassigned').trim() || 'Unassigned';
        const bizId = String(r.businessId || userBizMap.get(String(r.email || '').toLowerCase()) || '');
        const key = `${bizId}|||${dep}`;
        if (!grouped.has(key)) grouped.set(key, { perBatchRec: new Map(), completed: 0, businessId: bizId, department: dep });
        const k = String(r.batchId);
        const g = grouped.get(key);
        g.perBatchRec.set(k, (g.perBatchRec.get(k) || 0) + 1);
      }
      // Completed assignments per business+department = acknowledged acks mapped to recipient
      for (const a of ackRows.filter((a) => a.acknowledged)) {
        const key = `${String(a.batchId)}|||${String(a.email || '').toLowerCase()}`;
        const rec = recipientsByKey.get(key);
        if (!rec) continue;
        const dep = String(rec.department || 'Unassigned').trim() || 'Unassigned';
        const bizId = String(rec.businessId || userBizMap.get(String(rec.email || '').toLowerCase()) || '');
        const gKey = `${bizId}|||${dep}`;
        if (!grouped.has(gKey)) grouped.set(gKey, { perBatchRec: new Map(), completed: 0, businessId: bizId, department: dep });
        const g = grouped.get(gKey);
        g.completed += 1;
      }
      const rows = Array.from(grouped.values()).map((g) => {
        let totalAssignments = 0;
        let recipientsTotal = 0;
        for (const [batchId, rc] of g.perBatchRec.entries()) {
          recipientsTotal += rc;
          const dc = Number(docsPerBatch.get(String(batchId)) || 0);
          totalAssignments += rc * dc;
        }
        const completed = g.completed;
        const pending = Math.max(0, totalAssignments - completed);
        const completionRate =
          totalAssignments > 0 ? Math.round((completed / totalAssignments) * 1000) / 10 : 0;
        const businessId = g.businessId || 'unknown';
        const bizNameCandidate = bizMap.get(businessId) || (businessId !== 'unknown' ? businessId : 'Unassigned');
        const businessName =
          bizNameCandidate && bizNameCandidate.toLowerCase() !== 'unspecified'
            ? bizNameCandidate
            : 'Unassigned';
        return {
          department: g.department,
          businessId,
          businessName,
          totalUsers: recipientsTotal,
          totalAssignments,
          completed,
          pending,
          overdue: 0,
          completionRate,
        };
      });
      if (!hasFilters()) writeJsonCache('compliance_cache', rows);
      return res.json(rows);
    }

    // Default SQL path
    const totalsMaybe = all(
      `
      SELECT COALESCE(r.department,'Unassigned') as department, COALESCE(${bizExpr},'') as businessId, COALESCE(b.name,'') as businessName, COUNT(*) as totalAssignments
      FROM recipients r
      JOIN documents d ON d.batchId = r.batchId
      LEFT JOIN user_businesses ub ON LOWER(ub.email)=LOWER(r.email)
      LEFT JOIN businesses b ON b.id = COALESCE(r.businessId, ub.businessId)
      ${where}
      GROUP BY COALESCE(r.department,'Unassigned'), COALESCE(${bizExpr},''), COALESCE(b.name,'')
    `,
      params
    );
    const recipTotalsMaybe = all(
      `
      SELECT COALESCE(r.department,'Unassigned') as department, COALESCE(${bizExpr},'') as businessId, COALESCE(b.name,'') as businessName, COUNT(*) as recipientsTotal
      FROM recipients r
      LEFT JOIN user_businesses ub ON LOWER(ub.email)=LOWER(r.email)
      LEFT JOIN businesses b ON b.id = COALESCE(r.businessId, ub.businessId)
      ${where}
      GROUP BY COALESCE(r.department,'Unassigned'), COALESCE(${bizExpr},''), COALESCE(b.name,'')
    `,
      params
    );
    const acksMaybe = all(
      `
      SELECT COALESCE(r.department,'Unassigned') as department, COALESCE(${bizExpr},'') as businessId, COUNT(*) as completed
      FROM acks a
      JOIN recipients r ON r.batchId=a.batchId AND LOWER(r.email)=LOWER(a.email)
      LEFT JOIN user_businesses ub ON LOWER(ub.email)=LOWER(r.email)
      LEFT JOIN businesses b ON b.id = COALESCE(r.businessId, ub.businessId)
      ${where} AND a.acknowledged=1
      GROUP BY COALESCE(r.department,'Unassigned'), COALESCE(${bizExpr},'')
    `,
      params
    );
    const totals =
      totalsMaybe && typeof totalsMaybe.then === 'function' ? await totalsMaybe : totalsMaybe || [];
    const recipTotals =
      recipTotalsMaybe && typeof recipTotalsMaybe.then === 'function'
        ? await recipTotalsMaybe
        : recipTotalsMaybe || [];
    const acks =
      acksMaybe && typeof acksMaybe.then === 'function' ? await acksMaybe : acksMaybe || [];
    const keyFor = (dep, biz) => `${dep}|||${biz}`;
    const ackMap = new Map(
      acks.map((r) => [keyFor(String(r.department), String(r.businessId || '')), Number(r.completed)])
    );
    const recipMap = new Map(
      recipTotals.map((r) => [
        keyFor(String(r.department), String(r.businessId || '')),
        { count: Number(r.recipientsTotal), businessName: String(r.businessName || '') },
      ])
    );
    let rows = totals.map((t) => {
      const depRaw = String(t.department || '').trim();
      const dep = depRaw && depRaw.toLowerCase() !== 'unspecified' ? depRaw : 'Unassigned';
      const biz = String(t.businessId || '');
      const key = keyFor(dep, biz);
      const totalAssignments = Number(t.totalAssignments) || 0;
      const recipientsInfo = recipMap.get(key) || { count: 0, businessName: '' };
      const recipientsTotal = Number(recipientsInfo.count || 0);
      const completed = Number(ackMap.get(key) || 0);
      const pending = Math.max(0, totalAssignments - completed);
      const overdue = 0;
      const completionRate =
        totalAssignments > 0 ? Math.round((completed / totalAssignments) * 1000) / 10 : 0;
      const businessId = biz || 'unknown';
      const businessNameRaw = String(t.businessName || recipientsInfo.businessName || '').trim();
      const businessName =
        businessNameRaw && businessNameRaw.toLowerCase() !== 'unspecified'
          ? businessNameRaw
          : 'Unassigned';
      return {
        department: dep,
        businessId,
        businessName,
        totalUsers: recipientsTotal,
        totalAssignments,
        completed,
        pending,
        overdue,
        completionRate,
      };
    });
    // Optional search and pagination
    const qComp = String(req.query.q || '')
      .toLowerCase()
      .trim();
    if (qComp) {
      rows = rows.filter((r) =>
        String(r.department || '')
          .toLowerCase()
          .includes(qComp)
      );
    }
    const pagedComp = rows.slice(offsetComp, offsetComp + limitComp);
    res.json(pagedComp);
  });

  // Document performance stats (supports filters)
  app.get('/api/doc-stats', async (req, res) => {
    // Guardrails for RTDB: default to modest page size
    const limitDocs = Math.max(1, Math.min(Number(req.query.limit || 100), 500));
    const offsetDocs = Math.max(0, Number(req.query.offset || 0));
    const filters = [];
    const params = [];
    const hasFilters = () => filters.length > 0;
    if (req.query.businessId) {
      filters.push('r.businessId = ?');
      params.push(Number(req.query.businessId));
    }
    if (req.query.department) {
      filters.push('LOWER(r.department) = ?');
      params.push(String(req.query.department).toLowerCase());
    }
    if (req.query.primaryGroup) {
      filters.push('LOWER(r.primaryGroup) = ?');
      params.push(String(req.query.primaryGroup).toLowerCase());
    }
    const where = filters.length ? `WHERE ${filters.join(' AND ')}` : '';
    const isFirebase = db && (db.driver === 'firebase' || db.driver === 'rtdb');
    if (isFirebase) {
      if (!hasFilters()) {
        const cached = readJsonCache('doc_stats_cache');
        if (cached) {
          const qDocs = String(req.query.q || '').toLowerCase().trim();
          let out = Array.isArray(cached) ? cached : [];
          if (qDocs) {
            out = out.filter(
              (r) =>
                String(r.documentName || '')
                  .toLowerCase()
                  .includes(qDocs) ||
                String(r.batchName || '')
                  .toLowerCase()
                  .includes(qDocs)
            );
          }
          return res.json(out.slice(offsetDocs, offsetDocs + limitDocs));
        }
      }
      const [docsMaybe, recsMaybe, acksMaybe, batchesMaybe] = [
        all('SELECT id, title, batchId FROM documents'),
        all('SELECT id, batchId, businessId, email, department, primaryGroup FROM recipients'),
        all('SELECT documentId, batchId, email, acknowledged FROM acks'),
        all('SELECT id, name FROM batches'),
      ];
      const docs =
        docsMaybe && typeof docsMaybe.then === 'function' ? await docsMaybe : docsMaybe || [];
      const recs =
        recsMaybe && typeof recsMaybe.then === 'function' ? await recsMaybe : recsMaybe || [];
      const acks =
        acksMaybe && typeof acksMaybe.then === 'function' ? await acksMaybe : acksMaybe || [];
      const batches =
        batchesMaybe && typeof batchesMaybe.then === 'function'
          ? await batchesMaybe
          : batchesMaybe || [];
      const matchFilters = (r) => {
        if (req.query.businessId && String(r.businessId) !== String(req.query.businessId))
          return false;
        if (
          req.query.department &&
          String(r.department || '').toLowerCase() !== String(req.query.department).toLowerCase()
        )
          return false;
        if (
          req.query.primaryGroup &&
          String(r.primaryGroup || '').toLowerCase() !==
            String(req.query.primaryGroup).toLowerCase()
        )
          return false;
        return true;
      };
      const recsFiltered = recs.filter(matchFilters);
      let out = docs.map((d) => {
        const assigned = recsFiltered.filter((r) => String(r.batchId) === String(d.batchId)).length;
        const completed = acks
          .filter((a) => a.acknowledged && String(a.documentId) === String(d.id))
          .filter((a) =>
            recsFiltered.some(
              (r) =>
                String(r.batchId) === String(a.batchId) &&
                String(r.email || '').toLowerCase() === String(a.email || '').toLowerCase()
            )
          ).length;
        const batchName = (batches.find((b) => String(b.id) === String(d.batchId)) || {}).name;
        return {
          documentId: String(d.id),
          documentName: d.title,
          batchName,
          totalAssigned: assigned,
          completed,
        };
      });
      // Sort by documentId desc for parity
      out.sort((a, b) => (a.documentId < b.documentId ? 1 : -1));
      // Optional search and pagination
      const qDocs = String(req.query.q || '')
        .toLowerCase()
        .trim();
      if (qDocs) {
        out = out.filter(
          (r) =>
            String(r.documentName || '')
              .toLowerCase()
              .includes(qDocs) ||
            String(r.batchName || '')
              .toLowerCase()
              .includes(qDocs)
        );
      }
      const limitDocs = Math.max(1, Math.min(Number(req.query.limit || 100), 500));
      const offsetDocs = Math.max(0, Number(req.query.offset || 0));
      const pagedDocs = out.slice(offsetDocs, offsetDocs + limitDocs);
      return res.json(pagedDocs);
    }

    // Default SQL path
    const assignedMaybe = all(
      `SELECT d.id as documentId, d.title as documentName, b.name as batchName, COUNT(r.id) as totalAssigned FROM documents d JOIN batches b ON b.id=d.batchId JOIN recipients r ON r.batchId=d.batchId ${where} GROUP BY d.id, d.title, b.name ORDER BY d.id DESC`,
      params
    );
    const ackedMaybe = all(
      `SELECT d.id as documentId, COUNT(a.id) as completed FROM documents d LEFT JOIN acks a ON a.documentId=d.id AND a.acknowledged=1 JOIN recipients r ON r.batchId=d.batchId AND LOWER(r.email)=LOWER(a.email) ${where} GROUP BY d.id ORDER BY d.id DESC`,
      params
    );
    const assigned =
      assignedMaybe && typeof assignedMaybe.then === 'function'
        ? await assignedMaybe
        : assignedMaybe || [];
    const acked =
      ackedMaybe && typeof ackedMaybe.then === 'function' ? await ackedMaybe : ackedMaybe || [];
    const am = new Map(assigned.map((r) => [String(r.documentId), Number(r.totalAssigned)]));
    const info = new Map(
      assigned.map((r) => [
        String(r.documentId),
        { documentName: r.documentName, batchName: r.batchName },
      ])
    );
    const cm = new Map(acked.map((r) => [String(r.documentId), Number(r.completed)]));
    let out = Array.from(am.keys()).map((docId) => ({
      documentId: String(docId),
      documentName: (info.get(String(docId)) || {}).documentName,
      batchName: (info.get(String(docId)) || {}).batchName,
      totalAssigned: am.get(String(docId)) || 0,
      completed: cm.get(String(docId)) || 0,
    }));
    // Optional search and pagination
    const qDocs = String(req.query.q || '')
      .toLowerCase()
      .trim();
    if (qDocs) {
      out = out.filter(
        (r) =>
          String(r.documentName || '')
            .toLowerCase()
            .includes(qDocs) ||
          String(r.batchName || '')
            .toLowerCase()
            .includes(qDocs)
      );
    }
    const pagedDocs = out.slice(offsetDocs, offsetDocs + limitDocs);
    if (!hasFilters()) writeJsonCache('doc_stats_cache', out);
    res.json(pagedDocs);
  });

  // Trends over the last 30 days (supports filters)
  app.get('/api/trends', async (req, res) => {
    const filters = [];
    const params = [];
    const limitTrend = Math.max(1, Math.min(Number(req.query.limit || 30), 60));
    const windowDays = Math.max(1, Math.min(Number(req.query.windowDays || 30), 90));
    if (req.query.businessId) {
      filters.push('r.businessId = ?');
      params.push(Number(req.query.businessId));
    }
    if (req.query.department) {
      filters.push('LOWER(r.department) = ?');
      params.push(String(req.query.department).toLowerCase());
    }
    if (req.query.primaryGroup) {
      filters.push('LOWER(r.primaryGroup) = ?');
      params.push(String(req.query.primaryGroup).toLowerCase());
    }
    const where = filters.length ? `WHERE ${filters.join(' AND ')}` : '';

    // Completions per day
    const completionsMaybe = all(
      `SELECT substr(a.ackDate,1,10) as date, COUNT(*) as cnt
       FROM acks a
       ${filters.length ? 'JOIN recipients r ON r.batchId=a.batchId AND LOWER(r.email)=LOWER(a.email)' : ''}
       ${filters.length ? where + ' AND ' : 'WHERE '} a.ackDate >= date('now', ?)
       GROUP BY substr(a.ackDate,1,10)
       ORDER BY date`,
      [...params, `-${windowDays - 1} day`]
    );
    // New batches per day (use startDate as proxy)
    let newBatches = [];
    if (filters.length) {
      newBatches = all(
        `SELECT b.startDate as date, COUNT(DISTINCT b.id) as cnt
         FROM batches b
         JOIN recipients r ON r.batchId=b.id
         ${where} AND b.startDate IS NOT NULL AND b.startDate >= date('now', ?)
         GROUP BY b.startDate
         ORDER BY b.startDate`,
        [...params, `-${windowDays - 1} day`]
      );
    } else {
      newBatches = all(
        `SELECT startDate as date, COUNT(*) as cnt
         FROM batches
         WHERE startDate IS NOT NULL AND startDate >= date('now', ?)
         GROUP BY startDate
         ORDER BY startDate`,
        [`-${windowDays - 1} day`]
      );
    }
    // Active users per day (distinct emails with acks)
    const activeUsersMaybe = all(
      `SELECT substr(a.ackDate,1,10) as date, COUNT(DISTINCT LOWER(a.email)) as cnt
       FROM acks a
       ${filters.length ? 'JOIN recipients r ON r.batchId=a.batchId AND LOWER(r.email)=LOWER(a.email)' : ''}
       ${filters.length ? where + ' AND ' : 'WHERE '} a.ackDate >= date('now', ?)
       GROUP BY substr(a.ackDate,1,10)
       ORDER BY date`,
      [...params, `-${windowDays - 1} day`]
    );

    // Normalize to last 30 days, fill zeros for missing days
    const days = Array.from({ length: windowDays }, (_, i) =>
      new Date(Date.now() - (windowDays - 1 - i) * 24 * 60 * 60 * 1000).toISOString().slice(0, 10)
    );
    const toArray = (x) => (Array.isArray(x) ? x : []);
    const mapRows = (rows) => {
      const arr = toArray(rows);
      const m = new Map(arr.map((r) => [String(r.date), Number(r.cnt)]));
      return days.map((d) => ({ date: d, count: Number(m.get(d) || 0) }));
    };
    const completions =
      completionsMaybe && typeof completionsMaybe.then === 'function'
        ? await completionsMaybe
        : completionsMaybe || [];
    const activeUsers =
      activeUsersMaybe && typeof activeUsersMaybe.then === 'function'
        ? await activeUsersMaybe
        : activeUsersMaybe || [];
    if (newBatches && typeof newBatches.then === 'function') newBatches = await newBatches;
    const series = {
      completions: mapRows(completions).slice(-limitTrend),
      newBatches: mapRows(newBatches).slice(-limitTrend),
      activeUsers: mapRows(activeUsers).slice(-limitTrend),
    };
    res.json(series);
  });

  // Admin: rebuild trends cache
  app.post('/api/admin/trends/rebuild', async (req, res) => {
    try {
      const days = Math.max(1, Math.min(Number(req.body?.days || req.query?.days || 30) || 30, 90));
      const rows = await rebuildTrendsCache(days);
      res.json({ ok: true, windowDays: days, rows });
    } catch (e) {
      res.status(500).json({ error: 'rebuild_failed' });
    }
  });

  // Recipients listing with optional filters for analytics filter panels
  app.get('/api/recipients', (req, res) => {
    const filters = [];
    const params = [];
    if (req.query.businessId) {
      filters.push('businessId = ?');
      params.push(Number(req.query.businessId));
    }
    if (req.query.department) {
      filters.push('LOWER(department) = ?');
      params.push(String(req.query.department).toLowerCase());
    }
    if (req.query.primaryGroup) {
      filters.push('LOWER(primaryGroup) = ?');
      params.push(String(req.query.primaryGroup).toLowerCase());
    }
    const where = filters.length ? `WHERE ${filters.join(' AND ')}` : '';
    const qRec = String(req.query.q || '')
      .toLowerCase()
      .trim();
    const limitRec = Math.max(1, Math.min(Number(req.query.limit || 100), 1000));
    const offsetRec = Math.max(0, Number(req.query.offset || 0));
    let rows = all(
      `SELECT id, batchId, businessId, user, email, displayName, department, jobTitle, location, primaryGroup FROM recipients ${where} ORDER BY id DESC`,
      params
    );
    // Ensure rows is always an array
    if (!Array.isArray(rows)) rows = [];
    if (qRec) {
      rows = rows.filter(
        (r) =>
          String(r.email || '')
            .toLowerCase()
            .includes(qRec) ||
          String(r.displayName || '')
            .toLowerCase()
            .includes(qRec) ||
          String(r.department || '')
            .toLowerCase()
            .includes(qRec) ||
          String(r.primaryGroup || '')
            .toLowerCase()
            .includes(qRec)
      );
    }
    const paged = rows.slice(offsetRec, offsetRec + limitRec);
    res.json(paged);
  });

  // Recent activity feed: acknowledgements and batch creations (via startDate)
  app.get('/api/activity/recent', (req, res) => {
    try {
      const limit = Math.max(1, Math.min(Number(req.query.limit || 20), 100));

      // Latest acknowledgements
      let ackRows = all(
        `SELECT a.ackDate AS timestamp,
                LOWER(a.email) AS email,
                COALESCE(r.displayName, a.email) AS displayName,
                d.title AS documentTitle,
                b.name AS batchName
         FROM acks a
         JOIN documents d ON d.id = a.documentId
         JOIN batches b ON b.id = a.batchId
         LEFT JOIN recipients r ON r.batchId = a.batchId AND LOWER(r.email) = LOWER(a.email)
         WHERE a.ackDate IS NOT NULL
         ORDER BY a.ackDate DESC
         LIMIT ?`,
        [limit]
      );
      if (!Array.isArray(ackRows)) ackRows = [];
      ackRows = ackRows.map((r) => ({
        timestamp: r.timestamp,
        type: 'success',
        action: 'acknowledged',
        user: r.displayName || r.email,
        email: r.email,
        document: r.documentTitle,
        batch: r.batchName,
      }));

      // Recent batch creations (use startDate as proxy for creation date if available)
      let batchRows = all(
        `SELECT b.startDate AS timestamp,
                b.name AS batchName
         FROM batches b
         WHERE b.startDate IS NOT NULL
         ORDER BY b.startDate DESC
         LIMIT ?`,
        [Math.max(1, Math.floor(limit / 2))]
      );
      if (!Array.isArray(batchRows)) batchRows = [];
      batchRows = batchRows.map((r) => ({
        timestamp: r.timestamp,
        type: 'info',
        action: 'created batch',
        user: null,
        email: null,
        document: r.batchName,
        batch: r.batchName,
      }));

      // Merge and sort by timestamp desc
      const combined = ([].concat(ackRows, batchRows))
        .filter((ev) => !!ev.timestamp)
        .sort((a, b) => String(b.timestamp).localeCompare(String(a.timestamp)))
        .slice(0, limit);

      res.json(combined);
    } catch (e) {
      console.error('recent activity failed', e);
      res.status(500).json({ error: 'activity_failed' });
    }
  });

  // Detailed acknowledgement report (business + user + batch + document)
  app.get('/api/ack-report', async (req, res) => {
    try {
      // Clamp limits to protect RTDB from full scans
      const limit = Math.max(1, Math.min(Number(req.query.limit || 500), 1000));
      const offset = Math.max(0, Number(req.query.offset || 0));
      const q = String(req.query.q || '').toLowerCase().trim();
      const filterBiz = req.query.businessId ? String(req.query.businessId) : null;
      const filterDept = req.query.department ? String(req.query.department).toLowerCase() : null;
      const filterGroup = req.query.primaryGroup ? String(req.query.primaryGroup).toLowerCase() : null;
      const isFirebase = db && (db.driver === 'firebase' || db.driver === 'rtdb');

      if (isFirebase) {
        const [acksMaybe, docsMaybe, batchesMaybe, recsMaybe, bizMaybe, userBizMaybe] = [
          all('SELECT id, batchId, documentId, email, acknowledged, ackDate FROM acks'),
          all('SELECT id, title, version, url, localUrl, source, batchId FROM documents'),
          all('SELECT id, name, dueDate, createdAt FROM batches'),
          all('SELECT batchId, businessId, email, displayName, department, primaryGroup FROM recipients'),
          all('SELECT id, name FROM businesses'),
          all('SELECT email, businessId FROM user_businesses'),
        ];
        const acks = (acksMaybe && typeof acksMaybe.then === 'function' ? await acksMaybe : acksMaybe) || [];
        const docs = (docsMaybe && typeof docsMaybe.then === 'function' ? await docsMaybe : docsMaybe) || [];
        const batches = (batchesMaybe && typeof batchesMaybe.then === 'function' ? await batchesMaybe : batchesMaybe) || [];
        const recs = (recsMaybe && typeof recsMaybe.then === 'function' ? await recsMaybe : recsMaybe) || [];
        const businesses = (bizMaybe && typeof bizMaybe.then === 'function' ? await bizMaybe : bizMaybe) || [];
        const userBiz = (userBizMaybe && typeof userBizMaybe.then === 'function' ? await userBizMaybe : userBizMaybe) || [];
        const bizMap = new Map(businesses.map((b) => [String(b.id), b.name]));
        const docMap = new Map(docs.map((d) => [String(d.id), d]));
        const batchMap = new Map(batches.map((b) => [String(b.id), b]));
        const recKey = (batchId, email) => `${batchId}::${String(email || '').toLowerCase()}`;
        const recMap = new Map(recs.map((r) => [recKey(r.batchId, r.email), r]));
        const userBizMap = new Map(
          userBiz.map((u) => [String(u.email || '').toLowerCase(), u.businessId != null ? String(u.businessId) : null])
        );

        let rows = acks
          .filter((a) => a && a.batchId && a.documentId && a.batchId !== 'undefined' && a.documentId !== 'undefined')
          .map((a) => {
            const doc = docMap.get(String(a.documentId)) || {};
            const batch = batchMap.get(String(a.batchId)) || {};
            const rec = recMap.get(recKey(a.batchId, a.email)) || {};
            const emailLc = String(a.email || '').toLowerCase();
            const mappedBizId = userBizMap.get(emailLc);
            const businessId = rec.businessId != null
              ? String(rec.businessId)
              : batch.businessId != null
                ? String(batch.businessId)
                : mappedBizId != null
                  ? String(mappedBizId)
                  : null;
            const docVersion = Number.isFinite(Number(doc.version)) ? Number(doc.version) : 1;
            const documentUrl = doc.localUrl || doc.url || doc.originalUrl || null;
            return {
              ackId: a.id,
              businessId,
              businessName: businessId ? bizMap.get(businessId) || null : null,
              batchId: a.batchId,
              batchName: batch.name,
              documentId: a.documentId,
              documentTitle: doc.title,
              documentVersion: docVersion,
              documentSource: doc.source,
              documentUrl,
              email: a.email,
              displayName: rec.displayName,
              department: rec.department,
              primaryGroup: rec.primaryGroup,
              acknowledged: a.acknowledged,
              acknowledgedAt: a.ackDate,
              dueDate: batch.dueDate || batch.startDate || null,
              batchCreatedAt: batch.createdAt || batch.startDate || null,
            };
          });

        if (filterBiz) rows = rows.filter((r) => String(r.businessId) === filterBiz);
        if (filterDept)
          rows = rows.filter((r) => String(r.department || '').toLowerCase() === filterDept);
        if (filterGroup)
          rows = rows.filter((r) => String(r.primaryGroup || '').toLowerCase() === filterGroup);
        if (q) {
          rows = rows.filter(
            (r) =>
              String(r.email || '').toLowerCase().includes(q) ||
              String(r.documentTitle || '').toLowerCase().includes(q) ||
              String(r.batchName || '').toLowerCase().includes(q) ||
              String(r.businessName || '').toLowerCase().includes(q)
          );
        }

        const paged = rows.slice(offset, offset + limit);
        return res.json({ total: rows.length, items: paged });
      }

      // SQL path
      const filters = [];
      const params = [];
      if (filterBiz) {
        filters.push('COALESCE(r.businessId, b.businessId, ub.businessId) = ?');
        params.push(Number(filterBiz));
      }
      if (filterDept) {
        filters.push('LOWER(r.department) = ?');
        params.push(filterDept);
      }
      if (filterGroup) {
        filters.push('LOWER(r.primaryGroup) = ?');
        params.push(filterGroup);
      }
      if (q) {
        filters.push(
          '(LOWER(a.email) LIKE ? OR LOWER(d.title) LIKE ? OR LOWER(b.name) LIKE ? OR LOWER(biz.name) LIKE ?)' // search
        );
        const like = `%${q}%`;
        params.push(like, like, like, like);
      }
      const where = filters.length ? `WHERE ${filters.join(' AND ')}` : '';
      const dataMaybe = all(
        `SELECT a.id as ackId,
                a.email,
                a.ackDate as acknowledgedAt,
                a.acknowledged,
                d.id as documentId,
                d.title as documentTitle,
                d.version as documentVersion,
                d.url as documentUrl,
                d.localUrl as documentLocalUrl,
                d.source as documentSource,
                b.id as batchId,
                b.name as batchName,
                b.dueDate,
                b.createdAt as batchCreatedAt,
                COALESCE(r.businessId, b.businessId, ub.businessId) as businessId,
                biz.name as businessName,
                r.displayName,
                r.department,
                r.primaryGroup
         FROM acks a
         JOIN documents d ON d.id = a.documentId
         JOIN batches b ON b.id = a.batchId
         LEFT JOIN recipients r ON r.batchId = a.batchId AND LOWER(r.email) = LOWER(a.email)
         LEFT JOIN user_businesses ub ON LOWER(ub.email) = LOWER(a.email)
         LEFT JOIN businesses biz ON biz.id = COALESCE(r.businessId, b.businessId, ub.businessId)
         ${where}
         ORDER BY a.ackDate DESC
         LIMIT ? OFFSET ?`,
        [...params, limit, offset]
      );
      const rows = dataMaybe && typeof dataMaybe.then === 'function' ? await dataMaybe : dataMaybe || [];
      return res.json({
        total: rows.length,
        items: rows.map((r) => ({
          ...r,
          documentUrl: r.documentLocalUrl || r.documentUrl,
          documentVersion: Number.isFinite(Number(r.documentVersion)) ? Number(r.documentVersion) : 1,
        })),
      });
    } catch (e) {
      res.status(500).json({ error: 'ack_report_failed', details: e?.message || String(e) });
    }
  });

  // Simple streaming proxy to bypass X-Frame-Options/CSP on third-party hosts when embedding
  // Usage: GET /api/proxy?url=https%3A%2F%2Fexample.com%2Ffile.pdf
  app.get('/api/proxy', (req, res) => {
    try {
      const raw = (req.query.url || '').toString();
      if (!raw) return res.status(400).json({ error: 'url_required' });
      let target;
      try {
        target = new URL(raw);
      } catch {
        return res.status(400).json({ error: 'invalid_url' });
      }
      if (!/^https?:$/.test(target.protocol))
        return res.status(400).json({ error: 'unsupported_protocol' });
      const isDiag =
        String(req.query.diag || '').toLowerCase() === '1' ||
        String(req.query.diag || '').toLowerCase() === 'true';

      const forward = (urlObj, redirects = 0) => {
        const client = urlObj.protocol === 'https:' ? https : http;
        const agent = getProxyAgent(urlObj);
        const TIMEOUT_MS = Number(process.env.PROXY_TIMEOUT_MS || 15000);
        const reqOpts = { method: 'GET', headers: { 'User-Agent': 'Sunbeth-Proxy/1.0' }, agent };
        const r = client.request(urlObj, reqOpts, (upstream) => {
          // Handle simple redirects up to 3 hops
          if (
            upstream.statusCode >= 300 &&
            upstream.statusCode < 400 &&
            upstream.headers.location &&
            redirects < 3
          ) {
            try {
              const next = new URL(upstream.headers.location, urlObj);
              forward(next, redirects + 1);
            } catch {
              res.status(502).end();
            }
            return;
          }
          if (isDiag) {
            const ct = upstream.headers['content-type'] || '';
            const len = upstream.headers['content-length'] || null;
            try {
              upstream.destroy();
            } catch {}
            return res.json({
              ok: true,
              status: upstream.statusCode,
              contentType: ct,
              contentLength: len,
              finalUrl: urlObj.toString(),
              redirected: redirects > 0,
              proxyUsed: !!agent,
              timeoutMs: TIMEOUT_MS,
            });
          } else {
            // Propagate content-type if available; force inline disposition
            const ct = upstream.headers['content-type'] || 'application/octet-stream';
            res.setHeader('Content-Type', ct);
            res.setHeader('Cache-Control', 'no-store');
            res.removeHeader && res.removeHeader('X-Frame-Options');
            upstream.on('error', () => {
              try {
                res.destroy();
              } catch {}
            });
            upstream.pipe(res);
          }
        });
        r.on('timeout', () => {
          try {
            r.destroy(new Error('timeout'));
          } catch {}
        });
        r.setTimeout(TIMEOUT_MS);
        r.on('error', (e) => {
          if (isDiag && !res.headersSent)
            return res
              .status(200)
              .json({ ok: false, error: 'upstream_error', message: String(e?.message || e) });
          if (!res.headersSent) res.status(502).json({ error: 'upstream_error' });
          else
            try {
              res.destroy();
            } catch {}
        });
        r.end();
      };
      forward(target);
    } catch (e) {
      console.error('Proxy error', e);
      res.status(500).json({ error: 'proxy_failed' });
    }
  });

  // Authenticated Microsoft Graph streaming proxy for SharePoint files
  // Usage (query):
  //   - GET /api/proxy/graph?driveId=...&itemId=...&token=...
  //   - GET /api/proxy/graph?url=https%3A%2F%2Fcontoso.sharepoint.com%2F...&token=...
  // Token is optional if supplied via Authorization header; otherwise required as query param.
  app.get('/api/proxy/graph', (req, res) => {
    try {
      const driveId = (req.query.driveId || '').toString();
      const itemId = (req.query.itemId || '').toString();
      const rawUrl = (req.query.url || '').toString();
      const qToken = (req.query.token || '').toString();
      const hdrAuth = (req.headers['authorization'] || '').toString();
      const bearer = qToken
        ? `Bearer ${qToken}`
        : hdrAuth && /^Bearer\s+/i.test(hdrAuth)
          ? hdrAuth
          : '';
      const isDiag =
        String(req.query.diag || '').toLowerCase() === '1' ||
        String(req.query.diag || '').toLowerCase() === 'true';
      const download = (req.query.download || '').toString() === '1';
      if (!bearer) return res.status(401).json({ error: 'token_required' });

      let url;
      if (driveId && itemId) {
        url = new URL(
          `https://graph.microsoft.com/v1.0/drives/${encodeURIComponent(driveId)}/items/${encodeURIComponent(itemId)}/content`
        );
      } else if (rawUrl) {
        // Build shares URL id: 'u!' + base64urlencode(originalUrl)
        const b64 = Buffer.from(rawUrl, 'utf8')
          .toString('base64')
          .replace(/=/g, '')
          .replace(/\+/g, '-')
          .replace(/\//g, '_');
        const shareId = `u!${b64}`;
        url = new URL(`https://graph.microsoft.com/v1.0/shares/${shareId}/driveItem/content`);
      } else {
        return res.status(400).json({ error: 'missing_ids_or_url' });
      }

      const follow = (targetUrl, redirects = 0) => {
        const agent = getProxyAgent(targetUrl);
        const TIMEOUT_MS = Number(process.env.PROXY_TIMEOUT_MS || 15000);
        const opts = {
          method: 'GET',
          headers: { Authorization: bearer, 'User-Agent': 'Sunbeth-Graph-Proxy/1.0' },
          agent,
        };
        const r = https.request(targetUrl, opts, (upstream) => {
          // Handle Graph 302 redirect to a pre-authenticated blob URL
          if (
            upstream.statusCode >= 300 &&
            upstream.statusCode < 400 &&
            upstream.headers.location &&
            redirects < 3
          ) {
            try {
              const next = new URL(upstream.headers.location, targetUrl);
              // If caller wants a browser redirect (download=1 or explicit redir=1), send 302 to client instead of streaming
              const wantRedirect =
                !isDiag && (download || String(req.query.redir || '').toString() === '1');
              if (wantRedirect) {
                // Best-effort content-type hint for some browsers
                try {
                  const ct2 = upstream.headers['content-type'] || 'application/octet-stream';
                  res.setHeader('Content-Type', ct2);
                } catch {}
                return res.redirect(302, next.toString());
              }
              const client = next.protocol === 'https:' ? https : http;
              const agent2 = getProxyAgent(next);
              const r2 = client.request(
                next,
                {
                  method: 'GET',
                  headers: { 'User-Agent': 'Sunbeth-Graph-Proxy/1.0' },
                  agent: agent2,
                },
                (up2) => {
                  if (isDiag) {
                    const ct2 = up2.headers['content-type'] || '';
                    const len2 = up2.headers['content-length'] || null;
                    try {
                      up2.destroy();
                    } catch {}
                    return res.json({
                      ok: true,
                      phase: 'redirect',
                      status: up2.statusCode,
                      contentType: ct2,
                      contentLength: len2,
                      finalUrl: next.toString(),
                      redirected: true,
                      proxyUsed: !!agent2,
                      timeoutMs: TIMEOUT_MS,
                    });
                  } else {
                    const ct2 = up2.headers['content-type'] || 'application/octet-stream';
                    res.setHeader('Content-Type', ct2);
                    res.setHeader('Cache-Control', 'no-store');
                    if (download) {
                      try {
                        const cd = up2.headers['content-disposition'];
                        let name = null;
                        if (
                          cd &&
                          /filename\*=utf-8''([^;]+)|filename="?([^";]+)"?/i.test(String(cd))
                        ) {
                          const m = String(cd).match(
                            /filename\*=utf-8''([^;]+)|filename="?([^";]+)"?/i
                          );
                          name = decodeURIComponent(m[1] || m[2] || 'file');
                        }
                        if (!name) {
                          const candidate = decodeURIComponent(
                            (next.pathname || '').split('/').pop() || ''
                          ).trim();
                          name = candidate && candidate !== 'content' ? candidate : 'document';
                        }
                        if (/application\/pdf/i.test(ct2) && !/\.pdf$/i.test(name))
                          name = `${name}.pdf`;
                        res.setHeader('Content-Disposition', `attachment; filename="${name}"`);
                      } catch {}
                    }
                    up2.on('error', () => {
                      try {
                        res.destroy();
                      } catch {}
                    });
                    up2.pipe(res);
                  }
                }
              );
              r2.on('timeout', () => {
                try {
                  r2.destroy(new Error('timeout'));
                } catch {}
              });
              r2.setTimeout(TIMEOUT_MS);
              r2.on('error', (e) => {
                if (isDiag && !res.headersSent)
                  return res
                    .status(200)
                    .json({
                      ok: false,
                      phase: 'redirect',
                      error: 'upstream_error',
                      message: String(e?.message || e),
                    });
                if (!res.headersSent) res.status(502).json({ error: 'upstream_error' });
                else
                  try {
                    res.destroy();
                  } catch {}
              });
              r2.end();
              return;
            } catch {
              return isDiag
                ? res.status(200).json({ ok: false, error: 'redirect_failed' })
                : res.status(502).json({ error: 'redirect_failed' });
            }
          }
          if (isDiag) {
            const ct = upstream.headers['content-type'] || '';
            const len = upstream.headers['content-length'] || null;
            try {
              upstream.destroy();
            } catch {}
            return res.json({
              ok: true,
              phase: 'direct',
              status: upstream.statusCode,
              contentType: ct,
              contentLength: len,
              finalUrl: targetUrl.toString(),
              redirected: redirects > 0,
              proxyUsed: !!agent,
              timeoutMs: TIMEOUT_MS,
            });
          } else {
            // No redirect: stream as-is
            const ct = upstream.headers['content-type'] || 'application/octet-stream';
            res.setHeader('Content-Type', ct);
            res.setHeader('Cache-Control', 'no-store');
            if (download) {
              try {
                const cd = upstream.headers['content-disposition'];
                let name = null;
                if (cd && /filename\*=utf-8''([^;]+)|filename="?([^";]+)"?/i.test(String(cd))) {
                  const m = String(cd).match(/filename\*=utf-8''([^;]+)|filename="?([^";]+)"?/i);
                  name = decodeURIComponent(m[1] || m[2] || 'file');
                }
                if (!name) name = 'document';
                if (/application\/pdf/i.test(ct) && !/\.pdf$/i.test(name)) name = `${name}.pdf`;
                res.setHeader('Content-Disposition', `attachment; filename="${name}"`);
              } catch {}
            }
            upstream.on('error', () => {
              try {
                res.destroy();
              } catch {}
            });
            upstream.pipe(res);
          }
        });
        r.on('timeout', () => {
          try {
            r.destroy(new Error('timeout'));
          } catch {}
        });
        r.setTimeout(TIMEOUT_MS);
        r.on('error', (e) => {
          if (isDiag && !res.headersSent)
            return res
              .status(200)
              .json({
                ok: false,
                phase: 'direct',
                error: 'upstream_error',
                message: String(e?.message || e),
              });
          if (!res.headersSent) res.status(502).json({ error: 'upstream_error' });
          else
            try {
              res.destroy();
            } catch {}
        });
        r.end();
      };
      follow(url);
    } catch (e) {
      console.error('Graph proxy error', e);
      res.status(500).json({ error: 'proxy_failed' });
    }
  });

  // Settings API: External support toggle
  app.get('/api/settings/external-support', async (_req, res) => {
    try {
      const v = String((await getSettingAsync('external_support_enabled', '0')) || '0');
      const enabled = v === '1' || v.toLowerCase() === 'true';
      res.json({ enabled });
    } catch (e) {
      res.status(500).json({ error: 'failed' });
    }
  });
  app.put('/api/settings/external-support', async (req, res) => {
    try {
      const enabled = !!(
        req.body &&
        (req.body.enabled === true ||
          req.body.enabled === 'true' ||
          req.body.enabled === 1 ||
          req.body.enabled === '1')
      );
      const ok = await setSettingAsync('external_support_enabled', enabled ? '1' : '0');
      if (!ok) return res.status(500).json({ error: 'save_failed' });
      res.json({ enabled });
    } catch (e) {
      res.status(500).json({ error: 'failed' });
    }
  });
  // Settings API: Legal consent document (global)
  app.get('/api/settings/legal-consent', async (req, res) => {
    try {
      const isFirebase = db && (db.driver === 'firebase' || db.driver === 'rtdb');
      const idRaw = getSetting('legal_consent_file_id', null);
      const id = isFirebase ? (idRaw ? String(idRaw) : null) : idRaw != null ? Number(idRaw) : null;
      const allowPreviewRaw = getSetting('legal_consent_allow_preview', '0');
      const allowDenyRaw = getSetting('legal_consent_allow_deny', '0');
      const uploadCompletionPdfRaw = getSetting('upload_completion_pdf', '0');
      const allowPreview = String(allowPreviewRaw || '0').toLowerCase() === 'true' || String(allowPreviewRaw || '0') === '1';
      const allowDeny = String(allowDenyRaw || '0').toLowerCase() === 'true' || String(allowDenyRaw || '0') === '1';
      const uploadCompletionPdf = String(uploadCompletionPdfRaw || '0').toLowerCase() === 'true' || String(uploadCompletionPdfRaw || '0') === '1';
      if ((isFirebase && !id) || (!isFirebase && (!id || !Number.isFinite(id))))
        return res.json({
          fileId: null,
          url: null,
          name: null,
          version: null,
          sha256: null,
          size: null,
          mime: null,
          allowPreview,
          allowDeny,
          uploadCompletionPdf,
        });
      const row = isFirebase
        ? await one('SELECT id, original_name, sha256, size, mime FROM uploaded_files WHERE id=?', [
            id,
          ])
        : one('SELECT id, original_name, sha256, size, mime FROM uploaded_files WHERE id=?', [id]);
      if (!row)
        return res.json({
          fileId: null,
          url: null,
          name: null,
          version: null,
          sha256: null,
          size: null,
          mime: null,
          allowPreview,
          allowDeny,
          uploadCompletionPdf,
        });
      // Try to enrich with legal version metadata if available
      let version = null;
      try {
        const vIdRaw = getSetting('legal_consent_version_id', null);
        const vId = isFirebase
          ? vIdRaw
            ? String(vIdRaw)
            : null
          : vIdRaw != null
            ? Number(vIdRaw)
            : null;
        if ((isFirebase && vId) || (!isFirebase && vId && Number.isFinite(vId))) {
          const v = isFirebase
            ? await one('SELECT version FROM legal_doc_versions WHERE id=?', [vId])
            : one('SELECT version FROM legal_doc_versions WHERE id=?', [vId]);
          if (v && v.version != null) version = Number(v.version);
        }
      } catch {}
      return res.json({
        fileId: row.id,
        url: `/api/files/${row.id}`,
        name: row.original_name || 'document.pdf',
        version,
        sha256: row.sha256 || null,
        size: row.size || null,
        mime: row.mime || null,
        allowPreview,
        allowDeny,
        uploadCompletionPdf,
      });
    } catch (e) {
      res.status(500).json({ error: 'failed' });
    }
  });
  app.put(
    '/api/settings/legal-consent',
    validate({
      type: 'object',
      required: ['fileId'],
      additionalProperties: true,
      properties: {
        fileId: { anyOf: [{ type: 'integer' }, { type: 'string' }, { type: 'null' }] },
      },
    }),
    async (req, res) => {
      try {
        const isFirebase = db && (db.driver === 'firebase' || db.driver === 'rtdb');
        const fileId =
          req.body && req.body.fileId != null
            ? isFirebase
              ? String(req.body.fileId)
              : Number(req.body.fileId)
            : null;
        if (fileId === null) {
          // clear
          await setSettingAsync('legal_consent_file_id', '');
          try {
            await setSettingAsync('legal_consent_version_id', '');
          } catch {}
          try {
            const allowPreviewRaw = req.body?.allowPreview;
            const allowDenyRaw = req.body?.allowDeny;
            const uploadCompletionPdfRaw = req.body?.uploadCompletionPdf;
            const allowPreview = allowPreviewRaw === true || String(allowPreviewRaw) === '1';
            const allowDeny = allowDenyRaw === true || String(allowDenyRaw) === '1';
            const uploadCompletionPdf = uploadCompletionPdfRaw === true || String(uploadCompletionPdfRaw) === '1';
            await setSettingAsync('legal_consent_allow_preview', allowPreview ? '1' : '0');
            await setSettingAsync('legal_consent_allow_deny', allowDeny ? '1' : '0');
            await setSettingAsync('upload_completion_pdf', uploadCompletionPdf ? '1' : '0');
          } catch {}
          return res.json({ fileId: null });
        }
        if ((!isFirebase && (!Number.isFinite(fileId) || fileId <= 0)) || (isFirebase && !fileId))
          return res.status(400).json({ error: 'invalid_file_id' });
        const exists = isFirebase
          ? await one(
              'SELECT id, original_name, sha256, size, mime FROM uploaded_files WHERE id=?',
              [fileId]
            )
          : one('SELECT id, original_name, sha256, size, mime FROM uploaded_files WHERE id=?', [
              fileId,
            ]);
        if (!exists) return res.status(404).json({ error: 'file_not_found' });
        const ok = await setSettingAsync('legal_consent_file_id', String(fileId));
        if (!ok) return res.status(500).json({ error: 'save_failed' });
        try {
          const allowPreviewRaw = req.body?.allowPreview;
          const allowDenyRaw = req.body?.allowDeny;
          const uploadCompletionPdfRaw = req.body?.uploadCompletionPdf;
          if (allowPreviewRaw !== undefined) await setSettingAsync('legal_consent_allow_preview', (allowPreviewRaw === true || String(allowPreviewRaw) === '1') ? '1' : '0');
          if (allowDenyRaw !== undefined) await setSettingAsync('legal_consent_allow_deny', (allowDenyRaw === true || String(allowDenyRaw) === '1') ? '1' : '0');
          if (uploadCompletionPdfRaw !== undefined) await setSettingAsync('upload_completion_pdf', (uploadCompletionPdfRaw === true || String(uploadCompletionPdfRaw) === '1') ? '1' : '0');
        } catch {}
        // Record a new legal document version if not present for this sha256
        try {
          const sha = String(exists.sha256 || '');
          let verRow = null;
          if (sha) {
            verRow = isFirebase
              ? await one(
                  'SELECT id, version FROM legal_doc_versions WHERE sha256=? ORDER BY version DESC LIMIT 1',
                  [sha]
                )
              : one(
                  'SELECT id, version FROM legal_doc_versions WHERE sha256=? ORDER BY version DESC LIMIT 1',
                  [sha]
                );
          }
          if (!verRow) {
            // Determine next version number
            const maxVer = isFirebase
              ? await one('SELECT MAX(version) AS v FROM legal_doc_versions')
              : one('SELECT MAX(version) AS v FROM legal_doc_versions');
            const nextVer = maxVer && maxVer.v != null ? Number(maxVer.v) + 1 : 1;
            const now = new Date().toISOString();
            const createdBy =
              String(
                req.headers['x-user-email'] || req.headers['x-admin-email'] || ''
              ).toLowerCase() || null;
            db.run(
              `INSERT INTO legal_doc_versions (file_id, sha256, name, size, mime, effective_from, version, created_at, created_by)
                  VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
              [
                fileId,
                exists.sha256 || null,
                exists.original_name || null,
                exists.size || null,
                exists.mime || null,
                now,
                nextVer,
                now,
                createdBy,
              ]
            );
            const vId = isFirebase
              ? (await one('SELECT last_insert_rowid() as id'))?.id
              : one('SELECT last_insert_rowid() as id')?.id;
            if (vId) await setSettingAsync('legal_consent_version_id', String(vId));
          } else {
            // If already versioned for this sha, just mark current as active
            await setSettingAsync('legal_consent_version_id', String(verRow.id));
          }
        } catch {}
        res.json({ fileId });
      } catch (e) {
        res.status(500).json({ error: 'failed' });
      }
    }
  );

  // Consent receipts API
  // Record a consent for the current legal doc version
  app.post(
    '/api/consents',
    validate({
      type: 'object',
      required: ['email'],
      additionalProperties: true,
      properties: {
        email: { type: 'string', format: 'email' },
        batchId: { type: ['string', 'null'] },
        meta: { type: ['object', 'null'] },
      },
    }),
    async (req, res) => {
      try {
        const tenantId = req?.tenant?.id || null;
        const emailRaw = (
          req.body?.email ||
          req.headers['x-user-email'] ||
          req.headers['x-admin-email'] ||
          ''
        ).toString();
        const email = String(emailRaw || '')
          .trim()
          .toLowerCase();
        const batchId = req.body?.batchId != null ? String(req.body.batchId) : null;
        if (!email || !email.includes('@'))
          return res.status(400).json({ error: 'email_required' });
        // Resolve active legal doc
        const isFirebase = db && (db.driver === 'firebase' || db.driver === 'rtdb');
        const fileIdRaw = await getSettingAsync('legal_consent_file_id', null);
        const fileId = fileIdRaw != null
          ? isFirebase
            ? String(fileIdRaw).trim()
            : Number(fileIdRaw)
          : null;
        const hasFileId = isFirebase ? !!fileId : fileId && Number.isFinite(fileId);
        if (!hasFileId) return res.status(400).json({ error: 'legal_doc_not_configured' });
        const fi = one(
          'SELECT id, original_name, sha256, size, mime FROM uploaded_files WHERE id=?',
          [fileId]
        );
        if (!fi) return res.status(404).json({ error: 'legal_doc_file_missing' });
        const vIdRaw = await getSettingAsync('legal_consent_version_id', null);
        const legalVersionId = vIdRaw != null
          ? isFirebase
            ? String(vIdRaw).trim()
            : Number(vIdRaw)
          : null;
        let legalVersion = null;
        if (legalVersionId && (isFirebase || Number.isFinite(legalVersionId))) {
          const v = one('SELECT version FROM legal_doc_versions WHERE id=?', [legalVersionId]);
          if (v && v.version != null) legalVersion = Number(v.version);
        }
        const now = new Date().toISOString();
        const ip =
          req && (req.ip || req.headers['x-forwarded-for'])
            ? String(req.ip || req.headers['x-forwarded-for'])
            : '';
        const ua = req && req.get ? String(req.get('User-Agent') || '') : '';
        const receiptId = `rcpt_${Math.random().toString(36).slice(2)}_${Date.now().toString(36)}`;
        let receiptSig = null;
        try {
          const secret = process.env.CONSENT_RECEIPT_SECRET || '';
          if (secret) {
            const base = `${tenantId || ''}|${email}|${batchId || ''}|${fileId}|${fi.sha256 || ''}|${now}|${receiptId}`;
            receiptSig = require('crypto').createHmac('sha256', secret).update(base).digest('hex');
          }
        } catch {}
        const meta =
          req.body?.meta && typeof req.body.meta === 'object'
            ? JSON.stringify(req.body.meta)
            : null;
        db.run(
          `INSERT INTO consents (tenant_id, email, batch_id, consented_at, file_id, file_sha256, file_name, file_size, file_mime, legal_version_id, legal_version, ip, ua, receipt_id, receipt_sig, meta_json)
              VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
          [
            tenantId,
            email,
            batchId,
            now,
            fileId,
            fi.sha256 || null,
            fi.original_name || null,
            fi.size || null,
            fi.mime || null,
            legalVersionId || null,
            legalVersion || null,
            ip,
            ua,
            receiptId,
            receiptSig,
            meta,
          ]
        );
        persist(db);
        audit(req, 'legal_consent', email, 'ok', {
          batchId,
          fileId,
          version: legalVersion,
          receiptId,
        });
        return res.json({
          ok: true,
          receiptId,
          consentedAt: now,
          fileId,
          sha256: fi.sha256 || null,
          version: legalVersion,
        });
      } catch (e) {
        try {
          audit(req, 'legal_consent', req?.body?.email, 'error', { message: e.message });
        } catch {}
        res.status(500).json({ error: 'consent_failed', details: e?.message || String(e) });
      }
    }
  );

  // Receipt lookup (returns consent record by receipt id)
  app.get('/api/receipts/:id', (req, res) => {
    try {
      const id = String(req.params.id || '').trim();
      if (!id) return res.status(400).json({ error: 'id_required' });
      const r = one(
        `SELECT id, tenant_id as tenantId, email, batch_id as batchId, consented_at as consentedAt,
                            file_id as fileId, file_sha256 as sha256, file_name as name, file_size as size, file_mime as mime,
                            legal_version_id as legalVersionId, legal_version as version, ip, ua, receipt_id as receiptId, receipt_sig as receiptSig
                     FROM consents WHERE receipt_id=?`,
        [id]
      );
      if (!r) return res.status(404).json({ error: 'not_found' });
      res.json(r);
    } catch (e) {
      res.status(500).json({ error: 'lookup_failed' });
    }
  });

  // Admin export (SuperAdmin only via /api/admin/* guard earlier)
  app.get('/api/admin/consents/export', async (req, res) => {
    try {
      const tenantId = req.query.tenantId != null ? Number(req.query.tenantId) : null;
      const email = String(req.query.email || '')
        .trim()
        .toLowerCase();
      const batchId = String(req.query.batchId || '').trim();
      const since = String(req.query.since || '').trim();
      const until = String(req.query.until || '').trim();
      const limit = Math.max(1, Math.min(Number(req.query.limit || 200), 1000));
      const offset = Math.max(0, Number(req.query.offset || 0));
      const conds = [];
      const params = [];
      if (tenantId != null && !Number.isNaN(tenantId)) {
        conds.push('tenant_id=?');
        params.push(tenantId);
      }
      if (email) {
        conds.push('LOWER(email)=?');
        params.push(email);
      }
      if (batchId) {
        conds.push('batch_id=?');
        params.push(batchId);
      }
      if (since) {
        conds.push('consented_at>=?');
        params.push(since);
      }
      if (until) {
        conds.push('consented_at<=?');
        params.push(until);
      }
      const where = conds.length ? 'WHERE ' + conds.join(' AND ') : '';
      const isFirebase = db && (db.driver === 'firebase' || db.driver === 'rtdb');

      if (isFirebase) {
        const rowsMaybe = all(
          `SELECT id, tenant_id as tenantId, email, batch_id as batchId, consented_at as consentedAt, file_id as fileId, file_sha256 as sha256, file_name as name, file_size as size, file_mime as mime, legal_version_id as legalVersionId, legal_version as version, ip, ua, receipt_id as receiptId FROM consents ${where} ORDER BY consented_at DESC`,
          params
        );
        const rows =
          rowsMaybe && typeof rowsMaybe.then === 'function' ? await rowsMaybe : rowsMaybe || [];
        const paged = rows.slice(offset, offset + limit);
        return res.json({ total: rows.length, items: paged });
      }

        const countMaybe = one(`SELECT COUNT(*) as cnt FROM consents ${where}`, params);
        const countRow = countMaybe && typeof countMaybe.then === 'function' ? await countMaybe : countMaybe || { cnt: 0 };
        const total = Number(countRow.cnt || 0);
        const rowsMaybe = all(
          `SELECT id, tenant_id as tenantId, email, batch_id as batchId, consented_at as consentedAt, file_id as fileId, file_sha256 as sha256, file_name as name, file_size as size, file_mime as mime, legal_version_id as legalVersionId, legal_version as version, ip, ua, receipt_id as receiptId FROM consents ${where} ORDER BY id DESC LIMIT ? OFFSET ?`,
          [...params, limit, offset]
        );
        const rows = rowsMaybe && typeof rowsMaybe.then === 'function' ? await rowsMaybe : rowsMaybe || [];
        res.json({ total, items: rows });
    } catch (e) {
      res.status(500).json({ error: 'export_failed' });
    }
  });

  // Consent summary (premium analytics)
  app.get('/api/consents/summary', async (req, res) => {
    try {
      const isFirebase = db && (db.driver === 'firebase' || db.driver === 'rtdb');
      const filterBiz = req.query.businessId ? String(req.query.businessId) : null;
      const filterDept = req.query.department ? String(req.query.department).toLowerCase() : null;
      const filterGroup = req.query.primaryGroup ? String(req.query.primaryGroup).toLowerCase() : null;

      if (isFirebase) {
        const [consMaybe, recMaybe, batchMaybe, userBizMaybe] = [
          all('SELECT email, batch_id as batchId, consented_at as consentedAt FROM consents'),
          all('SELECT batchId, email, businessId, department, primaryGroup FROM recipients'),
          all('SELECT id, businessId FROM batches'),
          all('SELECT email, businessId FROM user_businesses'),
        ];
        const cons = (consMaybe && typeof consMaybe.then === 'function' ? await consMaybe : consMaybe) || [];
        const recs = (recMaybe && typeof recMaybe.then === 'function' ? await recMaybe : recMaybe) || [];
        const batches = (batchMaybe && typeof batchMaybe.then === 'function' ? await batchMaybe : batchMaybe) || [];
        const userBiz = (userBizMaybe && typeof userBizMaybe.then === 'function' ? await userBizMaybe : userBizMaybe) || [];
        const recIndex = new Map();
        for (const r of recs) {
          const key = `${String(r.batchId)}|${String(r.email || '').toLowerCase()}`;
          if (!recIndex.has(key)) recIndex.set(key, r);
        }
        const batchIndex = new Map(batches.map((b) => [String(b.id), b]));
        const userBizMap = new Map(
          userBiz.map((u) => [String(u.email || '').toLowerCase(), String(u.businessId || '')])
        );

        const filtered = cons.filter((c) => {
          const em = String(c.email || '').toLowerCase();
          const rec = recIndex.get(`${String(c.batchId)}|${em}`) || {};
          const batch = batchIndex.get(String(c.batchId)) || {};
          const bizId = String(rec.businessId || batch.businessId || userBizMap.get(em) || '');
          if (filterBiz && bizId !== filterBiz) return false;
          if (filterDept && String(rec.department || '').toLowerCase() !== filterDept) return false;
          if (filterGroup && String(rec.primaryGroup || '').toLowerCase() !== filterGroup) return false;
          return true;
        });

        const nowMs = Date.now();
        const uniq = new Set();
        let lastConsentedAt = null;
        let last7d = 0;
        let last30d = 0;
        for (const c of filtered) {
          const em = String(c.email || '').toLowerCase();
          uniq.add(em);
          const ts = new Date(c.consentedAt || c.consented_at || c.createdAt || 0).getTime();
          if (!Number.isNaN(ts)) {
            if (!lastConsentedAt || ts > new Date(lastConsentedAt).getTime())
              lastConsentedAt = new Date(ts).toISOString();
            if (ts >= nowMs - 7 * 24 * 3600 * 1000) last7d += 1;
            if (ts >= nowMs - 30 * 24 * 3600 * 1000) last30d += 1;
          }
        }

        return res.json({
          totalConsents: filtered.length,
          uniqueUsers: uniq.size,
          lastConsentedAt,
          last7d,
          last30d,
        });
      }

      const filters = [];
      const params = [];
      const bizExpr = 'COALESCE(r.businessId, b.businessId, ub.businessId)';
      if (filterBiz) {
        filters.push(`${bizExpr} = ?`);
        params.push(filterBiz);
      }
      if (filterDept) {
        filters.push('LOWER(r.department) = ?');
        params.push(filterDept);
      }
      if (filterGroup) {
        filters.push('LOWER(r.primaryGroup) = ?');
        params.push(filterGroup);
      }
      const where = filters.length ? `WHERE ${filters.join(' AND ')}` : '';
      const summaryMaybe = one(
        `SELECT
           COUNT(*) as totalConsents,
           COUNT(DISTINCT LOWER(c.email)) as uniqueUsers,
           MAX(c.consented_at) as lastConsentedAt,
           SUM(CASE WHEN c.consented_at >= datetime('now','-7 days') THEN 1 ELSE 0 END) as last7d,
           SUM(CASE WHEN c.consented_at >= datetime('now','-30 days') THEN 1 ELSE 0 END) as last30d
         FROM consents c
         LEFT JOIN recipients r ON r.batchId = c.batch_id AND LOWER(r.email)=LOWER(c.email)
         LEFT JOIN batches b ON b.id = c.batch_id
         LEFT JOIN user_businesses ub ON LOWER(ub.email)=LOWER(c.email)
         ${where}`,
        params
      );
      const summary = summaryMaybe && typeof summaryMaybe.then === 'function' ? await summaryMaybe : summaryMaybe || {};
      return res.json({
        totalConsents: Number(summary.totalConsents || 0),
        uniqueUsers: Number(summary.uniqueUsers || 0),
        lastConsentedAt: summary.lastConsentedAt || null,
        last7d: Number(summary.last7d || 0),
        last30d: Number(summary.last30d || 0),
      });
    } catch (e) {
      res.status(500).json({ error: 'consent_summary_failed', details: e?.message || String(e) });
    }
  });

  // Court-ready PDF report for consents
  app.get('/api/admin/consents/report', async (req, res) => {
    try {
      const format = String(req.query.format || 'pdf').toLowerCase();
      if (format !== 'pdf')
        return res.status(400).json({ error: 'unsupported_format', hint: 'Use ?format=pdf' });
      const tenantId = req.query.tenantId != null ? Number(req.query.tenantId) : null;
      const email = String(req.query.email || '')
        .trim()
        .toLowerCase();
      const batchId = String(req.query.batchId || '').trim();
      const since = String(req.query.since || '').trim();
      const until = String(req.query.until || '').trim();
      const conds = [];
      const params = [];
      if (tenantId != null && !Number.isNaN(tenantId)) {
        conds.push('tenant_id=?');
        params.push(tenantId);
      }
      if (email) {
        conds.push('LOWER(email)=?');
        params.push(email);
      }
      if (batchId) {
        conds.push('batch_id=?');
        params.push(batchId);
      }
      if (since) {
        conds.push('consented_at>=?');
        params.push(since);
      }
      if (until) {
        conds.push('consented_at<=?');
        params.push(until);
      }
      const where = conds.length ? 'WHERE ' + conds.join(' AND ') : '';
      const rows = all(
        `SELECT id, tenant_id as tenantId, email, batch_id as batchId, consented_at as consentedAt, file_id as fileId, file_sha256 as sha256, file_name as name, file_size as size, file_mime as mime, legal_version_id as legalVersionId, legal_version as version, ip, ua, receipt_id as receiptId, receipt_sig as receiptSig FROM consents ${where} ORDER BY id ASC`,
        params
      );

      const PDFDocument = require('pdfkit');
      res.setHeader('Content-Type', 'application/pdf');
      res.setHeader('Cache-Control', 'no-store');
      const doc = new PDFDocument({ size: 'A4', margin: 50 });
      doc.info.Title = 'Consent and Acknowledgement Report';
      doc.info.Author = 'Sunbeth Compliance Portal';
      doc.pipe(res);

      const title = 'Consent and Acknowledgement Report';
      doc.fontSize(18).text(title, { align: 'center' });
      doc.moveDown(0.5);
      doc.fontSize(10).fillColor('#666').text(`Generated: ${new Date().toISOString()}`);
      if (tenantId != null) doc.text(`Tenant ID: ${tenantId}`);
      if (email) doc.text(`Filter Email: ${email}`);
      if (batchId) doc.text(`Batch ID: ${batchId}`);
      if (since || until) doc.text(`Range: ${since || '—'} to ${until || '—'}`);
      doc.moveDown(0.5);
      doc.fillColor('#000');

      // Summary
      const total = rows.length;
      const uniqueUsers = new Set(rows.map((r) => r.email)).size;
      doc.fontSize(12).text('Summary', { underline: true });
      doc.fontSize(10).text(`Total consents: ${total}`);
      doc.text(`Unique users: ${uniqueUsers}`);
      doc.moveDown(0.5);

      // Table header
      const headers = [
        'Date/Time (UTC)',
        'User',
        'Batch',
        'File Name',
        'SHA-256',
        'Version',
        'Receipt ID',
      ];
      const widths = [100, 130, 70, 120, 170, 50, 160];
      const startX = doc.x;
      const startY = doc.y + 6;
      doc.fontSize(9).fillColor('#111');
      headers.forEach((h, i) => {
        doc.text(h, startX + widths.slice(0, i).reduce((a, b) => a + b, 0), startY, {
          width: widths[i],
        });
      });
      doc.moveDown(1.2);
      doc
        .moveTo(50, startY + 12)
        .lineTo(545, startY + 12)
        .strokeColor('#999')
        .stroke();
      doc.strokeColor('#000');

      // Rows
      let y = startY + 16;
      const lineHeight = 36;
      for (const r of rows) {
        if (y > 760) {
          doc.addPage();
          y = 60;
        }
        const cols = [
          (r.consentedAt || '').replace('T', ' ').replace('Z', 'Z'),
          r.email || '',
          String(r.batchId || ''),
          r.name || '',
          (r.sha256 || '').slice(0, 64),
          String(r.version != null ? r.version : ''),
          r.receiptId || '',
        ];
        cols.forEach((c, i) => {
          doc.text(String(c), startX + widths.slice(0, i).reduce((a, b) => a + b, 0), y, {
            width: widths[i],
          });
        });
        y += lineHeight - 18;
      }

      // Certification section
      if (y > 680) {
        doc.addPage();
        y = 60;
      }
      doc.moveDown(2);
      doc.fontSize(12).text('Certification', { underline: true });
      doc
        .fontSize(10)
        .text(
          'This report was generated by the Sunbeth Compliance Portal. Each record represents a user consent or acknowledgement.'
        );
      doc.text(
        'Where configured, a receipt signature (HMAC-SHA256) is generated using a server-held secret to attest integrity.'
      );
      doc.text(
        'Fields include: timestamp, user identifier, associated batch (if any), file name, file hash (SHA-256), document version, and receipt ID.'
      );
      if (process.env.CONSENT_RECEIPT_SECRET) {
        doc.text('\nReceipt signatures were enabled at generation time.');
      } else {
        doc.text('\nNote: Receipt signatures were not enabled at generation time.');
      }
      doc.moveDown(1);
      doc.text(`Records included: ${rows.length}`);

      // Footer
      doc.moveDown(2);
      doc
        .fillColor('#666')
        .fontSize(8)
        .text('Sunbeth Compliance Portal • https://sunbeth.example.com', { align: 'center' });

      doc.end();
    } catch (e) {
      res.status(500).json({ error: 'report_failed', details: e?.message || String(e) });
    }
  });

  // Admin export: Acknowledgements with legal consent context (yearly)
  // GET /api/admin/acks/export?year=2025&email=user@org.com&batchId=123
  app.get('/api/admin/acks/export', async (req, res) => {
    try {
      const isFirebase = db && (db.driver === 'firebase' || db.driver === 'rtdb');
      // Guardrail: cap rows returned to avoid huge RTDB scans
      const limit = Math.max(1, Math.min(Number(req.query.limit || 500), 1000));
      const year = String(req.query.year || '').trim();
      if (!/^\d{4}$/.test(year)) {
        const y = new Date().getUTCFullYear();
        req.query.year = String(y);
      }
      const Y = String(req.query.year);
      const emailFilter = String(req.query.email || '')
        .trim()
        .toLowerCase();
      const batchFilter = String(req.query.batchId || '').trim();

      if (isFirebase) {
        // Fetch tables and compute in JS
        const [acksMaybe, docsMaybe, batchesMaybe, recsMaybe, consentsMaybe] = [
          all('SELECT batchId, documentId, email, ackDate FROM acks'),
          all('SELECT id, title, batchId FROM documents'),
          all('SELECT id, name FROM batches'),
          all(
            'SELECT batchId, email, displayName, department, jobTitle, location, primaryGroup, businessId FROM recipients'
          ),
          all('SELECT LOWER(email) as email, consented_at as consentedAt FROM consents'),
        ];
        const acks =
          acksMaybe && typeof acksMaybe.then === 'function' ? await acksMaybe : acksMaybe || [];
        const docs =
          docsMaybe && typeof docsMaybe.then === 'function' ? await docsMaybe : docsMaybe || [];
        const batches =
          batchesMaybe && typeof batchesMaybe.then === 'function'
            ? await batchesMaybe
            : batchesMaybe || [];
        const recs =
          recsMaybe && typeof recsMaybe.then === 'function' ? await recsMaybe : recsMaybe || [];
        const consents =
          consentsMaybe && typeof consentsMaybe.then === 'function'
            ? await consentsMaybe
            : consentsMaybe || [];

        const byDoc = new Map(docs.map((d) => [String(d.id), d]));
        const byBatch = new Map(batches.map((b) => [String(b.id), b]));
        const recIndex = new Map(); // key: batchId|emailLower
        for (const r of recs) {
          const key = `${String(r.batchId)}|${String(r.email || '').toLowerCase()}`;
          if (!recIndex.has(key)) recIndex.set(key, r);
        }
        const latestConsentYear = new Map(); // key: emailLower|YYYY -> iso
        for (const c of consents) {
          const em = String(c.email || '').toLowerCase();
          const ts = String(c.consentedAt || '');
          if (!/^\d{4}/.test(ts)) continue;
          const yy = ts.slice(0, 4);
          const k = `${em}|${yy}`;
          const cur = latestConsentYear.get(k);
          if (!cur || String(ts) > String(cur)) latestConsentYear.set(k, ts);
        }

        const rows = [];
        for (const a of acks) {
          const ts = String(a.ackDate || '');
          if (!/^\d{4}/.test(ts)) continue;
          if (ts.slice(0, 4) !== Y) continue;
          const em = String(a.email || '').toLowerCase();
          if (emailFilter && em !== emailFilter) continue;
          if (batchFilter && String(a.batchId) !== batchFilter) continue;
          const d = byDoc.get(String(a.documentId)) || {};
          const b = byBatch.get(String(a.batchId)) || {};
          const r = recIndex.get(`${String(a.batchId)}|${em}`) || {};
          const consentAt = latestConsentYear.get(`${em}|${Y}`) || null;
          rows.push({
            year: Y,
            batchId: String(a.batchId),
            batchName: b.name || null,
            documentId: String(a.documentId),
            documentTitle: d.title || null,
            email: em,
            displayName: r.displayName || r.email || em,
            department: r.department || null,
            jobTitle: r.jobTitle || null,
            location: r.location || null,
            primaryGroup: r.primaryGroup || null,
            businessId: r.businessId != null ? Number(r.businessId) : null,
            acknowledgedAt: ts,
            legalConsentedAt: consentAt,
          });
        }
        // Sort for stable output
        rows.sort((x, y) =>
          x.acknowledgedAt < y.acknowledgedAt ? -1 : x.acknowledgedAt > y.acknowledgedAt ? 1 : 0
        );
        return res.json({ records: rows.slice(0, limit), total: rows.length });
      }

      // SQL path
      const params = [Y, Y];
      let where = 'WHERE substr(a.ackDate,1,4)=?';
      if (emailFilter) {
        where += ' AND LOWER(a.email)=?';
        params.push(emailFilter);
      }
      if (batchFilter) {
        where += ' AND a.batchId=?';
        params.push(Number(batchFilter));
      }
      const rows = all(
        `SELECT ? as year,
                a.batchId as batchId,
                b.name as batchName,
                a.documentId as documentId,
                d.title as documentTitle,
                LOWER(a.email) as email,
                COALESCE(r.displayName, a.email) as displayName,
                r.department as department,
                r.jobTitle as jobTitle,
                r.location as location,
                r.primaryGroup as primaryGroup,
                r.businessId as businessId,
                a.ackDate as acknowledgedAt,
                c.legalConsentedAt as legalConsentedAt
         FROM acks a
         JOIN documents d ON d.id=a.documentId
         JOIN batches b ON b.id=a.batchId
         LEFT JOIN recipients r ON r.batchId=a.batchId AND LOWER(r.email)=LOWER(a.email)
         LEFT JOIN (
           SELECT LOWER(email) as email_l, MAX(consented_at) as legalConsentedAt
           FROM consents
           WHERE consented_at IS NOT NULL AND substr(consented_at,1,4)=?
           GROUP BY LOWER(email)
         ) c ON c.email_l = LOWER(a.email)
         ${where}
         ORDER BY a.ackDate ASC`,
        params
      );
      return res.json({ records: rows || [] });
    } catch (e) {
      res.status(500).json({ error: 'export_failed', details: e?.message || String(e) });
    }
  });

  // --- Policy Scheduling (HR annual/recurring acknowledgements) ---
  // Admin CRUD for policy rules (tenant-aware; SuperAdmin guard already applied for /api/admin/*)
  app.get('/api/admin/policies', async (req, res) => {
    try {
      const isFirebase = db && (db.driver === 'firebase' || db.driver === 'rtdb');
      const tenantId =
        req.query.tenantId != null
          ? isFirebase
            ? String(req.query.tenantId)
            : Number(req.query.tenantId)
          : req?.tenant?.id || null;
      const where = tenantId != null ? 'WHERE tenant_id=?' : '';
      const params = tenantId != null ? [tenantId] : [];
      const maybe = all(
        `SELECT id, name, description, frequency, interval_days as intervalDays, required, file_id as fileId, sha256, tenant_id as tenantId, active, start_on as startOn, due_in_days as dueInDays, grace_days as graceDays, created_at as createdAt, updated_at as updatedAt FROM policy_rules ${where} ORDER BY id DESC`,
        params
      );
      const rows = maybe && typeof maybe.then === 'function' ? await maybe : maybe || [];
      // attach fileIds mapping (if exists) - async-aware
      const policies = await Promise.all(
        (rows || []).map(async (r) => {
          const maybeFiles = allQuiet(
            'SELECT file_id as fileId, sha256 FROM policy_rule_files WHERE policy_rule_id=? ORDER BY file_id',
            [r.id]
          );
          const files =
            maybeFiles && typeof maybeFiles.then === 'function'
              ? await maybeFiles
              : maybeFiles || [];
          const fileIds = files.length
            ? files.map((f) => Number(f.fileId))
            : r.fileId
              ? [Number(r.fileId)]
              : [];
          return { ...r, required: !!r.required, active: !!r.active, fileIds };
        })
      );
      res.json({ policies });
    } catch (e) {
      res.status(500).json({ error: 'list_failed' });
    }
  });
  app.post(
    '/api/admin/policies',
    validate({
      type: 'object',
      required: ['name'],
      additionalProperties: true,
      properties: {
        name: { type: 'string', minLength: 1 },
        description: { type: ['string', 'null'] },
        frequency: { type: 'string' },
        intervalDays: { type: ['integer', 'null'] },
        required: { type: 'boolean' },
        // Firebase/RTDB use opaque string ids; sqlite/postgres use integers
        fileId: { anyOf: [{ type: 'integer' }, { type: 'string' }, { type: 'null' }] },
        fileIds: {
          type: 'array',
          items: { anyOf: [{ type: 'integer', minimum: 1 }, { type: 'string', minLength: 1 }] },
        },
        startOn: { type: ['string', 'null'] },
        dueInDays: { type: ['integer', 'null'] },
        graceDays: { type: ['integer', 'null'] },
        active: { type: 'boolean' },
      },
    }),
    async (req, res) => {
      try {
        const isFirebase = db && (db.driver === 'firebase' || db.driver === 'rtdb');
        const tenantId = req?.tenant?.id || null;
        const {
          name,
          description = null,
          frequency = 'annual',
          intervalDays = null,
          required = true,
          fileId = null,
          fileIds = null,
          startOn = null,
          dueInDays = 30,
          graceDays = 0,
          active = true,
        } = req.body || {};
        const ids = Array.isArray(fileIds)
          ? fileIds
              .map((fid) => (isFirebase ? String(fid || '').trim() : Number(fid)))
              .filter((v) => (isFirebase ? v.length > 0 : Number.isFinite(v) && v > 0))
          : fileId
            ? [isFirebase ? String(fileId).trim() : Number(fileId)]
            : [];
        if (!name || ids.length === 0)
          return res.status(400).json({ error: 'name_and_files_required' });
        // validate files (async-aware)
        const fileRows = await Promise.all(
          ids.map((fid) => one('SELECT id, sha256 FROM uploaded_files WHERE id=?', [fid]))
        );
        const valid = fileRows.filter(Boolean);
        if (valid.length !== ids.length) return res.status(404).json({ error: 'file_not_found' });
        const first = valid[0];
        const now = new Date().toISOString();
        await db.run(
          `INSERT INTO policy_rules (tenant_id, name, description, frequency, interval_days, required, file_id, sha256, active, start_on, due_in_days, grace_days, created_at, updated_at)
              VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
          [
            tenantId,
            String(name),
            description,
            String(frequency),
            intervalDays != null ? Number(intervalDays) : null,
            required ? 1 : 0,
            isFirebase ? String(first.id) : Number(first.id),
            first.sha256 || null,
            active ? 1 : 0,
            startOn,
            Number(dueInDays) || 0,
            Number(graceDays) || 0,
            now,
            now,
          ]
        );
        const idRowMaybe = db.query('SELECT last_insert_rowid() as id');
        const idRow =
          idRowMaybe && typeof idRowMaybe.then === 'function' ? await idRowMaybe : idRowMaybe;
        const id = Array.isArray(idRow) && idRow[0] ? idRow[0].id : null;
        // insert mapping rows
        for (const fid of ids) {
          try {
            const rec = await one('SELECT sha256 FROM uploaded_files WHERE id=?', [fid]);
            await db.run(
              'INSERT OR IGNORE INTO policy_rule_files (policy_rule_id, file_id, sha256) VALUES (?, ?, ?)',
              [id, fid, rec?.sha256 || null]
            );
          } catch {}
        }
        persist(db);
        res.json({ id });
      } catch (e) {
        res.status(500).json({ error: 'create_failed' });
      }
    }
  );
  app.put(
    '/api/admin/policies/:id',
    validate({
      type: 'object',
      additionalProperties: true,
      properties: {
        name: { type: ['string', 'null'] },
        description: { type: ['string', 'null'] },
        frequency: { type: ['string', 'null'] },
        intervalDays: { type: ['integer', 'null'] },
        required: { type: ['boolean', 'null'] },
        fileId: { type: ['integer', 'null'] },
        fileIds: { type: 'array', items: { type: 'integer', minimum: 1 } },
        active: { type: ['boolean', 'null'] },
        startOn: { type: ['string', 'null'] },
        dueInDays: { type: ['integer', 'null'] },
        graceDays: { type: ['integer', 'null'] },
      },
    }),
    async (req, res) => {
      try {
        const isFirebase = db && (db.driver === 'firebase' || db.driver === 'rtdb');
        const id = isFirebase ? String(req.params.id) : Number(req.params.id);
        const cur = await one('SELECT * FROM policy_rules WHERE id=?', [id]);
        if (!cur) return res.status(404).json({ error: 'not_found' });
        const {
          name,
          description,
          frequency,
          intervalDays,
          required,
          fileId,
          fileIds,
          active,
          startOn,
          dueInDays,
          graceDays,
        } = req.body || {};
        let sha = cur.sha256;
        if (fileId != null && (isFirebase ? String(fileId) : Number(fileId)) !== cur.file_id) {
          const f = await one('SELECT sha256 FROM uploaded_files WHERE id=?', [
            isFirebase ? String(fileId) : Number(fileId),
          ]);
          if (!f) return res.status(404).json({ error: 'file_not_found' });
          sha = f.sha256 || null;
        }
        const now = new Date().toISOString();
        await db.run(
          `UPDATE policy_rules SET name=COALESCE(?, name), description=COALESCE(?, description), frequency=COALESCE(?, frequency), interval_days=COALESCE(?, interval_days), required=COALESCE(?, required), file_id=COALESCE(?, file_id), sha256=COALESCE(?, sha256), active=COALESCE(?, active), start_on=COALESCE(?, start_on), due_in_days=COALESCE(?, due_in_days), grace_days=COALESCE(?, grace_days), updated_at=? WHERE id=?`,
          [
            name ?? null,
            description ?? null,
            frequency ?? null,
            intervalDays ?? null,
            required != null ? (required ? 1 : 0) : null,
            fileId ?? null,
            sha,
            active != null ? (active ? 1 : 0) : null,
            startOn ?? null,
            dueInDays ?? null,
            graceDays ?? null,
            now,
            id,
          ]
        );
        // Replace mapping if fileIds provided
        if (Array.isArray(fileIds)) {
          try {
            await db.run('DELETE FROM policy_rule_files WHERE policy_rule_id=?', [id]);
          } catch {}
          const ids = fileIds.map(Number).filter((n) => Number.isFinite(n) && n > 0);
          for (const fid of ids) {
            try {
              const rec = await one('SELECT sha256 FROM uploaded_files WHERE id=?', [fid]);
              await db.run(
                'INSERT OR IGNORE INTO policy_rule_files (policy_rule_id, file_id, sha256) VALUES (?, ?, ?)',
                [id, fid, rec?.sha256 || null]
              );
            } catch {}
          }
          // ensure primary file_id follows first of list, for backward compatibility
          if (ids.length) {
            const first = ids[0];
            const f = await one('SELECT sha256 FROM uploaded_files WHERE id=?', [first]);
            await db.run('UPDATE policy_rules SET file_id=?, sha256=? WHERE id=?', [
              first,
              f?.sha256 || null,
              id,
            ]);
          }
        }
        persist(db);
        res.json({ ok: true });
      } catch (e) {
        res.status(500).json({ error: 'update_failed' });
      }
    }
  );
  app.delete('/api/admin/policies/:id', async (req, res) => {
    try {
      const isFirebase = db && (db.driver === 'firebase' || db.driver === 'rtdb');
      const id = isFirebase ? String(req.params.id) : Number(req.params.id);
      await db.run('DELETE FROM policy_rules WHERE id=?', [id]);
      persist(db);
      res.json({ ok: true });
    } catch (e) {
      res.status(500).json({ error: 'delete_failed' });
    }
  });

  // --- Policy Owners & Subscriptions (Admin) ---
  // List owners for a policy rule, including scopes
  app.get('/api/admin/policies/:id/owners', async (req, res) => {
    try {
      const isFirebase = db && (db.driver === 'firebase' || db.driver === 'rtdb');
      const policyId = isFirebase ? String(req.params.id) : Number(req.params.id);
      const ownersMaybe = all(
        'SELECT id, policy_rule_id as policyRuleId, owner_email as email, owner_name as name, role, created_at as createdAt FROM policy_owners WHERE policy_rule_id=? ORDER BY id ASC',
        [policyId]
      );
      const owners = ownersMaybe && typeof ownersMaybe.then === 'function' ? await ownersMaybe : ownersMaybe || [];
      const ids = owners.map((o) => o.id);
      let scopesByOwner = new Map();
      if (ids.length) {
        const placeholders = ids.map(() => '?').join(',');
        const scopesMaybe = all(
          `SELECT id, policy_owner_id as ownerId, scope_type as type, scope_value as value FROM policy_owner_scopes WHERE policy_owner_id IN (${placeholders})`,
          ids
        );
        const scopes = scopesMaybe && typeof scopesMaybe.then === 'function' ? await scopesMaybe : scopesMaybe || [];
        scopesByOwner = scopes.reduce((m, s) => {
          const arr = m.get(s.ownerId) || [];
          arr.push({ id: s.id, type: s.type, value: s.value });
          m.set(s.ownerId, arr);
          return m;
        }, new Map());
      }
      const withScopes = owners.map((o) => ({ ...o, scopes: scopesByOwner.get(o.id) || [] }));
      res.json({ owners: withScopes });
    } catch (e) {
      res.status(500).json({ error: 'list_failed' });
    }
  });
  // Create an owner for a policy rule
  app.post(
    '/api/admin/policies/:id/owners',
    validate({
      type: 'object',
      required: ['email'],
      additionalProperties: true,
      properties: {
        email: { type: 'string', format: 'email' },
        name: { type: ['string', 'null'] },
        role: { type: ['string', 'null'] },
        scopes: {
          type: 'array',
          items: {
            type: 'object',
            required: ['type', 'value'],
            properties: {
              type: { type: 'string' },
              value: { type: 'string' },
            },
          },
        },
      },
    }),
    async (req, res) => {
      try {
        const isFirebase = db && (db.driver === 'firebase' || db.driver === 'rtdb');
        const policyId = isFirebase ? String(req.params.id) : Number(req.params.id);
        const { email, name = null, role = null, scopes = [] } = req.body || {};
        const now = new Date().toISOString();
        await db.run(
          'INSERT INTO policy_owners (policy_rule_id, owner_email, owner_name, role, created_at) VALUES (?, ?, ?, ?, ?)',
          [policyId, String(email).toLowerCase(), name, role, now]
        );
        const idRowMaybe = db.query('SELECT last_insert_rowid() as id');
        const idRow = idRowMaybe && typeof idRowMaybe.then === 'function' ? await idRowMaybe : idRowMaybe;
        const ownerId = Array.isArray(idRow) && idRow[0] ? idRow[0].id : null;
        if (Array.isArray(scopes) && scopes.length && ownerId != null) {
          for (const s of scopes) {
            const st = String(s.type || '').trim();
            const sv = String(s.value || '').trim();
            if (!st || !sv) continue;
            try {
              await db.run(
                'INSERT INTO policy_owner_scopes (policy_owner_id, scope_type, scope_value) VALUES (?, ?, ?)',
                [ownerId, st, sv]
              );
            } catch {}
          }
        }
        persist(db);
        res.json({ id: ownerId });
      } catch (e) {
        if (String(e?.message || '').toLowerCase().includes('unique')) {
          return res.status(409).json({ error: 'owner_exists' });
        }
        res.status(500).json({ error: 'create_failed' });
      }
    }
  );
  // Update owner (and optionally replace scopes)
  app.put(
    '/api/admin/policies/:id/owners/:ownerId',
    validate({
      type: 'object',
      additionalProperties: true,
      properties: {
        email: { type: ['string', 'null'], format: 'email' },
        name: { type: ['string', 'null'] },
        role: { type: ['string', 'null'] },
        scopes: {
          type: 'array',
          items: {
            type: 'object',
            required: ['type', 'value'],
            properties: {
              type: { type: 'string' },
              value: { type: 'string' },
            },
          },
        },
      },
    }),
    async (req, res) => {
      try {
        const isFirebase = db && (db.driver === 'firebase' || db.driver === 'rtdb');
        const policyId = isFirebase ? String(req.params.id) : Number(req.params.id);
        const ownerId = isFirebase ? String(req.params.ownerId) : Number(req.params.ownerId);
        const cur = await one('SELECT * FROM policy_owners WHERE id=? AND policy_rule_id=?', [
          ownerId,
          policyId,
        ]);
        if (!cur) return res.status(404).json({ error: 'not_found' });
        const { email, name, role, scopes } = req.body || {};
        await db.run(
          'UPDATE policy_owners SET owner_email=COALESCE(?, owner_email), owner_name=COALESCE(?, owner_name), role=COALESCE(?, role) WHERE id=?',
          [email != null ? String(email).toLowerCase() : null, name ?? null, role ?? null, ownerId]
        );
        if (Array.isArray(scopes)) {
          try {
            await db.run('DELETE FROM policy_owner_scopes WHERE policy_owner_id=?', [ownerId]);
          } catch {}
          for (const s of scopes) {
            const st = String(s.type || '').trim();
            const sv = String(s.value || '').trim();
            if (!st || !sv) continue;
            try {
              await db.run(
                'INSERT INTO policy_owner_scopes (policy_owner_id, scope_type, scope_value) VALUES (?, ?, ?)',
                [ownerId, st, sv]
              );
            } catch {}
          }
        }
        persist(db);
        res.json({ ok: true });
      } catch (e) {
        if (String(e?.message || '').toLowerCase().includes('unique')) {
          return res.status(409).json({ error: 'owner_exists' });
        }
        res.status(500).json({ error: 'update_failed' });
      }
    }
  );
  // Delete owner
  app.delete('/api/admin/policies/:id/owners/:ownerId', async (req, res) => {
    try {
      const isFirebase = db && (db.driver === 'firebase' || db.driver === 'rtdb');
      const policyId = isFirebase ? String(req.params.id) : Number(req.params.id);
      const ownerId = isFirebase ? String(req.params.ownerId) : Number(req.params.ownerId);
      const cur = await one('SELECT id FROM policy_owners WHERE id=? AND policy_rule_id=?', [
        ownerId,
        policyId,
      ]);
      if (!cur) return res.status(404).json({ error: 'not_found' });
      await db.run('DELETE FROM policy_owners WHERE id=?', [ownerId]);
      persist(db);
      res.json({ ok: true });
    } catch (e) {
      res.status(500).json({ error: 'delete_failed' });
    }
  });
  // List subscriptions for a policy rule
  app.get('/api/admin/policies/:id/subscriptions', async (req, res) => {
    try {
      const isFirebase = db && (db.driver === 'firebase' || db.driver === 'rtdb');
      const policyId = isFirebase ? String(req.params.id) : Number(req.params.id);
      const rowsMaybe = all(
        'SELECT id, policy_rule_id as policyRuleId, target_type as targetType, target, frequency, enabled, created_at as createdAt FROM notification_subscriptions WHERE policy_rule_id=? ORDER BY id ASC',
        [policyId]
      );
      const rows = rowsMaybe && typeof rowsMaybe.then === 'function' ? await rowsMaybe : rowsMaybe || [];
      const subs = rows.map((r) => ({ ...r, enabled: !!r.enabled }));
      res.json({ subscriptions: subs });
    } catch (e) {
      res.status(500).json({ error: 'list_failed' });
    }
  });
  // Replace subscriptions for a policy rule
  app.put(
    '/api/admin/policies/:id/subscriptions',
    validate({
      type: 'object',
      required: ['subscriptions'],
      properties: {
        subscriptions: {
          type: 'array',
          items: {
            type: 'object',
            required: ['targetType', 'target'],
            properties: {
              targetType: { type: 'string' }, // email|webhook
              target: { type: 'string' },
              frequency: { type: ['string', 'null'] },
              enabled: { type: ['boolean', 'null'] },
            },
          },
        },
      },
    }),
    async (req, res) => {
      try {
        const isFirebase = db && (db.driver === 'firebase' || db.driver === 'rtdb');
        const policyId = isFirebase ? String(req.params.id) : Number(req.params.id);
        const { subscriptions = [] } = req.body || {};
        await db.run('DELETE FROM notification_subscriptions WHERE policy_rule_id=?', [policyId]);
        for (const s of subscriptions) {
          const tt = String(s.targetType || '').toLowerCase();
          const target = String(s.target || '').trim();
          if (!tt || !target) continue;
          const freq = s.frequency ? String(s.frequency) : 'instant';
          const enabled = s.enabled != null ? (s.enabled ? 1 : 0) : 1;
          await db.run(
            'INSERT INTO notification_subscriptions (policy_rule_id, target_type, target, frequency, enabled) VALUES (?, ?, ?, ?, ?)',
            [policyId, tt, target, freq, enabled]
          );
        }
        persist(db);
        res.json({ ok: true });
      } catch (e) {
        res.status(500).json({ error: 'save_failed' });
      }
    }
  );

  // --- Owner-Facing Endpoints (requires viewOwnerDash or Owner roles) ---
  const getRequesterEmail = (req) => {
    try {
      const hdr = (req.headers['x-user-email'] || req.headers['x-admin-email'] || '')
        .toString()
        .trim()
        .toLowerCase();
      const qp = (req.query && req.query.email ? String(req.query.email) : '')
        .trim()
        .toLowerCase();
      const body = (req.body && req.body.email ? String(req.body.email) : '')
        .trim()
        .toLowerCase();
      return hdr || qp || body || '';
    } catch {
      return '';
    }
  };
  const hasPermission = (email, permKey) => {
    try {
      const roles = resolveUserRoles(email, db);
      if (roles.includes('SuperAdmin')) return true;
      // Short-circuit for owner roles
      if (permKey === 'viewOwnerDash' && (roles.includes('OwnerAdmin') || roles.includes('OwnerManager')))
        return true;
      const roleRows = all(
        'SELECT permKey, MAX(value) as value FROM role_permissions WHERE LOWER(role) IN (' +
          roles.map(() => 'LOWER(?)').join(',') +
          ') GROUP BY permKey',
        roles
      );
      const eff = new Map();
      for (const r of roleRows) eff.set(r.permKey, !!r.value);
      const userRows = all('SELECT permKey, value FROM user_permissions WHERE LOWER(email)=LOWER(?)', [
        email,
      ]);
      for (const u of userRows) eff.set(u.permKey, !!u.value);
      return !!eff.get(permKey);
    } catch {
      return false;
    }
  };

  // List policies owned by the requester
  app.get('/api/owner/policies', async (req, res) => {
    try {
      const email = getRequesterEmail(req);
      if (!email || !email.includes('@')) return res.status(400).json({ error: 'email_required' });
      if (!hasPermission(email, 'viewOwnerDash')) return res.status(403).json({ error: 'forbidden' });
      const isFirebase = db && (db.driver === 'firebase' || db.driver === 'rtdb');
      const rowsMaybe = all(
        `SELECT p.id, p.name, p.description, p.frequency, p.interval_days as intervalDays, p.required,
                p.file_id as fileId, p.sha256, p.tenant_id as tenantId, p.active, p.start_on as startOn,
                p.due_in_days as dueInDays, p.grace_days as graceDays, p.created_at as createdAt, p.updated_at as updatedAt
         FROM policy_rules p
         JOIN policy_owners o ON o.policy_rule_id=p.id
         WHERE LOWER(o.owner_email)=LOWER(?) AND p.active=1
         ORDER BY p.id DESC`,
        [email]
      );
      const rows = rowsMaybe && typeof rowsMaybe.then === 'function' ? await rowsMaybe : rowsMaybe || [];
      const policies = await Promise.all(
        (rows || []).map(async (r) => {
          const maybeFiles = allQuiet(
            'SELECT file_id as fileId, sha256 FROM policy_rule_files WHERE policy_rule_id=? ORDER BY file_id',
            [r.id]
          );
          const files = maybeFiles && typeof maybeFiles.then === 'function' ? await maybeFiles : maybeFiles || [];
          const fileIds = files.length ? files.map((f) => Number(f.fileId)) : r.fileId ? [Number(r.fileId)] : [];
          return { ...r, required: !!r.required, active: !!r.active, fileIds };
        })
      );
      res.json({ policies });
    } catch (e) {
      res.status(500).json({ error: 'list_failed' });
    }
  });

  // --- Owner Policy Submissions (HR Review Workflow) ---
  // List own submissions
  app.get('/api/owner/policy-submissions', async (req, res) => {
    try {
      const email = getRequesterEmail(req);
      if (!email || !email.includes('@')) return res.status(400).json({ error: 'email_required' });
      if (!hasPermission(email, 'viewOwnerDash')) return res.status(403).json({ error: 'forbidden' });
      const tenantId = req?.tenant?.id || null;
      const rowsMaybe = all(
        `SELECT id, tenant_id as tenantId, title, description, source_type as sourceType, file_id as fileId, driveId, itemId, source_url as sourceUrl,
                status, owner_email as ownerEmail, submitted_by as submittedBy, submitted_at as submittedAt, reviewed_by as reviewedBy, reviewed_at as reviewedAt, review_comment as reviewComment
         FROM policy_submissions
         WHERE (tenant_id IS NULL OR tenant_id=?) AND LOWER(owner_email)=LOWER(?)
         ORDER BY id DESC`,
        [tenantId, email]
      );
      const rows = rowsMaybe && typeof rowsMaybe.then === 'function' ? await rowsMaybe : rowsMaybe || [];
      res.json({ submissions: rows });
    } catch (e) {
      res.status(500).json({ error: 'list_failed' });
    }
  });
  // Submit a new policy for HR review
  app.post(
    '/api/owner/policy-submissions',
    validate({
      type: 'object',
      required: ['title', 'sourceType'],
      properties: {
        title: { type: 'string', minLength: 1 },
        description: { type: ['string', 'null'] },
        sourceType: { type: 'string' }, // upload|sharepoint|url
        fileId: { type: ['integer', 'null'] },
        driveId: { type: ['string', 'null'] },
        itemId: { type: ['string', 'null'] },
        sourceUrl: { type: ['string', 'null'] },
      },
    }),
    async (req, res) => {
      try {
        const email = getRequesterEmail(req);
        if (!email || !email.includes('@')) return res.status(400).json({ error: 'email_required' });
        if (!hasPermission(email, 'viewOwnerDash')) return res.status(403).json({ error: 'forbidden' });
        const tenantId = req?.tenant?.id || null;
        const { title, description = null, sourceType, fileId = null, driveId = null, itemId = null, sourceUrl = null } = req.body || {};
        const st = String(sourceType || '').toLowerCase();
        if (!['upload', 'sharepoint', 'url'].includes(st)) return res.status(400).json({ error: 'invalid_sourceType' });
        if (st === 'upload' && !fileId) return res.status(400).json({ error: 'file_required' });
        if (st === 'sharepoint' && !(driveId && itemId)) return res.status(400).json({ error: 'drive_item_required' });
        const now = new Date().toISOString();
        await db.run(
          `INSERT INTO policy_submissions (tenant_id, title, description, source_type, file_id, driveId, itemId, source_url, status, owner_email, submitted_by, submitted_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'submitted', ?, ?, ?)`,
          [tenantId, String(title), description, st, fileId, driveId, itemId, sourceUrl, email, email, now]
        );
        const idRow = one('SELECT last_insert_rowid() as id');
        persist(db);
        res.json({ id: idRow?.id });
      } catch (e) {
        res.status(500).json({ error: 'create_failed' });
      }
    }
  );

  // --- HR/Admin Review Endpoints ---
  // List submissions by status (default: submitted)
  app.get('/api/admin/policy-submissions', (req, res) => {
    try {
      const status = (req.query.status || 'submitted').toString();
      const tenantId = req?.tenant?.id || null;
      const rows = all(
        `SELECT id, tenant_id as tenantId, title, description, source_type as sourceType, file_id as fileId, driveId, itemId, source_url as sourceUrl,
                status, owner_email as ownerEmail, submitted_by as submittedBy, submitted_at as submittedAt, reviewed_by as reviewedBy, reviewed_at as reviewedAt, review_comment as reviewComment
         FROM policy_submissions
         WHERE (tenant_id IS NULL OR tenant_id=?) AND status=?
         ORDER BY submitted_at ASC`,
        [tenantId, status]
      );
      res.json({ submissions: rows });
    } catch (e) {
      res.status(500).json({ error: 'list_failed' });
    }
  });
  // Approve a submission
  app.post('/api/admin/policy-submissions/:id/approve', (req, res) => {
    try {
      const id = Number(req.params.id);
      const reviewer = (req.headers['x-admin-email'] || req.headers['x-user-email'] || '').toString().toLowerCase();
      const comment = (req.body && req.body.comment) || null;
      const cur = one('SELECT id, status FROM policy_submissions WHERE id=?', [id]);
      if (!cur) return res.status(404).json({ error: 'not_found' });
      if (String(cur.status) !== 'submitted') return res.status(400).json({ error: 'invalid_state' });
      const now = new Date().toISOString();
      db.run(
        'UPDATE policy_submissions SET status="approved", reviewed_by=?, reviewed_at=?, review_comment=? WHERE id=?',
        [reviewer || null, now, comment, id]
      );
      persist(db);
      res.json({ ok: true });
    } catch (e) {
      res.status(500).json({ error: 'approve_failed' });
    }
  });
  // Reject a submission
  app.post('/api/admin/policy-submissions/:id/reject', (req, res) => {
    try {
      const id = Number(req.params.id);
      const reviewer = (req.headers['x-admin-email'] || req.headers['x-user-email'] || '').toString().toLowerCase();
      const comment = (req.body && req.body.comment) || null;
      const cur = one('SELECT id, status FROM policy_submissions WHERE id=?', [id]);
      if (!cur) return res.status(404).json({ error: 'not_found' });
      if (String(cur.status) !== 'submitted') return res.status(400).json({ error: 'invalid_state' });
      const now = new Date().toISOString();
      db.run(
        'UPDATE policy_submissions SET status="rejected", reviewed_by=?, reviewed_at=?, review_comment=? WHERE id=?',
        [reviewer || null, now, comment, id]
      );
      persist(db);
      res.json({ ok: true });
    } catch (e) {
      res.status(500).json({ error: 'reject_failed' });
    }
  });

  // Approved files list for Create Batch UI convenience
  app.get('/api/approved-policy-files', (req, res) => {
    try {
      const tenantId = req?.tenant?.id || null;
      const rows = all(
        `SELECT id, title, source_type as sourceType, file_id as fileId, driveId, itemId, source_url as sourceUrl
         FROM policy_submissions
         WHERE status='approved' AND (tenant_id IS NULL OR tenant_id=?)
         ORDER BY reviewed_at DESC NULLS LAST, id DESC`,
        [tenantId]
      );
      res.json({ files: rows });
    } catch (e) {
      res.status(500).json({ error: 'list_failed' });
    }
  });

  // Progress summary for a single owned policy (scoped by owner's scopes)
  app.get('/api/owner/policies/:id/progress', async (req, res) => {
    try {
      const email = getRequesterEmail(req);
      if (!email || !email.includes('@')) return res.status(400).json({ error: 'email_required' });
      if (!hasPermission(email, 'viewOwnerDash')) return res.status(403).json({ error: 'forbidden' });
      const isFirebase = db && (db.driver === 'firebase' || db.driver === 'rtdb');
      const policyId = isFirebase ? String(req.params.id) : Number(req.params.id);
      // Ensure requester is an owner of this policy
      const ownerRow = await one(
        'SELECT id FROM policy_owners WHERE policy_rule_id=? AND LOWER(owner_email)=LOWER(?)',
        [policyId, email]
      );
      if (!ownerRow) return res.status(403).json({ error: 'forbidden' });
      // Resolve files for policy
      const mappedMaybe = allQuiet(
        'SELECT file_id as fileId FROM policy_rule_files WHERE policy_rule_id=?',
        [policyId]
      );
      const mapped = mappedMaybe && typeof mappedMaybe.then === 'function' ? await mappedMaybe : mappedMaybe || [];
      const primary = one('SELECT file_id as fileId FROM policy_rules WHERE id=?', [policyId]);
      const fileIds = (mapped.length ? mapped.map((r) => Number(r.fileId)) : []).concat(
        primary && primary.fileId ? [Number(primary.fileId)] : []
      );
      const uniqueFileIds = Array.from(new Set(fileIds.filter((n) => Number.isFinite(n) && n > 0)));
      if (!uniqueFileIds.length) return res.json({ total: 0, completed: 0, percent: 0 });
      // Gather recipient emails in scope
      const scopesMaybe = all(
        `SELECT s.scope_type as type, s.scope_value as value
         FROM policy_owner_scopes s
         JOIN policy_owners o ON o.id=s.policy_owner_id
         WHERE o.policy_rule_id=? AND LOWER(o.owner_email)=LOWER(?)`,
        [policyId, email]
      );
      const scopes = scopesMaybe && typeof scopesMaybe.then === 'function' ? await scopesMaybe : scopesMaybe || [];
      // Group by type: OR within type, AND across types
      const byType = scopes.reduce((m, s) => {
        const t = String(s.type || '').toLowerCase();
        const v = String(s.value || '');
        if (!t || !v) return m;
        const arr = m.get(t) || [];
        arr.push(v);
        m.set(t, arr);
        return m;
      }, new Map());
      let where = '';
      const params = [];
      if (byType.size > 0) {
        const clauses = [];
        for (const [t, values] of byType.entries()) {
          const placeholders = values.map(() => '?').join(',');
          if (t === 'department') clauses.push(`LOWER(department) IN (${placeholders})`);
          else if (t === 'location') clauses.push(`LOWER(location) IN (${placeholders})`);
          else if (t === 'primarygroup') clauses.push(`LOWER(primaryGroup) IN (${placeholders})`);
          else if (t === 'businessid') clauses.push(`businessId IN (${placeholders})`);
          for (const v of values) {
            params.push(t === 'businessid' ? Number(v) : String(v).toLowerCase());
          }
        }
        where = `WHERE ${clauses.join(' AND ')}`;
      }
      const recRows = all(`SELECT DISTINCT LOWER(email) as email FROM recipients ${where}`, params);
      const recipients = recRows && typeof recRows.then === 'function' ? await recRows : recRows || [];
      const emails = Array.from(new Set((recipients || []).map((r) => String(r.email))));
      const total = emails.length;
      if (total === 0) return res.json({ total: 0, completed: 0, percent: 0 });
      // Ack counts by email for the policy's files
      const emailPlaceholders = emails.map(() => '?').join(',');
      const filePlaceholders = uniqueFileIds.map(() => '?').join(',');
      const ackRows = all(
        `SELECT LOWER(a.email) as email, COUNT(DISTINCT d.localFileId) as cnt
         FROM acks a
         JOIN documents d ON d.id=a.documentId
         WHERE a.acknowledged=1 AND d.localFileId IN (${filePlaceholders}) AND LOWER(a.email) IN (${emailPlaceholders})
         GROUP BY LOWER(a.email)`,
        [...uniqueFileIds, ...emails]
      );
      const acked = ackRows && typeof ackRows.then === 'function' ? await ackRows : ackRows || [];
      const byEmail = new Map(acked.map((r) => [String(r.email), Number(r.cnt || 0)]));
      const requiredCount = uniqueFileIds.length;
      let completed = 0;
      for (const e of emails) {
        if ((byEmail.get(e) || 0) >= requiredCount) completed += 1;
      }
      const percent = total === 0 ? 0 : Math.round((completed / total) * 100);
      res.json({ total, completed, percent });
    } catch (e) {
      res.status(500).json({ error: 'progress_failed' });
    }
  });

  // Request notifications dispatch for a policy (stub; wire actual delivery later)
  app.post('/api/owner/policies/:id/notify', async (req, res) => {
    try {
      const email = getRequesterEmail(req);
      if (!email || !email.includes('@')) return res.status(400).json({ error: 'email_required' });
      if (!hasPermission(email, 'notifyPolicyOwners')) return res.status(403).json({ error: 'forbidden' });
      const isFirebase = db && (db.driver === 'firebase' || db.driver === 'rtdb');
      const policyId = isFirebase ? String(req.params.id) : Number(req.params.id);
      const ownerRow = await one(
        'SELECT id FROM policy_owners WHERE policy_rule_id=? AND LOWER(owner_email)=LOWER(?)',
        [policyId, email]
      );
      if (!ownerRow) return res.status(403).json({ error: 'forbidden' });
      const subsMaybe = all(
        'SELECT target_type as targetType, target, frequency, enabled FROM notification_subscriptions WHERE policy_rule_id=? AND enabled=1',
        [policyId]
      );
      const subs = subsMaybe && typeof subsMaybe.then === 'function' ? await subsMaybe : subsMaybe || [];
      // For now, just acknowledge planned notifications (no external send yet)
      res.status(202).json({ queued: subs.length, targets: subs.map((s) => ({ type: s.targetType, target: s.target, frequency: s.frequency })) });
    } catch (e) {
      res.status(500).json({ error: 'notify_failed' });
    }
  });

  // Calculate due policies for a user (email required)
  app.get(
    '/api/policies/due',
    validate(
      {
        type: 'object',
        required: ['email'],
        additionalProperties: true,
        properties: { email: { type: 'string', format: 'email' } },
      },
      'query'
    ),
    async (req, res) => {
      try {
        const tenantId = req?.tenant?.id || null;
        const email = String(req.query.email || '')
          .trim()
          .toLowerCase();
        if (!email || !email.includes('@'))
          return res.status(400).json({ error: 'email_required' });
        const maybePolicies = all(
          `SELECT id, name, description, frequency, interval_days as intervalDays, required, file_id as fileId, sha256, tenant_id as tenantId, active, start_on as startOn, due_in_days as dueInDays, grace_days as graceDays FROM policy_rules WHERE active=1 AND (tenant_id = ? OR tenant_id = ?)`,
          [tenantId, tenantId]
        );
        const policies =
          maybePolicies && typeof maybePolicies.then === 'function'
            ? await maybePolicies
            : maybePolicies || [];
        const now = new Date();
        const freqDays = (p) => {
          const f = String(p.frequency || 'annual').toLowerCase();
          if (f === 'daily') return 1;
          if (f === 'weekly') return 7;
          if (f === 'monthly') return 30;
          if (f === 'quarterly') return 90;
          if (f === 'semiannual') return 182;
          if (f === 'annual' || f === 'annually' || f === 'yearly') return 365;
          if (f === 'custom' && p.intervalDays) return Math.max(1, Number(p.intervalDays));
          return 365;
        };
        const dueList = [];
        for (const p of policies) {
          // Determine files: mapping table or fallback to single fileId
          const mappedMaybe = allQuiet(
            'SELECT file_id as fileId FROM policy_rule_files WHERE policy_rule_id=?',
            [p.id]
          );
          const mapped =
            mappedMaybe && typeof mappedMaybe.then === 'function'
              ? await mappedMaybe
              : mappedMaybe || [];
          const files = mapped.length
            ? mapped.map((r) => Number(r.fileId))
            : p.fileId
              ? [Number(p.fileId)]
              : [];
          if (!files.length) continue;
          // For each file in this policy, compute due separately
          for (const fid of files) {
            const last = one(
              `SELECT MAX(a.ackDate) as lastAck
                            FROM acks a
                            JOIN documents d ON d.id=a.documentId
                            WHERE d.localFileId=? AND LOWER(a.email)=LOWER(?)`,
              [fid, email]
            );
            const lastAck = last && last.lastAck ? new Date(String(last.lastAck)) : null;
            const startOn = p.startOn ? new Date(String(p.startOn)) : null;
            const ndays = freqDays(p);
            let nextDueFrom = startOn || lastAck;
            if (!nextDueFrom) {
              // Default baseline: today minus ndays to mark as due
              nextDueFrom = new Date(now.getTime() - ndays * 24 * 60 * 60 * 1000 - 1);
            }
            const nextDue = new Date(nextDueFrom.getTime() + ndays * 24 * 60 * 60 * 1000);
            const graceEnd = new Date(
              nextDue.getTime() + (Number(p.graceDays) || 0) * 24 * 60 * 60 * 1000
            );
            const isDue = now >= nextDue;
            const isOverdue = now > graceEnd;
            if (isDue) {
              dueList.push({
                policyId: p.id,
                name: p.name,
                description: p.description,
                required: !!p.required,
                fileId: fid,
                frequency: p.frequency,
                intervalDays: p.intervalDays || null,
                lastAck: lastAck ? lastAck.toISOString() : null,
                nextDue: nextDue.toISOString(),
                graceUntil: graceEnd.toISOString(),
                overdue: isOverdue,
              });
            }
          }
        }
        res.json({ due: dueList });
      } catch (e) {
        res.status(500).json({ error: 'resolve_failed' });
      }
    }
  );

  // Acknowledge a policy document by fileId (creates a synthetic batch/doc if necessary)
  // Body: { email: string, fileId: number|string }
  app.post(
    '/api/policies/ack',
    validate({
      type: 'object',
      required: ['email', 'fileId'],
      additionalProperties: true,
      properties: {
        email: { type: 'string', format: 'email' },
        fileId: { anyOf: [{ type: 'integer', minimum: 1 }, { type: 'string', minLength: 1 }] },
      },
    }),
    async (req, res) => {
      try {
        const email = String(req.body?.email || '')
          .trim()
          .toLowerCase();
        const isFirebase = db && (db.driver === 'firebase' || db.driver === 'rtdb');
        const resolveMaybe = async (v) => (v && typeof v.then === 'function' ? await v : v);
        const newId = () => crypto.randomBytes(8).toString('hex');
        const fileIdRaw = req.body?.fileId;
        const fileId = isFirebase ? String(fileIdRaw || '').trim() : Number(fileIdRaw);
        if (!email || !email.includes('@'))
          return res.status(400).json({ error: 'email_required' });
        if (!isFirebase && (!Number.isFinite(fileId) || fileId <= 0))
          return res.status(400).json({ error: 'invalid_fileId' });
        if (isFirebase && !fileId)
          return res.status(400).json({ error: 'invalid_fileId' });

        // Enforce legal consent: require a consent on the current active legal doc version for this user
        try {
          const isFirebaseDriver = db && (db.driver === 'firebase' || db.driver === 'rtdb');
          const vIdRaw = await getSettingAsync('legal_consent_version_id', null);
          const activeVersionId = vIdRaw != null
            ? isFirebaseDriver
              ? String(vIdRaw).trim()
              : Number(vIdRaw)
            : null;
          const lfIdRaw = await getSettingAsync('legal_consent_file_id', null);
          const activeFileId = lfIdRaw != null
            ? isFirebaseDriver
              ? String(lfIdRaw).trim()
              : Number(lfIdRaw)
            : null;
          const hasVersion = isFirebaseDriver
            ? !!activeVersionId
            : activeVersionId && Number.isFinite(activeVersionId);
          if (hasVersion) {
            const exists = one(
              'SELECT id FROM consents WHERE LOWER(email)=LOWER(?) AND legal_version_id=?',
              [email, activeVersionId]
            );
            if (!exists) {
              return res
                .status(403)
                .json({
                  error: 'legal_consent_required',
                  legalFileId: activeFileId || null,
                  legalVersionId: activeVersionId,
                });
            }
          }
        } catch {}

        // Ensure the uploaded file exists
        const file = await resolveMaybe(
          one('SELECT id, original_name, mime FROM uploaded_files WHERE id=?', [fileId])
        );
        if (!file) return res.status(404).json({ error: 'file_not_found' });

        // Find or create a synthetic batch to host policy-only docs
        let batch = await resolveMaybe(
          one("SELECT id FROM batches WHERE name='Policy Acknowledgements' LIMIT 1")
        );
        if (!batch) {
          const now = new Date().toISOString().substring(0, 10);
          const batchIdGen = isFirebase ? newId() : null;
          if (isFirebase) {
            db.run(
              "INSERT INTO batches (id, name, startDate, dueDate, status, description) VALUES (?, 'Policy Acknowledgements', ?, NULL, 1, 'Synthetic batch for policy acknowledgements')",
              [batchIdGen, now]
            );
            batch = { id: batchIdGen };
          } else {
            db.run(
              "INSERT INTO batches (name, startDate, dueDate, status, description) VALUES ('Policy Acknowledgements', ?, NULL, 1, 'Synthetic batch for policy acknowledgements')",
              [now]
            );
            const idRow = one('SELECT last_insert_rowid() as id');
            batch = { id: idRow?.id };
          }
        }
        const batchId = isFirebase ? String(batch.id) : Number(batch.id);

        // Find or create a document entry referencing this file
        let doc = await resolveMaybe(
          one('SELECT id FROM documents WHERE batchId=? AND localFileId=?', [batchId, fileId])
        );
        if (!doc) {
          const localUrl = `/api/files/${fileId}`;
          const title = file.original_name || 'Policy Document';
          const docIdGen = isFirebase ? newId() : null;
          if (isFirebase) {
            db.run(
              'INSERT INTO documents (id, batchId, title, url, version, requiresSignature, source, localFileId, localUrl) VALUES (?, ?, ?, ?, 1, 0, ?, ?, ?)',
              [docIdGen, batchId, title, localUrl, 'local', fileId, localUrl]
            );
            doc = { id: docIdGen };
          } else {
            db.run(
              'INSERT INTO documents (batchId, title, url, version, requiresSignature, source, localFileId, localUrl) VALUES (?, ?, ?, 1, 0, ?, ?, ?)',
              [batchId, title, localUrl, 'local', fileId, localUrl]
            );
            const idRow = one('SELECT last_insert_rowid() as id');
            doc = { id: idRow?.id };
          }
        }
        const documentId = isFirebase ? String(doc.id) : Number(doc.id);

        // Ensure recipient exists for this batch (helps reporting/joins)
        const rec = await resolveMaybe(
          one('SELECT id FROM recipients WHERE batchId=? AND LOWER(email)=LOWER(?)', [
            batchId,
            email,
          ])
        );
        if (!rec) {
          db.run(
            'INSERT OR IGNORE INTO recipients (batchId, businessId, user, email, displayName) VALUES (?, NULL, ?, ?, ?)',
            [batchId, email, email, email]
          );
        }

        // Idempotent ack
        db.run('DELETE FROM acks WHERE batchId=? AND documentId=? AND LOWER(email)=LOWER(?)', [
          batchId,
          documentId,
          email,
        ]);
        const nowIso = new Date().toISOString();
        const ok = exec(
          isFirebase
            ? 'INSERT INTO acks (id, batchId, documentId, email, acknowledged, ackDate) VALUES (?, ?, ?, ?, 1, ?)' // explicit id for firebase adapters
            : 'INSERT INTO acks (batchId, documentId, email, acknowledged, ackDate) VALUES (?, ?, ?, 1, ?)',
          isFirebase ? [newId(), batchId, documentId, email, nowIso] : [batchId, documentId, email, nowIso]
        );
        if (!ok) return res.status(500).json({ error: 'ack_failed' });
        persist(db);

        // Notify batch subscribers (instant)
        (async () => {
          try {
            const subsRows = all(
              `SELECT target_type as targetType, target FROM batch_subscriptions WHERE batch_id=? AND enabled=1 AND LOWER(frequency)='instant'`,
              [batchId]
            );
            const subs = subsRows && typeof subsRows.then === 'function' ? await subsRows : subsRows || [];
            if (!Array.isArray(subs) || subs.length === 0) return;
            const mailer = (function () { try { return require('./src/services/mailer'); } catch { return null; } })();
            const subject = `Batch #${batchId} acknowledgement update`;
            const html = `<div style="font-family:Segoe UI,Tahoma,Arial,sans-serif"><p>User <b>${email}</b> acknowledged a document in batch <b>#${batchId}</b> on ${nowIso}.</p></div>`;
            const text = `User ${email} acknowledged a document in batch #${batchId} on ${nowIso}.`;
            for (const s of subs) {
              if (String(s.targetType).toLowerCase() === 'email') {
                try {
                  if (mailer && typeof mailer.sendHtml === 'function') await mailer.sendHtml(String(s.target), subject, html, text);
                  else console.log(`[BATCH:EMAIL:FALLBACK] To: ${s.target} :: ${text}`);
                } catch {}
              } else if (String(s.targetType).toLowerCase() === 'webhook') {
                try {
                  const targetUrl = new URL(String(s.target));
                  const client = targetUrl.protocol === 'https:' ? require('https') : require('http');
                  const payload = JSON.stringify({ event: 'batch_ack', batchId, email, at: nowIso, documentId });
                  await new Promise((resolve) => {
                    const req2 = client.request(targetUrl, { method: 'POST', headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(payload) } }, (up) => { up.on('data', () => {}); up.on('end', resolve); });
                    req2.on('error', () => resolve());
                    req2.write(payload);
                    req2.end();
                  });
                } catch {}
              }
            }
          } catch {}
        })();

        // Notify policy subscribers (instant) for policies linked to this fileId
        (async () => {
          try {
            // Map document.localFileId -> policy_rule_id(s)
            const mapRows = all(
              `SELECT DISTINCT pr.id as policyId
               FROM policy_rules pr
               LEFT JOIN policy_rule_files prf ON prf.policy_rule_id=pr.id
               WHERE (prf.file_id = ? OR pr.file_id = ?) AND pr.active=1`,
              [fileId, fileId]
            );
            const policies = mapRows && typeof mapRows.then === 'function' ? await mapRows : mapRows || [];
            if (!Array.isArray(policies) || policies.length === 0) return;
            const policyIds = policies.map((r) => r.policyId);
            const placeholders = policyIds.map(() => '?').join(',');
            const subsRows = all(
              `SELECT policy_rule_id as policyId, target_type as targetType, target
               FROM notification_subscriptions
               WHERE enabled=1 AND LOWER(frequency)='instant' AND policy_rule_id IN (${placeholders})`,
              policyIds
            );
            const subs = subsRows && typeof subsRows.then === 'function' ? await subsRows : subsRows || [];
            if (!Array.isArray(subs) || subs.length === 0) return;

            const mailer = (function () {
              try { return require('./src/services/mailer'); } catch { return null; }
            })();
            const subject = 'Policy acknowledgement completed';
            const htmlBody = (pid) => `
              <div style="font-family:Segoe UI,Tahoma,Arial,sans-serif">
                <h3 style="margin:0 0 10px 0">Acknowledgement Recorded</h3>
                <p>User <b>${email}</b> acknowledged a document for policy <b>#${pid}</b> on ${nowIso}.</p>
              </div>`;
            const textBody = (pid) => `User ${email} acknowledged a document for policy #${pid} on ${nowIso}.`;

            // Fire and forget deliveries
            for (const s of subs) {
              const pid = s.policyId;
              if (String(s.targetType).toLowerCase() === 'email') {
                try {
                  if (mailer && typeof mailer.sendHtml === 'function') {
                    await mailer.sendHtml(String(s.target), subject, htmlBody(pid), textBody(pid));
                  } else {
                    console.log(`[POLICY:EMAIL:FALLBACK] To: ${s.target} :: ${textBody(pid)}`);
                  }
                } catch (err) {
                  console.warn('instant email send failed', err?.message || err);
                }
              } else if (String(s.targetType).toLowerCase() === 'webhook') {
                try {
                  const targetUrl = new URL(String(s.target));
                  const client = targetUrl.protocol === 'https:' ? require('https') : require('http');
                  const payload = JSON.stringify({ event: 'policy_ack', policyId: pid, email, at: nowIso, fileId });
                  await new Promise((resolve) => {
                    const req2 = client.request(targetUrl, { method: 'POST', headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(payload) } }, (up) => { up.on('data', () => {}); up.on('end', resolve); });
                    req2.on('error', () => resolve());
                    req2.write(payload);
                    req2.end();
                  });
                } catch (err) {
                  console.warn('instant webhook post failed', err?.message || err);
                }
              }
            }
          } catch (err) {
            console.warn('instant notifications failed', err?.message || err);
          }
        })();

        // Notify per-business admins (instant) based on recipient's business
        (async () => {
          try {
            const resolveMaybe = async (v) => (v && typeof v.then === 'function' ? await v : v);
            // Try recipients mapping first
            const recRow = await resolveMaybe(
              one('SELECT businessId FROM recipients WHERE batchId=? AND LOWER(email)=LOWER(?)', [
                batchId,
                email,
              ])
            );
            let bizId = recRow ? recRow.businessId : null;
            if (!bizId) {
              const ubRow = await resolveMaybe(
                one(
                  'SELECT businessId FROM user_businesses WHERE LOWER(email)=LOWER(?) ORDER BY assignedAt DESC LIMIT 1',
                  [email]
                )
              );
              bizId = ubRow ? ubRow.businessId : null;
            }
            if (bizId != null) {
              const adminsRows = await resolveMaybe(
                all('SELECT email FROM business_admins WHERE businessId=? ORDER BY email ASC', [bizId])
              );
              const admins = Array.isArray(adminsRows) ? adminsRows.map((r) => String(r.email)) : [];
              if (admins.length > 0) {
                const mailer = (function () { try { return require('./src/services/mailer'); } catch { return null; } })();
                let bizName = null;
                try {
                  const bRow = await resolveMaybe(one('SELECT name FROM businesses WHERE id=?', [bizId]));
                  bizName = bRow && bRow.name ? String(bRow.name) : null;
                } catch {}
                const subject = `Acknowledgement: ${bizName ? bizName + ' ' : ''}Batch #${batchId}`;
                const html = '<div style="font-family:Segoe UI,Tahoma,Arial,sans-serif"><p>User <b>' + email + '</b> acknowledged document <b>#' + documentId + '</b> in batch <b>#' + batchId + '</b> on ' + nowIso + '.</p>' + (bizName ? '<p>Business: <b>' + bizName + '</b></p>' : '') + '</div>';
                const text = `User ${email} acknowledged document #${documentId} in batch #${batchId} on ${nowIso}.${bizName ? ` Business: ${bizName}.` : ''}`;
                for (const to of admins) {
                  try {
                    if (mailer && typeof mailer.sendHtml === 'function') await mailer.sendHtml(to, subject, html, text);
                    else console.log(`[BUSINESS:EMAIL:FALLBACK] To: ${to} :: ${text}`);
                  } catch {}
                }
              }
            }
          } catch {}
        })();

        return res.json({ ok: true, batchId, documentId, ackDate: nowIso });
      } catch (e) {
        return res.status(500).json({ error: 'ack_failed', details: e?.message || String(e) });
      }
    }
  );
  // Businesses
  app.get('/api/businesses', async (_req, res) => {
    try {
      const maybe = all(
        'SELECT id, name, code, isActive, description FROM businesses ORDER BY name'
      );
      const rows = maybe && typeof maybe.then === 'function' ? await maybe : maybe || [];
      res.json(
        (Array.isArray(rows) ? rows : []).map((r) => ({
          id: r.id,
          name: r.name,
          code: r.code,
          isActive: !!r.isActive,
          description: r.description,
        }))
      );
    } catch (e) {
      res.status(500).json({ error: 'list_failed', details: e?.message || String(e) });
    }
  });
  // Create business
  app.post('/api/businesses', async (req, res) => {
    const { name, code = null, isActive = true, description = null } = req.body || {};
    if (!name || String(name).trim().length === 0)
      return res.status(400).json({ error: 'name_required' });
    try {
      if (db && (db.driver === 'firebase' || db.driver === 'rtdb')) {
        await db.run(
          'INSERT INTO businesses (name, code, isActive, description) VALUES (?, ?, ?, ?)',
          [String(name).trim(), code, isActive ? 1 : 0, description]
        );
        const rows = await db.query('SELECT last_insert_rowid() as id');
        const id = Array.isArray(rows) && rows[0] ? rows[0].id : null;
        try {
          persist(db);
        } catch {}
        return res.json({ id });
      } else {
        db.run('INSERT INTO businesses (name, code, isActive, description) VALUES (?, ?, ?, ?)', [
          String(name).trim(),
          code,
          isActive ? 1 : 0,
          description,
        ]);
        const id = one('SELECT last_insert_rowid() as id')?.id;
        persist(db);
        return res.json({ id });
      }
    } catch (e) {
      console.error('Create business failed', e);
      res.status(500).json({ error: 'insert_failed' });
    }
  });
  // Update business
  app.put('/api/businesses/:id', async (req, res) => {
    const id = String(req.params.id);
    const { name, code, isActive, description } = req.body || {};
    try {
      const current = await one(
        'SELECT id, name, code, isActive, description FROM businesses WHERE id=?',
        [id]
      );
      if (!current) return res.status(404).json({ error: 'not_found' });
      const next = {
        name: name != null ? String(name).trim() : current.name,
        code: code != null ? code : current.code,
        isActive: isActive != null ? (isActive ? 1 : 0) : current.isActive,
        description: description != null ? description : current.description,
      };
      await db.run('UPDATE businesses SET name=?, code=?, isActive=?, description=? WHERE id=?', [
        next.name,
        next.code,
        next.isActive,
        next.description,
        id,
      ]);
      persist(db);
      res.json({ ok: true });
    } catch (e) {
      console.error('Update business failed', e);
      res.status(500).json({ error: 'update_failed' });
    }
  });
  // Delete business (sets recipients.businessId = NULL for references)
  app.delete('/api/businesses/:id', async (req, res) => {
    const id = String(req.params.id);
    try {
      await db.run('BEGIN');
      await db.run('UPDATE recipients SET businessId=NULL WHERE businessId=?', [id]);
      await db.run('DELETE FROM businesses WHERE id=?', [id]);
      // Clean up per-business admin mappings
      try { await db.run('DELETE FROM business_admins WHERE businessId=?', [id]); } catch {}
      await db.run('COMMIT');
      persist(db);
      res.json({ ok: true });
    } catch (e) {
      try {
        await db.run('ROLLBACK');
      } catch {}
      console.error('Delete business failed', e);
      res.status(500).json({ error: 'delete_failed' });
    }
  });

  // Per-Business Admin Emails
  app.get('/api/businesses/:id/admins', async (req, res) => {
    try {
      const isFirebase = db && (db.driver === 'firebase' || db.driver === 'rtdb');
      const rawId = req.params.id;
      const id = isFirebase ? String(rawId) : Number(rawId);
      if (!isFirebase && !Number.isFinite(id)) return res.status(400).json({ error: 'invalid_id' });
      const maybe = all('SELECT email FROM business_admins WHERE businessId=? ORDER BY email ASC', [id]);
      const rows = maybe && typeof maybe.then === 'function' ? await maybe : maybe || [];
      res.json({ emails: (Array.isArray(rows) ? rows : []).map(r => String(r.email)) });
    } catch (e) {
      res.status(500).json({ error: 'list_failed', details: e?.message || String(e) });
    }
  });

  app.put('/api/businesses/:id/admins', async (req, res) => {
    try {
      const isFirebase = db && (db.driver === 'firebase' || db.driver === 'rtdb');
      const rawId = req.params.id;
      const id = isFirebase ? String(rawId) : Number(rawId);
      if (!isFirebase && !Number.isFinite(id)) return res.status(400).json({ error: 'invalid_id' });
      const emails = Array.isArray(req.body?.emails) ? req.body.emails : [];
      await db.run('BEGIN');
      await db.run('DELETE FROM business_admins WHERE businessId=?', [id]);
      for (const e of emails) {
        const v = String(e || '').trim().toLowerCase();
        if (!v || !v.includes('@')) continue;
        await db.run('INSERT OR IGNORE INTO business_admins (businessId, email) VALUES (?, ?)', [id, v]);
      }
      await db.run('COMMIT');
      persist(db);
      res.json({ ok: true });
    } catch (e) {
      try { await db.run('ROLLBACK'); } catch {}
      res.status(500).json({ error: 'save_failed', details: e?.message || String(e) });
    }
  });

  // Batches assigned to a user (via recipients)
  app.get('/api/batches', async (req, res) => {
    try {
      const email = (req.query.email || '').toString().trim().toLowerCase();
      const isFirebase = db && (db.driver === 'firebase' || db.driver === 'rtdb');
      if (!email) {
        // return all (admin view) if no email specified
        const maybe = db.query(
          'SELECT id, name, startDate, dueDate, status, description FROM batches ORDER BY id DESC'
        );
        const rows = maybe && typeof maybe.then === 'function' ? await maybe : maybe || [];
        return res.json((Array.isArray(rows) ? rows : []).map(mapBatch));
      }

      // Firebase/RTDB adapters do not support SQL JOINs reliably; compute in JS
      if (isFirebase) {
        // Get recipient rows for this email (case-insensitive)
        const recMaybe = all('SELECT batchId FROM recipients WHERE LOWER(email)=LOWER(?)', [email]);
        const recRows =
          recMaybe && typeof recMaybe.then === 'function' ? await recMaybe : recMaybe || [];
        const idSet = new Set(
          (Array.isArray(recRows) ? recRows : []).map((r) => String(r.batchId))
        );
        if (idSet.size === 0) return res.json([]);
        // Fetch all batches and filter by the recipient-linked ids
        const bMaybe = all('SELECT id, name, startDate, dueDate, status, description FROM batches');
        let batches = bMaybe && typeof bMaybe.then === 'function' ? await bMaybe : bMaybe || [];
        batches = (Array.isArray(batches) ? batches : []).filter((b) => idSet.has(String(b.id)));
        // Sort by id desc (string ids under RTDB)
        batches.sort((a, b) => String(b.id).localeCompare(String(a.id)));
        return res.json(batches.map(mapBatch));
      }

      // Default SQL path (sqlite/libsql)
      const maybe2 = db.query(
        `SELECT DISTINCT b.id, b.name, b.startDate, b.dueDate, b.status, b.description
         FROM batches b
         JOIN recipients r ON r.batchId=b.id
         WHERE LOWER(r.email)=? ORDER BY b.id DESC`,
        [email]
      );
      const rows2 = maybe2 && typeof maybe2.then === 'function' ? await maybe2 : maybe2 || [];
      return res.json((Array.isArray(rows2) ? rows2 : []).map(mapBatch));
    } catch (e) {
      return res.status(500).json({ error: 'list_failed', details: e?.message || String(e) });
    }
  });

  // Documents by batch
  app.get('/api/batches/:id/documents', async (req, res) => {
    const isFirebase = db && (db.driver === 'firebase' || db.driver === 'rtdb');
    const id = isFirebase ? String(req.params.id) : Number(req.params.id);
    const maybe = all(
      'SELECT id, batchId, title, url, version, requiresSignature, driveId, itemId, source, localFileId, localUrl FROM documents WHERE batchId=? ORDER BY id',
      [id]
    );
    const rows = maybe && typeof maybe.then === 'function' ? await maybe : maybe || [];
    res.json((Array.isArray(rows) ? rows : []).map(mapDoc));
  });

  // Batch subscriptions: list
  app.get('/api/batches/:id/subscriptions', async (req, res) => {
    try {
      const isFirebase = db && (db.driver === 'firebase' || db.driver === 'rtdb');
      const id = isFirebase ? String(req.params.id) : Number(req.params.id);
      const rowsMaybe = all(
        'SELECT id, batch_id as batchId, target_type as targetType, target, frequency, enabled, created_at as createdAt FROM batch_subscriptions WHERE batch_id=? ORDER BY id',
        [id]
      );
      const rows = rowsMaybe && typeof rowsMaybe.then === 'function' ? await rowsMaybe : rowsMaybe || [];
      res.json({ subscriptions: rows.map((r) => ({ ...r, enabled: !!r.enabled })) });
    } catch (e) {
      res.status(500).json({ error: 'list_failed' });
    }
  });

  // Batch subscriptions: replace list (requires sendNotifications)
  app.put(
    '/api/batches/:id/subscriptions',
    validate({
      type: 'object',
      required: ['subscriptions'],
      properties: {
        subscriptions: {
          type: 'array',
          items: {
            type: 'object',
            required: ['targetType', 'target'],
            properties: {
              targetType: { type: 'string' },
              target: { type: 'string' },
              frequency: { type: ['string', 'null'] },
              enabled: { type: ['boolean', 'null'] },
            },
          },
        },
      },
    }),
    async (req, res) => {
      try {
        const isFirebase = db && (db.driver === 'firebase' || db.driver === 'rtdb');
        const id = isFirebase ? String(req.params.id) : Number(req.params.id);
        const emailHdr = (req.headers['x-user-email'] || req.headers['x-admin-email'] || '')
          .toString()
          .trim()
          .toLowerCase();
        if (!emailHdr) return res.status(403).json({ error: 'forbidden' });
        // Permission check: sendNotifications
        const roles = resolveUserRoles(emailHdr, db);
        let allowed = false;
        if (roles.includes('SuperAdmin')) allowed = true;
        if (!allowed) {
          const roleRows = all(
            'SELECT permKey, MAX(value) as value FROM role_permissions WHERE LOWER(role) IN (' +
              roles.map(() => 'LOWER(?)').join(',') +
              ') GROUP BY permKey',
            roles
          );
          const eff = new Map();
          for (const r of roleRows) eff.set(r.permKey, !!r.value);
          const userRows = all('SELECT permKey, value FROM user_permissions WHERE LOWER(email)=LOWER(?)', [
            emailHdr,
          ]);
          for (const u of userRows) eff.set(u.permKey, !!u.value);
          allowed = !!eff.get('sendNotifications');
        }
        if (!allowed) return res.status(403).json({ error: 'forbidden' });

        const { subscriptions = [] } = req.body || {};
        await db.run('DELETE FROM batch_subscriptions WHERE batch_id=?', [id]);
        for (const s of subscriptions) {
          const tt = String(s.targetType || '').toLowerCase();
          const target = String(s.target || '').trim();
          if (!tt || !target) continue;
          const freq = s.frequency ? String(s.frequency) : 'instant';
          const enabled = s.enabled != null ? (s.enabled ? 1 : 0) : 1;
          await db.run(
            'INSERT INTO batch_subscriptions (batch_id, target_type, target, frequency, enabled) VALUES (?, ?, ?, ?, ?)',
            [id, tt, target, freq, enabled]
          );
        }
        persist(db);
        res.json({ ok: true });
      } catch (e) {
        res.status(500).json({ error: 'save_failed' });
      }
    }
  );

  // Recipients by batch (convenience for verification and UI)
  app.get('/api/batches/:id/recipients', async (req, res) => {
    const isFirebase = db && (db.driver === 'firebase' || db.driver === 'rtdb');
    const id = isFirebase ? String(req.params.id) : Number(req.params.id);
    const maybe = all(
      'SELECT id, batchId, businessId, user, email, displayName, department, jobTitle, location, primaryGroup FROM recipients WHERE batchId=? ORDER BY id DESC',
      [id]
    );
    const rows = maybe && typeof maybe.then === 'function' ? await maybe : maybe || [];
    res.json(Array.isArray(rows) ? rows : []);
  });

  // Completion status for all recipients in a batch
  // Returns [{ email, displayName, department, jobTitle, location, primaryGroup, businessId, businessName, acknowledged, total, completed, completionAt }]
  app.get('/api/batches/:id/completions', async (req, res) => {
    try {
      const isFirebase = db && (db.driver === 'firebase' || db.driver === 'rtdb');
      const id = isFirebase ? String(req.params.id) : Number(req.params.id);
      if ((!isFirebase && !Number.isFinite(id)) || (isFirebase && !id))
        return res.status(400).json({ error: 'invalid_batch_id' });

      if (isFirebase) {
        const docsMaybe = all('SELECT id FROM documents WHERE batchId=?', [id]);
        const docs =
          docsMaybe && typeof docsMaybe.then === 'function' ? await docsMaybe : docsMaybe || [];
        const total = Array.isArray(docs) ? docs.length : 0;
        if (total === 0) return res.json([]);

        const recMaybe = all(
          'SELECT email, displayName, department, jobTitle, location, primaryGroup, businessId FROM recipients WHERE batchId=?',
          [id]
        );
        const recs =
          recMaybe && typeof recMaybe.then === 'function' ? await recMaybe : recMaybe || [];
        const ackMaybe = all('SELECT email, ackDate, acknowledged FROM acks WHERE batchId=?', [id]);
        const acks =
          ackMaybe && typeof ackMaybe.then === 'function' ? await ackMaybe : ackMaybe || [];
        const bizMaybe = all('SELECT id, name FROM businesses');
        const businesses =
          bizMaybe && typeof bizMaybe.then === 'function' ? await bizMaybe : bizMaybe || [];
        const bizMap = new Map(
          (Array.isArray(businesses) ? businesses : []).map((b) => [String(b.id), b.name])
        );

        const grouped = {};
        for (const r of Array.isArray(recs) ? recs : []) {
          const email = String(r.email || '').toLowerCase();
          if (!email) continue;
          const emailAcks = (Array.isArray(acks) ? acks : []).filter(
            (a) => String(a.email || '').toLowerCase() === email && (a.acknowledged ? 1 : 0) === 1
          );
          const acknowledged = emailAcks.length;
          const completed = acknowledged >= total;
          const lastAckDate = emailAcks.reduce(
            (m, a) => (m && m > a.ackDate ? m : a.ackDate),
            null
          );
          grouped[email] = {
            email,
            displayName: r.displayName || r.email || '',
            department: r.department || null,
            jobTitle: r.jobTitle || null,
            location: r.location || null,
            primaryGroup: r.primaryGroup || null,
            businessId:
              r.businessId != null
                ? isFirebase
                  ? String(r.businessId)
                  : Number(r.businessId)
                : null,
            businessName: r.businessId != null ? bizMap.get(String(r.businessId)) || null : null,
            acknowledged,
            total,
            completed,
            completionAt: completed ? lastAckDate || null : null,
          };
        }
        return res.json(Object.values(grouped));
      }

      // Default SQL path (sqlite/libsql)
      const totalRow = one('SELECT COUNT(*) as c FROM documents WHERE batchId=?', [id]);
      const total = totalRow?.c || 0;
      if (total === 0) return res.json([]);

      const rows = all(
        `SELECT LOWER(r.email) as email,
                COALESCE(r.displayName, r.email) as displayName,
                r.department, r.jobTitle, r.location, r.primaryGroup,
                r.businessId,
                b.name as businessName,
                COUNT(CASE WHEN a.acknowledged=1 THEN 1 END) as acknowledged,
                MAX(a.ackDate) as lastAckDate
         FROM recipients r
         LEFT JOIN acks a ON a.batchId=r.batchId AND LOWER(a.email)=LOWER(r.email)
         LEFT JOIN businesses b ON b.id=r.businessId
         WHERE r.batchId=?
         GROUP BY LOWER(r.email), r.displayName, r.department, r.jobTitle, r.location, r.primaryGroup, r.businessId, b.name`,
        [id]
      );
      const mapped = rows.map((r) => {
        const acknowledged = Number(r.acknowledged) || 0;
        const completed = acknowledged >= total;
        const completionAt = completed ? r.lastAckDate || null : null;
        return {
          email: String(r.email || ''),
          displayName: r.displayName || r.email || '',
          department: r.department || null,
          jobTitle: r.jobTitle || null,
          location: r.location || null,
          primaryGroup: r.primaryGroup || null,
          businessId: r.businessId != null ? Number(r.businessId) : null,
          businessName: r.businessName || null,
          acknowledged,
          total,
          completed,
          completionAt,
        };
      });
      res.json(mapped);
    } catch (e) {
      console.error('completions endpoint failed', e);
      res.status(500).json({ error: 'completions_failed' });
    }
  });

  // Acked doc ids for user
  app.get('/api/batches/:id/acks', async (req, res) => {
    const isFirebase = db && (db.driver === 'firebase' || db.driver === 'rtdb');
    const id = isFirebase ? String(req.params.id) : Number(req.params.id);
    const email = (req.query.email || '').toString().toLowerCase();
    const maybeRows = all(
      'SELECT documentId FROM acks WHERE batchId=? AND LOWER(email)=? AND acknowledged=1',
      [id, email]
    );
    const rows =
      maybeRows && typeof maybeRows.then === 'function' ? await maybeRows : maybeRows || [];
    res.json({ ids: (Array.isArray(rows) ? rows : []).map((r) => String(r.documentId)) });
  });

  // Progress for a user in a batch
  app.get('/api/batches/:id/progress', async (req, res) => {
    const isFirebase = db && (db.driver === 'firebase' || db.driver === 'rtdb');
    const id = isFirebase ? String(req.params.id) : Number(req.params.id);
    const email = (req.query.email || '').toString().toLowerCase();
    if (isFirebase) {
      const docsMaybe = all('SELECT id FROM documents WHERE batchId=?', [id]);
      const docs =
        docsMaybe && typeof docsMaybe.then === 'function' ? await docsMaybe : docsMaybe || [];
      const acksMaybe = all(
        'SELECT id FROM acks WHERE batchId=? AND LOWER(email)=? AND acknowledged=1',
        [id, email]
      );
      const acks =
        acksMaybe && typeof acksMaybe.then === 'function' ? await acksMaybe : acksMaybe || [];
      const total = Array.isArray(docs) ? docs.length : 0;
      const acknowledged = Array.isArray(acks) ? acks.length : 0;
      const percent = total === 0 ? 0 : Math.round((acknowledged / total) * 100);
      return res.json({ acknowledged, total, percent });
    }
    const maybeTotal = one('SELECT COUNT(*) as c FROM documents WHERE batchId=?', [id]);
    const totalRow =
      maybeTotal && typeof maybeTotal.then === 'function' ? await maybeTotal : maybeTotal;
    const maybeAck = one(
      'SELECT COUNT(*) as c FROM acks WHERE batchId=? AND LOWER(email)=? AND acknowledged=1',
      [id, email]
    );
    const ackRow = maybeAck && typeof maybeAck.then === 'function' ? await maybeAck : maybeAck;
    const total = totalRow?.c || 0;
    const acknowledged = ackRow?.c || 0;
    const percent = total === 0 ? 0 : Math.round((acknowledged / total) * 100);
    res.json({ acknowledged, total, percent });
  });

  // Admin: preview reminder targets without sending
  app.get('/api/reminders/preview', async (req, res) => {
    try {
      const now = new Date();
      const settings = await getReminderSettings();
      const daysWindowRaw = req.query?.days ?? settings.days ?? process.env.REMINDER_DAYS ?? 3;
      const daysWindow = Number.isFinite(Number(daysWindowRaw)) ? Number(daysWindowRaw) : 3;
      const throttleHoursRaw = req.query?.throttleHours ?? process.env.REMINDER_THROTTLE_HOURS ?? 24;
      const throttleHours = Number.isFinite(Number(throttleHoursRaw)) ? Number(throttleHoursRaw) : 24;
      const windowEnd = new Date(now.getTime() + daysWindow * 24 * 60 * 60 * 1000);

      const batchesMaybe = all(
        'SELECT id, name, dueDate, status FROM batches WHERE dueDate IS NOT NULL AND status = 1'
      );
      const batches = batchesMaybe && typeof batchesMaybe.then === 'function' ? await batchesMaybe : batchesMaybe || [];

      let actionable = 0;
      let skippedRecent = 0;
      const batchesConsidered = [];

      for (const b of batches) {
        const batchId = b.id;
        const dueStr = String(b.dueDate || '').trim();
        const due = dueStr ? new Date(dueStr) : null;
        if (!due || Number.isNaN(due.getTime())) continue;
        if (due > windowEnd) continue; // not within reminder window

        batchesConsidered.push(batchId);

        const docsRow = one('SELECT COUNT(*) as c FROM documents WHERE batchId=?', [batchId]);
        const docCount = docsRow?.c || 0;
        if (docCount === 0) continue;

        const recipientsMaybe = all(
          `SELECT LOWER(r.email) as email,
                  COUNT(d.id) as totalDocs,
                  COUNT(CASE WHEN a.acknowledged=1 THEN 1 END) as acked
           FROM recipients r
           JOIN documents d ON d.batchId = r.batchId
           LEFT JOIN acks a ON a.batchId = r.batchId AND a.documentId = d.id AND LOWER(a.email)=LOWER(r.email) AND a.acknowledged=1
           WHERE r.batchId = ?
           GROUP BY LOWER(r.email)`,
          [batchId]
        );
        const recRows = recipientsMaybe && typeof recipientsMaybe.then === 'function' ? await recipientsMaybe : recipientsMaybe || [];

        for (const r of recRows) {
          const total = Number(r.totalDocs) || 0;
          const acked = Number(r.acked) || 0;
          if (total === 0 || acked >= total) continue;

          const lastRow = one(
            'SELECT sentAt FROM reminder_logs WHERE batchId=? AND LOWER(email)=LOWER(?) ORDER BY sentAt DESC LIMIT 1',
            [batchId, r.email]
          );
          if (lastRow?.sentAt) {
            const last = new Date(String(lastRow.sentAt));
            const deltaMs = now.getTime() - last.getTime();
            if (!Number.isNaN(deltaMs) && deltaMs < throttleHours * 60 * 60 * 1000) {
              skippedRecent++;
              continue;
            }
          }

          actionable++;
        }
      }

      res.json({ ok: true, actionable, skippedRecent, batchesConsidered, daysWindow, throttleHours, enabled: settings.enabled });
    } catch (e) {
      console.error('reminders preview failed', e);
      res.status(500).json({ error: 'reminders_preview_failed', message: e?.message || 'unknown' });
    }
  });

  // Admin: send reminder emails for batches nearing due date (or overdue)
  app.post('/api/reminders/run', async (req, res) => {
    try {
      const mailer = (function () {
        try {
          return require('./src/services/mailer');
        } catch (e) {
          console.error('mailer load failed', e);
          return null;
        }
      })();
      if (!mailer || typeof mailer.sendHtml !== 'function') {
        return res.status(500).json({ error: 'mailer_unavailable' });
      }

      const now = new Date();
      const settings = await getReminderSettings();
      const daysWindowRaw = req.body?.days ?? req.query?.days ?? settings.days ?? process.env.REMINDER_DAYS ?? 3;
      const daysWindow = Number.isFinite(Number(daysWindowRaw)) ? Number(daysWindowRaw) : 3;
      const throttleHoursRaw = req.body?.throttleHours ?? req.query?.throttleHours ?? process.env.REMINDER_THROTTLE_HOURS ?? 24;
      const throttleHours = Number.isFinite(Number(throttleHoursRaw)) ? Number(throttleHoursRaw) : 24;
      const windowEnd = new Date(now.getTime() + daysWindow * 24 * 60 * 60 * 1000);

      const force = req.body?.force === true || String(req.body?.force) === '1' || req.query?.force === '1';
      if (!settings.enabled && !force) {
        return res.status(400).json({ error: 'reminders_disabled', message: 'Auto reminders are disabled in settings.' });
      }

      const baseUrl = (
        getSetting('frontend_base_url', process.env.FRONTEND_BASE_URL || '') ||
        (req.headers.origin && String(req.headers.origin)) ||
        'http://localhost:3000'
      ).replace(/\/$/, '');

      const batchesMaybe = all(
        'SELECT id, name, dueDate, status FROM batches WHERE dueDate IS NOT NULL AND status = 1'
      );
      const batches = batchesMaybe && typeof batchesMaybe.then === 'function' ? await batchesMaybe : batchesMaybe || [];

      let sent = 0;
      let skippedRecent = 0;
      const batchesConsidered = [];

      for (const b of batches) {
        const batchId = b.id;
        const dueStr = String(b.dueDate || '').trim();
        const due = dueStr ? new Date(dueStr) : null;
        if (!due || Number.isNaN(due.getTime())) continue;
        if (due > windowEnd) continue; // not within reminder window yet

        batchesConsidered.push(batchId);

        const docsRow = one('SELECT COUNT(*) as c FROM documents WHERE batchId=?', [batchId]);
        const docCount = docsRow?.c || 0;
        if (docCount === 0) continue;

        const recipientsMaybe = all(
          `SELECT LOWER(r.email) as email,
                  COALESCE(r.displayName, r.email) as displayName,
                  COUNT(d.id) as totalDocs,
                  COUNT(CASE WHEN a.acknowledged=1 THEN 1 END) as acked
           FROM recipients r
           JOIN documents d ON d.batchId = r.batchId
           LEFT JOIN acks a ON a.batchId = r.batchId AND a.documentId = d.id AND LOWER(a.email)=LOWER(r.email) AND a.acknowledged=1
           WHERE r.batchId = ?
           GROUP BY LOWER(r.email), r.displayName`,
          [batchId]
        );
        const recRows = recipientsMaybe && typeof recipientsMaybe.then === 'function' ? await recipientsMaybe : recipientsMaybe || [];

        for (const r of recRows) {
          const total = Number(r.totalDocs) || 0;
          const acked = Number(r.acked) || 0;
          if (total === 0 || acked >= total) continue; // already complete

          // Throttle per recipient per batch
          const lastRow = one(
            'SELECT sentAt FROM reminder_logs WHERE batchId=? AND LOWER(email)=LOWER(?) ORDER BY sentAt DESC LIMIT 1',
            [batchId, r.email]
          );
          if (lastRow?.sentAt) {
            const last = new Date(String(lastRow.sentAt));
            const deltaMs = now.getTime() - last.getTime();
            if (!Number.isNaN(deltaMs) && deltaMs < throttleHours * 60 * 60 * 1000) {
              skippedRecent++;
              continue;
            }
          }

          const outstanding = total - acked;
          const subject = `Reminder: ${b.name} due ${due.toLocaleDateString()}`;
          const portalLink = `${baseUrl}/acknowledgements/${batchId}`;
          const html = `<div style="font-family:Segoe UI,Tahoma,Arial,sans-serif;color:#111"><h2 style="margin:0 0 12px 0">Reminder: ${b.name}</h2><p style="margin:0 0 10px 0">You still have <strong>${outstanding}</strong> of <strong>${total}</strong> documents to acknowledge.</p><p style="margin:0 0 10px 0">Due date: <strong>${due.toLocaleString()}</strong></p><p style="margin:0 0 12px 0">Please complete your acknowledgements before the deadline.</p><p style="margin:0"><a href="${portalLink}" target="_blank" rel="noopener" style="display:inline-block;padding:10px 14px;background:#2563eb;color:#fff;text-decoration:none;border-radius:6px;font-weight:600">Open Acknowledgement Portal</a></p><p style="margin:14px 0 0 0;color:#555;font-size:12px">If the button does not work, copy and paste this link: ${portalLink}</p></div>`;
          const text = `Reminder: ${b.name}\nOutstanding: ${outstanding}/${total}\nDue: ${due.toLocaleString()}\nLink: ${portalLink}`;

          try {
            await mailer.sendHtml(r.email, subject, html, text);
            exec('INSERT INTO reminder_logs (batchId, email, sentAt) VALUES (?, ?, ?)', [
              batchId,
              r.email,
              now.toISOString(),
            ]);
            sent++;
          } catch (e) {
            console.warn('reminder send failed', { batchId, email: r.email, err: e?.message });
          }
        }
      }

      res.json({ ok: true, sent, skippedRecent, batchesConsidered });
    } catch (e) {
      console.error('reminders run failed', e);
      res.status(500).json({ error: 'reminders_failed', message: e?.message || 'unknown' });
    }
  });

  // Admin: create batch
  app.post('/api/batches', async (req, res) => {
    const { logger } = req;

    try {
      logger.info('batch-create', 'Starting batch creation process');

      const {
        name,
        startDate = null,
        dueDate = null,
        description = null,
        status = 1,
      } = req.body || {};

      // Validate required fields
      if (!name || typeof name !== 'string' || !name.trim()) {
        logger.error('batch-create', 'Validation failed: name is required', { providedName: name });
        return res
          .status(400)
          .json({
            error: 'name_required',
            message: 'Batch name is required and must be a non-empty string',
          });
      }

      // Validate optional fields
      if (startDate !== null && startDate !== '' && typeof startDate !== 'string') {
        logger.error('batch-create', 'Validation failed: invalid startDate format', { startDate });
        return res
          .status(400)
          .json({ error: 'invalid_start_date', message: 'Start date must be a string or null' });
      }

      if (dueDate !== null && dueDate !== '' && typeof dueDate !== 'string') {
        logger.error('batch-create', 'Validation failed: invalid dueDate format', { dueDate });
        return res
          .status(400)
          .json({ error: 'invalid_due_date', message: 'Due date must be a string or null' });
      }

      const trimmedName = name.trim();
      const finalStartDate = startDate === '' || startDate === null ? null : startDate;
      const finalDueDate = dueDate === '' || dueDate === null ? null : dueDate;
      const finalDescription = description === '' || description === null ? null : description;
      const finalStatus = Number.isInteger(status) ? status : 1;

      logger.debug('batch-create', 'Validated input parameters', {
        name: trimmedName,
        startDate: finalStartDate,
        dueDate: finalDueDate,
        description: finalDescription ? 'provided' : 'null',
        status: finalStatus,
      });

      // Insert into database
      logger.info('batch-create', 'Inserting batch into database');
      const sql =
        'INSERT INTO batches (name, startDate, dueDate, status, description) VALUES (?, ?, ?, ?, ?)';
      const params = [trimmedName, finalStartDate, finalDueDate, finalStatus, finalDescription];

      logger.debug('batch-create', 'Executing SQL insert', { sql, params });

      // Driver-aware insert and ID retrieval
      let id;
      if (db && (db.driver === 'firebase' || db.driver === 'rtdb')) {
        try {
          await db.run(sql, params);
          const rows = await db.query('SELECT last_insert_rowid() as id');
          id = Array.isArray(rows) && rows[0] ? rows[0].id : null;
        } catch (e) {
          logger.error('batch-create', 'Database insert failed (async driver)', {
            error: e?.message || String(e),
          });
          return res
            .status(500)
            .json({ error: 'insert_failed', message: 'Failed to insert batch into database' });
        }
      } else {
        const ok = exec(sql, params);
        if (!ok) {
          logger.error('batch-create', 'Database insert failed', { sql, params });
          return res
            .status(500)
            .json({ error: 'insert_failed', message: 'Failed to insert batch into database' });
        }
        const idResult = one('SELECT last_insert_rowid() as id');
        id = idResult?.id;
      }

      if (!id) {
        logger.error('batch-create', 'Failed to retrieve generated batch ID');
        return res
          .status(500)
          .json({
            error: 'id_retrieval_failed',
            message: 'Batch created but ID could not be retrieved',
          });
      }

      // Verify batch exists and is accessible
      {
        const maybe = one('SELECT id, name FROM batches WHERE id = ?', [id]);
        const verifyBatch = maybe && typeof maybe.then === 'function' ? await maybe : maybe;
        if (!verifyBatch) {
          logger.error(
            'batch-create',
            'Batch verification failed - batch not found after creation',
            { batchId: id }
          );
          return res
            .status(500)
            .json({
              error: 'verification_failed',
              message: 'Batch created but verification failed',
            });
        }
        logger.info('batch-create', 'Batch created and verified successfully', {
          batchId: id,
          name: trimmedName,
          startDate: finalStartDate,
          dueDate: finalDueDate,
          verifiedName: verifyBatch.name,
        });
      }

      res.json({ id, batchId: id });
    } catch (error) {
      logger.error('batch-create', 'Unexpected error during batch creation', {
        error: error.message,
        stack: error.stack,
      });
      res
        .status(500)
        .json({
          error: 'internal_error',
          message: 'An unexpected error occurred during batch creation',
        });
    }
  });

  // Admin: create batch WITH documents and recipients atomically
  app.post('/api/batches/full', async (req, res) => {
    const { logger } = req;
    try {
      logger.info('batch-full-create', 'Starting full batch creation process');

      const body = req.body || {};
      const {
        name,
        startDate = null,
        dueDate = null,
        description = null,
        status = 1,
      } = body.batch || body;
      const documents = Array.isArray(body.documents) ? body.documents : [];
      const recipients = Array.isArray(body.recipients) ? body.recipients : [];

      // Validate batch
      if (!name || typeof name !== 'string' || !name.trim()) {
        logger.error('batch-full-create', 'Validation failed: name is required', {
          providedName: name,
        });
        return res
          .status(400)
          .json({
            error: 'name_required',
            message: 'Batch name is required and must be a non-empty string',
          });
      }
      const trimmedName = name.trim();
      const finalStartDate = startDate === '' || startDate === null ? null : startDate;
      const finalDueDate = dueDate === '' || dueDate === null ? null : dueDate;
      const finalDescription = description === '' || description === null ? null : description;
      const finalStatus = Number.isInteger(status) ? status : 1;

      // Enforce at least one document and one recipient when creating
      if (documents.length === 0) {
        logger.warn('batch-full-create', 'No documents provided in full create');
        return res
          .status(400)
          .json({
            error: 'documents_required',
            message: 'At least one document is required to create a batch',
          });
      }
      if (recipients.length === 0) {
        logger.warn('batch-full-create', 'No recipients provided in full create');
        return res
          .status(400)
          .json({
            error: 'recipients_required',
            message: 'At least one recipient is required to create a batch',
          });
      }

      // Begin transaction (noop for Firebase)
      logger.debug('batch-full-create', 'Beginning DB transaction');

      // Support async flow for Firebase driver
      if (db && (db.driver === 'firebase' || db.driver === 'rtdb')) {
        let newBatchId = null;
        let docsInserted = 0;
        let recsInserted = 0;
        try {
          try {
            await db.run('BEGIN');
          } catch {}
          // Insert batch
          await db.run(
            'INSERT INTO batches (name, startDate, dueDate, status, description) VALUES (?, ?, ?, ?, ?)',
            [trimmedName, finalStartDate, finalDueDate, finalStatus, finalDescription]
          );
          const idRows = await db.query('SELECT last_insert_rowid() as id');
          newBatchId = Array.isArray(idRows) && idRows[0] ? idRows[0].id : null;
          if (!newBatchId) throw new Error('failed_to_create_batch');

          // Insert documents
          for (let i = 0; i < documents.length; i++) {
            const d = documents[i] || {};
            const {
              title,
              url,
              version = 1,
              requiresSignature = 0,
              driveId = null,
              itemId = null,
              source = null,
              localFileId = null,
              localUrl = null,
            } = d;
            if (!title || !url) continue;
            await db.run(
              'INSERT OR IGNORE INTO documents (batchId, title, url, version, requiresSignature, driveId, itemId, source, localFileId, localUrl) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
              [
                newBatchId,
                String(title),
                String(url),
                Number(version) || 1,
                requiresSignature ? 1 : 0,
                driveId,
                itemId,
                source,
                localFileId,
                localUrl,
              ]
            );
            docsInserted++;
          }

          // Insert recipients
          const processedEmails = new Set();
          for (let i = 0; i < recipients.length; i++) {
            const r = recipients[i] || {};
            const {
              businessId = null,
              user = null,
              email = null,
              displayName = null,
              department = null,
              jobTitle = null,
              location = null,
              primaryGroup = null,
            } = r;
            const emailLower = String(email || user || '')
              .trim()
              .toLowerCase();
            if (!emailLower || !emailLower.includes('@') || emailLower.length < 5) continue;
            if (processedEmails.has(emailLower)) continue;
            processedEmails.add(emailLower);
            await db.run(
              `INSERT OR IGNORE INTO recipients (batchId, businessId, user, email, displayName, department, jobTitle, location, primaryGroup)
                          VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
              [
                newBatchId,
                businessId,
                emailLower,
                emailLower,
                displayName,
                department,
                jobTitle,
                location,
                primaryGroup,
              ]
            );
            recsInserted++;
          }

          if (docsInserted === 0) throw new Error('no_documents_created');
          if (recsInserted === 0) throw new Error('no_recipients_created');

          try {
            await db.run('COMMIT');
          } catch {}
          try {
            persist(db);
          } catch {}
          logger.info('batch-full-create', 'Full batch creation successful', {
            batchId: newBatchId,
            docsInserted,
            recsInserted,
          });
          return res.json({
            id: newBatchId,
            batchId: newBatchId,
            documentsInserted: docsInserted,
            recipientsInserted: recsInserted,
          });
        } catch (txErr) {
          try {
            await db.run('ROLLBACK');
          } catch {}
          logger.error('batch-full-create', 'Transaction failed, rolled back', {
            error: txErr?.message || String(txErr),
          });
          const code =
            txErr?.message === 'no_documents_created'
              ? 400
              : txErr?.message === 'no_recipients_created'
                ? 400
                : 500;
          return res.status(code).json({ error: txErr?.message || 'tx_failed' });
        }
      }

      // Default (SQLite/libsql) synchronous flow
      db.run('BEGIN');
      let newBatchId = null;
      let docsInserted = 0;
      let recsInserted = 0;

      try {
        // Insert batch
        db.run(
          'INSERT INTO batches (name, startDate, dueDate, status, description) VALUES (?, ?, ?, ?, ?)',
          [trimmedName, finalStartDate, finalDueDate, finalStatus, finalDescription]
        );
        const idRow = one('SELECT last_insert_rowid() as id');
        newBatchId = idRow?.id;
        if (!newBatchId) throw new Error('failed_to_create_batch');

        // Insert documents
        for (let i = 0; i < documents.length; i++) {
          const d = documents[i] || {};
          const {
            title,
            url,
            version = 1,
            requiresSignature = 0,
            driveId = null,
            itemId = null,
            source = null,
            localFileId = null,
            localUrl = null,
          } = d;
          if (!title || !url) continue;
          db.run(
            'INSERT OR IGNORE INTO documents (batchId, title, url, version, requiresSignature, driveId, itemId, source, localFileId, localUrl) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
            [
              newBatchId,
              String(title),
              String(url),
              Number(version) || 1,
              requiresSignature ? 1 : 0,
              driveId,
              itemId,
              source,
              localFileId,
              localUrl,
            ]
          );
          docsInserted++;
        }

        // Insert recipients
        const processedEmails = new Set();
        for (let i = 0; i < recipients.length; i++) {
          const r = recipients[i] || {};
          const {
            businessId = null,
            user = null,
            email = null,
            displayName = null,
            department = null,
            jobTitle = null,
            location = null,
            primaryGroup = null,
          } = r;
          const emailLower = String(email || user || '')
            .trim()
            .toLowerCase();
          if (!emailLower || !emailLower.includes('@') || emailLower.length < 5) continue;
          if (processedEmails.has(emailLower)) continue;
          processedEmails.add(emailLower);
          db.run(
            `INSERT OR IGNORE INTO recipients (batchId, businessId, user, email, displayName, department, jobTitle, location, primaryGroup)
                  VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
            [
              newBatchId,
              businessId,
              emailLower,
              emailLower,
              displayName,
              department,
              jobTitle,
              location,
              primaryGroup,
            ]
          );
          recsInserted++;
        }

        // Ensure we created relations
        if (docsInserted === 0) throw new Error('no_documents_created');
        if (recsInserted === 0) throw new Error('no_recipients_created');

        // Commit
        db.run('COMMIT');
        persist(db);
        logger.info('batch-full-create', 'Full batch creation successful', {
          batchId: newBatchId,
          docsInserted,
          recsInserted,
        });
        return res.json({
          id: newBatchId,
          batchId: newBatchId,
          documentsInserted: docsInserted,
          recipientsInserted: recsInserted,
        });
      } catch (txErr) {
        // Rollback on any error
        try {
          db.run('ROLLBACK');
        } catch {}
        logger.error('batch-full-create', 'Transaction failed, rolled back', {
          error: txErr?.message || String(txErr),
        });
        const code =
          txErr?.message === 'no_documents_created'
            ? 400
            : txErr?.message === 'no_recipients_created'
              ? 400
              : 500;
        return res.status(code).json({ error: txErr?.message || 'tx_failed' });
      }
    } catch (error) {
      logger.error('batch-full-create', 'Unexpected error during full batch creation', {
        error: error?.message || String(error),
      });
      return res.status(500).json({ error: 'internal_error' });
    }
  });

  // Admin: update batch (optionally add recipients)
  app.put('/api/batches/:id', async (req, res) => {
    const isFirebase = db && (db.driver === 'firebase' || db.driver === 'rtdb');
    const id = isFirebase ? String(req.params.id) : Number(req.params.id);
    const { name, startDate = null, dueDate = null, status, description = null } = req.body || {};
    const recList = Array.isArray(req.body?.recipients) ? req.body.recipients : [];
    try {
      const maybeCur = one(
        'SELECT id, name, startDate, dueDate, status, description FROM batches WHERE id=?',
        [id]
      );
      const current = maybeCur && typeof maybeCur.then === 'function' ? await maybeCur : maybeCur;
      if (!current) return res.status(404).json({ error: 'not_found' });
      const next = {
        name: name != null ? String(name).trim() : current.name,
        startDate: startDate !== undefined ? startDate : current.startDate,
        dueDate: dueDate !== undefined ? dueDate : current.dueDate,
        status: status != null ? Number(status) : current.status,
        description: description !== undefined ? description : current.description,
      };
      await db.run(
        'UPDATE batches SET name=?, startDate=?, dueDate=?, status=?, description=? WHERE id=?',
        [next.name, next.startDate, next.dueDate, next.status, next.description, id]
      );

      // Optional recipients addition
      let recipientsInserted = 0;
      if (recList.length > 0) {
        const processed = new Set();
        for (let i = 0; i < recList.length; i++) {
          const r = recList[i] || {};
          const {
            businessId = null,
            user = null,
            email = null,
            displayName = null,
            department = null,
            jobTitle = null,
            location = null,
            primaryGroup = null,
          } = r;
          const emailLower = String(email || user || '')
            .trim()
            .toLowerCase();
          if (!emailLower || !emailLower.includes('@') || emailLower.length < 5) continue;
          if (processed.has(emailLower)) continue;
          processed.add(emailLower);
          try {
            if (isFirebase) {
              const maybeExists = one(
                'SELECT id FROM recipients WHERE batchId=? AND LOWER(email)=LOWER(?)',
                [id, emailLower]
              );
              const exists =
                maybeExists && typeof maybeExists.then === 'function'
                  ? await maybeExists
                  : maybeExists;
              if (exists) continue;
              await db.run(
                `INSERT OR IGNORE INTO recipients (batchId, businessId, user, email, displayName, department, jobTitle, location, primaryGroup)
                            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
                [
                  id,
                  businessId,
                  emailLower,
                  emailLower,
                  displayName,
                  department,
                  jobTitle,
                  location,
                  primaryGroup,
                ]
              );
            } else {
              db.run(
                `INSERT OR IGNORE INTO recipients (batchId, businessId, user, email, displayName, department, jobTitle, location, primaryGroup)
                      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
                [
                  id,
                  businessId,
                  emailLower,
                  emailLower,
                  displayName,
                  department,
                  jobTitle,
                  location,
                  primaryGroup,
                ]
              );
            }
            recipientsInserted++;
          } catch {}
        }
      }
      try {
        persist(db);
      } catch {}
      res.json({ ok: true, recipientsInserted });
    } catch (e) {
      console.error('Update batch failed', e);
      res.status(500).json({ error: 'update_failed' });
    }
  });

  // Admin: bulk add documents
  app.post('/api/batches/:id/documents', async (req, res) => {
    const { logger } = req;

    try {
      logger.info('documents-create', 'Starting bulk document addition process');

      const id =
        db && (db.driver === 'firebase' || db.driver === 'rtdb')
          ? String(req.params.id)
          : Number(req.params.id);
      if (db && (db.driver === 'firebase' || db.driver === 'rtdb')) {
        if (!id || typeof id !== 'string') {
          logger.error('documents-create', 'Invalid batch ID provided (firebase)', {
            providedId: req.params.id,
          });
          return res
            .status(400)
            .json({ error: 'invalid_batch_id', message: 'Batch ID must be a non-empty string' });
        }
      } else {
        if (!Number.isInteger(id) || id <= 0) {
          logger.error('documents-create', 'Invalid batch ID provided', {
            providedId: req.params.id,
            parsedId: id,
          });
          return res
            .status(400)
            .json({ error: 'invalid_batch_id', message: 'Batch ID must be a positive integer' });
        }
      }

      // Check if batch exists
      const maybeBatch = one('SELECT id, name FROM batches WHERE id = ?', [id]);
      const batchExists =
        maybeBatch && typeof maybeBatch.then === 'function' ? await maybeBatch : maybeBatch;
      if (!batchExists) {
        logger.error('documents-create', 'Batch not found', { batchId: id });
        return res
          .status(404)
          .json({ error: 'batch_not_found', message: 'Specified batch does not exist' });
      }

      logger.info('documents-create', 'Batch verified for document insertion', {
        batchId: id,
        batchName: batchExists.name,
      });

      const docs = Array.isArray(req.body?.documents) ? req.body.documents : [];
      logger.info('documents-create', 'Processing document list', {
        batchId: id,
        totalDocuments: docs.length,
      });

      if (docs.length === 0) {
        logger.warn('documents-create', 'No documents provided in request');
        return res.json({ inserted: 0, message: 'No documents provided' });
      }

      let count = 0;
      let skipped = 0;
      const errors = [];

      logger.debug('documents-create', 'Starting database transaction');
      db.run('BEGIN');

      try {
        for (let i = 0; i < docs.length; i++) {
          const d = docs[i];
          const {
            title,
            url,
            version = 1,
            requiresSignature = 0,
            driveId = null,
            itemId = null,
            source = null,
            localFileId = null,
            localUrl = null,
          } = d || {};

          // Validate document fields
          if (!title || !url) {
            logger.warn('documents-create', `Document ${i + 1} missing required fields`, {
              index: i,
              hasTitle: !!title,
              hasUrl: !!url,
            });
            skipped++;
            errors.push(`Document ${i + 1}: Missing title or URL`);
            continue;
          }

          if (typeof title !== 'string' || typeof url !== 'string') {
            logger.warn('documents-create', `Document ${i + 1} has invalid field types`, {
              index: i,
              titleType: typeof title,
              urlType: typeof url,
            });
            skipped++;
            errors.push(`Document ${i + 1}: Title and URL must be strings`);
            continue;
          }

          logger.debug('documents-create', `Processing document ${i + 1}`, {
            title: title.substring(0, 50) + (title.length > 50 ? '...' : ''),
            url: url.substring(0, 100) + (url.length > 100 ? '...' : ''),
            version,
            requiresSignature: !!requiresSignature,
          });

          try {
            if (db && (db.driver === 'firebase' || db.driver === 'rtdb')) {
              await db.run(
                'INSERT OR IGNORE INTO documents (batchId, title, url, version, requiresSignature, driveId, itemId, source, localFileId, localUrl) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
                [
                  id,
                  String(title),
                  String(url),
                  Number(version) || 1,
                  requiresSignature ? 1 : 0,
                  driveId,
                  itemId,
                  source,
                  localFileId,
                  localUrl,
                ]
              );
            } else {
              db.run(
                'INSERT OR IGNORE INTO documents (batchId, title, url, version, requiresSignature, driveId, itemId, source, localFileId, localUrl) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
                [
                  id,
                  String(title),
                  String(url),
                  Number(version) || 1,
                  requiresSignature ? 1 : 0,
                  driveId,
                  itemId,
                  source,
                  localFileId,
                  localUrl,
                ]
              );
            }
            count++;
          } catch (docError) {
            logger.error('documents-create', `Failed to insert document ${i + 1}`, {
              index: i,
              error: docError.message,
              title: title.substring(0, 50),
            });
            errors.push(`Document ${i + 1}: ${docError.message}`);
            skipped++;
          }
        }

        logger.debug('documents-create', 'Committing database transaction');
        db.run('COMMIT');
        persist(db);

        logger.info('documents-create', 'Document addition completed', {
          batchId: id,
          inserted: count,
          skipped: skipped,
          totalProcessed: docs.length,
        });

        const result = { inserted: count };
        if (skipped > 0) {
          result.skipped = skipped;
          result.errors = errors;
        }

        res.json(result);
      } catch (transactionError) {
        logger.error('documents-create', 'Transaction failed, rolling back', {
          error: transactionError.message,
          batchId: id,
          processedCount: count,
        });
        db.run('ROLLBACK');
        throw transactionError;
      }
    } catch (e) {
      logger.error('documents-create', 'Unexpected error during document creation', {
        error: e.message,
        stack: e.stack,
        batchId: req.params.id,
      });

      try {
        db.run('ROLLBACK');
      } catch (rollbackError) {
        logger.error('documents-create', 'Failed to rollback transaction', {
          error: rollbackError.message,
        });
      }

      res.status(500).json({ error: 'insert_failed', message: 'Failed to add documents to batch' });
    }
  });

  // Admin: remove documents from a batch
  // Supports deletion by document ids or by URLs (convenient for clients that track URLs)
  // DELETE /api/batches/:id/documents
  // Body: { ids?: number[], urls?: string[] }
  // Also supports single query params: ?docId=123 or ?url=...
  app.delete('/api/batches/:id/documents', async (req, res) => {
    try {
      const logger = req && req.logger ? req.logger : null;
      const isFirebase = db && (db.driver === 'firebase' || db.driver === 'rtdb');
      const batchId = isFirebase ? String(req.params.id) : Number(req.params.id);
      if (
        (isFirebase && (!batchId || typeof batchId !== 'string')) ||
        (!isFirebase && (!Number.isInteger(batchId) || batchId <= 0))
      ) {
        return res.status(400).json({ error: 'invalid_batch_id' });
      }
      const body = req.body || {};
      const ids = Array.isArray(body.ids)
        ? body.ids.map((x) => Number(x)).filter((n) => Number.isInteger(n) && n > 0)
        : [];
      const urls = Array.isArray(body.urls)
        ? body.urls.map((u) => String(u).trim()).filter(Boolean)
        : [];
      // Query fallbacks
      const qId = req.query.docId != null ? Number(req.query.docId) : null;
      const qUrl = req.query.url != null ? String(req.query.url) : null;
      if (Number.isInteger(qId) && qId > 0) ids.push(qId);
      if (qUrl && qUrl.trim()) urls.push(qUrl.trim());

      try {
        logger && logger.info
          ? logger.info('documents-delete:start', { batchId, ids, urls, qId, qUrl })
          : console.log('[documents-delete:start]', { batchId, ids, urls, qId, qUrl });
      } catch {}

      if (ids.length === 0 && urls.length === 0) {
        return res.status(400).json({ error: 'ids_or_urls_required' });
      }

      let removed = 0;
      await db.run('BEGIN');
      try {
        for (const id of ids) {
          try {
            const maybeBefore = one(
              'SELECT COUNT(*) as c FROM documents WHERE batchId=? AND id=?',
              [batchId, id]
            );
            const before =
              maybeBefore && typeof maybeBefore.then === 'function'
                ? (await maybeBefore)?.c || 0
                : maybeBefore?.c || 0;
            await db.run('DELETE FROM documents WHERE batchId=? AND id=?', [batchId, id]);
            const maybeAfter = one('SELECT COUNT(*) as c FROM documents WHERE batchId=? AND id=?', [
              batchId,
              id,
            ]);
            const after =
              maybeAfter && typeof maybeAfter.then === 'function'
                ? (await maybeAfter)?.c || 0
                : maybeAfter?.c || 0;
            const delta = Math.max(0, Number(before) - Number(after));
            removed += delta;
            try {
              logger && logger.debug
                ? logger.debug('documents-delete:by-id', { id, before, after, delta })
                : console.log('[documents-delete:by-id]', { id, before, after, delta });
            } catch {}
          } catch (e) {
            try {
              logger && logger.error
                ? logger.error('documents-delete:by-id-error', {
                    id,
                    error: String(e?.message || e),
                  })
                : console.error('[documents-delete:by-id-error]', id, e);
            } catch {}
          }
        }
        for (const u of urls) {
          const raw = String(u || '').trim();
          const normalized = (function (s) {
            try {
              // strip query/hash and trailing slash for resilient matching
              let base = s.split('#')[0];
              base = base.split('?')[0];
              return base.replace(/\/$/, '');
            } catch {
              return s;
            }
          })(raw);

          let urlRemoved = 0;
          try {
            logger && logger.debug
              ? logger.debug('documents-delete:url-normalize', { raw, normalized })
              : console.log('[documents-delete:url-normalize]', { raw, normalized });
          } catch {}

          // Try exact matches first (canonical url and local server url)
          try {
            const maybeBU = one('SELECT COUNT(*) as c FROM documents WHERE batchId=? AND url=?', [
              batchId,
              raw,
            ]);
            const beforeUrl =
              maybeBU && typeof maybeBU.then === 'function'
                ? (await maybeBU)?.c || 0
                : maybeBU?.c || 0;
            await db.run('DELETE FROM documents WHERE batchId=? AND url=?', [batchId, raw]);
            const maybeAU = one('SELECT COUNT(*) as c FROM documents WHERE batchId=? AND url=?', [
              batchId,
              raw,
            ]);
            const afterUrl =
              maybeAU && typeof maybeAU.then === 'function'
                ? (await maybeAU)?.c || 0
                : maybeAU?.c || 0;
            const deltaUrl = Math.max(0, Number(beforeUrl) - Number(afterUrl));
            urlRemoved += deltaUrl;
          } catch {}
          try {
            const maybeBL = one(
              'SELECT COUNT(*) as c FROM documents WHERE batchId=? AND localUrl=?',
              [batchId, raw]
            );
            const beforeLocal =
              maybeBL && typeof maybeBL.then === 'function'
                ? (await maybeBL)?.c || 0
                : maybeBL?.c || 0;
            await db.run('DELETE FROM documents WHERE batchId=? AND localUrl=?', [batchId, raw]);
            const maybeAL = one(
              'SELECT COUNT(*) as c FROM documents WHERE batchId=? AND localUrl=?',
              [batchId, raw]
            );
            const afterLocal =
              maybeAL && typeof maybeAL.then === 'function'
                ? (await maybeAL)?.c || 0
                : maybeAL?.c || 0;
            const deltaLocal = Math.max(0, Number(beforeLocal) - Number(afterLocal));
            urlRemoved += deltaLocal;
          } catch {}

          // Then try normalized variants (helps when clients passed ?download=1, hashes, or trailing slash)
          if (normalized && normalized !== raw) {
            try {
              const maybeBUN = one(
                'SELECT COUNT(*) as c FROM documents WHERE batchId=? AND url=?',
                [batchId, normalized]
              );
              const beforeUrlN =
                maybeBUN && typeof maybeBUN.then === 'function'
                  ? (await maybeBUN)?.c || 0
                  : maybeBUN?.c || 0;
              await db.run('DELETE FROM documents WHERE batchId=? AND url=?', [
                batchId,
                normalized,
              ]);
              const maybeAUN = one(
                'SELECT COUNT(*) as c FROM documents WHERE batchId=? AND url=?',
                [batchId, normalized]
              );
              const afterUrlN =
                maybeAUN && typeof maybeAUN.then === 'function'
                  ? (await maybeAUN)?.c || 0
                  : maybeAUN?.c || 0;
              const deltaUrlN = Math.max(0, Number(beforeUrlN) - Number(afterUrlN));
              urlRemoved += deltaUrlN;
            } catch {}
            try {
              const maybeBLN = one(
                'SELECT COUNT(*) as c FROM documents WHERE batchId=? AND localUrl=?',
                [batchId, normalized]
              );
              const beforeLocalN =
                maybeBLN && typeof maybeBLN.then === 'function'
                  ? (await maybeBLN)?.c || 0
                  : maybeBLN?.c || 0;
              await db.run('DELETE FROM documents WHERE batchId=? AND localUrl=?', [
                batchId,
                normalized,
              ]);
              const maybeALN = one(
                'SELECT COUNT(*) as c FROM documents WHERE batchId=? AND localUrl=?',
                [batchId, normalized]
              );
              const afterLocalN =
                maybeALN && typeof maybeALN.then === 'function'
                  ? (await maybeALN)?.c || 0
                  : maybeALN?.c || 0;
              const deltaLocalN = Math.max(0, Number(beforeLocalN) - Number(afterLocalN));
              urlRemoved += deltaLocalN;
            } catch {}
          }

          removed += urlRemoved;
          try {
            logger && logger.debug
              ? logger.debug('documents-delete:by-url', { raw, normalized, delta: urlRemoved })
              : console.log('[documents-delete:by-url]', { raw, normalized, delta: urlRemoved });
          } catch {}
        }
        await db.run('COMMIT');
        try {
          persist(db);
        } catch {}
      } catch (e) {
        try {
          await db.run('ROLLBACK');
        } catch {}
        try {
          logger && logger.error
            ? logger.error('documents-delete:tx-error', { error: String(e?.message || e) })
            : console.error('[documents-delete:tx-error]', e);
        } catch {}
        return res.status(500).json({ error: 'delete_failed', details: e?.message || String(e) });
      }
      try {
        logger && logger.info
          ? logger.info('documents-delete:done', {
              batchId,
              idsCount: ids.length,
              urlsCount: urls.length,
              removed,
            })
          : console.log('[documents-delete:done]', {
              batchId,
              idsCount: ids.length,
              urlsCount: urls.length,
              removed,
            });
      } catch {}
      return res.json({ ok: true, removed });
    } catch (e) {
      try {
        const logger = req && req.logger ? req.logger : null;
        logger && logger.error
          ? logger.error('documents-delete:failed', { error: String(e?.message || e) })
          : console.error('[documents-delete:failed]', e);
      } catch {}
      return res.status(500).json({ error: 'delete_failed', details: e?.message || String(e) });
    }
  });

  // Admin: bulk add recipients
  app.post('/api/batches/:id/recipients', async (req, res) => {
    const { logger } = req;

    try {
      logger.info('recipients-create', 'Starting bulk recipient addition process');

      const id =
        db && (db.driver === 'firebase' || db.driver === 'rtdb')
          ? String(req.params.id)
          : Number(req.params.id);
      if (db && (db.driver === 'firebase' || db.driver === 'rtdb')) {
        if (!id || typeof id !== 'string') {
          logger.error('recipients-create', 'Invalid batch ID provided (firebase)', {
            providedId: req.params.id,
          });
          return res
            .status(400)
            .json({ error: 'invalid_batch_id', message: 'Batch ID must be a non-empty string' });
        }
      } else {
        if (!Number.isInteger(id) || id <= 0) {
          logger.error('recipients-create', 'Invalid batch ID provided', {
            providedId: req.params.id,
            parsedId: id,
          });
          return res
            .status(400)
            .json({ error: 'invalid_batch_id', message: 'Batch ID must be a positive integer' });
        }
      }

      // Check if batch exists
      const maybeBatch = one('SELECT id, name FROM batches WHERE id = ?', [id]);
      const batchExists =
        maybeBatch && typeof maybeBatch.then === 'function' ? await maybeBatch : maybeBatch;
      if (!batchExists) {
        logger.error('recipients-create', 'Batch not found', { batchId: id });
        return res
          .status(404)
          .json({ error: 'batch_not_found', message: 'Specified batch does not exist' });
      }

      logger.info('recipients-create', 'Batch verified for recipient insertion', {
        batchId: id,
        batchName: batchExists.name,
      });

      const list = Array.isArray(req.body?.recipients) ? req.body.recipients : [];
      logger.info('recipients-create', 'Processing recipient list', {
        batchId: id,
        totalRecipients: list.length,
      });

      if (list.length === 0) {
        logger.warn('recipients-create', 'No recipients provided in request');
        return res.json({ inserted: 0, message: 'No recipients provided' });
      }

      let count = 0;
      let skipped = 0;
      const errors = [];
      const processedEmails = new Set();

      logger.debug('recipients-create', 'Starting database transaction');
      db.run('BEGIN');

      try {
        for (let i = 0; i < list.length; i++) {
          const r = list[i];
          const {
            businessId = null,
            user = null,
            email = null,
            displayName = null,
            department = null,
            jobTitle = null,
            location = null,
            primaryGroup = null,
          } = r || {};

          const emailRaw = email || user || '';
          const emailLower = String(emailRaw).trim().toLowerCase();

          // Validate email
          if (!emailLower) {
            logger.warn('recipients-create', `Recipient ${i + 1} missing email`, {
              index: i,
              providedEmail: emailRaw,
              providedUser: user,
            });
            skipped++;
            errors.push(`Recipient ${i + 1}: Missing email address`);
            continue;
          }

          // Basic email format validation
          if (!emailLower.includes('@') || emailLower.length < 5) {
            logger.warn('recipients-create', `Recipient ${i + 1} has invalid email format`, {
              index: i,
              email: emailLower,
            });
            skipped++;
            errors.push(`Recipient ${i + 1}: Invalid email format`);
            continue;
          }

          // Check for duplicates in current batch
          if (processedEmails.has(emailLower)) {
            logger.warn('recipients-create', `Recipient ${i + 1} is duplicate in current request`, {
              index: i,
              email: emailLower,
            });
            skipped++;
            errors.push(`Recipient ${i + 1}: Duplicate email in request`);
            continue;
          }

          processedEmails.add(emailLower);

          logger.debug('recipients-create', `Processing recipient ${i + 1}`, {
            email: emailLower,
            displayName: displayName || 'none',
            businessId: businessId || 'none',
            department: department || 'none',
          });

          try {
            if (db && (db.driver === 'firebase' || db.driver === 'rtdb')) {
              await db.run(
                `INSERT OR IGNORE INTO recipients (batchId, businessId, user, email, displayName, department, jobTitle, location, primaryGroup)
                            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
                [
                  id,
                  businessId,
                  emailLower,
                  emailLower,
                  displayName,
                  department,
                  jobTitle,
                  location,
                  primaryGroup,
                ]
              );
            } else {
              db.run(
                `INSERT OR IGNORE INTO recipients (batchId, businessId, user, email, displayName, department, jobTitle, location, primaryGroup)
                      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
                [
                  id,
                  businessId,
                  emailLower,
                  emailLower,
                  displayName,
                  department,
                  jobTitle,
                  location,
                  primaryGroup,
                ]
              );
            }
            count++;
          } catch (recipientError) {
            logger.error('recipients-create', `Failed to insert recipient ${i + 1}`, {
              index: i,
              email: emailLower,
              error: recipientError.message,
            });
            errors.push(`Recipient ${i + 1}: ${recipientError.message}`);
            skipped++;
          }
        }

        logger.debug('recipients-create', 'Committing database transaction');
        db.run('COMMIT');
        persist(db);

        logger.info('recipients-create', 'Recipient addition completed', {
          batchId: id,
          inserted: count,
          skipped: skipped,
          totalProcessed: list.length,
          uniqueEmails: processedEmails.size,
        });

        const result = { inserted: count };
        if (skipped > 0) {
          result.skipped = skipped;
          result.errors = errors;
        }

        res.json(result);
      } catch (transactionError) {
        logger.error('recipients-create', 'Transaction failed, rolling back', {
          error: transactionError.message,
          batchId: id,
          processedCount: count,
        });
        db.run('ROLLBACK');
        throw transactionError;
      }
    } catch (e) {
      logger.error('recipients-create', 'Unexpected error during recipient creation', {
        error: e.message,
        stack: e.stack,
        batchId: req.params.id,
      });

      try {
        db.run('ROLLBACK');
      } catch (rollbackError) {
        logger.error('recipients-create', 'Failed to rollback transaction', {
          error: rollbackError.message,
        });
      }

      res
        .status(500)
        .json({ error: 'insert_failed', message: 'Failed to add recipients to batch' });
    }
  });

  // Admin: delete batch (cascade delete related data)
  app.delete('/api/batches/:id', async (req, res) => {
    const isFirebase = db && (db.driver === 'firebase' || db.driver === 'rtdb');
    const id = isFirebase ? String(req.params.id) : Number(req.params.id);
    try {
      await db.run('BEGIN');
      await db.run('DELETE FROM acks WHERE batchId=?', [id]);
      await db.run('DELETE FROM documents WHERE batchId=?', [id]);
      await db.run('DELETE FROM recipients WHERE batchId=?', [id]);
      await db.run('DELETE FROM batches WHERE id=?', [id]);
      await db.run('COMMIT');
      try {
        persist(db);
      } catch {}
      res.json({ ok: true });
    } catch (e) {
      try {
        await db.run('ROLLBACK');
      } catch {}
      console.error('Delete batch failed', e);
      res.status(500).json({ error: 'delete_failed' });
    }
  });

  // Roles management API
  // List roles
  app.get('/api/roles', async (_req, res) => {
    try {
      const maybe = all('SELECT id, email, role, createdAt FROM roles ORDER BY role, LOWER(email)');
      const rows = maybe && typeof maybe.then === 'function' ? await maybe : maybe || [];
      res.json(
        (Array.isArray(rows) ? rows : []).map((r) => ({
          id: r.id,
          email: String(r.email).toLowerCase(),
          role: String(r.role),
          createdAt: r.createdAt,
        }))
      );
    } catch (e) {
      console.error('List roles failed', e);
      res.status(500).json({ error: 'list_failed' });
    }
  });
  // Create role
  app.post('/api/roles', async (req, res) => {
    try {
      const { email, role } = req.body || {};
      const e = String(email || '')
        .trim()
        .toLowerCase();
      const r = String(role || '').trim();
      if (!e || !e.includes('@')) return res.status(400).json({ error: 'invalid_email' });
      // Allow only Admin or Manager via API to avoid accidental grant of SuperAdmin; env remains authoritative for SuperAdmin
      if (!['Admin', 'Manager'].includes(r)) return res.status(400).json({ error: 'invalid_role' });
      const now = new Date().toISOString();
      if (db && (db.driver === 'firebase' || db.driver === 'rtdb')) {
        await db.run('INSERT OR IGNORE INTO roles (email, role, createdAt) VALUES (?, ?, ?)', [
          e,
          r,
          now,
        ]);
      } else {
        const ok = exec('INSERT OR IGNORE INTO roles (email, role, createdAt) VALUES (?, ?, ?)', [
          e,
          r,
          now,
        ]);
        if (!ok) return res.status(400).json({ error: 'insert_failed' });
      }
      const maybeId = one('SELECT last_insert_rowid() as id');
      const idRow = maybeId && typeof maybeId.then === 'function' ? await maybeId : maybeId;
      const id = idRow?.id;
      res.json({ id, email: e, role: r, createdAt: now });
    } catch (e) {
      console.error('Create role failed', e);
      res.status(500).json({ error: 'insert_failed' });
    }
  });
  // Delete role
  app.delete('/api/roles/:id', async (req, res) => {
    try {
      const isFirebase = db && (db.driver === 'firebase' || db.driver === 'rtdb');
      const id = isFirebase ? String(req.params.id) : Number(req.params.id);
      if ((!isFirebase && (!Number.isInteger(id) || id <= 0)) || (isFirebase && !id))
        return res.status(400).json({ error: 'invalid_id' });
      if (isFirebase) {
        await db.run('DELETE FROM roles WHERE id=?', [id]);
      } else {
        const ok = exec('DELETE FROM roles WHERE id=?', [id]);
        if (!ok) return res.status(400).json({ error: 'delete_failed' });
      }
      res.json({ ok: true });
    } catch (e) {
      console.error('Delete role failed', e);
      res.status(500).json({ error: 'delete_failed' });
    }
  });

  // Acknowledge a document
  app.post('/api/ack', async (req, res) => {
    const isFirebase = db && (db.driver === 'firebase' || db.driver === 'rtdb');
    const { batchId, documentId, email } = req.body || {};
    if (!batchId || !documentId || !email) return res.status(400).json({ error: 'missing_fields' });
    const e = String(email).toLowerCase();
    try {
      if (isFirebase) {
        await db.run('DELETE FROM acks WHERE batchId=? AND documentId=? AND LOWER(email)=?', [
          String(batchId),
          String(documentId),
          e,
        ]);
        const now = new Date().toISOString();
        await db.run(
          'INSERT INTO acks (batchId, documentId, email, acknowledged, ackDate) VALUES (?, ?, ?, 1, ?)',
          [String(batchId), String(documentId), e, now]
        );
        try {
          persist(db);
        } catch {}
        // Notify per-business admins (fire-and-forget, non-blocking)
        (async () => {
          try {
            const resolveMaybe = async (v) => (v && typeof v.then === 'function' ? await v : v);
            const bIdRaw = await resolveMaybe(
              one('SELECT businessId FROM recipients WHERE batchId=? AND LOWER(email)=LOWER(?)', [
                String(batchId),
                e,
              ])
            );
            let bizId = bIdRaw ? bIdRaw.businessId : null;
            if (!bizId) {
              const ubRow = await resolveMaybe(
                one(
                  'SELECT businessId FROM user_businesses WHERE LOWER(email)=LOWER(?) ORDER BY assignedAt DESC LIMIT 1',
                  [e]
                )
              );
              bizId = ubRow ? ubRow.businessId : null;
            }
            if (bizId != null) {
              const adminsRows = await resolveMaybe(
                all('SELECT email FROM business_admins WHERE businessId=? ORDER BY email ASC', [bizId])
              );
              const admins = Array.isArray(adminsRows) ? adminsRows.map((r) => String(r.email)) : [];
              if (admins.length > 0) {
                const mailer = (function () { try { return require('./src/services/mailer'); } catch { return null; } })();
                let bizName = null;
                try {
                  const bRow = await resolveMaybe(one('SELECT name FROM businesses WHERE id=?', [bizId]));
                  bizName = bRow && bRow.name ? String(bRow.name) : null;
                } catch {}
                const subject = `Acknowledgement: ${bizName ? bizName + ' ' : ''}Batch #${batchId}`;
                const html = '<div style="font-family:Segoe UI,Tahoma,Arial,sans-serif"><p>User <b>' + e + '</b> acknowledged document <b>#' + documentId + '</b> in batch <b>#' + batchId + '</b> on ' + now + '.</p>' + (bizName ? '<p>Business: <b>' + bizName + '</b></p>' : '') + '</div>';
                const text = 'User ' + e + ' acknowledged document #' + documentId + ' in batch #' + batchId + ' on ' + now + '.' + (bizName ? ' Business: ' + bizName + '.' : '');
                for (const to of admins) {
                  try {
                    if (mailer && typeof mailer.sendHtml === 'function') await mailer.sendHtml(to, subject, html, text);
                    else console.log(`[BUSINESS:EMAIL:FALLBACK] To: ${to} :: ${text}`);
                  } catch {}
                }
              }
            }
          } catch {}
        })();
        return res.json({ ok: true });
      } else {
        // Idempotent: delete existing then insert
        db.run('DELETE FROM acks WHERE batchId=? AND documentId=? AND LOWER(email)=?', [
          Number(batchId),
          Number(documentId),
          e,
        ]);
        const now = new Date().toISOString();
        const ok = exec(
          'INSERT INTO acks (batchId, documentId, email, acknowledged, ackDate) VALUES (?, ?, ?, 1, ?)',
          [Number(batchId), Number(documentId), e, now]
        );
        if (!ok) return res.status(400).json({ error: 'insert_failed' });
        // Notify per-business admins (fire-and-forget, non-blocking)
        (async () => {
          try {
            const bIdRow = one('SELECT businessId FROM recipients WHERE batchId=? AND LOWER(email)=LOWER(?)', [
              Number(batchId),
              e,
            ]);
            const bIdRes = bIdRow && typeof bIdRow.then === 'function' ? await bIdRow : bIdRow;
            let bizId = bIdRes ? bIdRes.businessId : null;
            if (!bizId) {
              const ubRowMaybe = one(
                'SELECT businessId FROM user_businesses WHERE LOWER(email)=LOWER(?) ORDER BY assignedAt DESC LIMIT 1',
                [e]
              );
              const ubRow = ubRowMaybe && typeof ubRowMaybe.then === 'function' ? await ubRowMaybe : ubRowMaybe;
              bizId = ubRow ? ubRow.businessId : null;
            }
            if (bizId != null) {
              const adminsRowsMaybe = all('SELECT email FROM business_admins WHERE businessId=? ORDER BY email ASC', [bizId]);
              const adminsRows = adminsRowsMaybe && typeof adminsRowsMaybe.then === 'function' ? await adminsRowsMaybe : adminsRowsMaybe || [];
              const admins = Array.isArray(adminsRows) ? adminsRows.map((r) => String(r.email)) : [];
              if (admins.length > 0) {
                const mailer = (function () { try { return require('./src/services/mailer'); } catch { return null; } })();
                let bizName = null;
                try {
                  const bRowMaybe = one('SELECT name FROM businesses WHERE id=?', [bizId]);
                  const bRow = bRowMaybe && typeof bRowMaybe.then === 'function' ? await bRowMaybe : bRowMaybe;
                  bizName = bRow && bRow.name ? String(bRow.name) : null;
                } catch {}
                const subject = `Acknowledgement: ${bizName ? bizName + ' ' : ''}Batch #${batchId}`;
                const html = '<div style="font-family:Segoe UI,Tahoma,Arial,sans-serif"><p>User <b>' + e + '</b> acknowledged document <b>#' + documentId + '</b> in batch <b>#' + batchId + '</b> on ' + now + '.</p>' + (bizName ? '<p>Business: <b>' + bizName + '</b></p>' : '') + '</div>';
                const text = 'User ' + e + ' acknowledged document #' + documentId + ' in batch #' + batchId + ' on ' + now + '.' + (bizName ? ' Business: ' + bizName + '.' : '');
                for (const to of admins) {
                  try {
                    if (mailer && typeof mailer.sendHtml === 'function') await mailer.sendHtml(to, subject, html, text);
                    else console.log(`[BUSINESS:EMAIL:FALLBACK] To: ${to} :: ${text}`);
                  } catch {}
                }
              }
            }
          } catch {}
        })();
        return res.json({ ok: true });
      }
    } catch (err) {
      return res.status(500).json({ error: 'insert_failed', details: err?.message || String(err) });
    }
  });

  // Seed sample data for a specific user email
  app.post('/api/seed', (req, res) => {
    const email = (req.query.email || req.body?.email || '').toString().trim().toLowerCase();
    if (!email) return res.status(400).json({ error: 'email_required' });
    try {
      db.run('BEGIN');
      // Create a batch
      const name = 'Demo Batch';
      const startDate = new Date().toISOString().substring(0, 10);
      const dueDate = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString().substring(0, 10);
      db.run(
        'INSERT INTO batches (name, startDate, dueDate, status, description) VALUES (?, ?, ?, 1, ?)',
        [name, startDate, dueDate, 'Seeded demo batch']
      );
      const batchId = one('SELECT last_insert_rowid() as id')?.id;
      // Add two docs
      db.run(
        'INSERT INTO documents (batchId, title, url, version, requiresSignature) VALUES (?, ?, ?, ?, ?)',
        [
          batchId,
          'Code of Conduct',
          'https://www.w3.org/WAI/ER/tests/xhtml/testfiles/resources/pdf/dummy.pdf',
          1,
          0,
        ]
      );
      db.run(
        'INSERT INTO documents (batchId, title, url, version, requiresSignature) VALUES (?, ?, ?, ?, ?)',
        [batchId, 'IT Security Policy', 'https://www.africau.edu/images/default/sample.pdf', 1, 0]
      );
      // Add recipient (user)
      db.run(
        `INSERT INTO recipients (batchId, businessId, user, email, displayName, department, jobTitle, location, primaryGroup)
              VALUES (?, NULL, ?, ?, ?, NULL, NULL, NULL, NULL)`,
        [batchId, email, email, 'Demo User']
      );
      db.run('COMMIT');
      persist(db);
      res.json({ ok: true, batchId });
    } catch (e) {
      try {
        db.run('ROLLBACK');
      } catch {}
      console.error('Seed failed', e);
      res.status(500).json({ error: 'seed_failed' });
    }
  });

  // Return the configured Express app; the caller decides how to serve it.
  return app;
}

// Lazy, singleton initializer for the Express app (works in serverless and traditional modes)
let __appPromise = null;
async function getApp() {
  if (!__appPromise) {
    __appPromise = start();
  }
  return __appPromise;
}

// Export async getter for serverless handlers to await
module.exports = getApp;

// If running this file directly (not in serverless), start the HTTP server
if (!IS_SERVERLESS && require.main === module) {
  (async () => {
    try {
      const app = await getApp();
      app.listen(PORT, () => {
        console.log(`API listening on http://localhost:${PORT}`);
      });
    } catch (err) {
      console.error('Failed to start server:', err);
      process.exit(1);
    }
  })();
}

function mapBatch(r) {
  return {
    toba_batchid: String(r.id),
    toba_name: r.name,
    toba_startdate: r.startDate || null,
    toba_duedate: r.dueDate || null,
    toba_status: r.status != null ? String(r.status) : null,
  };
}
function mapDoc(r) {
  return {
    toba_documentid: String(r.id),
    toba_title: r.title,
    toba_version: r.version != null ? String(r.version) : '1',
    toba_requiressignature: !!r.requiresSignature,
    // Prefer local server URL when available to ensure resilient viewing/downloading
    toba_fileurl: r.localUrl || r.url,
    // Also expose the original canonical URL (e.g., SharePoint) when a local backup exists
    toba_originalurl: r.url || null,
    toba_driveid: r.driveId || null,
    toba_itemid: r.itemId || null,
    toba_source: r.source || null,
    // expose local linkage for debugging/advanced UI (non-breaking to consumers)
    toba_localfileid: r.localFileId != null ? String(r.localFileId) : null,
    toba_localurl: r.localUrl || null,
  };
}

function bootstrapSchema(db) {
  db.run(`CREATE TABLE IF NOT EXISTS external_users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT NOT NULL UNIQUE,
    name TEXT,
    phone TEXT,
    password_hash TEXT NOT NULL,
    mfa_enabled INTEGER DEFAULT 0,
    mfa_secret TEXT,
    status TEXT DEFAULT 'active',
    created_at TEXT DEFAULT (datetime('now')),
    last_login TEXT
  );`);
  // Non-breaking column adds (safe to ignore errors if columns already exist)
  try { db.run(`ALTER TABLE external_users ADD COLUMN department TEXT`); } catch {}
  try { db.run(`ALTER TABLE external_users ADD COLUMN business_id INTEGER`); } catch {}
  db.run(
    `CREATE UNIQUE INDEX IF NOT EXISTS ux_external_users_email ON external_users(LOWER(email));`
  );
  db.run(`CREATE TABLE IF NOT EXISTS notification_emails (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT NOT NULL UNIQUE
  );`);
  try {
    db.run('PRAGMA foreign_keys = ON');
  } catch {}
  db.run(`CREATE TABLE IF NOT EXISTS businesses (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    code TEXT,
    isActive INTEGER DEFAULT 1,
    description TEXT
  );`);
  // Admin notification recipients per business
  db.run(`CREATE TABLE IF NOT EXISTS business_admins (
    businessId INTEGER NOT NULL,
    email TEXT NOT NULL,
    PRIMARY KEY (businessId, email),
    FOREIGN KEY (businessId) REFERENCES businesses(id) ON DELETE CASCADE
  );`);
  try { db.run('CREATE INDEX IF NOT EXISTS idx_business_admins_business ON business_admins(businessId)'); } catch {}
  try { db.run('CREATE INDEX IF NOT EXISTS idx_business_admins_email ON business_admins(LOWER(email))'); } catch {}
  db.run(`CREATE TABLE IF NOT EXISTS batches (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    startDate TEXT,
    dueDate TEXT,
    status INTEGER DEFAULT 1,
    description TEXT
  );`);
  db.run(`CREATE TABLE IF NOT EXISTS documents (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    batchId INTEGER NOT NULL,
    title TEXT NOT NULL,
    url TEXT NOT NULL,
    version INTEGER DEFAULT 1,
    requiresSignature INTEGER DEFAULT 0,
    driveId TEXT,
    itemId TEXT,
    source TEXT,
    localFileId INTEGER,
    localUrl TEXT,
    FOREIGN KEY (batchId) REFERENCES batches(id) ON DELETE CASCADE
  );`);
  db.run(`CREATE TABLE IF NOT EXISTS recipients (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    batchId INTEGER NOT NULL,
    businessId INTEGER,
    user TEXT,
    email TEXT,
    displayName TEXT,
    department TEXT,
    jobTitle TEXT,
    location TEXT,
    primaryGroup TEXT,
    FOREIGN KEY (batchId) REFERENCES batches(id) ON DELETE CASCADE,
    FOREIGN KEY (businessId) REFERENCES businesses(id) ON DELETE SET NULL
  );`);
  db.run(`CREATE TABLE IF NOT EXISTS acks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    batchId INTEGER NOT NULL,
    documentId INTEGER NOT NULL,
    email TEXT NOT NULL,
    acknowledged INTEGER DEFAULT 1,
    ackDate TEXT,
    FOREIGN KEY (batchId) REFERENCES batches(id) ON DELETE CASCADE,
    FOREIGN KEY (documentId) REFERENCES documents(id) ON DELETE CASCADE
  );`);
  db.run(`CREATE TABLE IF NOT EXISTS reminder_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    batchId INTEGER NOT NULL,
    email TEXT NOT NULL,
    sentAt TEXT NOT NULL,
    FOREIGN KEY (batchId) REFERENCES batches(id) ON DELETE CASCADE
  );`);
  db.run(
    `CREATE INDEX IF NOT EXISTS idx_reminder_logs_batch_email ON reminder_logs(batchId, LOWER(email));`
  );
  // Certificates issued (verification support)
  db.run(`CREATE TABLE IF NOT EXISTS certificates (
    id TEXT PRIMARY KEY,
    email TEXT NOT NULL,
    user_name TEXT,
    batch_id INTEGER,
    completed_on TEXT,
    issued_at TEXT DEFAULT (datetime('now')),
    doc_titles TEXT, -- JSON array of strings
    department TEXT,
    jobTitle TEXT,
    location TEXT,
    businessName TEXT,
    primaryGroup TEXT,
    status TEXT DEFAULT 'issued'
  );`);
  db.run(`CREATE INDEX IF NOT EXISTS idx_certificates_email ON certificates(LOWER(email));`);
  db.run(`CREATE INDEX IF NOT EXISTS idx_certificates_batch ON certificates(batch_id);`);
  // App settings key/value store
  db.run(`CREATE TABLE IF NOT EXISTS app_settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
  );`);

  // Audit log table for auth/security events
  db.run(`CREATE TABLE IF NOT EXISTS audit_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT,
    event TEXT,
    email TEXT,
    ip TEXT,
    ua TEXT,
    result TEXT,
    details TEXT
  );`);

  // Indexes and uniqueness constraints
  db.run(`CREATE INDEX IF NOT EXISTS idx_documents_batch ON documents(batchId);`);
  db.run(`CREATE INDEX IF NOT EXISTS idx_recipients_batch ON recipients(batchId);`);
  db.run(`CREATE INDEX IF NOT EXISTS idx_acks_batch ON acks(batchId);`);
  db.run(`CREATE INDEX IF NOT EXISTS idx_acks_doc ON acks(documentId);`);
  db.run(
    `CREATE UNIQUE INDEX IF NOT EXISTS ux_recipients_batch_email ON recipients(batchId, LOWER(email));`
  );
  db.run(`CREATE UNIQUE INDEX IF NOT EXISTS ux_documents_batch_url ON documents(batchId, url);`);

  // Local uploaded files for on-server PDF backup
  db.run(`CREATE TABLE IF NOT EXISTS uploaded_files (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    original_name TEXT,
    stored_name TEXT,
    rel_path TEXT NOT NULL,
    size INTEGER,
    mime TEXT,
    sha256 TEXT,
    uploaded_at TEXT,
    uploaded_by TEXT,
    source_type TEXT,
    source_url TEXT,
    driveId TEXT,
    itemId TEXT
  );`);

  // Roles table for RBAC overrides (DB-managed roles)
  db.run(`CREATE TABLE IF NOT EXISTS roles (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT NOT NULL,
    role TEXT NOT NULL,
    createdAt TEXT
  );`);
  db.run(`CREATE UNIQUE INDEX IF NOT EXISTS ux_roles_email_role ON roles(LOWER(email), role);`);

  // Role-based and user-based permissions
  db.run(`CREATE TABLE IF NOT EXISTS role_permissions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    role TEXT NOT NULL,
    permKey TEXT NOT NULL,
    value INTEGER NOT NULL DEFAULT 1
  );`);
  db.run(
    `CREATE UNIQUE INDEX IF NOT EXISTS ux_role_perm ON role_permissions(LOWER(role), permKey);`
  );
  db.run(`CREATE TABLE IF NOT EXISTS user_permissions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT NOT NULL,
    permKey TEXT NOT NULL,
    value INTEGER NOT NULL DEFAULT 1
  );`);
  db.run(
    `CREATE UNIQUE INDEX IF NOT EXISTS ux_user_perm ON user_permissions(LOWER(email), permKey);`
  );

  // Multi-tenant core tables (tenants, modules, licenses)
  db.run(`CREATE TABLE IF NOT EXISTS tenants (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    code TEXT NOT NULL UNIQUE,
    parent_id INTEGER,
    is_active INTEGER DEFAULT 1,
    is_owner INTEGER DEFAULT 0,
    created_at TEXT DEFAULT (datetime('now')),
    FOREIGN KEY (parent_id) REFERENCES tenants(id) ON DELETE SET NULL
  );`);
  db.run(`CREATE UNIQUE INDEX IF NOT EXISTS ux_tenants_code ON tenants(UPPER(code));`);
  db.run(`CREATE TABLE IF NOT EXISTS tenant_modules (
    tenant_id INTEGER NOT NULL,
    module_name TEXT NOT NULL,
    enabled INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (tenant_id, module_name),
    FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE
  );`);
  db.run(`CREATE TABLE IF NOT EXISTS licenses (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    tenant_id INTEGER NOT NULL,
    plan TEXT,
    seats INTEGER,
    status TEXT DEFAULT 'active',
    is_free INTEGER DEFAULT 0,
    valid_from TEXT,
    valid_to TEXT,
    created_at TEXT DEFAULT (datetime('now')),
    FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE
  );`);
  // Theme catalog and assignments
  db.run(`CREATE TABLE IF NOT EXISTS themes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    description TEXT,
    light_json TEXT,
    dark_json TEXT,
    base_theme_id INTEGER,
    is_system INTEGER DEFAULT 0,
    created_at TEXT DEFAULT (datetime('now')),
    updated_at TEXT,
    FOREIGN KEY (base_theme_id) REFERENCES themes(id) ON DELETE SET NULL
  );`);
  db.run(`CREATE UNIQUE INDEX IF NOT EXISTS ux_themes_name ON themes(LOWER(name));`);
  db.run(`CREATE TABLE IF NOT EXISTS theme_assignments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    theme_id INTEGER NOT NULL,
    target_type TEXT NOT NULL, -- 'global' | 'tenant' | 'module' | 'plugin'
    target_id TEXT,            -- null for global; tenant id as text; module name; plugin id
    enabled INTEGER NOT NULL DEFAULT 1,
    created_at TEXT DEFAULT (datetime('now')),
    FOREIGN KEY (theme_id) REFERENCES themes(id) ON DELETE CASCADE
  );`);
  db.run(
    `CREATE INDEX IF NOT EXISTS idx_theme_assignments_target ON theme_assignments(target_type, target_id);`
  );
  // Tenant custom domains
  db.run(`CREATE TABLE IF NOT EXISTS tenant_domains (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    tenant_id INTEGER NOT NULL,
    domain TEXT NOT NULL UNIQUE,
    is_primary INTEGER DEFAULT 0,
    verified INTEGER DEFAULT 0,
    added_at TEXT DEFAULT (datetime('now')),
    FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE
  );`);
  db.run(
    `CREATE UNIQUE INDEX IF NOT EXISTS ux_tenant_domains_domain ON tenant_domains(LOWER(domain));`
  );
  // Tenant settings (JSON blob for theme and other preferences)
  db.run(`CREATE TABLE IF NOT EXISTS tenant_settings (
    tenant_id INTEGER PRIMARY KEY,
    theme_json TEXT,
    FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE
  );`);
  // Caches for analytics to reduce RTDB scans
  db.run(`CREATE TABLE IF NOT EXISTS stats_cache (id INTEGER PRIMARY KEY CHECK (id=1), payload TEXT, updatedAt TEXT);`);
  db.run(`CREATE TABLE IF NOT EXISTS compliance_cache (id INTEGER PRIMARY KEY CHECK (id=1), payload TEXT, updatedAt TEXT);`);
  db.run(`CREATE TABLE IF NOT EXISTS doc_stats_cache (id INTEGER PRIMARY KEY CHECK (id=1), payload TEXT, updatedAt TEXT);`);
 // Daily trends cache for analytics (reduces RTDB scans)
 db.run(`CREATE TABLE IF NOT EXISTS trends_daily (
    date TEXT PRIMARY KEY,
    completions INTEGER,
    newBatches INTEGER,
    activeUsers INTEGER
  );`);
  // Customization requests (like WordPress site custom requests)
  db.run(`CREATE TABLE IF NOT EXISTS customization_requests (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    tenant_id INTEGER NOT NULL,
    contact_name TEXT,
    contact_email TEXT,
    contact_phone TEXT,
    description TEXT,
    scope TEXT,
    priority TEXT DEFAULT 'normal',
    status TEXT DEFAULT 'open',
    created_at TEXT DEFAULT (datetime('now')),
    FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE
  );`);

  // HR policy rules (recurring acknowledgements per document)
  db.run(`CREATE TABLE IF NOT EXISTS policy_rules (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    tenant_id INTEGER,
    name TEXT NOT NULL,
    description TEXT,
    frequency TEXT DEFAULT 'annual', -- daily|weekly|monthly|quarterly|semiannual|annual|custom
    interval_days INTEGER,
    required INTEGER DEFAULT 1,
    file_id INTEGER NOT NULL,
    sha256 TEXT,
    active INTEGER DEFAULT 1,
    start_on TEXT,
    due_in_days INTEGER DEFAULT 30,
    grace_days INTEGER DEFAULT 0,
    created_at TEXT DEFAULT (datetime('now')),
    updated_at TEXT,
    FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE SET NULL,
    FOREIGN KEY (file_id) REFERENCES uploaded_files(id) ON DELETE CASCADE
  );`);
  db.run(`CREATE INDEX IF NOT EXISTS idx_policy_rules_tenant ON policy_rules(tenant_id);`);
  db.run(`CREATE INDEX IF NOT EXISTS idx_policy_rules_active ON policy_rules(active);`);

  // Mapping table for group policies (multiple files per policy rule)
  db.run(`CREATE TABLE IF NOT EXISTS policy_rule_files (
    policy_rule_id INTEGER NOT NULL,
    file_id INTEGER NOT NULL,
    sha256 TEXT,
    PRIMARY KEY (policy_rule_id, file_id),
    FOREIGN KEY (policy_rule_id) REFERENCES policy_rules(id) ON DELETE CASCADE,
    FOREIGN KEY (file_id) REFERENCES uploaded_files(id) ON DELETE CASCADE
  );`);
  db.run(
    `CREATE INDEX IF NOT EXISTS idx_policy_rule_files_rule ON policy_rule_files(policy_rule_id);`
  );
  // Policy submissions (HR review workflow)
  db.run(`CREATE TABLE IF NOT EXISTS policy_submissions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    tenant_id INTEGER,
    title TEXT NOT NULL,
    description TEXT,
    source_type TEXT NOT NULL, -- 'upload' | 'sharepoint' | 'url'
    file_id INTEGER,           -- references uploaded_files when upload/local
    driveId TEXT,
    itemId TEXT,
    source_url TEXT,
    status TEXT NOT NULL DEFAULT 'submitted', -- submitted|approved|rejected
    owner_email TEXT,
    submitted_by TEXT,
    submitted_at TEXT DEFAULT (datetime('now')),
    reviewed_by TEXT,
    reviewed_at TEXT,
    review_comment TEXT,
    FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE SET NULL,
    FOREIGN KEY (file_id) REFERENCES uploaded_files(id) ON DELETE SET NULL
  );`);
  db.run(`CREATE INDEX IF NOT EXISTS idx_policy_submissions_status ON policy_submissions(status);`);

  // Batch subscriptions (notify on ack for batches)
  db.run(`CREATE TABLE IF NOT EXISTS batch_subscriptions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    batch_id INTEGER NOT NULL,
    target_type TEXT NOT NULL, -- 'email' | 'webhook'
    target TEXT NOT NULL,
    frequency TEXT DEFAULT 'instant', -- currently only 'instant' used
    enabled INTEGER DEFAULT 1,
    created_at TEXT DEFAULT (datetime('now')),
    FOREIGN KEY (batch_id) REFERENCES batches(id) ON DELETE CASCADE
  );`);
  db.run(`CREATE INDEX IF NOT EXISTS idx_batch_subs_batch ON batch_subscriptions(batch_id);`);

  // Policy owners and scoping
  db.run(`CREATE TABLE IF NOT EXISTS policy_owners (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    policy_rule_id INTEGER NOT NULL,
    owner_email TEXT NOT NULL,
    owner_name TEXT,
    role TEXT,
    created_at TEXT DEFAULT (datetime('now')),
    FOREIGN KEY (policy_rule_id) REFERENCES policy_rules(id) ON DELETE CASCADE
  );`);
  db.run(
    `CREATE UNIQUE INDEX IF NOT EXISTS ux_policy_owners_rule_email ON policy_owners(policy_rule_id, LOWER(owner_email));`
  );
  db.run(`CREATE TABLE IF NOT EXISTS policy_owner_scopes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    policy_owner_id INTEGER NOT NULL,
    scope_type TEXT NOT NULL,
    scope_value TEXT NOT NULL,
    FOREIGN KEY (policy_owner_id) REFERENCES policy_owners(id) ON DELETE CASCADE
  );`);
  db.run(
    `CREATE INDEX IF NOT EXISTS idx_policy_owner_scopes_owner ON policy_owner_scopes(policy_owner_id);`
  );

  // Notification subscriptions for policy events (digest or instant)
  db.run(`CREATE TABLE IF NOT EXISTS notification_subscriptions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    policy_rule_id INTEGER NOT NULL,
    target_type TEXT NOT NULL, -- 'email' | 'webhook'
    target TEXT NOT NULL,
    frequency TEXT DEFAULT 'instant', -- 'instant' | 'daily' | 'weekly'
    enabled INTEGER DEFAULT 1,
    created_at TEXT DEFAULT (datetime('now')),
    FOREIGN KEY (policy_rule_id) REFERENCES policy_rules(id) ON DELETE CASCADE
  );`);
  db.run(
    `CREATE INDEX IF NOT EXISTS idx_notify_subs_rule ON notification_subscriptions(policy_rule_id);`
  );

  // Legal document versioning (for consent auditing)
  db.run(`CREATE TABLE IF NOT EXISTS legal_doc_versions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    file_id INTEGER,
    sha256 TEXT,
    name TEXT,
    size INTEGER,
    mime TEXT,
    effective_from TEXT, -- ISO
    version INTEGER,
    created_at TEXT,
    created_by TEXT,
    FOREIGN KEY (file_id) REFERENCES uploaded_files(id) ON DELETE SET NULL
  );`);
  db.run(
    `CREATE UNIQUE INDEX IF NOT EXISTS ux_legal_doc_versions_sha_ver ON legal_doc_versions(sha256, version);`
  );

  // Consent receipts (per tenant + user + optional batch + legal version)
  db.run(`CREATE TABLE IF NOT EXISTS consents (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    tenant_id INTEGER,
    email TEXT NOT NULL,
    batch_id TEXT,
    consented_at TEXT,
    file_id INTEGER,
    file_sha256 TEXT,
    file_name TEXT,
    file_size INTEGER,
    file_mime TEXT,
    legal_version_id INTEGER,
    legal_version INTEGER,
    ip TEXT,
    ua TEXT,
    receipt_id TEXT UNIQUE,
    receipt_sig TEXT,
    meta_json TEXT,
    FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE SET NULL,
    FOREIGN KEY (file_id) REFERENCES uploaded_files(id) ON DELETE SET NULL,
    FOREIGN KEY (legal_version_id) REFERENCES legal_doc_versions(id) ON DELETE SET NULL
  );`);
  db.run(`CREATE INDEX IF NOT EXISTS idx_consents_email ON consents(LOWER(email));`);
  db.run(`CREATE INDEX IF NOT EXISTS idx_consents_tenant ON consents(tenant_id);`);
  db.run(`CREATE INDEX IF NOT EXISTS idx_consents_batch ON consents(batch_id);`);

  // Completion uploads registry (idempotency for SharePoint uploads)
  db.run(`CREATE TABLE IF NOT EXISTS completion_uploads (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    batchId INTEGER NOT NULL,
    email TEXT NOT NULL,
    fileName TEXT,
    driveId TEXT,
    itemId TEXT,
    webUrl TEXT,
    uploadedAt TEXT DEFAULT (datetime('now'))
  );`);
  db.run(`CREATE UNIQUE INDEX IF NOT EXISTS ux_completion_uploads_batch_email ON completion_uploads(batchId, LOWER(email));`);

  // Optional seed: default business (only when AUTO_SEED_DEFAULT_BUSINESS=1)
  try {
    if (String(process.env.AUTO_SEED_DEFAULT_BUSINESS || '').trim() === '1') {
      const c = (db.query && db.query('SELECT COUNT(*) as c FROM businesses')[0]?.c) || 0;
      if (Number(c) === 0) {
        db.run('INSERT INTO businesses (name, code, isActive, description) VALUES (?, ?, ?, ?)', [
          'Default Business',
          'DEF',
          1,
          'Auto-created',
        ]);
      }
    }
  } catch {}
  try {
    db.run(
      "INSERT OR IGNORE INTO app_settings (key, value) VALUES ('external_support_enabled','0')"
    );
  } catch {}
  // Seed an owner tenant if none
  try {
    const t = one('SELECT id FROM tenants WHERE is_owner=1 LIMIT 1');
    if (!t) {
      db.run(
        "INSERT INTO tenants (name, code, is_owner, is_active) VALUES ('Owner Tenant','OWNER',1,1)"
      );
    }
  } catch {}
}

// Best-effort migrations for existing databases (adds new columns if missing)
function migrateSchema(db) {
  try {
    db.run('ALTER TABLE documents ADD COLUMN driveId TEXT');
  } catch {}
  try {
    db.run('ALTER TABLE documents ADD COLUMN itemId TEXT');
  } catch {}
  try {
    db.run('ALTER TABLE documents ADD COLUMN source TEXT');
  } catch {}
  // Ensure audit_logs table exists for older databases
  try {
    db.run(`CREATE TABLE IF NOT EXISTS audit_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT,
    event TEXT,
    email TEXT,
    ip TEXT,
    ua TEXT,
    result TEXT,
    details TEXT
  );`);
  } catch {}
  // Ensure app_settings table and default flag
  try {
    db.run(`CREATE TABLE IF NOT EXISTS app_settings (key TEXT PRIMARY KEY, value TEXT NOT NULL);`);
  } catch {}
  try {
    db.run(
      "INSERT OR IGNORE INTO app_settings (key, value) VALUES ('external_support_enabled','0')"
    );
  } catch {}
  // roles table added in later versions
  try {
    db.run(`CREATE TABLE IF NOT EXISTS roles (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT NOT NULL,
    role TEXT NOT NULL,
    createdAt TEXT
  );`);
  } catch {}
  try {
    db.run(`CREATE UNIQUE INDEX IF NOT EXISTS ux_roles_email_role ON roles(LOWER(email), role);`);
  } catch {}
  // Permissions tables
  try {
    db.run(
      `CREATE TABLE IF NOT EXISTS role_permissions (id INTEGER PRIMARY KEY AUTOINCREMENT, role TEXT NOT NULL, permKey TEXT NOT NULL, value INTEGER NOT NULL DEFAULT 1);`
    );
  } catch {}
  try {
    db.run(
      `CREATE UNIQUE INDEX IF NOT EXISTS ux_role_perm ON role_permissions(LOWER(role), permKey);`
    );
  } catch {}
  try {
    db.run(
      `CREATE TABLE IF NOT EXISTS user_permissions (id INTEGER PRIMARY KEY AUTOINCREMENT, email TEXT NOT NULL, permKey TEXT NOT NULL, value INTEGER NOT NULL DEFAULT 1);`
    );
  } catch {}
  try {
    db.run(
      `CREATE UNIQUE INDEX IF NOT EXISTS ux_user_perm ON user_permissions(LOWER(email), permKey);`
    );
  } catch {}
  // Tenancy tables
  try {
    db.run(
      `CREATE TABLE IF NOT EXISTS tenants (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, code TEXT NOT NULL UNIQUE, parent_id INTEGER, is_active INTEGER DEFAULT 1, is_owner INTEGER DEFAULT 0, created_at TEXT DEFAULT (datetime('now')), FOREIGN KEY (parent_id) REFERENCES tenants(id) ON DELETE SET NULL);`
    );
  } catch {}
  try {
    db.run(`CREATE UNIQUE INDEX IF NOT EXISTS ux_tenants_code ON tenants(UPPER(code));`);
  } catch {}
  try {
    db.run(
      `CREATE TABLE IF NOT EXISTS tenant_modules (tenant_id INTEGER NOT NULL, module_name TEXT NOT NULL, enabled INTEGER NOT NULL DEFAULT 0, PRIMARY KEY (tenant_id, module_name), FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE);`
    );
  } catch {}
  try {
    db.run(
      `CREATE TABLE IF NOT EXISTS licenses (id INTEGER PRIMARY KEY AUTOINCREMENT, tenant_id INTEGER NOT NULL, plan TEXT, seats INTEGER, status TEXT DEFAULT 'active', is_free INTEGER DEFAULT 0, valid_from TEXT, valid_to TEXT, created_at TEXT DEFAULT (datetime('now')), FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE);`
    );
  } catch {}
  // Domains and settings
  try {
    db.run(
      `CREATE TABLE IF NOT EXISTS tenant_domains (id INTEGER PRIMARY KEY AUTOINCREMENT, tenant_id INTEGER NOT NULL, domain TEXT NOT NULL UNIQUE, is_primary INTEGER DEFAULT 0, verified INTEGER DEFAULT 0, added_at TEXT DEFAULT (datetime('now')), FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE);`
    );
  } catch {}
  try {
    db.run(
      `CREATE UNIQUE INDEX IF NOT EXISTS ux_tenant_domains_domain ON tenant_domains(LOWER(domain));`
    );
  } catch {}
  try {
    db.run(
      `CREATE TABLE IF NOT EXISTS tenant_settings (tenant_id INTEGER PRIMARY KEY, theme_json TEXT, FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE);`
    );
  } catch {}
  // Add generic settings JSON for tenant-scoped flags and options
  try {
    db.run(`ALTER TABLE tenant_settings ADD COLUMN settings_json TEXT`);
  } catch {}
  // Customization requests table
  try {
    db.run(
      `CREATE TABLE IF NOT EXISTS customization_requests (id INTEGER PRIMARY KEY AUTOINCREMENT, tenant_id INTEGER NOT NULL, contact_name TEXT, contact_email TEXT, contact_phone TEXT, description TEXT, scope TEXT, priority TEXT DEFAULT 'normal', status TEXT DEFAULT 'open', created_at TEXT DEFAULT (datetime('now')), FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE);`
    );
  } catch {}
  // Themes tables
  try {
    db.run(
      `CREATE TABLE IF NOT EXISTS themes (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, description TEXT, light_json TEXT, dark_json TEXT, base_theme_id INTEGER, is_system INTEGER DEFAULT 0, created_at TEXT DEFAULT (datetime('now')), updated_at TEXT, FOREIGN KEY (base_theme_id) REFERENCES themes(id) ON DELETE SET NULL);`
    );
  } catch {}
  try {
    db.run(`CREATE UNIQUE INDEX IF NOT EXISTS ux_themes_name ON themes(LOWER(name));`);
  } catch {}
  try {
    db.run(
      `CREATE TABLE IF NOT EXISTS theme_assignments (id INTEGER PRIMARY KEY AUTOINCREMENT, theme_id INTEGER NOT NULL, target_type TEXT NOT NULL, target_id TEXT, enabled INTEGER NOT NULL DEFAULT 1, created_at TEXT DEFAULT (datetime('now')), FOREIGN KEY (theme_id) REFERENCES themes(id) ON DELETE CASCADE);`
    );
  } catch {}
  try {
    db.run(
      `CREATE INDEX IF NOT EXISTS idx_theme_assignments_target ON theme_assignments(target_type, target_id);`
    );
  } catch {}
  // Local uploads table for older DBs
  try {
    db.run(
      `CREATE TABLE IF NOT EXISTS uploaded_files (id INTEGER PRIMARY KEY AUTOINCREMENT, original_name TEXT, stored_name TEXT, rel_path TEXT NOT NULL, size INTEGER, mime TEXT, sha256 TEXT, uploaded_at TEXT, uploaded_by TEXT);`
    );
  } catch {}
  try {
    db.run(`ALTER TABLE uploaded_files ADD COLUMN source_type TEXT`);
  } catch {}
  try {
    db.run(`ALTER TABLE uploaded_files ADD COLUMN source_url TEXT`);
  } catch {}
  try {
    db.run(`ALTER TABLE uploaded_files ADD COLUMN driveId TEXT`);
  } catch {}
  try {
    db.run(`ALTER TABLE uploaded_files ADD COLUMN itemId TEXT`);
  } catch {}
  try {
    db.run(`CREATE UNIQUE INDEX IF NOT EXISTS ux_uploaded_files_sha ON uploaded_files(sha256)`);
  } catch {}
  // Documents local file linkage
  try {
    db.run(`ALTER TABLE documents ADD COLUMN localFileId INTEGER`);
  } catch {}
  try {
    db.run(`ALTER TABLE documents ADD COLUMN localUrl TEXT`);
  } catch {}
  // Legal versioning tables (if upgrading)
  try {
    db.run(
      `CREATE TABLE IF NOT EXISTS legal_doc_versions (id INTEGER PRIMARY KEY AUTOINCREMENT, file_id INTEGER, sha256 TEXT, name TEXT, size INTEGER, mime TEXT, effective_from TEXT, version INTEGER, created_at TEXT, created_by TEXT, FOREIGN KEY (file_id) REFERENCES uploaded_files(id) ON DELETE SET NULL);`
    );
  } catch {}
  try {
    db.run(
      `CREATE UNIQUE INDEX IF NOT EXISTS ux_legal_doc_versions_sha_ver ON legal_doc_versions(sha256, version);`
    );
  } catch {}
  try {
    db.run(
      `CREATE TABLE IF NOT EXISTS consents (id INTEGER PRIMARY KEY AUTOINCREMENT, tenant_id INTEGER, email TEXT NOT NULL, batch_id TEXT, consented_at TEXT, file_id INTEGER, file_sha256 TEXT, file_name TEXT, file_size INTEGER, file_mime TEXT, legal_version_id INTEGER, legal_version INTEGER, ip TEXT, ua TEXT, receipt_id TEXT UNIQUE, receipt_sig TEXT, meta_json TEXT, FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE SET NULL, FOREIGN KEY (file_id) REFERENCES uploaded_files(id) ON DELETE SET NULL, FOREIGN KEY (legal_version_id) REFERENCES legal_doc_versions(id) ON DELETE SET NULL);`
    );
  } catch {}
  try {
    db.run(`CREATE INDEX IF NOT EXISTS idx_consents_email ON consents(LOWER(email));`);
  } catch {}
  try {
    db.run(`CREATE INDEX IF NOT EXISTS idx_consents_tenant ON consents(tenant_id);`);
  } catch {}
  try {
    db.run(`CREATE INDEX IF NOT EXISTS idx_consents_batch ON consents(batch_id);`);
  } catch {}
  // Policy rules table
  try {
    db.run(
      `CREATE TABLE IF NOT EXISTS policy_rules (id INTEGER PRIMARY KEY AUTOINCREMENT, tenant_id INTEGER, name TEXT NOT NULL, description TEXT, frequency TEXT DEFAULT 'annual', interval_days INTEGER, required INTEGER DEFAULT 1, file_id INTEGER NOT NULL, sha256 TEXT, active INTEGER DEFAULT 1, start_on TEXT, due_in_days INTEGER DEFAULT 30, grace_days INTEGER DEFAULT 0, created_at TEXT DEFAULT (datetime('now')), updated_at TEXT, FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE SET NULL, FOREIGN KEY (file_id) REFERENCES uploaded_files(id) ON DELETE CASCADE);`
    );
  } catch {}
  try {
    db.run(`CREATE INDEX IF NOT EXISTS idx_policy_rules_tenant ON policy_rules(tenant_id);`);
  } catch {}
  try {
    db.run(`CREATE INDEX IF NOT EXISTS idx_policy_rules_active ON policy_rules(active);`);
  } catch {}
  // Policy owners
  try {
    db.run(
      `CREATE TABLE IF NOT EXISTS policy_owners (id INTEGER PRIMARY KEY AUTOINCREMENT, policy_rule_id INTEGER NOT NULL, owner_email TEXT NOT NULL, owner_name TEXT, role TEXT, created_at TEXT DEFAULT (datetime('now')), FOREIGN KEY (policy_rule_id) REFERENCES policy_rules(id) ON DELETE CASCADE);`
    );
  } catch {}
  try {
    db.run(
      `CREATE UNIQUE INDEX IF NOT EXISTS ux_policy_owners_rule_email ON policy_owners(policy_rule_id, LOWER(owner_email));`
    );
  } catch {}
  try {
    db.run(
      `CREATE TABLE IF NOT EXISTS policy_owner_scopes (id INTEGER PRIMARY KEY AUTOINCREMENT, policy_owner_id INTEGER NOT NULL, scope_type TEXT NOT NULL, scope_value TEXT NOT NULL, FOREIGN KEY (policy_owner_id) REFERENCES policy_owners(id) ON DELETE CASCADE);`
    );
  } catch {}
  try {
    db.run(
      `CREATE INDEX IF NOT EXISTS idx_policy_owner_scopes_owner ON policy_owner_scopes(policy_owner_id);`
    );
  } catch {}
  // Notification subscriptions
  try {
    db.run(
      `CREATE TABLE IF NOT EXISTS notification_subscriptions (id INTEGER PRIMARY KEY AUTOINCREMENT, policy_rule_id INTEGER NOT NULL, target_type TEXT NOT NULL, target TEXT NOT NULL, frequency TEXT DEFAULT 'instant', enabled INTEGER DEFAULT 1, created_at TEXT DEFAULT (datetime('now')), FOREIGN KEY (policy_rule_id) REFERENCES policy_rules(id) ON DELETE CASCADE);`
    );
  } catch {}
  try {
    db.run(
      `CREATE INDEX IF NOT EXISTS idx_notify_subs_rule ON notification_subscriptions(policy_rule_id);`
    );
  } catch {}

  // Completion uploads registry (idempotency for SharePoint uploads)
  try {
    db.run(
      `CREATE TABLE IF NOT EXISTS completion_uploads (id INTEGER PRIMARY KEY AUTOINCREMENT, batchId INTEGER NOT NULL, email TEXT NOT NULL, fileName TEXT, driveId TEXT, itemId TEXT, webUrl TEXT, uploadedAt TEXT DEFAULT (datetime('now')));`
    );
  } catch {}
  try {
    db.run(
      `CREATE UNIQUE INDEX IF NOT EXISTS ux_completion_uploads_batch_email ON completion_uploads(batchId, LOWER(email));`
    );
  } catch {}
}

function persist(db) {
  try {
    if (db && typeof db.persist === 'function') {
      db.persist();
      return;
    }
  } catch {}
  try {
    if (db && typeof db.export === 'function') {
      const data = db.export();
      const buffer = Buffer.from(data);
      fs.writeFileSync(DB_PATH, buffer);
    }
  } catch {}
}

// Resolve user roles using DB roles and environment. Groups not evaluated server-side.
function resolveUserRoles(email, db) {
  const e = String(email || '')
    .trim()
    .toLowerCase();
  const roles = ['Employee'];
  try {
    const envList = (s) =>
      String(s || '')
        .split(',')
        .map((x) => String(x).trim().toLowerCase())
        .filter((x) => x && x.includes('@'));
    const superAdmins = envList(process.env.REACT_APP_SUPER_ADMINS);
    if (superAdmins.includes(e)) roles.push('SuperAdmin');
  } catch {}
  try {
    const fromDb = (function () {
      try {
        return all('SELECT role FROM roles WHERE LOWER(email)=LOWER(?)', [e]);
      } catch {
        return [];
      }
    })();
    for (const r of fromDb) {
      const role = String(r.role);
      if (!roles.includes(role)) roles.push(role);
    }
  } catch {}
  return roles;
}

// In serverless environments, initialize on import; avoid double-starting in local run
if (IS_SERVERLESS) {
  start().catch((err) => {
    console.error('Failed to start SQLite API', err);
    process.exit(1);
  });
}
