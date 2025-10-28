// Simple database adapter factory to make the API driver-agnostic.
// Implements:
// - 'sqlite' via sql.js (WASM)
// - 'libsql' (Turso) for durable serverless
// - 'pg' / 'supabase' via node-postgres (PostgreSQL)
//
// All adapters expose a uniform { run, query, persist? } interface and hide
// driver-specific differences (placeholders, last_insert_rowid, etc.).

const fs = require('fs');
const path = require('path');
const initSqlJs = require('sql.js');

/**
 * Create a DB adapter based on environment or passed driver.
 * @param {Object} opts
 * @param {string} opts.driver - e.g. 'sqlite' (default), 'postgres', 'mysql', 'mssql'.
 * @param {string} opts.dataDir - folder path for DB files (sqlite).
 * @param {string} opts.dbPath - full path to sqlite db file.
 * @param {(db:any)=>void} opts.bootstrapSchema - callback to create schema in a fresh DB.
 * @param {(db:any)=>void} opts.migrateSchema - callback to migrate existing DB.
 * @returns {Promise<{ adapter: { driver:string, run:Function, query:Function, persist?:Function } }>}
 */
async function createDbAdapter({ driver = process.env.DB_DRIVER || 'sqlite', dataDir, dbPath, bootstrapSchema, migrateSchema }) {
  const normalized = String(driver || 'sqlite').toLowerCase();

  // PostgreSQL (Supabase) adapter using node-postgres
  if (['pg', 'postgres', 'supabase'].includes(normalized)) {
    const { Pool } = require('pg');
    // Prefer SUPABASE_DB_URL if provided, else DATABASE_URL or PG_CONNECTION_STRING
    // Also support user-provided custom names from Vercel env (sunbeth_*)
    const connectionString =
      process.env.SUPABASE_DB_URL ||
      process.env.DATABASE_URL ||
      process.env.PG_CONNECTION_STRING ||
      process.env.sunbeth_POSTGRES_URL ||
      process.env.sunbeth_POSTGRES_PRISMA_URL ||
      process.env.sunbeth_POSTGRES_URL_NON_POOLING;
    if (!connectionString) throw new Error('Postgres adapter requires SUPABASE_DB_URL or DATABASE_URL');

    const pool = new Pool({
      connectionString,
      // Supabase often requires SSL when using pooled connections
      ssl: (process.env.PGSSLMODE || 'require') !== 'disable' ? { rejectUnauthorized: false } : false
    });

    // Helper: convert SQLite-style '?' placeholders to $1, $2 ... for pg
    function convertPlaceholders(sql, params) {
      let index = 0; const out = [];
      const newSql = sql.replace(/\?/g, () => { index++; out.push(index); return `$${index}`; });
      return { sql: newSql, params };
    }

    // Track last inserted id to emulate last_insert_rowid() calls in code
    let lastInsertId = null;

    async function execQuery(sql, params = []) {
      // Basic transaction commands passthrough
      const upper = sql.trim().toUpperCase();
      if (upper === 'BEGIN' || upper === 'COMMIT' || upper === 'ROLLBACK') {
        await pool.query(upper);
        return { rows: [] };
      }

      let addOnConflictDoNothing = false;
      let needsReturningId = false;
      let pgSql = sql;

      // Rewrite SQLite-specific INSERT OR IGNORE -> ON CONFLICT DO NOTHING
      if (/^\s*INSERT\s+OR\s+IGNORE\s+INTO\s+/i.test(pgSql)) {
        addOnConflictDoNothing = true;
        pgSql = pgSql.replace(/^\s*INSERT\s+OR\s+IGNORE\s+INTO\s+/i, 'INSERT INTO ');
      }

      // If this is a plain INSERT without RETURNING, add RETURNING id to capture lastInsertId
      if (/^\s*INSERT\s+INTO\s+/i.test(pgSql) && !/RETURNING\s+\w+/i.test(pgSql)) {
        needsReturningId = true;
      }

      if (addOnConflictDoNothing) {
        // Append ON CONFLICT DO NOTHING (safe even without specifying columns)
        pgSql = `${pgSql} ON CONFLICT DO NOTHING`;
      }

      // Convert placeholders
      const conv = convertPlaceholders(pgSql, params);
      const finalSql = needsReturningId ? `${conv.sql} RETURNING id` : conv.sql;
      const result = await pool.query(finalSql, conv.params);
      if (needsReturningId) {
        lastInsertId = result?.rows?.[0]?.id ?? null;
      }
      return result;
    }

    const adapter = {
      driver: 'pg',
      async run(sql, params = []) { await execQuery(sql, params); },
      async query(sql, params = []) {
        // Emulate SELECT last_insert_rowid() as id
        if (/select\s+last_insert_rowid\(\)\s+as\s+id/i.test(sql)) {
          return [{ id: lastInsertId }];
        }
        const conv = convertPlaceholders(sql, params);
        const rs = await pool.query(conv.sql, conv.params);
        return Array.isArray(rs?.rows) ? rs.rows : [];
      },
      // No-op persist for remote DBs
      persist() {}
    };

    // Intentionally do NOT call bootstrap/migrate for Postgres by default.
    // Schema should be provisioned via SQL migration in Supabase.
    return { adapter };
  }

  // Remote libSQL/Turso adapter for durable persistence on Vercel
  if (['libsql', 'turso'].includes(normalized)) {
    const { createClient } = require('@libsql/client');
    // Support both LIBSQL_* and TURSO_* env names for convenience
    const url = process.env.LIBSQL_URL || process.env.TURSO_DATABASE_URL;
    const authToken = process.env.LIBSQL_AUTH_TOKEN || process.env.TURSO_AUTH_TOKEN;
    if (!url) throw new Error('libsql adapter requires LIBSQL_URL (or TURSO_DATABASE_URL)');
    const client = createClient({ url, authToken });

    // Ensure schema exists (idempotent)
    try { if (typeof bootstrapSchema === 'function') await bootstrapSchema({
      run: (sql, params=[]) => client.execute({ sql, args: params }),
      query: (sql, params=[]) => client.execute({ sql, args: params })
    }); } catch {}
    try { if (typeof migrateSchema === 'function') await migrateSchema({
      run: (sql, params=[]) => client.execute({ sql, args: params }),
      query: (sql, params=[]) => client.execute({ sql, args: params })
    }); } catch {}

    const adapter = {
      driver: 'libsql',
      async run(sql, params = []) { await client.execute({ sql, args: params }); },
      async query(sql, params = []) {
        const rs = await client.execute({ sql, args: params });
        // rs.rows is already an array of objects
        return Array.isArray(rs?.rows) ? rs.rows : [];
      },
      // No-op for remote DB
      persist() {}
    };
    return { adapter };
  }

  if (normalized === 'sqlite') {
    if (dataDir && !fs.existsSync(dataDir)) fs.mkdirSync(dataDir, { recursive: true });
    // Ensure the sql.js WASM file is resolvable in serverless environments (e.g., Vercel)
    // locateFile tells sql.js where to load sql-wasm.wasm from. Using require.resolve ensures bundlers include it.
    const SQL = await initSqlJs({
      locateFile: (file) => {
        try {
          // e.g., file = 'sql-wasm.wasm'
          return require.resolve('sql.js/dist/' + file);
        } catch (e) {
          // Fallback to node_modules path relative to this file
          return path.join(process.cwd(), 'node_modules', 'sql.js', 'dist', file);
        }
      }
    });

    let sqliteDb;
    if (dbPath && fs.existsSync(dbPath)) {
      const filebuffer = fs.readFileSync(dbPath);
      sqliteDb = new SQL.Database(filebuffer);
    } else {
      sqliteDb = new SQL.Database();
      try { sqliteDb.run('PRAGMA foreign_keys = ON'); } catch {}
      if (typeof bootstrapSchema === 'function') bootstrapSchema(sqliteDb);
      // persist initial schema to disk
      try {
        const data = sqliteDb.export();
        const buffer = Buffer.from(data);
        if (dbPath) fs.writeFileSync(dbPath, buffer);
      } catch {}
    }
    try { sqliteDb.run('PRAGMA foreign_keys = ON'); } catch {}
    try { if (typeof migrateSchema === 'function') migrateSchema(sqliteDb); } catch {}

    const adapter = {
      driver: 'sqlite',
      run(sql, params = []) {
        sqliteDb.run(sql, params);
      },
      query(sql, params = []) {
        const stmt = sqliteDb.prepare(sql);
        const rows = [];
        try {
          stmt.bind(params);
          while (stmt.step()) rows.push(stmt.getAsObject());
        } finally {
          stmt.free();
        }
        return rows;
      },
      persist() {
        try {
          const data = sqliteDb.export();
          const buffer = Buffer.from(data);
          if (dbPath) fs.writeFileSync(dbPath, buffer);
        } catch {}
      },
      // expose raw for rare fallback needs
      raw: sqliteDb
    };
    return { adapter };
  }

  // Placeholders for other drivers. They share the same surface so routes won't change.
  if (['postgres', 'pg'].includes(normalized)) {
    throw new Error('Postgres adapter not configured. Set DB_DRIVER=sqlite or implement postgres adapter.');
  }
  if (['mysql', 'mysql2'].includes(normalized)) {
    throw new Error('MySQL adapter not configured. Set DB_DRIVER=sqlite or implement mysql adapter.');
  }
  if (['mssql', 'sqlserver'].includes(normalized)) {
    throw new Error('MSSQL adapter not configured. Set DB_DRIVER=sqlite or implement mssql adapter.');
  }

  throw new Error(`Unsupported DB_DRIVER: ${driver}`);
}

module.exports = { createDbAdapter };
