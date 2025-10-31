// Simple database adapter factory to make the API driver-agnostic.
// Currently implements 'sqlite' on top of sql.js (WASM), 'firebase' on Firestore,
// and 'libsql'/'turso' for remote SQLite. Other drivers can be
// added behind the same run/query/persist interface without changing routes.

const fs = require('fs');
const path = require('path');
const initSqlJs = require('sql.js');
const { FirebaseAdapter } = require('./firebase');
const { FirebaseRtdbAdapter } = require('./firebase_rtdb');

/**
 * Create a DB adapter based on environment or passed driver.
 * @param {Object} opts
 * @param {string} opts.driver - e.g. 'sqlite' (default), 'firebase', 'libsql', 'turso', 'postgres', 'mysql', 'mssql'.
 * @param {string} opts.dataDir - folder path for DB files (sqlite).
 * @param {string} opts.dbPath - full path to sqlite db file.
 * @param {(db:any)=>void} opts.bootstrapSchema - callback to create schema in a fresh DB.
 * @param {(db:any)=>void} opts.migrateSchema - callback to migrate existing DB.
 * @returns {Promise<{ adapter: { driver:string, run:Function, query:Function, persist?:Function } }>}
 */
async function createDbAdapter({ driver = process.env.DB_DRIVER || 'sqlite', dataDir, dbPath, bootstrapSchema, migrateSchema }) {
  let normalized = String(driver || 'sqlite').toLowerCase().trim();
  // Map common aliases and sanitize unexpected values
  if (normalized === 'supabase') normalized = 'libsql';
  if (normalized === 'sqlite3' || normalized === 'sqljs' || normalized === 'wasm') normalized = 'sqlite';
  const known = new Set(['sqlite','firebase','firebase-rtdb','rtdb','libsql','turso']);
  if (!known.has(normalized)) {
    // Default to sqlite if an unknown driver is provided
    try { console.warn(`Unknown DB_DRIVER: ${driver}; defaulting to sqlite`); } catch {}
    normalized = 'sqlite';
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

  // Firebase Firestore adapter for cloud-native deployments
  if (normalized === 'firebase') {
    const firebaseAdapter = new FirebaseAdapter();
    
    const adapter = {
      driver: 'firebase',
      async run(sql, params = []) {
        try {
          return await firebaseAdapter.run(sql, params);
        } catch (err) {
          console.error('Firebase run error:', err);
          throw err;
        }
      },
      async query(sql, params = []) {
        try {
          return await firebaseAdapter.query(sql, params);
        } catch (err) {
          console.error('Firebase query error:', err);
          return [];
        }
      },
      persist() {
        // No-op for Firebase as it's automatically persistent
        return firebaseAdapter.persist();
      },
      // Expose raw Firebase adapter for advanced use cases
      raw: firebaseAdapter
    };
    
    // Initialize schema if needed (Firebase doesn't need explicit schema creation)
    if (typeof bootstrapSchema === 'function') {
      console.log('Firebase: Schema bootstrap not needed (NoSQL database)');
    }
    if (typeof migrateSchema === 'function') {
      console.log('Firebase: Schema migration not needed (NoSQL database)');
    }
    
    return { adapter };
  }

  // Firebase Realtime Database adapter
  if (normalized === 'firebase-rtdb' || normalized === 'rtdb') {
    const rtdb = new FirebaseRtdbAdapter();
    const adapter = {
      driver: 'rtdb',
      async run(sql, params = []) { return await rtdb.run(sql, params); },
      async query(sql, params = []) {
        try { return await rtdb.query(sql, params); } catch (e) { console.error('RTDB query error:', e); return []; }
      },
      persist() { return rtdb.persist(); },
      raw: rtdb
    };
    // No schema bootstrap/migration for RTDB
    console.log('Firebase RTDB: Schema bootstrap/migration not required');
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
