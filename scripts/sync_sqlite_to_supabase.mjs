// One-way sync from local SQLite (sql.js file) to Supabase Postgres
// Purpose: keep SQLite as primary while mirroring core data to Supabase as a warm backup/standby
// Usage (PowerShell):
//   node .\scripts\sync_sqlite_to_supabase.mjs
//   # optional: specify DB file
//   node .\scripts\sync_sqlite_to_supabase.mjs .\\data\\sunbeth.db

import 'dotenv/config';
import fs from 'fs';
import path from 'path';
import pg from 'pg';
import initSqlJs from 'sql.js';

function pgConnString() {
  return (
    process.env.SUPABASE_DB_URL ||
    process.env.DATABASE_URL ||
    process.env.PG_CONNECTION_STRING ||
    process.env.sunbeth_POSTGRES_URL ||
    process.env.sunbeth_POSTGRES_PRISMA_URL ||
    process.env.sunbeth_POSTGRES_URL_NON_POOLING
  );
}

function safe(v) {
  return v === undefined ? null : v;
}

async function openSqlite(dbPath) {
  const SQL = await initSqlJs({
    locateFile: (file) => {
      try { return require.resolve('sql.js/dist/' + file); } catch {}
      return path.join(process.cwd(), 'node_modules', 'sql.js', 'dist', file);
    }
  });
  if (!fs.existsSync(dbPath)) throw new Error(`SQLite DB not found at ${dbPath}`);
  const filebuffer = fs.readFileSync(dbPath);
  const sqliteDb = new SQL.Database(filebuffer);
  return sqliteDb;
}

function allSqlite(db, sql, params=[]) {
  const stmt = db.prepare(sql);
  const rows = [];
  try {
    stmt.bind(params);
    while (stmt.step()) rows.push(stmt.getAsObject());
  } finally {
    stmt.free();
  }
  return rows;
}

async function syncCore(sqliteDb, pool) {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    // Batches
    const batches = allSqlite(sqliteDb, 'SELECT id, name, startDate, dueDate, status, description FROM batches ORDER BY id');
    for (const r of batches) {
      await client.query(
        `INSERT INTO batches (id,name,startdate,duedate,status,description)
         VALUES ($1,$2,$3,$4,$5,$6)
         ON CONFLICT (id) DO UPDATE SET name=EXCLUDED.name, startdate=EXCLUDED.startdate, duedate=EXCLUDED.duedate, status=EXCLUDED.status, description=EXCLUDED.description`,
        [r.id, r.name, r.startDate || null, r.dueDate || null, r.status ?? 1, r.description || null]
      );
    }

    // Documents
    const docs = allSqlite(sqliteDb, 'SELECT id, batchId, title, url, version, requiresSignature, driveId, itemId, source, localFileId, localUrl FROM documents ORDER BY id');
    for (const r of docs) {
      await client.query(
        `INSERT INTO documents (id,batchid,title,url,version,requiressignature,driveid,itemid,source,localfileid,localurl)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
         ON CONFLICT (id) DO UPDATE SET title=EXCLUDED.title, url=EXCLUDED.url, version=EXCLUDED.version, requiressignature=EXCLUDED.requiressignature, driveid=EXCLUDED.driveid, itemid=EXCLUDED.itemid, source=EXCLUDED.source, localfileid=EXCLUDED.localfileid, localurl=EXCLUDED.localurl`,
        [r.id, r.batchId, r.title, r.url, r.version ?? 1, r.requiresSignature ? 1 : 0, safe(r.driveId), safe(r.itemId), safe(r.source), safe(r.localFileId), safe(r.localUrl)]
      );
    }

    // Recipients
    const recips = allSqlite(sqliteDb, 'SELECT id, batchId, businessId, user, email, displayName, department, jobTitle, location, primaryGroup FROM recipients ORDER BY id');
    for (const r of recips) {
      await client.query(
        `INSERT INTO recipients (id,batchid,businessid,"user",email,displayname,department,jobtitle,location,primarygroup)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
         ON CONFLICT (id) DO UPDATE SET batchid=EXCLUDED.batchid, businessid=EXCLUDED.businessid, "user"=EXCLUDED."user", email=EXCLUDED.email, displayname=EXCLUDED.displayname, department=EXCLUDED.department, jobtitle=EXCLUDED.jobtitle, location=EXCLUDED.location, primarygroup=EXCLUDED.primarygroup`,
        [r.id, r.batchId, safe(r.businessId), safe(r.user), safe(r.email), safe(r.displayName), safe(r.department), safe(r.jobTitle), safe(r.location), safe(r.primaryGroup)]
      );
    }

    // Acks
    const acks = allSqlite(sqliteDb, 'SELECT id, batchId, documentId, email, acknowledged, ackDate FROM acks ORDER BY id');
    for (const r of acks) {
      await client.query(
        `INSERT INTO acks (id,batchid,documentid,email,acknowledged,ackdate)
         VALUES ($1,$2,$3,$4,$5,$6)
         ON CONFLICT (id) DO UPDATE SET email=EXCLUDED.email, acknowledged=EXCLUDED.acknowledged, ackdate=EXCLUDED.ackdate`,
        [r.id, r.batchId, r.documentId, r.email, r.acknowledged ? 1 : 0, safe(r.ackDate)]
      );
    }

    await client.query('COMMIT');
  } catch (e) {
    try { await client.query('ROLLBACK'); } catch {}
    throw e;
  } finally {
    client.release();
  }
}

async function main() {
  const dbFile = process.argv[2] || path.join(process.cwd(), 'sunbeth_doc_backend', 'data', 'sunbeth.db');
  const connectionString = pgConnString();
  if (!connectionString) {
    console.error('No Postgres connection string found in env.');
    process.exit(2);
  }
  const pool = new pg.Pool({
    connectionString,
    ssl: (process.env.PGSSLMODE || 'require') !== 'disable' ? { rejectUnauthorized: false } : false,
  });

  try {
    const sqliteDb = await openSqlite(dbFile);
    await syncCore(sqliteDb, pool);
    console.log('Sync complete: batches, documents, recipients, acks');
  } catch (e) {
    console.error('Sync failed:', e.message || e);
    process.exit(1);
  } finally {
    await pool.end();
  }
}

main();
