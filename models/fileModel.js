const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const mime = require('mime-types');
const { getEnv } = require('../config/env');
const { getDb } = require('../config/db');

async function ensureSchema(db) {
  try {
    db.run?.("CREATE TABLE IF NOT EXISTS uploaded_files (id INTEGER PRIMARY KEY AUTOINCREMENT, original_name TEXT, stored_name TEXT, rel_path TEXT NOT NULL, size INTEGER, mime TEXT, sha256 TEXT, uploaded_at TEXT, uploaded_by TEXT, source_type TEXT, source_url TEXT, driveId TEXT, itemId TEXT)");
    db.run?.('CREATE UNIQUE INDEX IF NOT EXISTS ux_uploaded_files_sha ON uploaded_files(sha256)');
  } catch {}
}

function getUploadsDir() {
  const env = getEnv();
  const dataDir = env.DATA_DIR || path.join(process.cwd(), 'data');
  return path.join(dataDir, 'uploads');
}

async function saveUpload({ buffer, originalName, mimetype, uploadedBy = '', sourceType = null, sourceUrl = null, driveId = null, itemId = null }) {
  const db = await getDb();
  await ensureSchema(db);
  const sha256 = crypto.createHash('sha256').update(buffer).digest('hex');
  const uploadsDir = getUploadsDir();
  if (!fs.existsSync(uploadsDir)) fs.mkdirSync(uploadsDir, { recursive: true });
  const ext = mime.extension(mimetype || mime.lookup(originalName || '') || '') || 'bin';
  const storedName = `${sha256}.${ext}`;
  const relPath = `uploads/${storedName}`;
  const absPath = path.join(uploadsDir, storedName);
  if (!fs.existsSync(absPath)) fs.writeFileSync(absPath, buffer);
  const uploadedAt = new Date().toISOString();
  // Insert or ignore if duplicate sha
  try {
    const probe = db.query?.('SELECT id FROM uploaded_files WHERE sha256=? LIMIT 1', [sha256]);
    const existing = probe && probe[0] ? probe[0].id : null;
    if (!existing) {
      try {
        db.run?.('INSERT INTO uploaded_files (original_name, stored_name, rel_path, size, mime, sha256, uploaded_at, uploaded_by, source_type, source_url, driveId, itemId) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)', [originalName || '', storedName, relPath, buffer.length, mimetype || mime.lookup(originalName || '') || 'application/octet-stream', sha256, uploadedAt, uploadedBy || 'system', sourceType, sourceUrl, driveId, itemId]);
      } catch {
        try { db.run?.('ALTER TABLE uploaded_files ADD COLUMN source_type TEXT'); } catch {}
        try { db.run?.('ALTER TABLE uploaded_files ADD COLUMN source_url TEXT'); } catch {}
        try { db.run?.('ALTER TABLE uploaded_files ADD COLUMN driveId TEXT'); } catch {}
        try { db.run?.('ALTER TABLE uploaded_files ADD COLUMN itemId TEXT'); } catch {}
        db.run?.('INSERT INTO uploaded_files (original_name, stored_name, rel_path, size, mime, sha256, uploaded_at, uploaded_by, source_type, source_url, driveId, itemId) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)', [originalName || '', storedName, relPath, buffer.length, mimetype || mime.lookup(originalName || '') || 'application/octet-stream', sha256, uploadedAt, uploadedBy || 'system', sourceType, sourceUrl, driveId, itemId]);
      }
      db.persist?.();
    }
    const row = db.query?.('SELECT id, original_name, rel_path, mime, size, sha256 FROM uploaded_files WHERE sha256=? LIMIT 1', [sha256]);
    const id = row && row[0] ? row[0].id : existing;
    return { id, original_name: originalName || '', rel_path: relPath, mime: row && row[0] ? row[0].mime : (mimetype || 'application/octet-stream'), size: row && row[0] ? row[0].size : buffer.length, sha256 };
  } catch (e) {
    return null;
  }
}

async function getFileById(id) {
  const db = await getDb();
  await ensureSchema(db);
  const rows = db.query?.('SELECT id, original_name, stored_name, rel_path, size, mime, sha256, uploaded_at FROM uploaded_files WHERE id=?', [Number(id)]);
  return rows && rows[0] ? rows[0] : null;
}

async function listFiles({ limit = 50 } = {}) {
  const db = await getDb();
  await ensureSchema(db);
  const rows = db.query?.('SELECT id, original_name, size, mime, uploaded_at, sha256 FROM uploaded_files ORDER BY id DESC LIMIT ?', [Number(limit)]);
  return Array.isArray(rows) ? rows : [];
}

module.exports = { saveUpload, getFileById, listFiles, getUploadsDir };
