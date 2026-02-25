const path = require('path');
const fs = require('fs');
const mime = require('mime-types');
const multer = require('multer');
const { saveUpload, getFileById, listFiles, getUploadsDir } = require('../models/fileModel');
const { getDb } = require('../config/db');

const upload = multer({ storage: multer.memoryStorage() });

async function uploadFile(req, res) {
  if (!req.file) return res.status(400).json({ error: 'no_file_uploaded' });
  const MAX_SIZE = Number(process.env.LOCAL_UPLOAD_MAX_BYTES || 100 * 1024 * 1024);
  if (req.file.size > MAX_SIZE) return res.status(400).json({ error: 'file_too_large', max: MAX_SIZE });
  const origName = req.file.originalname || 'file';
  const guessed = req.file.mimetype || mime.lookup(origName) || 'application/octet-stream';
  const isPdf = /pdf/i.test(guessed) || /\.pdf$/i.test(origName || '');
  if (!isPdf) return res.status(400).json({ error: 'unsupported_type', allowed: 'application/pdf' });
  const rec = await saveUpload({ buffer: req.file.buffer, originalName: origName, mimetype: guessed, uploadedBy: (req.headers['x-admin-email'] || req.headers['x-user-email'] || '') });
  try { require('../utils/logger').info('files:upload', { reqId: req.id, name: origName, size: req.file.size, mime: guessed, id: rec?.id }); } catch {}
  if (!rec) return res.status(500).json({ error: 'save_failed' });
  const url = rec.id != null ? `/api/files/${rec.id}` : null;
  res.json({ id: rec.id, name: rec.original_name, size: rec.size, mime: rec.mime, sha256: rec.sha256, url });
}

async function listLibrary(req, res) {
  const limit = Number(req.query.limit || 50);
  const rows = await listFiles({ limit });
  try { require('../utils/logger').info('library:list', { reqId: req.id, count: Array.isArray(rows) ? rows.length : 0, limit }); } catch {}
  const out = rows.map(r => ({ id: r.id, name: r.original_name, size: r.size, mime: r.mime, uploadedAt: r.uploaded_at, sha256: r.sha256, url: `/api/files/${r.id}` }));
  res.json({ files: out });
}

async function streamFile(req, res) {
  const id = Number(req.params.id);
  const row = await getFileById(id);
  if (!row) return res.status(404).json({ error: 'not_found' });
  const uploadsDir = getUploadsDir();
  const absPath = path.join(uploadsDir, row.stored_name);
  if (!fs.existsSync(absPath)) return res.status(404).json({ error: 'missing_file' });
  try { require('../utils/logger').info('files:stream', { reqId: req.id, id, name: row.original_name, size: row.size, mime: row.mime }); } catch {}
  const download = String(req.query.download || '').toLowerCase() === '1';
  res.setHeader('Content-Type', row.mime || 'application/octet-stream');
  res.setHeader('Content-Length', row.size);
  res.setHeader('Cache-Control', 'private, max-age=60');
  if (download) res.setHeader('Content-Disposition', `attachment; filename="${row.original_name}"`);
  fs.createReadStream(absPath).pipe(res);
}

module.exports = { upload, uploadFile, listLibrary, streamFile };

async function saveGraph(req, res) {
  try {
    const driveId = String(req.body?.driveId || '') || '';
    const itemId = String(req.body?.itemId || '') || '';
    const rawUrl = String(req.body?.url || '');
    const nameHint = String(req.body?.name || 'document.pdf');
    const qToken = (req.query?.token || '').toString();
    const hdrAuth = (req.headers['authorization'] || '').toString();
    const bearer = qToken ? `Bearer ${qToken}` : (hdrAuth && /^Bearer\s+/i.test(hdrAuth) ? hdrAuth : '');
    if (!bearer) return res.status(401).json({ error: 'token_required' });

    let target;
    if (driveId && itemId) {
      target = `https://graph.microsoft.com/v1.0/drives/${encodeURIComponent(driveId)}/items/${encodeURIComponent(itemId)}/content`;
    } else if (rawUrl) {
      const b64 = Buffer.from(rawUrl, 'utf8').toString('base64').replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
      const shareId = `u!${b64}`;
      target = `https://graph.microsoft.com/v1.0/shares/${shareId}/driveItem/content`;
    } else {
      return res.status(400).json({ error: 'missing_ids_or_url' });
    }

    try { require('../utils/logger').info('graph:fetch', { reqId: req.id, driveId, itemId, rawUrl: rawUrl || undefined, target }); } catch {}
    const resp = await fetch(target, { headers: { Authorization: bearer, 'User-Agent': 'Sunbeth-Graph-Importer/1.0' } });
    if (!resp.ok) return res.status(resp.status).json({ error: 'graph_fetch_failed' });
    const arrayBuffer = await resp.arrayBuffer();
    const buffer = Buffer.from(arrayBuffer);
    const contentType = resp.headers.get('content-type') || 'application/octet-stream';

    const uploadedBy = String(req.headers['x-user-email'] || req.headers['x-admin-email'] || '').toLowerCase() || null;
    const rec = await saveUpload({ buffer, originalName: nameHint, mimetype: contentType, uploadedBy, sourceType: 'sharepoint', sourceUrl: rawUrl || null, driveId: driveId || null, itemId: itemId || null });
    try { require('../utils/logger').info('graph:saved', { reqId: req.id, id: rec?.id, name: nameHint, mime: contentType, size: rec?.size }); } catch {}
    if (!rec) return res.status(500).json({ error: 'save_failed' });
    const url = rec.id != null ? `/api/files/${rec.id}` : null;
    res.json({ id: rec.id, name: nameHint, url, mime: contentType, size: rec.size, sha256: rec.sha256 });
  } catch (e) {
    try { require('../utils/logger').error('graph:error', { reqId: req.id, message: e?.message || String(e) }); } catch {}
    res.status(500).json({ error: 'save_graph_failed', details: e?.message || String(e) });
  }
}

async function streamByPath(req, res) {
  const relPath = String(req.params.relPath || '').replace(/\\/g, '/');
  const uploadsDir = getUploadsDir().replace(/\\/g, '/');
  const absPath = path.join(uploadsDir, path.basename(relPath));
  if (!fs.existsSync(absPath)) return res.status(404).json({ error: 'not_found' });
  const guessed = mime.lookup(absPath) || 'application/octet-stream';
  try { require('../utils/logger').info('files:byPath', { reqId: req.id, relPath, mime: guessed }); } catch {}
  res.setHeader('Content-Type', guessed);
  fs.createReadStream(absPath).pipe(res);
}

module.exports.saveGraph = saveGraph;
module.exports.streamByPath = streamByPath;
