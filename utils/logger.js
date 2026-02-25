const fs = require('fs');
const path = require('path');

const LOG_DIR = process.env.LOG_DIR || path.join(process.cwd(), 'logs');
const LOG_FILE = path.join(LOG_DIR, 'app.log');

function ensureLogDir() {
  try { if (!fs.existsSync(LOG_DIR)) fs.mkdirSync(LOG_DIR, { recursive: true }); } catch {}
}

function ts() {
  return new Date().toISOString();
}

function write(line) {
  ensureLogDir();
  try { fs.appendFile(LOG_FILE, line + '\n', () => {}); } catch {}
}

function fmt(level, msg, meta) {
  const base = { level, time: ts(), message: String(msg) };
  const payload = Object.assign(base, meta || {});
  return JSON.stringify(payload);
}

function info(msg, meta) {
  const line = fmt('info', msg, meta);
  try { console.log(msg, meta || ''); } catch {}
  write(line);
}

function warn(msg, meta) {
  const line = fmt('warn', msg, meta);
  try { console.warn(msg, meta || ''); } catch {}
  write(line);
}

function error(msg, meta) {
  const line = fmt('error', msg, meta);
  try { console.error(msg, meta || ''); } catch {}
  write(line);
}

module.exports = { info, warn, error, LOG_FILE };
