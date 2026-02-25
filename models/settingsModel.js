const { getDb } = require('../config/db');

async function getSetting(key, fallback = null) {
  try {
    const db = await getDb();
    const rows = db.query('SELECT value FROM app_settings WHERE key=?', [String(key)]);
    return rows && rows[0] ? rows[0].value : fallback;
  } catch {
    return fallback;
  }
}

async function setSetting(key, value) {
  try {
    const db = await getDb();
    db.run('INSERT INTO app_settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value', [String(key), String(value)]);
    db.persist?.();
    return true;
  } catch {
    return false;
  }
}

module.exports = { getSetting, setSetting };
