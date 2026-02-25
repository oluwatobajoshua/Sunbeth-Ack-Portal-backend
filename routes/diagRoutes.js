const express = require('express');
const { getEnv } = require('../config/env');
const { getDb } = require('../config/db');

const router = express.Router();

router.get('/diag/db', async (_req, res) => {
  try {
    const env = getEnv();
    let driver = env.DB_DRIVER || 'unknown';
    try {
      const db = await getDb();
      if (db && db.driver) driver = String(db.driver);
    } catch {}
    res.json({ driver, canary: { ok: 1 } });
  } catch (e) {
    res.status(500).json({ driver: 'unknown', error: String(e && e.message ? e.message : e) });
  }
});

module.exports = router;
