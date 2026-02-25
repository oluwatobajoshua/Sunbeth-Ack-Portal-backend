const { getEnv } = require('../config/env');
const { getDb } = require('../config/db');

async function getHealth(_req, res) {
  const env = getEnv();
  let driver = env.DB_DRIVER;
  try { console.log('Health endpoint called'); } catch {}
  try { driver = (await getDb()).driver || driver; } catch {}
  res.json({ ok: true, env: { node: process.version, driver, port: env.PORT } });
}

module.exports = { getHealth };
