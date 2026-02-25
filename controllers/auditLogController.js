const { listAuditLogs, seedDemoAuditLogs } = require('../models/auditLogModel');
const { asyncHandler } = require('../utils/helpers');

const getAuditLogs = asyncHandler(async (req, res) => {
  const limit = Math.min(parseInt(req.query.limit || '50', 10), 500);
  const logs = await listAuditLogs({ limit });
  try { require('../utils/logger').info('audit:get', { reqId: req.id, count: Array.isArray(logs) ? logs.length : 0, limit }); } catch {}
  res.json({ logs: Array.isArray(logs) ? logs : [] });
});

const postSeedDemo = asyncHandler(async (_req, res) => {
  const result = await seedDemoAuditLogs();
  try { require('../utils/logger').info('audit:seedDemo', { inserted: result?.inserted || 0 }); } catch {}
  res.json({ ok: true, ...result });
});

module.exports = { getAuditLogs, postSeedDemo };
