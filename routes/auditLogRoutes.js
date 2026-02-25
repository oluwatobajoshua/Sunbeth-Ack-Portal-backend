const express = require('express');
const { getAuditLogs, postSeedDemo } = require('../controllers/auditLogController');
const router = express.Router();

router.get('/audit-logs', getAuditLogs);
router.post('/audit-logs/seed-demo', postSeedDemo);

module.exports = router;
