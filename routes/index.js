const express = require('express');
const health = require('./healthRoutes');
const audit = require('./auditLogRoutes');
const themes = require('./themeRoutes');
const tenants = require('./tenantRoutes');
const settings = require('./settingsRoutes');
const flags = require('./flagsRoutes');
const externalUsers = require('./externalUserRoutes');
const files = require('./fileRoutes');
const diag = require('./diagRoutes');
const sharepoint = require('./sharepointRoutes');
const emails = require('./emailsRoutes');
let businessRecipients = null;
try { businessRecipients = require('./businessRecipientsRoutes'); } catch {}

const router = express.Router();

router.use('/api', health);
router.use('/api', audit);
router.use('/api', themes);
router.use('/api', tenants);
router.use('/api', settings);
router.use('/api', flags);
router.use('/api', externalUsers);
router.use('/api', files);
router.use('/api', diag);
router.use('/api', sharepoint);
router.use('/api', emails);
if (businessRecipients) router.use('/api', businessRecipients);

module.exports = router;
