const express = require('express');
const { getAdminSettings, putAdminSettings, getSharePointSettingsPublic, putSharePointSettingsPublic } = require('../controllers/settingsController');
const router = express.Router();

router.get('/admin/settings', getAdminSettings);
router.put('/admin/settings', putAdminSettings);
router.get('/settings/sharepoint', getSharePointSettingsPublic);
router.put('/settings/sharepoint', putSharePointSettingsPublic);

module.exports = router;
