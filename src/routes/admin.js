// src/routes/admin.js
const express = require('express');
const router = express.Router();
const adminController = require('../controllers/adminController');

router.get('/tenants', adminController.getTenants);
router.post('/tenants', adminController.createTenant);
router.put('/tenants/:id', adminController.updateTenant);
router.get('/settings', adminController.getSettings);
router.put('/settings', adminController.updateSettings);
// ...add more admin endpoints as needed

module.exports = router;
