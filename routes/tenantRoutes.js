const express = require('express');
const {
  getAdminTenants,
  postAdminTenants,
  putAdminTenantById,
  getAdminTenantModules,
  putAdminTenantModules,
  getAdminTenantLicenses,
  postAdminTenantLicenses,
  getAdminTenantDomains,
  postAdminTenantDomains,
  deleteAdminTenantDomainById,
  getAdminTenantTheme,
  putAdminTenantTheme,
} = require('../controllers/tenantController');

const router = express.Router();

router.get('/admin/tenants', getAdminTenants);
router.post('/admin/tenants', postAdminTenants);
router.put('/admin/tenants/:id', putAdminTenantById);

router.get('/admin/tenants/:id/modules', getAdminTenantModules);
router.put('/admin/tenants/:id/modules', putAdminTenantModules);

router.get('/admin/tenants/:id/licenses', getAdminTenantLicenses);
router.post('/admin/tenants/:id/licenses', postAdminTenantLicenses);

router.get('/admin/tenants/:id/domains', getAdminTenantDomains);
router.post('/admin/tenants/:id/domains', postAdminTenantDomains);
router.delete('/admin/tenants/:id/domains/:domainId', deleteAdminTenantDomainById);

router.get('/admin/tenants/:id/theme', getAdminTenantTheme);
router.put('/admin/tenants/:id/theme', putAdminTenantTheme);

module.exports = router;
