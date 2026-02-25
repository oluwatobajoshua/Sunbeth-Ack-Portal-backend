const { asyncHandler } = require('../utils/helpers');
const {
  listTenants,
  createTenant,
  updateTenant,
  getTenantModules,
  setTenantModuleEnabled,
  listLicenses,
  createLicense,
  listDomains,
  createDomain,
  deleteDomain,
  getTenantTheme,
  putTenantTheme,
} = require('../models/tenantModel');

const getAdminTenants = asyncHandler(async (_req, res) => {
  const tenants = await listTenants();
  res.json({ tenants });
});

const postAdminTenants = asyncHandler(async (req, res) => {
  const { name, code, parentId=null, isActive=true, isOwner=false } = req.body || {};
  const out = await createTenant({ name, code, parentId, isActive, isOwner });
  res.json(out);
});

const putAdminTenantById = asyncHandler(async (req, res) => {
  const id = Number(req.params.id);
  const { name, code, parentId, isActive, isOwner } = req.body || {};
  await updateTenant(id, { name, code, parentId, isActive, isOwner });
  res.json({ ok: true });
});

const getAdminTenantModules = asyncHandler(async (req, res) => {
  const id = Number(req.params.id);
  const modules = await getTenantModules(id);
  res.json({ modules });
});

const putAdminTenantModules = asyncHandler(async (req, res) => {
  const id = Number(req.params.id);
  const { module, enabled } = req.body || {};
  await setTenantModuleEnabled(id, module, enabled);
  res.json({ ok: true });
});

const getAdminTenantLicenses = asyncHandler(async (req, res) => {
  const id = Number(req.params.id);
  const licenses = await listLicenses(id);
  res.json({ licenses });
});

const postAdminTenantLicenses = asyncHandler(async (req, res) => {
  const id = Number(req.params.id);
  const out = await createLicense(id, req.body || {});
  res.json(out);
});

const getAdminTenantDomains = asyncHandler(async (req, res) => {
  const id = Number(req.params.id);
  const domains = await listDomains(id);
  res.json({ domains });
});

const postAdminTenantDomains = asyncHandler(async (req, res) => {
  const id = Number(req.params.id);
  const out = await createDomain(id, req.body || {});
  res.json(out);
});

const deleteAdminTenantDomainById = asyncHandler(async (req, res) => {
  const id = Number(req.params.id);
  const domainId = Number(req.params.domainId);
  await deleteDomain(id, domainId);
  res.json({ ok: true });
});

const getAdminTenantTheme = asyncHandler(async (req, res) => {
  const id = Number(req.params.id);
  const out = await getTenantTheme(id);
  res.json(out);
});

const putAdminTenantTheme = asyncHandler(async (req, res) => {
  const id = Number(req.params.id);
  const theme = req.body?.theme || req.body || {};
  const out = await putTenantTheme(id, theme);
  res.json(out);
});

module.exports = {
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
};
