const { listThemes, createTheme, getTheme, updateTheme, deleteTheme, cloneTheme, listAssignments, resolveEffectiveTheme } = require('../models/themeModel');
const { asyncHandler } = require('../utils/helpers');

const getAdminThemes = asyncHandler(async (_req, res) => {
  const themes = await listThemes();
  res.json({ themes });
});

const postAdminTheme = asyncHandler(async (req, res) => {
  const { name, description=null, light=null, dark=null, baseThemeId=null } = req.body || {};
  const out = await createTheme({ name, description, light, dark, baseThemeId });
  res.json(out);
});

const getAdminThemeById = asyncHandler(async (req, res) => {
  const r = await getTheme(Number(req.params.id));
  if (!r) return res.status(404).json({ error: 'not_found' });
  res.json(r);
});

const putAdminThemeById = asyncHandler(async (req, res) => {
  const id = Number(req.params.id);
  const { name, description, light, dark } = req.body || {};
  await updateTheme(id, { name, description, light, dark });
  res.json({ ok: true });
});

const deleteAdminThemeById = asyncHandler(async (req, res) => {
  const id = Number(req.params.id);
  await deleteTheme(id);
  res.json({ ok: true });
});

const postAdminThemeClone = asyncHandler(async (req, res) => {
  const id = Number(req.params.id);
  const name = req.body?.name;
  const out = await cloneTheme(id, name);
  res.json(out);
});

const getAdminThemeAssignments = asyncHandler(async (req, res) => {
  const targetType = String(req.query.targetType || '').trim();
  const targetId = req.query.targetId != null ? String(req.query.targetId) : null;
  const assignments = await listAssignments({ targetType, targetId });
  res.json({ assignments });
});

const getEffectiveTheme = asyncHandler(async (req, res) => {
  const tenantId = req?.tenant?.id || null;
  const module = String(req.query.module || '').trim();
  const plugin = String(req.query.plugin || '').trim();
  const out = await resolveEffectiveTheme({ tenantId, module, plugin });
  res.json(out);
});

module.exports = { getAdminThemes, postAdminTheme, getAdminThemeById, putAdminThemeById, deleteAdminThemeById, postAdminThemeClone, getAdminThemeAssignments, getEffectiveTheme };
