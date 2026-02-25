const express = require('express');
const {
  getAdminThemes,
  postAdminTheme,
  getAdminThemeById,
  putAdminThemeById,
  deleteAdminThemeById,
  postAdminThemeClone,
  getAdminThemeAssignments,
  getEffectiveTheme,
} = require('../controllers/themeController');

const router = express.Router();

// Admin theme catalog
router.get('/admin/themes', getAdminThemes);
router.post('/admin/themes', postAdminTheme);
router.get('/admin/themes/:id', getAdminThemeById);
router.put('/admin/themes/:id', putAdminThemeById);
router.delete('/admin/themes/:id', deleteAdminThemeById);
router.post('/admin/themes/:id/clone', postAdminThemeClone);

// Admin theme assignments
router.get('/admin/theme-assignments', getAdminThemeAssignments);

// Effective theme resolution
router.get('/theme/effective', getEffectiveTheme);

module.exports = router;
