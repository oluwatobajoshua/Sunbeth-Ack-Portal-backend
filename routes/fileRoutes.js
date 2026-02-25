const express = require('express');
const { asyncHandler } = require('../utils/helpers');
const { adminGuard } = require('../middlewares/adminGuard');
const files = require('../controllers/fileController');

const router = express.Router();

router.post('/files/upload', adminGuard, files.upload.single('file'), asyncHandler(files.uploadFile));
router.get('/library/list', adminGuard, asyncHandler(files.listLibrary));
router.get('/files/:id', asyncHandler(files.streamFile));
router.post('/library/save-graph', adminGuard, express.json({ limit: '1mb' }), asyncHandler(files.saveGraph));
router.get('/files/by-path/:relPath', asyncHandler(files.streamByPath));

module.exports = router;
