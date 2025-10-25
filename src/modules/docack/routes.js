const express = require('express');
const router = express.Router();

// Minimal admin/health endpoint for the Document Acknowledgement module
router.get('/admin/health', (_req, res) => {
  res.json({ module: 'docack', ok: true });
});

module.exports = router;
