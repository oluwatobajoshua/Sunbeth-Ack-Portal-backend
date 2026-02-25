// src/routes/batches.js
const express = require('express');
const router = express.Router();
const batchesController = require('../controllers/batchesController');

router.get('/', batchesController.getAllBatches);
router.post('/', batchesController.createBatch);
router.get('/:id', batchesController.getBatchById);
router.put('/:id', batchesController.updateBatch);
router.delete('/:id', batchesController.deleteBatch);

module.exports = router;
