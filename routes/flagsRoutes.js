const express = require('express');
const { getEffectiveFlagsRoute } = require('../controllers/flagsController');
const router = express.Router();

router.get('/flags/effective', getEffectiveFlagsRoute);

module.exports = router;
