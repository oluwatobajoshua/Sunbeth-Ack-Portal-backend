const { asyncHandler } = require('../utils/helpers');
const { getEffectiveFlags } = require('../models/flagsModel');

const getEffectiveFlagsRoute = asyncHandler(async (req, res) => {
  const tenantId = req?.tenant?.id || null;
  const out = await getEffectiveFlags(tenantId);
  res.json(out);
});

module.exports = { getEffectiveFlagsRoute };
