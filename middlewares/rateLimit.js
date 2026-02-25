function makeRateLimiter({ windowMs = 60 * 1000, max = 60, keyGenerator } = {}) {
  const rateLimit = require('express-rate-limit');
  return rateLimit({
    windowMs,
    max,
    keyGenerator: keyGenerator || ((req) => (req.ip || 'ip')),
    standardHeaders: true,
    legacyHeaders: false,
  });
}

module.exports = { makeRateLimiter };
