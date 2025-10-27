// Lightweight health check for Vercel to avoid heavy boot on cold starts
// Support both CommonJS and ESM export styles for broader runtime compatibility
function handler(_req, res) {
  res.status(200).json({ ok: true });
}

module.exports = handler;
exports.default = handler;
