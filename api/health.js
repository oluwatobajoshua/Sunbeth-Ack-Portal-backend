// Lightweight health check for Vercel to avoid heavy boot on cold starts
module.exports = (_req, res) => {
  res.status(200).json({ ok: true });
};
