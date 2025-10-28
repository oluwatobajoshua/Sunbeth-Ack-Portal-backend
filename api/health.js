// Lightweight health check for Vercel Node runtime
module.exports = (_req, res) => {
  res.status(200).json({ ok: true });
};
