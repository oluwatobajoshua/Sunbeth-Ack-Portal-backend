// Lightweight health check for Vercel to avoid heavy boot on cold starts
// Support both CommonJS and ESM export styles, and both Node/Edge runtimes
function handler(req, res) {
  try {
    // Node.js runtime path (Express-style response)
    if (res && typeof res.status === 'function' && typeof res.json === 'function') {
      return res.status(200).json({ ok: true });
    }
    // Edge/runtime or fetch-style: return a Response object
    const body = JSON.stringify({ ok: true });
    return new Response(body, { status: 200, headers: { 'content-type': 'application/json; charset=utf-8' } });
  } catch (_e) {
    try {
      if (res && typeof res.status === 'function' && typeof res.json === 'function') {
        return res.status(200).json({ ok: true });
      }
    } catch (_ignore) { /* fallback below */ }
    return new Response(JSON.stringify({ ok: true }), { status: 200, headers: { 'content-type': 'application/json; charset=utf-8' } });
  }
}

module.exports = handler;
exports.default = handler;
// Hint Vercel to use Node runtime when available
module.exports.config = { runtime: 'nodejs20.x' };
