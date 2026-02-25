function asyncHandler(fn) {
  return function wrapped(req, res, next) {
    Promise.resolve(fn(req, res, next)).catch(next);
  };
}

function toArray(x) {
  if (Array.isArray(x)) return x;
  if (!x) return [];
  if (typeof x === 'object') return Object.values(x);
  return [x];
}

function ok(res, data = {}) { return res.json({ ok: true, ...data }); }
function fail(res, status = 500, error = 'error') { return res.status(status).json({ ok: false, error }); }

module.exports = { asyncHandler, toArray, ok, fail };
