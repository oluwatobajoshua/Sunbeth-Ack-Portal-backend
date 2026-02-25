// Placeholder auth middleware. Extend with real auth later.
function auth(req, _res, next) {
  const header = req.headers['authorization'] || '';
  // Very basic token parsing ("Bearer token")
  const token = header.startsWith('Bearer ') ? header.slice(7) : null;
  req.user = token ? { id: 'token-user', roles: ['user'] } : null;
  next();
}

module.exports = { auth };
