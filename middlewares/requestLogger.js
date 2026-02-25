const { info } = require('../utils/logger');

function genId() {
  try { return require('crypto').randomUUID(); } catch {
    return Math.random().toString(16).slice(2) + Date.now().toString(16);
  }
}

function requestLogger(req, res, next) {
  const start = process.hrtime.bigint();
  const id = (req.headers['x-request-id'] || genId()).toString();
  req.id = id;
  const metaStart = {
    reqId: id,
    method: req.method,
    url: req.originalUrl || req.url,
    ip: req.ip,
    adminEmail: (req.headers['x-admin-email'] || req.headers['x-user-email'] || '').toString().toLowerCase() || undefined,
  };
  info('request:start', metaStart);
  res.on('finish', () => {
    const end = process.hrtime.bigint();
    const durMs = Number((end - start) / 1000000n);
    const metaEnd = {
      reqId: id,
      status: res.statusCode,
      durationMs: durMs,
      method: req.method,
      url: req.originalUrl || req.url,
    };
    info('request:finish', metaEnd);
  });
  next();
}

module.exports = { requestLogger };
