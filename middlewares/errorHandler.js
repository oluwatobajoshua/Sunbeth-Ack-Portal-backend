const { error } = require('../utils/logger');

function errorHandler(err, req, res, next) {
  const status = err.status || 500;
  const code = err.code || 'ERR_INTERNAL';
  const message = err.message || 'Unexpected error';
  const payload = { error: { code, message } };
  if (process.env.NODE_ENV !== 'production' && err.stack) {
    payload.error.stack = err.stack.split('\n').slice(0, 5);
  }
  try {
    error('request:error', {
      reqId: req.id,
      method: req.method,
      url: req.originalUrl || req.url,
      status,
      code,
      message,
    });
  } catch {}
  res.status(status).json(payload);
}

module.exports = { errorHandler };
