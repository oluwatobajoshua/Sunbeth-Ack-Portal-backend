// Centralized environment access without extra deps
function getEnv() {
  const env = process.env;
  return {
    NODE_ENV: env.NODE_ENV || 'development',
    PORT: parseInt(env.PORT || '4000', 10),
    DB_DRIVER: (env.DB_DRIVER || 'sqlite').toLowerCase(),
    DATA_DIR: env.DATA_DIR || undefined,
    DB_PATH: env.DB_PATH || undefined,
  };
}

module.exports = { getEnv };
