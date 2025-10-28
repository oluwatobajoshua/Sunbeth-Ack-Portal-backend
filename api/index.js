// Vercel Serverless entry for the Express app
// Ensure we pick the Supabase (Postgres) server path in serverless by forcing
// DB driver selection before loading the main app. This prevents accidental
// fallback to sqlite/sql.js (which requires a wasm asset not bundled by default).
let cachedApp = null;

module.exports = async (req, res) => {
	if (!cachedApp) {
		// Force driver detection up-front so index.js branches to pg-only server
		const hasPgUrl = (
			process.env.SUPABASE_DB_URL ||
			process.env.DATABASE_URL ||
			process.env.PG_CONNECTION_STRING ||
			process.env.sunbeth_POSTGRES_URL ||
			process.env.sunbeth_POSTGRES_PRISMA_URL ||
			process.env.sunbeth_POSTGRES_URL_NON_POOLING
		);
		if (hasPgUrl && !process.env.DB_DRIVER) {
			process.env.DB_DRIVER = 'pg';
		}
		const getApp = require('..');
		cachedApp = await getApp();
	}
	return cachedApp(req, res);
};

// For completeness if some environments look for named handler
module.exports.handler = module.exports;
