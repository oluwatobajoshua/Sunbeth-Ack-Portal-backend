// Vercel Serverless entry for the Express app
// Lazily initialize the app once, then forward Node req/res to Express
let cachedApp = null;

module.exports = async (req, res) => {
	try {
		if (!cachedApp) {
			const getApp = require('..');
			cachedApp = await getApp();
		}
		return cachedApp(req, res);
	} catch (e) {
		try {
			res.statusCode = 500;
			res.setHeader('Content-Type', 'application/json');
			res.end(JSON.stringify({ error: 'init_failed', message: e?.message || String(e), stack: (e && e.stack) ? String(e.stack).split('\n').slice(0,5) : undefined }));
		} catch {}
	}
};

// For completeness if some environments look for named handler
module.exports.handler = module.exports;
