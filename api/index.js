// Vercel Serverless entry for the Express app
// Lazily initialize the app once, then forward Node req/res to Express
let cachedApp = null;

module.exports = async (req, res) => {
	if (!cachedApp) {
		const getApp = require('..');
		cachedApp = await getApp();
	}
	return cachedApp(req, res);
};

// For completeness if some environments look for named handler
module.exports.handler = module.exports;
