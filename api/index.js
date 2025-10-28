// Vercel Serverless entry point for the Express app
// Export a Node-compatible serverless handler as the default export
const serverless = require('serverless-http');
const app = require('..');

module.exports = serverless(app);
// For completeness if some environments look for named handler
module.exports.handler = module.exports;
