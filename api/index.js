// Vercel Serverless entry point for the Express app
// Export both the Express app and a serverless handler for compatibility
const serverless = require('serverless-http');
const app = require('..');

module.exports = app;
module.exports.handler = serverless(app);
