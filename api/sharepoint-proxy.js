// Proxy for fetching SharePoint files using app credentials (service principal)
const express = require('express');
const router = express.Router();
// Node 18+ ships global fetch; avoid extra dependency in serverless env
const fetchFn = global.fetch;
if (!fetchFn) {
  throw new Error('Fetch API not available in this runtime');
}

// These should be set in your .env file
const TENANT_ID = process.env.MS_TENANT_ID;
const CLIENT_ID = process.env.MS_CLIENT_ID;
const CLIENT_SECRET = process.env.MS_CLIENT_SECRET;

// Helper: get app-only token for Microsoft Graph
async function getAppGraphToken() {
  const url = `https://login.microsoftonline.com/${TENANT_ID}/oauth2/v2.0/token`;
  const params = new URLSearchParams();
  params.append('grant_type', 'client_credentials');
  params.append('client_id', CLIENT_ID);
  params.append('client_secret', CLIENT_SECRET);
  params.append('scope', 'https://graph.microsoft.com/.default');

  const res = await fetchFn(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: params
  });
  if (!res.ok) throw new Error('Failed to get Graph token');
  const data = await res.json();
  return data.access_token;
}

// GET /api/sharepoint-proxy?fileUrl=...
router.get('/', async (req, res) => {
  const fileUrl = req.query.fileUrl;
  if (!fileUrl) return res.status(400).json({ error: 'missing_fileUrl' });
  try {
    const token = await getAppGraphToken();
    // fileUrl should be a full Graph API URL, e.g. https://graph.microsoft.com/v1.0/sites/.../drives/.../items/.../content
    const spRes = await fetchFn(fileUrl, {
      headers: { Authorization: `Bearer ${token}` }
    });
    if (!spRes.ok) {
      return res.status(spRes.status).json({ error: 'sharepoint_fetch_failed', status: spRes.status });
    }
    // Stream the PDF directly
    res.setHeader('Content-Type', spRes.headers.get('content-type') || 'application/pdf');
    spRes.body.pipe(res);
  } catch (e) {
    res.status(500).json({ error: 'sharepoint_proxy_error', details: String(e) });
  }
});

module.exports = router;
