#!/usr/bin/env node
import http from 'http';
import https from 'https';

const base = process.argv[2] || 'http://localhost:4000';
const batchId = process.argv[3];
const email = (process.argv[4] || '').toLowerCase();
const displayName = process.argv[5] || email;

if (!batchId || !email) {
  console.error('Usage: node scripts/add-recipient.mjs <base> <batchId> <email> [displayName]');
  process.exit(2);
}

const url = new URL(`/api/batches/${encodeURIComponent(batchId)}/recipients`, base);
const payload = JSON.stringify({ recipients: [{ email, displayName }] });

const client = url.protocol === 'https:' ? https : http;
const req = client.request(url, { method: 'POST', headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(payload) } }, (res) => {
  const chunks = [];
  res.on('data', c => chunks.push(c));
  res.on('end', () => {
    const body = Buffer.concat(chunks).toString('utf8');
    try { console.log(JSON.stringify({ status: res.statusCode, body: JSON.parse(body) }, null, 2)); }
    catch { console.log(JSON.stringify({ status: res.statusCode, body }, null, 2)); }
  });
});
req.on('error', (e) => { console.error('Request failed', e.message); process.exit(1); });
req.end(payload);
