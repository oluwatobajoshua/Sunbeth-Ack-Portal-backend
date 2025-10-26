// Simple integration test for /api/policies/ack
// Prerequisites: Backend server running locally on http://127.0.0.1:4000
// Usage: node scripts/test-policies-ack.js "user@example.com" <fileId>

async function main() {
  const base = process.env.API_BASE || 'http://127.0.0.1:4000';
  const email = process.argv[2] || process.env.TEST_EMAIL;
  const fileId = Number(process.argv[3] || process.env.TEST_FILE_ID);
  if (!email || !email.includes('@') || !Number.isFinite(fileId)) {
    console.error('Usage: node scripts/test-policies-ack.js "user@example.com" <fileId>');
    process.exit(2);
  }
  console.log('Testing /api/policies/ack for', { email, fileId });
  const ackRes = await fetch(`${base}/api/policies/ack`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email, fileId })
  });
  const text = await ackRes.text();
  console.log('ACK status:', ackRes.status, text);
  if (!ackRes.ok) process.exit(1);

  // Verify it no longer appears due
  const dueRes = await fetch(`${base}/api/policies/due?email=${encodeURIComponent(email)}`);
  const dueJson = await dueRes.json().catch(() => ({}));
  const stillDue = Array.isArray(dueJson.due) && dueJson.due.some(p => Number(p.fileId) === Number(fileId));
  console.log('Due check after ack:', { stillDue, due: dueJson.due?.length });
  if (stillDue) process.exit(1);
  console.log('Success');
}

main().catch(err => { console.error('Test failed', err); process.exit(1); });
