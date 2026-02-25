// e2e test for inviting and logging in an external user via Google
// Requires Node >= 20
const assert = require('assert').strict;

const BASE = 'http://localhost:4000';
const TEST_EMAIL = 'ogunsakinoluwatoba@gmail.com';
const TEST_NAME = 'Oluwatoba Ogunsakin';

async function inviteExternalUser() {
  const res = await fetch(`${BASE}/api/external-users/invite`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email: TEST_EMAIL, name: TEST_NAME })
  });
  assert.equal(res.status, 200, 'Invite should succeed');
  const body = await res.json();
  assert.ok(body.ok, 'Invite response should have ok: true');
}

async function googleLoginExternalUser(idToken) {
  const res = await fetch(`${BASE}/api/external-users/google-login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ idToken })
  });
  assert.equal(res.status, 200, 'Google login should succeed');
  const body = await res.json();
  assert.ok(body.ok, 'Login response should have ok: true');
  assert.equal(body.email, TEST_EMAIL);
}

async function runE2E() {
  await inviteExternalUser();
  // Manual step: obtain a valid Google idToken for TEST_EMAIL
  // const idToken = '...';
  // await googleLoginExternalUser(idToken);
  console.log('Invite test passed. For login, supply a valid Google idToken.');
}

runE2E().catch(e => {
  console.error('E2E test failed:', e);
  process.exit(1);
});
