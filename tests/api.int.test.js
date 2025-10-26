// Basic integration tests using Node's built-in test runner
// Requires Node >= 20
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { setTimeout as delay } from 'node:timers/promises';

const PORT = 4100;
const BASE = `http://127.0.0.1:${PORT}`;
const ADMIN = 'admin.tester@sunbeth.local';

let serverProc;

async function waitForHealthy(timeoutMs = 10000) {
  const start = Date.now();
  while (Date.now() - start < timeoutMs) {
    try {
      const res = await fetch(`${BASE}/api/health`);
      if (res.ok) {
        const j = await res.json();
        if (j && j.ok === true) return true;
      }
    } catch {}
    await delay(200);
  }
  throw new Error('Server did not become healthy in time');
}

before(async () => {
  serverProc = spawn(process.execPath, ['index.js'], {
    cwd: process.cwd(),
    env: {
      ...process.env,
      PORT: String(PORT),
      REACT_APP_SUPER_ADMINS: ADMIN,
      NODE_ENV: 'test',
    },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  // Optional: log errors if start fails
  serverProc.stderr.on('data', () => {});
  await waitForHealthy(15000);
});

after(() => {
  try { serverProc?.kill('SIGTERM'); } catch {}
});

test('health endpoint returns ok', async () => {
  const res = await fetch(`${BASE}/api/health`);
  assert.equal(res.status, 200);
  const body = await res.json();
  assert.equal(body.ok, true);
});

test('admin policies list is accessible with adminEmail query', async () => {
  const url = `${BASE}/api/admin/policies?adminEmail=${encodeURIComponent(ADMIN)}`;
  const res = await fetch(url);
  assert.equal(res.status, 200);
  const body = await res.json();
  assert.ok(body && typeof body === 'object' && Array.isArray(body.policies));
});
