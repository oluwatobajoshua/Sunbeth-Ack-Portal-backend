import 'dotenv/config';
import pg from 'pg';

function connString() {
  return (
    process.env.SUPABASE_DB_URL ||
    process.env.DATABASE_URL ||
    process.env.PG_CONNECTION_STRING ||
    process.env.sunbeth_POSTGRES_URL ||
    process.env.sunbeth_POSTGRES_PRISMA_URL ||
    process.env.sunbeth_POSTGRES_URL_NON_POOLING
  );
}

async function main() {
  const connectionString = connString();
  if (!connectionString) {
    console.error('No Postgres connection string found in env.');
    process.exit(2);
  }
  const pool = new pg.Pool({
    connectionString,
    ssl: (process.env.PGSSLMODE || 'require') !== 'disable' ? { rejectUnauthorized: false } : false,
  });

  const email = process.argv[2] || 'seed+sunbeth@example.com';
  console.log('Using email:', email);

  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    const name = `Demo Batch ${new Date().toISOString().slice(0,19).replace('T',' ')}`;
    const startDate = new Date().toISOString().substring(0,10);
    const dueDate = new Date(Date.now() + 7*24*60*60*1000).toISOString().substring(0,10);

    const insBatch = await client.query(
      'INSERT INTO batches (name, startdate, duedate, status, description) VALUES ($1,$2,$3,1,$4) RETURNING id',
      [name, startDate, dueDate, 'Seeded demo batch (smoke)']
    );
    const batchId = insBatch.rows[0].id;

    const doc1 = await client.query(
      'INSERT INTO documents (batchid, title, url, version, requiressignature) VALUES ($1,$2,$3,1,0) RETURNING id',
      [batchId, 'Code of Conduct', 'https://www.w3.org/WAI/ER/tests/xhtml/testfiles/resources/pdf/dummy.pdf']
    );
    const doc2 = await client.query(
      'INSERT INTO documents (batchid, title, url, version, requiressignature) VALUES ($1,$2,$3,1,0) RETURNING id',
      [batchId, 'IT Security Policy', 'https://www.africau.edu/images/default/sample.pdf']
    );

    await client.query(
      'INSERT INTO recipients (batchid, businessid, "user", email, displayname, department, jobtitle, location, primarygroup) VALUES ($1, NULL, $2, $3, $4, NULL, NULL, NULL, NULL)',
      [batchId, email, email, 'Demo User']
    );

    await client.query('COMMIT');

    const batches = await client.query('SELECT id, name, startdate, duedate, status FROM batches ORDER BY id DESC LIMIT 5');
    console.log('Recent batches:', batches.rows);

    const totalBatches = await client.query('SELECT COUNT(*)::int AS c FROM batches');
    const activeBatches = await client.query('SELECT COUNT(*)::int AS c FROM batches WHERE status=1');
    const totalRecipients = await client.query('SELECT COUNT(*)::int AS c FROM recipients');
    const ackTrue = await client.query('SELECT COUNT(*)::int AS c FROM acks WHERE acknowledged=1');
    const completionRate = totalRecipients.rows[0].c > 0 ? Math.round((ackTrue.rows[0].c / totalRecipients.rows[0].c) * 1000) / 10 : 0;

    console.log('Stats:', {
      totalBatches: totalBatches.rows[0].c,
      activeBatches: activeBatches.rows[0].c,
      totalUsers: totalRecipients.rows[0].c,
      completionRate,
    });

    console.log('Smoke test OK');
  } catch (e) {
    try { await client.query('ROLLBACK'); } catch {}
    console.error('Smoke test failed:', e.message || e);
    process.exit(1);
  } finally {
    client.release();
    await pool.end();
  }
}

main();
