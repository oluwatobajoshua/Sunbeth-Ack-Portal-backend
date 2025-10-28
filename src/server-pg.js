const express = require('express');
const cors = require('cors');

function getPgPool() {
  const { Pool } = require('pg');
  const connectionString = (
    process.env.SUPABASE_DB_URL ||
    process.env.DATABASE_URL ||
    process.env.PG_CONNECTION_STRING ||
    process.env.sunbeth_POSTGRES_URL ||
    process.env.sunbeth_POSTGRES_PRISMA_URL ||
    process.env.sunbeth_POSTGRES_URL_NON_POOLING
  );
  if (!connectionString) throw new Error('Missing Postgres connection string for Supabase');
  const pool = new Pool({
    connectionString,
    ssl: (process.env.PGSSLMODE || 'require') !== 'disable' ? { rejectUnauthorized: false } : false
  });
  return pool;
}

function mapBatch(r) {
  return {
    toba_batchid: String(r.id),
    toba_name: r.name,
    toba_startdate: r.startdate || null,
    toba_duedate: r.duedate || null,
    toba_status: r.status != null ? String(r.status) : null
  };
}
function mapDoc(r) {
  return {
    toba_documentid: String(r.id),
    toba_title: r.title,
    toba_version: r.version != null ? String(r.version) : '1',
    toba_requiressignature: !!r.requiressignature,
    toba_fileurl: r.localurl || r.url,
    toba_originalurl: r.url || null,
    toba_driveid: r.driveid || null,
    toba_itemid: r.itemid || null,
    toba_source: r.source || null,
    toba_localfileid: r.localfileid != null ? String(r.localfileid) : null,
    toba_localurl: r.localurl || null
  };
}

async function createPgApp() {
  const pool = getPgPool();
  const app = express();
  try { app.use(require('helmet')()); } catch {}
  try { app.use(require('compression')()); } catch {}
  app.use(cors());
  app.use(express.json({ limit: '2mb' }));

  app.get('/api/health', (_req, res) => res.json({ ok: true }));
  app.get('/', (_req, res) => res.type('text/plain').send('Sunbeth API (Supabase)'));

  // List batches; optional ?email=
  app.get('/api/batches', async (req, res) => {
    try {
      const email = (req.query.email || '').toString().trim().toLowerCase();
      if (email) {
        const rs = await pool.query(
          `SELECT DISTINCT b.id, b.name, b.startdate, b.duedate, b.status
           FROM batches b JOIN recipients r ON r.batchid=b.id
           WHERE LOWER(r.email)=LOWER($1)
           ORDER BY b.id DESC LIMIT 500`, [email]
        );
        return res.json(rs.rows.map(mapBatch));
      }
      const rs = await pool.query(`SELECT id, name, startdate, duedate, status FROM batches ORDER BY id DESC LIMIT 500`);
      return res.json(rs.rows.map(mapBatch));
    } catch (e) { return res.status(500).json({ error: 'list_failed', details: e.message }); }
  });

  app.get('/api/batches/:id/documents', async (req, res) => {
    try {
      const id = Number(req.params.id);
      if (!Number.isFinite(id)) return res.status(400).json({ error: 'invalid_id' });
      const rs = await pool.query(`SELECT id, batchid, title, url, version, requiressignature, driveid, itemid, source, localfileid, localurl FROM documents WHERE batchid=$1 ORDER BY id ASC`, [id]);
      return res.json(rs.rows.map(mapDoc));
    } catch (e) { return res.status(500).json({ error: 'list_failed', details: e.message }); }
  });

  // Progress for a batch for user (or overall if no email)
  app.get('/api/batches/:id/progress', async (req, res) => {
    try {
      const id = Number(req.params.id);
      const email = (req.query.email || '').toString().trim().toLowerCase();
      if (!Number.isFinite(id)) return res.status(400).json({ error: 'invalid_id' });
      const totalRs = await pool.query(`SELECT COUNT(*)::int AS c FROM documents WHERE batchid=$1`, [id]);
      const total = totalRs.rows[0]?.c || 0;
      let ack = 0;
      if (email) {
        const ackRs = await pool.query(
          `SELECT COUNT(*)::int AS c FROM acks a WHERE a.batchid=$1 AND LOWER(a.email)=LOWER($2) AND a.acknowledged=1`, [id, email]
        );
        ack = ackRs.rows[0]?.c || 0;
      } else {
        const ackRs = await pool.query(`SELECT COUNT(*)::int AS c FROM acks WHERE batchid=$1 AND acknowledged=1`, [id]);
        ack = ackRs.rows[0]?.c || 0;
      }
      const percent = total > 0 ? Math.round((ack / total) * 1000) / 10 : 0;
      return res.json({ acknowledged: ack, total, percent });
    } catch (e) { return res.status(500).json({ error: 'progress_failed', details: e.message }); }
  });

  // Acknowledged doc ids for a batch for a user
  app.get('/api/batches/:id/acks', async (req, res) => {
    try {
      const id = Number(req.params.id);
      const email = (req.query.email || '').toString().trim().toLowerCase();
      if (!Number.isFinite(id) || !email) return res.status(400).json({ error: 'invalid_params' });
      const rs = await pool.query(`SELECT documentid FROM acks WHERE batchid=$1 AND LOWER(email)=LOWER($2) AND acknowledged=1`, [id, email]);
      return res.json({ ids: rs.rows.map(r => String(r.documentid)) });
    } catch (e) { return res.status(500).json({ error: 'list_failed', details: e.message }); }
  });

  // Stats (overview)
  app.get('/api/stats', async (_req, res) => {
    try {
      const tb = await pool.query(`SELECT COUNT(*)::int AS c FROM batches`);
      const ab = await pool.query(`SELECT COUNT(*)::int AS c FROM batches WHERE status=1`);
      const tu = await pool.query(`SELECT COUNT(*)::int AS c FROM recipients`);
      const ack = await pool.query(`SELECT COUNT(*)::int AS c FROM acks WHERE acknowledged=1`);
      const completionRate = tu.rows[0].c > 0 ? Math.round((ack.rows[0].c / tu.rows[0].c) * 1000) / 10 : 0;
      return res.json({ totalBatches: tb.rows[0].c, activeBatches: ab.rows[0].c, totalUsers: tu.rows[0].c, completionRate, overdueBatches: 0, avgCompletionTime: 0 });
    } catch (e) { return res.status(500).json({ error: 'stats_failed', details: e.message }); }
  });

  // Acknowledge a document
  app.post('/api/ack', async (req, res) => {
    try {
      const { batchId, documentId, email } = req.body || {};
      if (!batchId || !documentId || !email) return res.status(400).json({ error: 'missing_fields' });
      await pool.query(`DELETE FROM acks WHERE batchid=$1 AND documentid=$2 AND LOWER(email)=LOWER($3)`, [batchId, documentId, email]);
      await pool.query(`INSERT INTO acks (batchid, documentid, email, acknowledged, ackdate) VALUES ($1,$2,LOWER($3),1,$4)`, [batchId, documentId, email, new Date().toISOString()]);
      return res.json({ ok: true });
    } catch (e) { return res.status(500).json({ error: 'ack_failed', details: e.message }); }
  });

  // Seed sample data for a specific user email
  app.post('/api/seed', async (req, res) => {
    const email = (req.query.email || req.body?.email || '').toString().trim().toLowerCase();
    if (!email) return res.status(400).json({ error: 'email_required' });
    try {
      await pool.query('BEGIN');
      const name = 'Demo Batch';
      const startDate = new Date().toISOString().substring(0,10);
      const dueDate = new Date(Date.now() + 7*24*60*60*1000).toISOString().substring(0,10);
      const ins = await pool.query(`INSERT INTO batches (name, startdate, duedate, status, description) VALUES ($1,$2,$3,1,$4) RETURNING id`, [name, startDate, dueDate, 'Seeded demo batch']);
      const batchId = ins.rows[0].id;
      await pool.query(`INSERT INTO documents (batchid, title, url, version, requiressignature) VALUES ($1,$2,$3,1,0)`, [batchId, 'Code of Conduct', 'https://www.w3.org/WAI/ER/tests/xhtml/testfiles/resources/pdf/dummy.pdf']);
      await pool.query(`INSERT INTO documents (batchid, title, url, version, requiressignature) VALUES ($1,$2,$3,1,0)`, [batchId, 'IT Security Policy', 'https://www.africau.edu/images/default/sample.pdf']);
      await pool.query(`INSERT INTO recipients (batchid, businessid, "user", email, displayname, department, jobtitle, location, primarygroup) VALUES ($1, NULL, $2, $3, $4, NULL, NULL, NULL, NULL)`, [batchId, email, email, 'Demo User']);
      await pool.query('COMMIT');
      return res.json({ ok: true, batchId });
    } catch (e) {
      try { await pool.query('ROLLBACK'); } catch {}
      return res.status(500).json({ error: 'seed_failed', details: e.message });
    }
  });

  // Admin: Notification Emails (used by Admin Panel UI)
  app.get('/api/notification-emails', async (_req, res) => {
    try {
      // table: notification_emails(email text primary key)
      const rs = await pool.query('select email from notification_emails order by lower(email) asc');
      return res.json({ emails: rs.rows.map(r => String(r.email)) });
    } catch (e) {
      // Return empty list if table missing to keep Admin UI functional
      if (/relation "notification_emails" does not exist/i.test(String(e.message))) {
        return res.json({ emails: [] });
      }
      return res.status(500).json({ error: 'load_failed', details: e.message });
    }
  });
  app.post('/api/notification-emails', async (req, res) => {
    try {
      const emails = Array.isArray(req.body?.emails) ? req.body.emails : [];
      await pool.query('begin');
      try {
        await pool.query('create table if not exists notification_emails (email text primary key)');
        await pool.query('delete from notification_emails');
        for (const raw of emails) {
          if (typeof raw !== 'string') continue;
          const e = raw.trim().toLowerCase();
          if (!e || !e.includes('@')) continue;
          await pool.query('insert into notification_emails(email) values($1) on conflict (email) do nothing', [e]);
        }
        await pool.query('commit');
      } catch (e) {
        try { await pool.query('rollback'); } catch {}
        throw e;
      }
      return res.json({ success: true });
    } catch (e) {
      return res.status(500).json({ error: 'save_failed', details: e.message });
    }
  });

  return app;
}

module.exports = { createPgApp };
