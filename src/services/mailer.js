// Lightweight mailer wrapper. Prefers Microsoft Graph (MSAL app-only) if configured; else uses Nodemailer SMTP; else logs.
// Env vars:
//  Graph (preferred):
//    MS_TENANT_ID or GRAPH_TENANT_ID
//    MS_CLIENT_ID or GRAPH_CLIENT_ID
//    MS_CLIENT_SECRET or GRAPH_CLIENT_SECRET
//    MS_SENDER_UPN or GRAPH_SENDER_UPN (sender mailbox UPN/email)
//    MSAL_MAIL_ENABLED (optional, 'true' to force Graph; defaults to Graph when creds present)
//  SMTP (fallback):
//    SMTP_HOST, SMTP_PORT, SMTP_SECURE (true|false), SMTP_USER, SMTP_PASS, SMTP_FROM

let nodemailer = null;
try { nodemailer = require('nodemailer'); } catch {}

// Use global fetch (Node 18+) for Graph calls
const fetchFn = global.fetch;

function graphConfig() {
  const tenant = process.env.MS_TENANT_ID || process.env.GRAPH_TENANT_ID || '';
  const clientId = process.env.MS_CLIENT_ID || process.env.GRAPH_CLIENT_ID || '';
  const clientSecret = process.env.MS_CLIENT_SECRET || process.env.GRAPH_CLIENT_SECRET || '';
  const senderUpn = process.env.MS_SENDER_UPN || process.env.GRAPH_SENDER_UPN || '';
  const enabled = String(process.env.MSAL_MAIL_ENABLED || '').toLowerCase() === 'true';
  return { tenant, clientId, clientSecret, senderUpn, enabled };
}

async function getGraphToken() {
  const { tenant, clientId, clientSecret } = graphConfig();
  if (!tenant || !clientId || !clientSecret) return null;
  if (!fetchFn) return null;
  const url = `https://login.microsoftonline.com/${tenant}/oauth2/v2.0/token`;
  const params = new URLSearchParams();
  params.append('grant_type', 'client_credentials');
  params.append('client_id', clientId);
  params.append('client_secret', clientSecret);
  params.append('scope', 'https://graph.microsoft.com/.default');
  const res = await fetchFn(url, { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body: params });
  if (!res.ok) return null;
  const data = await res.json();
  return data && data.access_token ? String(data.access_token) : null;
}

async function sendViaGraph(to, subject, html, text) {
  try {
    const cfg = graphConfig();
    const preferGraph = cfg.enabled || (cfg.tenant && cfg.clientId && cfg.clientSecret && cfg.senderUpn);
    if (!preferGraph) return { ok: false, reason: 'graph_not_configured' };
    const token = await getGraphToken();
    if (!token) return { ok: false, reason: 'graph_token_failed' };
    if (!cfg.senderUpn) return { ok: false, reason: 'graph_sender_missing' };
    const url = `https://graph.microsoft.com/v1.0/users/${encodeURIComponent(cfg.senderUpn)}/sendMail`;
    const payload = {
      message: {
        subject: String(subject || ''),
        body: { contentType: 'HTML', content: String(html || (text || '')) },
        toRecipients: [{ emailAddress: { address: String(to) } }],
      },
      saveToSentItems: false,
    };
    const res = await fetchFn(url, {
      method: 'POST',
      headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });
    if (res.status === 202 || res.ok) return { ok: true };
    return { ok: false, status: res.status };
  } catch (e) {
    try { console.warn('[MAIL:GRAPH] send failed', e?.message || e); } catch {}
    return { ok: false, error: String(e?.message || e) };
  }
}

function getTransport() {
  try {
    const host = process.env.SMTP_HOST || '';
    const port = Number(process.env.SMTP_PORT || 587);
    const secure = String(process.env.SMTP_SECURE || 'false').toLowerCase() === 'true';
    const user = process.env.SMTP_USER || '';
    const pass = process.env.SMTP_PASS || '';
    if (!host) return null;
    const auth = (user && pass) ? { user, pass } : undefined;
    return nodemailer && nodemailer.createTransport({ host, port, secure, auth });
  } catch { return null; }
}

async function sendHtml(to, subject, html, text) {
  // Prefer Graph/MSAL if configured
  const graphRes = await sendViaGraph(to, subject, html, text);
  if (graphRes && graphRes.ok) return graphRes;
  // Fallback to SMTP
  const from = process.env.SMTP_FROM || 'no-reply@localhost';
  const transport = getTransport();
  if (!transport) {
    // Fallback to console logging
    try { console.log(`[MAIL:FALLBACK] To: ${to}, Subj: ${subject}`); } catch {}
    return { ok: false, fallback: true };
  }
  const message = { from, to, subject, html, text: text || undefined };
  await transport.sendMail(message);
  return { ok: true };
}

async function sendOnboardingEmail(email, name, link) {
  const brand = process.env.BRAND_NAME || process.env.REACT_APP_BRAND_NAME || 'Acknowledgement Portal';
  const subject = `Complete your onboarding to ${brand}`;
  const html = `
    <div style="font-family:Segoe UI,Tahoma,Arial,sans-serif">
      <h2 style="margin:0 0 12px 0">Set your password</h2>
      <p>Hello ${name || email},</p>
      <p>Welcome to ${brand}. Click the button below to set your password and finish onboarding.</p>
      <p style="margin:16px 0"><a href="${link}" style="background:#0c5343;color:#fff;padding:10px 14px;text-decoration:none;border-radius:6px" target="_blank" rel="noopener">Set Password</a></p>
      <p style="color:#666;font-size:12px">If the button does not work, copy this link into your browser:<br/><span style="word-break:break-all;color:#444">${link}</span></p>
    </div>`;
  const text = `Hello ${name || email},\n\nWelcome to ${brand}. Open this link to set your password: ${link}`;
  return sendHtml(email, subject, html, text);
}

module.exports = { sendHtml, sendOnboardingEmail };
