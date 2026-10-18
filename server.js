// Elijah & Blessed — gate check-in app.
// Ushers sign in with a shared PIN, scan or type an invitation code (or find a guest by name),
// and record arrivals. All ushers share one check-in record in Postgres.
//
// Environment:
//   DATABASE_URL    Postgres connection string (Render sets this from the blueprint)
//   GATE_PIN        PIN ushers enter to use the app
//   ADMIN_PIN       PIN for the admin view (totals, export, undo any entry)
//   SESSION_SECRET  random string used to sign sign-in cookies
//   PGSSL=1         set only if your database needs SSL (Render's internal URL does not)

const express = require('express');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { Pool } = require('pg');

const { DATABASE_URL, GATE_PIN, ADMIN_PIN, SESSION_SECRET } = process.env;
if (!DATABASE_URL || !GATE_PIN || !SESSION_SECRET) {
  console.error('Missing DATABASE_URL, GATE_PIN or SESSION_SECRET.');
  process.exit(1);
}

// Guest list: card number, name on the card, admits, and a SHA-256 of the invitation code
// (the codes themselves are not stored here).
const GUESTS = JSON.parse(fs.readFileSync(path.join(__dirname, 'guests.json'), 'utf8'));
const byNo = new Map(GUESTS.map((g) => [g.no, g]));
const sha = (s) => crypto.createHash('sha256').update(s).digest('hex');

const pool = new Pool({ connectionString: DATABASE_URL, ssl: process.env.PGSSL ? { rejectUnauthorized: false } : false, max: 5 });

async function migrate() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS checkins (no text PRIMARY KEY, count int NOT NULL DEFAULT 0, updated_at timestamptz NOT NULL DEFAULT now());
    CREATE TABLE IF NOT EXISTS entries (id bigserial PRIMARY KEY, no text NOT NULL, n int NOT NULL, usher text, undone boolean NOT NULL DEFAULT false, at timestamptz NOT NULL DEFAULT now());
    CREATE INDEX IF NOT EXISTS entries_at ON entries (at DESC);
  `);
}

// --- sessions: signed cookie "role.usher.expiry.sig" ---
const sign = (v) => crypto.createHmac('sha256', SESSION_SECRET).update(v).digest('base64url');
function makeSession(role, usher) {
  const v = `${role}.${Buffer.from(usher).toString('base64url')}.${Date.now() + 1000 * 60 * 60 * 24 * 3}`;
  return `${v}.${sign(v)}`;
}
function readSession(req) {
  const m = /(?:^|;\s*)gate=([^;]+)/.exec(req.headers.cookie || '');
  if (!m) return null;
  const parts = decodeURIComponent(m[1]).split('.');
  if (parts.length !== 4) return null;
  const v = parts.slice(0, 3).join('.');
  const a = Buffer.from(sign(v)), b = Buffer.from(parts[3]);
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return null;
  if (Number(parts[2]) < Date.now()) return null;
  return { role: parts[0], usher: Buffer.from(parts[1], 'base64url').toString() };
}
const safeEq = (x, y) => { const a = sha(String(x)), b = sha(String(y)); return crypto.timingSafeEqual(Buffer.from(a), Buffer.from(b)); };

// Slow down PIN guessing: 8 tries per 10 minutes per IP.
const tries = new Map();
function limited(ip) {
  const now = Date.now(), t = (tries.get(ip) || []).filter((x) => now - x < 600000);
  tries.set(ip, t);
  return t.length >= 8;
}

const app = express();
app.set('trust proxy', 1);
app.use(express.json({ limit: '10kb' }));
app.use((req, res, next) => { res.set('X-Content-Type-Options', 'nosniff'); res.set('Referrer-Policy', 'no-referrer'); next(); });
app.use(express.static(path.join(__dirname, 'public'), { extensions: ['html'] }));

app.post('/api/login', (req, res) => {
  const ip = req.ip;
  if (limited(ip)) return res.status(429).json({ error: 'Too many tries. Wait 10 minutes and try again.' });
  const pin = String(req.body.pin || '').trim();
  const usher = String(req.body.usher || '').trim().slice(0, 40) || 'Usher';
  let role = null;
  if (ADMIN_PIN && safeEq(pin, ADMIN_PIN)) role = 'admin';
  else if (safeEq(pin, GATE_PIN)) role = 'usher';
  if (!role) { tries.get(ip).push(Date.now()); return res.status(401).json({ error: 'That PIN is not right.' }); }
  res.set('Set-Cookie', `gate=${encodeURIComponent(makeSession(role, usher))}; Path=/; HttpOnly; SameSite=Strict; Max-Age=259200${req.secure ? '; Secure' : ''}`);
  res.json({ role, usher });
});
app.post('/api/logout', (req, res) => { res.set('Set-Cookie', 'gate=; Path=/; Max-Age=0'); res.json({ ok: true }); });

function auth(level) {
  return (req, res, next) => {
    const s = readSession(req);
    if (!s) return res.status(401).json({ error: 'Sign in again.' });
    if (level === 'admin' && s.role !== 'admin') return res.status(403).json({ error: 'Admin PIN needed.' });
    req.session = s; next();
  };
}

app.get('/api/me', auth('usher'), (req, res) => res.json(req.session));

app.get('/api/state', auth('usher'), async (req, res) => {
  const { rows } = await pool.query('SELECT no, count FROM checkins WHERE count > 0');
  const recent = (await pool.query('SELECT no, n, usher, at FROM entries ORDER BY id DESC LIMIT 20')).rows;
  const inMap = Object.fromEntries(rows.map((r) => [r.no, r.count]));
  res.json({
    guests: GUESTS.map((g) => ({ no: g.no, name: g.name, admits: g.admits, in: inMap[g.no] || 0 })),
    recent,
  });
});

// Check a scanned or typed code. Codes look like 073-3QJ3N.
app.post('/api/verify', auth('usher'), (req, res) => {
  const m = String(req.body.code || '').toUpperCase().match(/(\d{3})\s*-\s*([A-HJ-NP-Z2-9]{5})/);
  if (!m) return res.json({ valid: false, reason: 'format' });
  const g = byNo.get(m[1]);
  if (!g || g.codeHash !== sha(`${m[1]}-${m[2]}`)) return res.json({ valid: false, reason: 'unknown', code: `${m[1]}-${m[2]}` });
  res.json({ valid: true, no: g.no });
});

// Record arrivals (n > 0) or remove the last entry (undo). Capped at the card's admits, safe when ushers act at once.
app.post('/api/checkin', auth('usher'), async (req, res) => {
  const g = byNo.get(String(req.body.no));
  const n = parseInt(req.body.n, 10);
  if (!g || !Number.isInteger(n) || n < 1 || n > 20) return res.status(400).json({ error: 'Unknown card.' });
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    await client.query('INSERT INTO checkins (no, count) VALUES ($1, 0) ON CONFLICT (no) DO NOTHING', [g.no]);
    const cur = (await client.query('SELECT count FROM checkins WHERE no = $1 FOR UPDATE', [g.no])).rows[0].count;
    const add = Math.min(n, g.admits - cur);
    if (add <= 0) { await client.query('ROLLBACK'); return res.status(409).json({ error: `All ${g.admits} places on this card are already used.`, in: cur }); }
    await client.query('UPDATE checkins SET count = count + $2, updated_at = now() WHERE no = $1', [g.no, add]);
    await client.query('INSERT INTO entries (no, n, usher) VALUES ($1, $2, $3)', [g.no, add, req.session.usher]);
    await client.query('COMMIT');
    res.json({ in: cur + add, added: add });
  } catch (e) { await client.query('ROLLBACK').catch(() => {}); console.error(e); res.status(500).json({ error: 'Could not save. Try again.' }); }
  finally { client.release(); }
});

app.post('/api/undo', auth('usher'), async (req, res) => {
  const g = byNo.get(String(req.body.no));
  if (!g) return res.status(400).json({ error: 'Unknown card.' });
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const last = (await client.query('SELECT id, n FROM entries WHERE no = $1 AND n > 0 AND NOT undone ORDER BY id DESC LIMIT 1 FOR UPDATE', [g.no])).rows[0];
    if (!last) { await client.query('ROLLBACK'); return res.status(409).json({ error: 'Nothing to undo.' }); }
    await client.query('UPDATE checkins SET count = GREATEST(0, count - $2), updated_at = now() WHERE no = $1', [g.no, last.n]);
    await client.query('INSERT INTO entries (no, n, usher) VALUES ($1, $2, $3)', [g.no, -last.n, req.session.usher]);
    await client.query('UPDATE entries SET undone = true WHERE id = $1', [last.id]);
    await client.query('COMMIT');
    res.json({ ok: true });
  } catch (e) { await client.query('ROLLBACK').catch(() => {}); console.error(e); res.status(500).json({ error: 'Could not undo. Try again.' }); }
  finally { client.release(); }
});

// Admin: full arrivals as CSV.
app.get('/api/export.csv', auth('admin'), async (req, res) => {
  const { rows } = await pool.query('SELECT no, count, updated_at FROM checkins');
  const m = Object.fromEntries(rows.map((r) => [r.no, r]));
  const q = (v) => `"${String(v ?? '').replace(/"/g, '""')}"`;
  const lines = ['Card,Name,Admits,Arrived,Last update'].concat(GUESTS.map((g) => [g.no, g.name.replace(/\n/g, ' '), g.admits, m[g.no]?.count || 0, m[g.no]?.updated_at?.toISOString() || ''].map(q).join(',')));
  res.set('Content-Type', 'text/csv; charset=utf-8');
  res.set('Content-Disposition', 'attachment; filename="wedding-arrivals.csv"');
  res.send(lines.join('\n') + '\n');
});

app.get('/healthz', (req, res) => res.send('ok'));

migrate().then(() => {
  const port = process.env.PORT || 3000;
  app.listen(port, () => console.log(`Gate app on :${port} with ${GUESTS.length} cards`));
}).catch((e) => { console.error('Database setup failed:', e.message); process.exit(1); });
