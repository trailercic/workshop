require('dotenv').config();
const express = require('express');
const cookieParser = require('cookie-parser');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const path = require('path');
const { pool, initDb } = require('./db');

const app = express();
app.set('trust proxy', 1);
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET;

if (!JWT_SECRET) {
  console.error('ERROR: JWT_SECRET is not set in environment variables. Set it before running in production.');
}

app.use(express.json());
app.use((req, res, next) => {
  res.setHeader('X-Robots-Tag', 'noindex, nofollow, noarchive');
  next();
});
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

// ---------- helpers ----------
function signToken(user) {
  return jwt.sign({ username: user.username, role: user.role }, JWT_SECRET || 'dev-only-secret-change-me', {
    expiresIn: '12h',
  });
}

function requireAuth(req, res, next) {
  const token = req.cookies.token;
  if (!token) return res.status(401).json({ error: 'You are not logged in.' });
  try {
    req.user = jwt.verify(token, JWT_SECRET || 'dev-only-secret-change-me');
    next();
  } catch (e) {
    return res.status(401).json({ error: 'Your session has expired, please log in again.' });
  }
}

function requireRole(...roles) {
  return (req, res, next) => {
    if (!roles.includes(req.user.role)) {
      return res.status(403).json({ error: 'You do not have permission for this action.' });
    }
    next();
  };
}

async function logEvent(orderId, action, actor, detail) {
  await pool.query(
    'INSERT INTO order_events (order_id, action, actor, detail, created_at) VALUES ($1,$2,$3,$4,$5)',
    [orderId, action, actor, detail || null, Date.now()]
  );
}

const COOKIE_OPTS = {
  httpOnly: true,
  sameSite: 'lax',
  secure: process.env.NODE_ENV === 'production',
  maxAge: 12 * 60 * 60 * 1000,
};

// ---------- auth routes ----------
// Simple in-memory brute-force guard: after 6 failed attempts from the same
// IP within 10 minutes, further logins are blocked for that window.
const loginAttempts = new Map(); // ip -> { count, firstAttempt }
const LOGIN_MAX_ATTEMPTS = 6;
const LOGIN_WINDOW_MS = 10 * 60 * 1000;

function isRateLimited(ip) {
  const entry = loginAttempts.get(ip);
  if (!entry) return false;
  if (Date.now() - entry.firstAttempt > LOGIN_WINDOW_MS) {
    loginAttempts.delete(ip);
    return false;
  }
  return entry.count >= LOGIN_MAX_ATTEMPTS;
}

function recordFailedAttempt(ip) {
  const entry = loginAttempts.get(ip);
  if (!entry || Date.now() - entry.firstAttempt > LOGIN_WINDOW_MS) {
    loginAttempts.set(ip, { count: 1, firstAttempt: Date.now() });
  } else {
    entry.count += 1;
  }
}

app.post('/api/login', async (req, res) => {
  const ip = req.ip;
  if (isRateLimited(ip)) {
    return res.status(429).json({ error: 'Too many failed attempts. Try again in a few minutes.' });
  }

  const { username, password } = req.body || {};
  if (!username || !password) return res.status(400).json({ error: 'Enter your username and password.' });

  const { rows } = await pool.query('SELECT * FROM users WHERE lower(username) = lower($1)', [username]);
  const user = rows[0];
  if (!user) {
    recordFailedAttempt(ip);
    return res.status(401).json({ error: 'Incorrect username or password.' });
  }

  const ok = await bcrypt.compare(password, user.pass_hash);
  if (!ok) {
    recordFailedAttempt(ip);
    return res.status(401).json({ error: 'Incorrect username or password.' });
  }

  loginAttempts.delete(ip);
  const token = signToken(user);
  res.cookie('token', token, COOKIE_OPTS);
  res.json({ username: user.username, role: user.role });
});

app.post('/api/logout', (req, res) => {
  res.clearCookie('token', COOKIE_OPTS);
  res.json({ ok: true });
});

app.get('/api/me', requireAuth, (req, res) => {
  res.json({ username: req.user.username, role: req.user.role });
});

// ---------- orders routes ----------
// Public, read-only board for the "screen" role — no login required.
// Intended for a TV/tablet permanently showing the warehouse display.
app.get('/api/public/board', async (req, res) => {
  const { rows } = await pool.query('SELECT * FROM orders WHERE issued_at IS NULL ORDER BY created_at ASC');
  res.json(rows);
});

app.get('/api/orders', requireAuth, async (req, res) => {
  const { rows } = await pool.query('SELECT * FROM orders WHERE issued_at IS NULL ORDER BY created_at ASC');
  res.json(rows);
});

app.post('/api/orders', requireAuth, async (req, res) => {
  const { serviceOrder, items, note, priority } = req.body || {};

  if (!Array.isArray(items) || items.length === 0) {
    return res.status(400).json({ error: 'Add at least one part.' });
  }

  const cleanItems = [];
  for (const raw of items) {
    const part = (raw && raw.part ? String(raw.part) : '').trim();
    if (!part) continue;
    const qty = Math.max(1, parseInt(raw.qty, 10) || 1);
    cleanItems.push({ part, qty, state: 'none' });
  }
  if (cleanItems.length === 0) {
    return res.status(400).json({ error: 'Add at least one part with a name.' });
  }

  const id = Date.now().toString(36).toUpperCase() + Math.random().toString(36).slice(2, 5).toUpperCase();
  const createdAt = Date.now();
  const safePriority = priority === 'hitno' ? 'hitno' : 'normal';

  const userRow = await pool.query('SELECT location FROM users WHERE username = $1', [req.user.username]);
  const location = userRow.rows[0]?.location || 'SOHO';

  await pool.query(
    `INSERT INTO orders (id, service_order, requester, note, priority, status, items, location, created_at)
     VALUES ($1,$2,$3,$4,$5,'novo',$6,$7,$8)`,
    [id, (serviceOrder || '').trim(), req.user.username, (note || '').trim(), safePriority, JSON.stringify(cleanItems), location, createdAt]
  );

  await logEvent(id, 'created', req.user.username, (serviceOrder || '').trim() || null);

  res.json({ id, ticket: '#' + id.slice(-6) });
});

const ITEM_STATE_CYCLE = ['none', 'green', 'yellow', 'red'];

app.patch('/api/orders/:id/items/:index', requireAuth, requireRole('magacioner', 'admin'), async (req, res) => {
  const { id, index } = req.params;
  const idx = parseInt(index, 10);

  const { rows } = await pool.query('SELECT items FROM orders WHERE id = $1', [id]);
  if (!rows.length) return res.status(404).json({ error: 'Order not found.' });

  const items = Array.isArray(rows[0].items) ? rows[0].items : [];
  if (!items[idx]) return res.status(400).json({ error: 'Invalid item.' });

  const currentState = items[idx].state || 'none';
  const nextState = ITEM_STATE_CYCLE[(ITEM_STATE_CYCLE.indexOf(currentState) + 1) % ITEM_STATE_CYCLE.length];
  items[idx] = { part: items[idx].part, qty: items[idx].qty, state: nextState };

  await pool.query('UPDATE orders SET items = $1 WHERE id = $2', [JSON.stringify(items), id]);
  await logEvent(id, 'item_marked', req.user.username, `${items[idx].part}: ${nextState}`);

  res.json({ ok: true, items });
});

const STATUS_ACTION_LABEL = {
  u_obradi: 'claimed',
  ceka_delove: 'waiting',
  spremno: 'ready',
};

const STATUS_DISPLAY_NAME = {
  novo: 'New',
  u_obradi: 'In Progress',
  ceka_delove: 'Waiting for Parts',
  spremno: 'Ready',
};

app.patch('/api/orders/:id', requireAuth, requireRole('magacioner', 'admin'), async (req, res) => {
  const { status, expectedStatus } = req.body || {};
  if (!['novo', 'u_obradi', 'ceka_delove', 'spremno'].includes(status)) {
    return res.status(400).json({ error: 'Invalid status.' });
  }

  const prevRow = await pool.query('SELECT status FROM orders WHERE id = $1', [req.params.id]);
  if (!prevRow.rows.length) return res.status(404).json({ error: 'Order not found.' });
  const prevStatus = prevRow.rows[0].status;

  if (expectedStatus && expectedStatus !== prevStatus) {
    const lastEvent = await pool.query(
      'SELECT actor FROM order_events WHERE order_id = $1 ORDER BY created_at DESC LIMIT 1',
      [req.params.id]
    );
    const actor = lastEvent.rows[0]?.actor || 'someone else';
    return res.status(409).json({
      error: `Already updated by ${actor} — now: ${STATUS_DISPLAY_NAME[prevStatus] || prevStatus}.`,
      currentStatus: prevStatus,
    });
  }

  await pool.query('UPDATE orders SET status = $1 WHERE id = $2', [status, req.params.id]);

  const label = status === 'u_obradi' && prevStatus === 'ceka_delove' ? 'resumed' : STATUS_ACTION_LABEL[status];
  if (label && status !== prevStatus) {
    await logEvent(req.params.id, label, req.user.username);
  }

  res.json({ ok: true });
});

app.patch('/api/orders/:id/note', requireAuth, requireRole('magacioner', 'admin'), async (req, res) => {
  const { note } = req.body || {};
  const cleanNote = (note || '').toString().trim();

  const { rows } = await pool.query('SELECT id FROM orders WHERE id = $1', [req.params.id]);
  if (!rows.length) return res.status(404).json({ error: 'Order not found.' });

  await pool.query('UPDATE orders SET note = $1 WHERE id = $2', [cleanNote, req.params.id]);
  await logEvent(req.params.id, 'note_updated', req.user.username, cleanNote || '(cleared)');

  res.json({ ok: true, note: cleanNote });
});

app.post('/api/orders/:id/issue', requireAuth, requireRole('magacioner', 'admin'), async (req, res) => {
  const { rows } = await pool.query('SELECT status FROM orders WHERE id = $1', [req.params.id]);
  if (!rows.length) return res.status(404).json({ error: 'Order not found.' });

  const issuedAt = Date.now();
  await pool.query('UPDATE orders SET issued_by = $1, issued_at = $2 WHERE id = $3', [req.user.username, issuedAt, req.params.id]);
  await logEvent(req.params.id, 'issued', req.user.username);

  res.json({ ok: true });
});

// ---------- history (admin only) ----------
// ---------- backup (admin only) ----------
// Supabase's free tier has no automated backups, so this lets an admin
// download a full snapshot of the data on demand.
app.get('/api/backup', requireAuth, requireRole('admin'), async (req, res) => {
  const [usersRes, ordersRes, eventsRes] = await Promise.all([
    pool.query('SELECT username, role, location, created_at FROM users ORDER BY created_at ASC'),
    pool.query('SELECT * FROM orders ORDER BY created_at ASC'),
    pool.query('SELECT * FROM order_events ORDER BY created_at ASC'),
  ]);

  const backup = {
    generated_at: new Date().toISOString(),
    users: usersRes.rows,
    orders: ordersRes.rows,
    order_events: eventsRes.rows,
  };

  res.setHeader('Content-Disposition', `attachment; filename="backup-${new Date().toISOString().slice(0, 10)}.json"`);
  res.json(backup);
});

app.get('/api/history', requireAuth, requireRole('admin'), async (req, res) => {
  const { rows: orders } = await pool.query(
    'SELECT * FROM orders WHERE issued_at IS NOT NULL ORDER BY issued_at DESC LIMIT 200'
  );
  if (orders.length === 0) return res.json([]);

  const ids = orders.map((o) => o.id);
  const { rows: events } = await pool.query(
    'SELECT * FROM order_events WHERE order_id = ANY($1) ORDER BY created_at ASC',
    [ids]
  );

  const eventsByOrder = {};
  events.forEach((e) => {
    if (!eventsByOrder[e.order_id]) eventsByOrder[e.order_id] = [];
    eventsByOrder[e.order_id].push(e);
  });

  res.json(orders.map((o) => ({ ...o, events: eventsByOrder[o.id] || [] })));
});

// ---------- user management (admin only) ----------
app.get('/api/users', requireAuth, requireRole('admin'), async (req, res) => {
  const { rows } = await pool.query('SELECT username, role, location, pass_hash, created_at FROM users ORDER BY created_at ASC');
  const out = await Promise.all(rows.map(async (u) => {
    let warnDefault = false;
    if (u.username === 'admin') {
      warnDefault = await bcrypt.compare('admin123', u.pass_hash);
    }
    return { username: u.username, role: u.role, location: u.location, created_at: u.created_at, warn_default: warnDefault };
  }));
  res.json(out);
});

app.post('/api/users', requireAuth, requireRole('admin'), async (req, res) => {
  const { username, password, role, location } = req.body || {};
  if (!username || !password) return res.status(400).json({ error: 'Fill in username and password.' });
  if (password.length < 4) return res.status(400).json({ error: 'Password must be at least 4 characters.' });
  if (!['narucilac', 'magacioner', 'admin'].includes(role)) return res.status(400).json({ error: 'Invalid role.' });

  let safeLocation = null;
  if (role === 'narucilac') {
    if (!['SOHO', 'MEPA'].includes(location)) return res.status(400).json({ error: 'Invalid location.' });
    safeLocation = location;
  }

  const existing = await pool.query('SELECT username FROM users WHERE lower(username) = lower($1)', [username]);
  if (existing.rows.length) return res.status(409).json({ error: 'Username already exists.' });

  const hash = await bcrypt.hash(password, 10);
  await pool.query('INSERT INTO users (username, pass_hash, role, location) VALUES ($1,$2,$3,$4)', [username.trim(), hash, role, safeLocation]);
  res.json({ ok: true });
});

app.patch('/api/users/:username', requireAuth, requireRole('admin'), async (req, res) => {
  const { password } = req.body || {};
  if (!password || password.length < 4) return res.status(400).json({ error: 'Password must be at least 4 characters.' });
  const hash = await bcrypt.hash(password, 10);
  await pool.query('UPDATE users SET pass_hash = $1 WHERE username = $2', [hash, req.params.username]);
  res.json({ ok: true });
});

app.delete('/api/users/:username', requireAuth, requireRole('admin'), async (req, res) => {
  const target = req.params.username;
  const adminCountRes = await pool.query("SELECT COUNT(*)::int AS n FROM users WHERE role = 'admin'");
  const targetRes = await pool.query('SELECT role FROM users WHERE username = $1', [target]);
  if (!targetRes.rows.length) return res.status(404).json({ error: 'User does not exist.' });

  if (targetRes.rows[0].role === 'admin' && adminCountRes.rows[0].n <= 1) {
    return res.status(400).json({ error: 'The last admin account cannot be deleted.' });
  }

  await pool.query('DELETE FROM users WHERE username = $1', [target]);
  if (target === req.user.username) res.clearCookie('token', COOKIE_OPTS);
  res.json({ ok: true, self: target === req.user.username });
});

// ---------- fallback to SPA ----------
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

initDb()
  .then(() => {
    app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
  })
  .catch((err) => {
    console.error('Database connection error:', err);
    process.exit(1);
  });
