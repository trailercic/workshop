require('dotenv').config();
const express = require('express');
const cookieParser = require('cookie-parser');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const path = require('path');
const { pool, initDb } = require('./db');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET;

if (!JWT_SECRET) {
  console.error('ERROR: JWT_SECRET is not set in environment variables. Set it before running in production.');
}

app.use(express.json());
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

const COOKIE_OPTS = {
  httpOnly: true,
  sameSite: 'lax',
  secure: process.env.NODE_ENV === 'production',
  maxAge: 12 * 60 * 60 * 1000,
};

// ---------- auth routes ----------
app.post('/api/login', async (req, res) => {
  const { username, password } = req.body || {};
  if (!username || !password) return res.status(400).json({ error: 'Enter your username and password.' });

  const { rows } = await pool.query('SELECT * FROM users WHERE lower(username) = lower($1)', [username]);
  const user = rows[0];
  if (!user) return res.status(401).json({ error: 'Incorrect username or password.' });

  const ok = await bcrypt.compare(password, user.pass_hash);
  if (!ok) return res.status(401).json({ error: 'Incorrect username or password.' });

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
app.get('/api/orders', requireAuth, async (req, res) => {
  const { rows } = await pool.query('SELECT * FROM orders ORDER BY created_at ASC');
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
    cleanItems.push({ part, qty });
  }
  if (cleanItems.length === 0) {
    return res.status(400).json({ error: 'Add at least one part with a name.' });
  }

  const id = Date.now().toString(36).toUpperCase() + Math.random().toString(36).slice(2, 5).toUpperCase();
  const createdAt = Date.now();
  const safePriority = priority === 'hitno' ? 'hitno' : 'normal';

  await pool.query(
    `INSERT INTO orders (id, service_order, requester, note, priority, status, items, created_at)
     VALUES ($1,$2,$3,$4,$5,'novo',$6,$7)`,
    [id, (serviceOrder || '').trim(), req.user.username, (note || '').trim(), safePriority, JSON.stringify(cleanItems), createdAt]
  );

  res.json({ id, ticket: '#' + id.slice(-6) });
});

app.patch('/api/orders/:id', requireAuth, requireRole('magacioner', 'admin'), async (req, res) => {
  const { status } = req.body || {};
  if (!['novo', 'u_obradi', 'spremno'].includes(status)) {
    return res.status(400).json({ error: 'Invalid status.' });
  }
  await pool.query('UPDATE orders SET status = $1 WHERE id = $2', [status, req.params.id]);
  res.json({ ok: true });
});

app.delete('/api/orders/:id', requireAuth, requireRole('magacioner', 'admin'), async (req, res) => {
  await pool.query('DELETE FROM orders WHERE id = $1', [req.params.id]);
  res.json({ ok: true });
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
  if (!['SOHO', 'MEPA'].includes(location)) return res.status(400).json({ error: 'Invalid location.' });

  const existing = await pool.query('SELECT username FROM users WHERE lower(username) = lower($1)', [username]);
  if (existing.rows.length) return res.status(409).json({ error: 'Username already exists.' });

  const hash = await bcrypt.hash(password, 10);
  await pool.query('INSERT INTO users (username, pass_hash, role, location) VALUES ($1,$2,$3,$4)', [username.trim(), hash, role, location]);
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
