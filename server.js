require('dotenv').config();
const express = require('express');
const cookieParser = require('cookie-parser');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const path = require('path');
const RingCentralSDK = require('@ringcentral/sdk').SDK;
const { pool, initDb } = require('./db');

const app = express();
app.set('trust proxy', 1);
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET;

if (!JWT_SECRET) {
  console.error('ERROR: JWT_SECRET is not set in environment variables. Set it before running in production.');
}

app.use(express.json({ limit: '2mb' }));
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

// ---------- ticket locks (in-memory, so only one person edits at a time) ----------
const ticketLocks = new Map(); // orderId -> { username, lockedAt }
const LOCK_TIMEOUT_MS = 5 * 60 * 1000; // stale locks (crashed tab, lost connection) expire after 5 min

function getActiveLock(orderId) {
  const lock = ticketLocks.get(orderId);
  if (!lock) return null;
  if (Date.now() - lock.lockedAt > LOCK_TIMEOUT_MS) {
    ticketLocks.delete(orderId);
    return null;
  }
  return lock;
}

function attachLockInfo(rows) {
  return rows.map((r) => {
    const lock = getActiveLock(r.id);
    return { ...r, locked_by: lock ? lock.username : null };
  });
}

// ---------- live updates (Server-Sent Events) ----------
// Broadcasts a lightweight "something changed" signal to every connected
// screen/browser so boards refresh immediately instead of waiting for the
// next poll. No order data is sent through this channel — clients still
// fetch the actual data via the existing REST routes.
const sseClients = new Set();

function broadcastUpdate() {
  for (const client of sseClients) {
    client.write('data: update\n\n');
  }
}

setInterval(() => {
  for (const client of sseClients) {
    client.write(': keep-alive\n\n');
  }
}, 25000);

app.get('/api/events', (req, res) => {
  res.set({
    'Content-Type': 'text/event-stream',
    'Cache-Control': 'no-cache',
    Connection: 'keep-alive',
  });
  res.flushHeaders();
  res.write('data: connected\n\n');

  sseClients.add(res);
  req.on('close', () => sseClients.delete(res));
});

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
  res.json({ username: user.username, role: user.role, canManageOwnTickets: !!user.can_manage_own_tickets });
});

app.post('/api/logout', (req, res) => {
  res.clearCookie('token', COOKIE_OPTS);
  res.json({ ok: true });
});

app.get('/api/me', requireAuth, async (req, res) => {
  const { rows } = await pool.query('SELECT can_manage_own_tickets FROM users WHERE username = $1', [req.user.username]);
  res.json({
    username: req.user.username,
    role: req.user.role,
    canManageOwnTickets: !!(rows[0] && rows[0].can_manage_own_tickets),
  });
});

// ---------- orders routes ----------
const ACTIVE_BOARD_WHERE = "issued_at IS NULL AND cancelled_at IS NULL AND (is_estimate = false OR estimate_approved_at IS NOT NULL)";

// Public, read-only board for the "screen" role — no login required.
// Intended for a TV/tablet permanently showing the warehouse display.
app.get('/api/public/board', async (req, res) => {
  const { rows } = await pool.query(`SELECT * FROM orders WHERE ${ACTIVE_BOARD_WHERE} ORDER BY created_at ASC`);
  res.json(attachLockInfo(rows));
});

app.get('/api/orders', requireAuth, async (req, res) => {
  const { rows } = await pool.query(`SELECT * FROM orders WHERE ${ACTIVE_BOARD_WHERE} ORDER BY created_at ASC`);
  res.json(attachLockInfo(rows));
});

// Estimator queue: orders flagged as an estimate, waiting for approval.
app.get('/api/estimates', requireAuth, requireRole('estimator', 'admin'), async (req, res) => {
  const { rows } = await pool.query(
    "SELECT * FROM orders WHERE is_estimate = true AND estimate_approved_at IS NULL AND issued_at IS NULL AND cancelled_at IS NULL ORDER BY created_at ASC"
  );
  res.json(rows);
});

app.post('/api/orders/:id/approve-estimate', requireAuth, requireRole('estimator', 'admin'), async (req, res) => {
  const { rows } = await pool.query('SELECT id, is_estimate, estimate_approved_at FROM orders WHERE id = $1', [req.params.id]);
  if (!rows.length) return res.status(404).json({ error: 'Order not found.' });
  if (!rows[0].is_estimate) return res.status(400).json({ error: 'This order is not an estimate.' });
  if (rows[0].estimate_approved_at) return res.status(400).json({ error: 'This estimate was already approved.' });

  await pool.query(
    'UPDATE orders SET estimate_approved_by = $1, estimate_approved_at = $2 WHERE id = $3',
    [req.user.username, Date.now(), req.params.id]
  );
  await logEvent(req.params.id, 'estimate_approved', req.user.username);

  broadcastUpdate();
  res.json({ ok: true });
});

app.get('/api/my-orders', requireAuth, async (req, res) => {
  let canManageAll = req.user.role === 'admin';
  if (!canManageAll) {
    const perm = await pool.query('SELECT can_manage_own_tickets FROM users WHERE username = $1', [req.user.username]);
    canManageAll = !!(perm.rows[0] && perm.rows[0].can_manage_own_tickets);
  }

  if (!canManageAll) {
    return res.status(403).json({ error: 'You do not have permission to manage tickets.' });
  }

  // This permission grants oversight of every requester's tickets, not just
  // the caller's own — hence no "WHERE requester = ..." filter here.
  const { rows } = await pool.query('SELECT * FROM orders ORDER BY created_at DESC LIMIT 200');
  res.json(rows);
});

app.post('/api/orders/:id/lock', requireAuth, requireRole('magacioner', 'admin'), async (req, res) => {
  const id = req.params.id;
  const existing = getActiveLock(id);
  if (existing && existing.username !== req.user.username) {
    return res.status(409).json({ error: `Currently open by ${existing.username}.`, lockedBy: existing.username });
  }
  ticketLocks.set(id, { username: req.user.username, lockedAt: Date.now() });
  broadcastUpdate();
  res.json({ ok: true });
});

app.post('/api/orders/:id/unlock', requireAuth, requireRole('magacioner', 'admin'), async (req, res) => {
  const id = req.params.id;
  const existing = ticketLocks.get(id);
  if (existing && existing.username === req.user.username) {
    ticketLocks.delete(id);
  }
  broadcastUpdate();
  res.json({ ok: true });
});

app.post('/api/orders', requireAuth, async (req, res) => {
  const { serviceOrder, items, note, priority, isEstimate } = req.body || {};

  if (!Array.isArray(items) || items.length === 0) {
    return res.status(400).json({ error: 'Add at least one part.' });
  }

  const cleanItems = [];
  for (const raw of items) {
    const part = (raw && raw.part ? String(raw.part) : '').trim();
    if (!part) continue;
    const qty = Math.max(1, parseInt(raw.qty, 10) || 1);
    let photo = null;
    if (raw && raw.photo && typeof raw.photo === 'string' && raw.photo.startsWith('data:image/') && raw.photo.length <= 1_500_000) {
      photo = raw.photo;
    }
    cleanItems.push({ part, qty, state: 'none', photo });
  }
  if (cleanItems.length === 0) {
    return res.status(400).json({ error: 'Add at least one part with a name.' });
  }

  const cleanServiceOrder = (serviceOrder || '').trim();
  let finalServiceOrder = cleanServiceOrder;

  if (cleanServiceOrder) {
    const existingRows = await pool.query(
      `SELECT service_order FROM orders WHERE lower(service_order) = lower($1) OR lower(service_order) LIKE lower($1) || '/%'`,
      [cleanServiceOrder]
    );
    if (existingRows.rows.length) {
      let maxSuffix = 0;
      for (const row of existingRows.rows) {
        const so = row.service_order || '';
        const match = so.match(/\/(\d+)$/);
        if (match) {
          const n = parseInt(match[1], 10);
          if (n > maxSuffix) maxSuffix = n;
        }
      }
      finalServiceOrder = `${cleanServiceOrder}/${maxSuffix + 1}`;
    }
  }

  const id = Date.now().toString(36).toUpperCase() + Math.random().toString(36).slice(2, 5).toUpperCase();
  const createdAt = Date.now();
  const safePriority = priority === 'hitno' ? 'hitno' : 'normal';

  const userRow = await pool.query('SELECT location FROM users WHERE username = $1', [req.user.username]);
  const location = userRow.rows[0]?.location || 'SOHO';
  const safeIsEstimate = !!isEstimate;

  await pool.query(
    `INSERT INTO orders (id, service_order, requester, note, priority, status, items, location, is_estimate, created_at)
     VALUES ($1,$2,$3,$4,$5,'novo',$6,$7,$8,$9)`,
    [id, finalServiceOrder, req.user.username, (note || '').trim(), safePriority, JSON.stringify(cleanItems), location, safeIsEstimate, createdAt]
  );

  await logEvent(id, 'created', req.user.username, (finalServiceOrder ? finalServiceOrder : '(no SO)') + (safeIsEstimate ? ' — estimate' : ''));

  broadcastUpdate();
  res.json({ id, ticket: '#' + id.slice(-6), serviceOrder: finalServiceOrder, isEstimate: safeIsEstimate });
});

const ITEM_STATE_CYCLE = ['none', 'green', 'yellow', 'red'];

app.patch('/api/orders/:id/items/:index', requireAuth, requireRole('magacioner', 'admin'), async (req, res) => {
  const { id, index } = req.params;
  const idx = parseInt(index, 10);

  const { rows } = await pool.query('SELECT items FROM orders WHERE id = $1', [id]);
  if (!rows.length) return res.status(404).json({ error: 'Order not found.' });

  const items = Array.isArray(rows[0].items) ? rows[0].items : [];
  if (!items[idx]) return res.status(400).json({ error: 'Invalid item.' });
  if (items[idx].state === 'removed') return res.status(400).json({ error: 'This part was removed and can no longer be marked.' });

  const currentState = items[idx].state || 'none';
  const nextState = ITEM_STATE_CYCLE[(ITEM_STATE_CYCLE.indexOf(currentState) + 1) % ITEM_STATE_CYCLE.length];
  items[idx] = { ...items[idx], state: nextState };

  await pool.query('UPDATE orders SET items = $1 WHERE id = $2', [JSON.stringify(items), id]);
  await logEvent(id, 'item_marked', req.user.username, `${items[idx].part}: ${nextState}`);

  broadcastUpdate();
  res.json({ ok: true, items });
});

app.patch('/api/orders/:id/items/:index/photo', requireAuth, requireRole('magacioner', 'admin'), async (req, res) => {
  const { id, index } = req.params;
  const idx = parseInt(index, 10);
  const { photo } = req.body || {};

  if (photo && (typeof photo !== 'string' || !photo.startsWith('data:image/') || photo.length > 1_500_000)) {
    return res.status(400).json({ error: 'Invalid or oversized photo.' });
  }

  const { rows } = await pool.query('SELECT items FROM orders WHERE id = $1', [id]);
  if (!rows.length) return res.status(404).json({ error: 'Order not found.' });

  const items = Array.isArray(rows[0].items) ? rows[0].items : [];
  if (!items[idx]) return res.status(400).json({ error: 'Invalid item.' });

  items[idx] = { ...items[idx], photo: photo || null };

  await pool.query('UPDATE orders SET items = $1 WHERE id = $2', [JSON.stringify(items), id]);
  await logEvent(id, photo ? 'photo_added' : 'photo_removed', req.user.username, items[idx].part);

  broadcastUpdate();
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

  if (status === 'spremno' && prevStatus !== 'spremno') {
    await pool.query('UPDATE orders SET status = $1, ready_at = $2 WHERE id = $3', [status, Date.now(), req.params.id]);
  } else if (prevStatus === 'spremno' && status !== 'spremno') {
    await pool.query('UPDATE orders SET status = $1, ready_at = NULL WHERE id = $2', [status, req.params.id]);
  } else {
    await pool.query('UPDATE orders SET status = $1 WHERE id = $2', [status, req.params.id]);
  }

  const label =
    status === 'u_obradi' && prevStatus === 'ceka_delove' ? 'resumed' :
    status === 'u_obradi' && prevStatus === 'spremno' ? 'reopened' :
    STATUS_ACTION_LABEL[status];
  if (label && status !== prevStatus) {
    await logEvent(req.params.id, label, req.user.username);
  }

  broadcastUpdate();
  res.json({ ok: true });
});

app.patch('/api/orders/:id/note', requireAuth, requireRole('magacioner', 'admin'), async (req, res) => {
  const { note } = req.body || {};
  const cleanNote = (note || '').toString().trim();

  const { rows } = await pool.query('SELECT id FROM orders WHERE id = $1', [req.params.id]);
  if (!rows.length) return res.status(404).json({ error: 'Order not found.' });

  await pool.query('UPDATE orders SET note = $1 WHERE id = $2', [cleanNote, req.params.id]);
  await logEvent(req.params.id, 'note_updated', req.user.username, cleanNote || '(cleared)');

  broadcastUpdate();
  res.json({ ok: true, note: cleanNote });
});

app.post('/api/orders/:id/issue', requireAuth, requireRole('magacioner', 'admin'), async (req, res) => {
  const { rows } = await pool.query('SELECT status FROM orders WHERE id = $1', [req.params.id]);
  if (!rows.length) return res.status(404).json({ error: 'Order not found.' });

  const issuedAt = Date.now();
  await pool.query('UPDATE orders SET issued_by = $1, issued_at = $2 WHERE id = $3', [req.user.username, issuedAt, req.params.id]);
  await logEvent(req.params.id, 'issued', req.user.username);

  broadcastUpdate();
  res.json({ ok: true });
});

// A requester with the "can manage tickets" permission may withdraw ANY
// order, or remove a single part from ANY order, at any point before it's
// actually issued. Admins can always do this too.
async function canManageOrder(req, res, order) {
  if (!order) {
    res.status(404).json({ error: 'Order not found.' });
    return false;
  }
  if (req.user.role !== 'admin') {
    const { rows } = await pool.query('SELECT can_manage_own_tickets FROM users WHERE username = $1', [req.user.username]);
    if (!rows.length || !rows[0].can_manage_own_tickets) {
      res.status(403).json({ error: 'You do not have permission to manage tickets.' });
      return false;
    }
  }
  if (order.issued_at || order.cancelled_at) {
    res.status(400).json({ error: 'This order has already been completed and can no longer be changed.' });
    return false;
  }
  return true;
}

app.post('/api/orders/:id/cancel', requireAuth, async (req, res) => {
  const { rows } = await pool.query('SELECT * FROM orders WHERE id = $1', [req.params.id]);
  if (!(await canManageOrder(req, res, rows[0]))) return;

  await pool.query('UPDATE orders SET cancelled_by = $1, cancelled_at = $2 WHERE id = $3', [req.user.username, Date.now(), req.params.id]);
  await logEvent(req.params.id, 'cancelled', req.user.username);

  broadcastUpdate();
  res.json({ ok: true });
});

app.delete('/api/orders/:id/items/:index', requireAuth, async (req, res) => {
  const { rows } = await pool.query('SELECT * FROM orders WHERE id = $1', [req.params.id]);
  const order = rows[0];
  if (!(await canManageOrder(req, res, order))) return;

  const items = Array.isArray(order.items) ? [...order.items] : [];
  const idx = parseInt(req.params.index, 10);
  if (!items[idx]) return res.status(400).json({ error: 'Invalid item.' });
  if (items[idx].state === 'removed') return res.status(400).json({ error: 'This part was already removed.' });

  const activeCount = items.filter((it) => it.state !== 'removed').length;
  if (activeCount <= 1) {
    return res.status(400).json({ error: 'An order needs at least one active part — withdraw the whole order instead.' });
  }

  // Keep the item visible but marked, instead of deleting it outright, so
  // the warehouse can clearly see something was pulled from an order they
  // may already be working on.
  items[idx] = { part: items[idx].part, qty: items[idx].qty, state: 'removed', removedBy: req.user.username };

  let newStatus = order.status;
  if (order.status === 'ceka_delove' || order.status === 'spremno') {
    newStatus = 'u_obradi';
  }

  await pool.query('UPDATE orders SET items = $1, status = $2 WHERE id = $3', [JSON.stringify(items), newStatus, req.params.id]);
  await logEvent(req.params.id, 'item_removed', req.user.username, items[idx].part);
  if (newStatus !== order.status) {
    await logEvent(req.params.id, 'returned_to_progress', req.user.username, `"${items[idx].part}" was removed`);
  }

  broadcastUpdate();
  res.json({ ok: true, items, status: newStatus });
});

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
    "SELECT * FROM orders WHERE issued_at IS NOT NULL OR cancelled_at IS NOT NULL ORDER BY COALESCE(issued_at, cancelled_at) DESC LIMIT 200"
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
  const { rows } = await pool.query('SELECT username, role, location, can_manage_own_tickets, pass_hash, created_at FROM users ORDER BY created_at ASC');
  const out = await Promise.all(rows.map(async (u) => {
    let warnDefault = false;
    if (u.username === 'admin') {
      warnDefault = await bcrypt.compare('admin123', u.pass_hash);
    }
    return {
      username: u.username, role: u.role, location: u.location,
      canManageOwnTickets: !!u.can_manage_own_tickets,
      created_at: u.created_at, warn_default: warnDefault,
    };
  }));
  res.json(out);
});

app.post('/api/users', requireAuth, requireRole('admin'), async (req, res) => {
  const { username, password, role, location, canManageOwnTickets } = req.body || {};
  if (!username || !password) return res.status(400).json({ error: 'Fill in username and password.' });
  if (password.length < 4) return res.status(400).json({ error: 'Password must be at least 4 characters.' });
  if (!['narucilac', 'magacioner', 'admin', 'estimator'].includes(role)) return res.status(400).json({ error: 'Invalid role.' });

  let safeLocation = null;
  let safeCanManage = false;
  if (role === 'narucilac') {
    if (!['SOHO', 'MEPA'].includes(location)) return res.status(400).json({ error: 'Invalid location.' });
    safeLocation = location;
    safeCanManage = !!canManageOwnTickets;
  }

  const existing = await pool.query('SELECT username FROM users WHERE lower(username) = lower($1)', [username]);
  if (existing.rows.length) return res.status(409).json({ error: 'Username already exists.' });

  const hash = await bcrypt.hash(password, 10);
  await pool.query(
    'INSERT INTO users (username, pass_hash, role, location, can_manage_own_tickets) VALUES ($1,$2,$3,$4,$5)',
    [username.trim(), hash, role, safeLocation, safeCanManage]
  );
  res.json({ ok: true });
});

app.patch('/api/users/:username', requireAuth, requireRole('admin'), async (req, res) => {
  const { password } = req.body || {};
  if (!password || password.length < 4) return res.status(400).json({ error: 'Password must be at least 4 characters.' });
  const hash = await bcrypt.hash(password, 10);
  await pool.query('UPDATE users SET pass_hash = $1 WHERE username = $2', [hash, req.params.username]);
  res.json({ ok: true });
});

app.patch('/api/users/:username/permissions', requireAuth, requireRole('admin'), async (req, res) => {
  const { canManageOwnTickets } = req.body || {};
  const { rows } = await pool.query('SELECT role FROM users WHERE username = $1', [req.params.username]);
  if (!rows.length) return res.status(404).json({ error: 'User does not exist.' });
  if (rows[0].role !== 'narucilac') return res.status(400).json({ error: 'This permission only applies to Requester accounts.' });

  await pool.query('UPDATE users SET can_manage_own_tickets = $1 WHERE username = $2', [!!canManageOwnTickets, req.params.username]);
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

// ---------- SMS alerts via RingCentral ----------
// Texts the warehouse when a ticket has been sitting unclaimed in "New"
// for too long. Requires RC_CLIENT_ID, RC_CLIENT_SECRET, RC_JWT,
// RC_FROM_NUMBER, and RC_TO_NUMBER to be set — if they aren't, this
// feature quietly does nothing rather than crashing the app.
const RC_SERVER = process.env.RC_SERVER || 'https://platform.ringcentral.com';
const SMS_CONFIGURED = !!(
  process.env.RC_CLIENT_ID && process.env.RC_CLIENT_SECRET && process.env.RC_JWT &&
  process.env.RC_FROM_NUMBER && process.env.RC_TO_NUMBER
);

let rcPlatform = null;
if (SMS_CONFIGURED) {
  const rcsdk = new RingCentralSDK({
    server: RC_SERVER,
    clientId: process.env.RC_CLIENT_ID,
    clientSecret: process.env.RC_CLIENT_SECRET,
  });
  rcPlatform = rcsdk.platform();
} else {
  console.log('SMS alerts disabled — RingCentral environment variables are not fully set.');
}

async function sendSms(text) {
  if (!SMS_CONFIGURED || !rcPlatform) return;
  try {
    await rcPlatform.login({ jwt: process.env.RC_JWT });
    const toNumbers = process.env.RC_TO_NUMBER.split(',').map((n) => n.trim()).filter(Boolean);
    await rcPlatform.post('/restapi/v1.0/account/~/extension/~/sms', {
      from: { phoneNumber: process.env.RC_FROM_NUMBER },
      to: toNumbers.map((phoneNumber) => ({ phoneNumber })),
      text,
    });
  } catch (err) {
    console.error('Failed to send SMS via RingCentral:', err.message || err);
  }
}

// ---------- alert warehouse about tickets stuck in New ----------
const STALE_NEW_ALERT_MS = 15 * 60 * 1000; // 15 minutes
const STALE_NEW_CHECK_INTERVAL_MS = 2 * 60 * 1000; // check every 2 minutes

async function alertStaleNewOrders() {
  if (!SMS_CONFIGURED) return;
  try {
    const cutoff = Date.now() - STALE_NEW_ALERT_MS;
    const { rows } = await pool.query(
      "SELECT id, service_order, location FROM orders WHERE status = 'novo' AND created_at <= $1 AND stale_notified_at IS NULL",
      [cutoff]
    );
    if (rows.length === 0) return;

    for (const row of rows) {
      const label = row.service_order || ('#' + row.id.slice(-6));
      await sendSms(`Workshop alert: ticket ${label} (${row.location}) has been waiting 15+ min unclaimed in New.`);
      await pool.query('UPDATE orders SET stale_notified_at = $1 WHERE id = $2', [Date.now(), row.id]);
      await logEvent(row.id, 'sms_alert_sent', 'auto', '15+ minutes unclaimed');
    }
  } catch (err) {
    console.error('Stale-ticket SMS check failed:', err);
  }
}

// ---------- auto-issue orders left sitting in Ready too long ----------
const READY_AUTO_ISSUE_MS = 60 * 60 * 1000; // 1 hour
const AUTO_ISSUE_CHECK_INTERVAL_MS = 5 * 60 * 1000; // check every 5 minutes

async function autoIssueStaleReadyOrders() {
  try {
    const cutoff = Date.now() - READY_AUTO_ISSUE_MS;
    const { rows } = await pool.query(
      "SELECT id FROM orders WHERE status = 'spremno' AND issued_at IS NULL AND ready_at IS NOT NULL AND ready_at <= $1",
      [cutoff]
    );
    if (rows.length === 0) return;

    for (const row of rows) {
      await pool.query('UPDATE orders SET issued_by = $1, issued_at = $2 WHERE id = $3', ['auto', Date.now(), row.id]);
      await logEvent(row.id, 'issued', 'auto', 'Automatically issued after 1 hour in Ready');
    }
    broadcastUpdate();
  } catch (err) {
    console.error('Auto-issue check failed:', err);
  }
}

initDb()
  .then(() => {
    app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
    setInterval(autoIssueStaleReadyOrders, AUTO_ISSUE_CHECK_INTERVAL_MS);
    setInterval(alertStaleNewOrders, STALE_NEW_CHECK_INTERVAL_MS);
  })
  .catch((err) => {
    console.error('Database connection error:', err);
    process.exit(1);
  });
