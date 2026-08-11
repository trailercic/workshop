const { Pool } = require('pg');
const bcrypt = require('bcryptjs');

if (!process.env.DATABASE_URL) {
  console.error('GREŠKA: DATABASE_URL nije podešen u environment varijablama.');
}

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false },
});

async function initDb() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      username    TEXT PRIMARY KEY,
      pass_hash   TEXT NOT NULL,
      role        TEXT NOT NULL CHECK (role IN ('narucilac','magacioner','admin')),
      created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
    );
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS orders (
      id          TEXT PRIMARY KEY,
      part        TEXT NOT NULL,
      code        TEXT,
      qty         INTEGER NOT NULL DEFAULT 1,
      requester   TEXT NOT NULL,
      note        TEXT,
      priority    TEXT NOT NULL DEFAULT 'normal' CHECK (priority IN ('normal','hitno')),
      status      TEXT NOT NULL DEFAULT 'novo' CHECK (status IN ('novo','u_obradi','spremno')),
      created_at  BIGINT NOT NULL
    );
  `);

  const { rows } = await pool.query('SELECT COUNT(*)::int AS n FROM users');
  if (rows[0].n === 0) {
    const hash = await bcrypt.hash('admin123', 10);
    await pool.query(
      'INSERT INTO users (username, pass_hash, role) VALUES ($1, $2, $3)',
      ['admin', hash, 'admin']
    );
    console.log('Kreiran podrazumevani admin nalog: admin / admin123 — promenite odmah po prijavi.');
  }
}

module.exports = { pool, initDb };
