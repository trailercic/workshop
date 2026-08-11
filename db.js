const { Pool } = require('pg');
const bcrypt = require('bcryptjs');

if (!process.env.DATABASE_URL) {
  console.error('ERROR: DATABASE_URL is not set in environment variables.');
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
      location    TEXT NOT NULL DEFAULT 'SOHO' CHECK (location IN ('SOHO','MEPA')),
      created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
    );
  `);

  // Migration for installs created before the location column existed.
  await pool.query(`
    ALTER TABLE users ADD COLUMN IF NOT EXISTS location TEXT NOT NULL DEFAULT 'SOHO';
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS orders (
      id            TEXT PRIMARY KEY,
      part          TEXT,
      code          TEXT,
      qty           INTEGER,
      requester     TEXT NOT NULL,
      note          TEXT,
      priority      TEXT NOT NULL DEFAULT 'normal' CHECK (priority IN ('normal','hitno')),
      status        TEXT NOT NULL DEFAULT 'novo' CHECK (status IN ('novo','u_obradi','spremno')),
      service_order TEXT,
      items         JSONB NOT NULL DEFAULT '[]'::jsonb,
      created_at    BIGINT NOT NULL
    );
  `);

  // Migration: make old single-part columns optional and add the new
  // service_order / items (multi-part) columns for installs created
  // before this change.
  await pool.query(`
    DO $$
    BEGIN
      IF EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='orders' AND column_name='part') THEN
        ALTER TABLE orders ALTER COLUMN part DROP NOT NULL;
      END IF;
      IF EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='orders' AND column_name='qty') THEN
        ALTER TABLE orders ALTER COLUMN qty DROP NOT NULL;
      END IF;
    END $$;
  `);
  await pool.query(`ALTER TABLE orders ADD COLUMN IF NOT EXISTS service_order TEXT;`);
  await pool.query(`ALTER TABLE orders ADD COLUMN IF NOT EXISTS items JSONB NOT NULL DEFAULT '[]'::jsonb;`);

  const { rows } = await pool.query('SELECT COUNT(*)::int AS n FROM users');
  if (rows[0].n === 0) {
    const hash = await bcrypt.hash('admin123', 10);
    await pool.query(
      'INSERT INTO users (username, pass_hash, role) VALUES ($1, $2, $3)',
      ['admin', hash, 'admin']
    );
    console.log('Default admin account created: admin / admin123 — change it right after logging in.');
  }
}

module.exports = { pool, initDb };
