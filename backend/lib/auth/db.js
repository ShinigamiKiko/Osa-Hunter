'use strict';

const { Pool } = require('pg');
const fs       = require('fs');
const path     = require('path');

let _pool = null;

function getPool() {
  if (!_pool) {
    _pool = new Pool({
      host:     process.env.PGHOST     || 'postgres',
      port:     parseInt(process.env.PGPORT || '5432', 10),
      database: process.env.PGDATABASE || 'osa',
      user:     process.env.PGUSER     || 'osa',
      password: process.env.PGPASSWORD || 'osa',
      max: 10,
      idleTimeoutMillis: 30000,
      connectionTimeoutMillis: 5000,
    });
    _pool.on('error', err => console.error('[pg] idle client error:', err.message));
  }
  return _pool;
}

// Run all migrations in /migrations/*.sql in order
async function runMigrations() {
  const pool = getPool();
  const migDir = path.join(__dirname, '../../migrations');

  // Create migrations tracker table
  await pool.query(`
    CREATE TABLE IF NOT EXISTS _migrations (
      name       VARCHAR(255) PRIMARY KEY,
      applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `);

  const files = fs.readdirSync(migDir)
    .filter(f => f.endsWith('.sql'))
    .sort();

  for (const file of files) {
    const { rows } = await pool.query(
      'SELECT 1 FROM _migrations WHERE name = $1',
      [file]
    );
    if (rows.length) {
      console.log(`[migrations] ✓ ${file} already applied`);
      continue;
    }
    const sql = fs.readFileSync(path.join(migDir, file), 'utf8');
    await pool.query(sql);
    await pool.query('INSERT INTO _migrations (name) VALUES ($1)', [file]);
    console.log(`[migrations] ✅ applied ${file}`);
  }
}

async function seedAdmin() {
  const pool = getPool();
  const { rows } = await pool.query('SELECT COUNT(*) FROM users');
  if (parseInt(rows[0].count, 10) > 0) return; // already seeded

  const bcrypt = require('bcryptjs');
  const hash = await bcrypt.hash('admin', 12);
  await pool.query(
    `INSERT INTO users (username, password, role) VALUES ('admin', $1, 'admin')`,
    [hash]
  );
  console.log('[auth] ✅ Default admin/admin account created');
}

module.exports = { getPool, runMigrations, seedAdmin };
