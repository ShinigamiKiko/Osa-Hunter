'use strict';

const express  = require('express');
const bcrypt   = require('bcryptjs');
const router   = express.Router();
const { getPool } = require('./db');
const { requireAdmin } = require('./middleware');
const { RateLimiter } = require('../shared/primitives');

// 10 login attempts per minute per IP
const loginLimiter = new RateLimiter(10, 60000);

const SALT_ROUNDS = 12;

// ── GET /api/auth/status — public, shows if setup needed ────────
router.get('/auth/status', async (req, res) => {
  try {
    const { rows } = await getPool().query('SELECT COUNT(*) FROM users');
    const count = parseInt(rows[0].count, 10);
    return res.json({ configured: count > 0 });
  } catch (e) {
    return res.status(500).json({ error: e.message });
  }
});

// ── POST /api/auth/login ──────────────────────────────────────
router.post('/auth/login', (req, res, next) => {
  // req.ip respects app.set('trust proxy', 1) — do NOT read X-Forwarded-For manually
  const ip = req.ip || req.socket?.remoteAddress || 'unknown';
  if (!loginLimiter.check(ip)) return res.status(429).json({ error: 'Too many login attempts. Please wait.' });
  next();
}, async (req, res) => {
  const { username, password } = req.body || {};
  if (!username || !password)
    return res.status(400).json({ error: 'username and password required' });

  try {
    const pool = getPool();

    const { rows } = await pool.query(
      'SELECT id, username, password, role FROM users WHERE username = $1',
      [username.trim()]
    );
    if (!rows.length) return res.status(401).json({ error: 'Invalid credentials' });

    const user = rows[0];
    const valid = await bcrypt.compare(password, user.password);
    if (!valid) return res.status(401).json({ error: 'Invalid credentials' });

    req.session.user = { id: user.id, username: user.username, role: user.role };
    return res.json({ ok: true, user: req.session.user });

  } catch (e) {
    console.error('[auth/login]', e.message);
    return res.status(500).json({ error: 'Login failed' });
  }
});

// ── POST /api/auth/logout ─────────────────────────────────────
router.post('/auth/logout', (req, res) => {
  req.session.destroy(() => res.json({ ok: true }));
});

// ── GET /api/auth/me ──────────────────────────────────────────
router.get('/auth/me', (req, res) => {
  if (!req.session?.user) return res.status(401).json({ error: 'Not authenticated' });
  return res.json({ user: req.session.user });
});

// ── GET /api/auth/users — admin only ─────────────────────────
router.get('/auth/users', requireAdmin, async (req, res) => {
  try {
    const { rows } = await getPool().query(
      'SELECT id, username, role, created_at FROM users ORDER BY id'
    );
    return res.json({ users: rows });
  } catch (e) {
    return res.status(500).json({ error: e.message });
  }
});

// ── POST /api/auth/users — create user (admin only) ──────────
router.post('/auth/users', requireAdmin, async (req, res) => {
  const { username, password, role = 'user' } = req.body || {};
  if (!username || !password)
    return res.status(400).json({ error: 'username and password required' });
  if (!['admin', 'user'].includes(role))
    return res.status(400).json({ error: 'role must be admin or user' });

  try {
    const hash = await bcrypt.hash(password, SALT_ROUNDS);
    const { rows } = await getPool().query(
      `INSERT INTO users (username, password, role) VALUES ($1, $2, $3)
       RETURNING id, username, role, created_at`,
      [username.trim(), hash, role]
    );
    return res.status(201).json({ user: rows[0] });
  } catch (e) {
    if (e.code === '23505') return res.status(409).json({ error: 'Username already exists' });
    return res.status(500).json({ error: e.message });
  }
});

// ── DELETE /api/auth/users/:id — admin only ───────────────────
router.delete('/auth/users/:id', requireAdmin, async (req, res) => {
  const id = parseInt(req.params.id, 10);
  if (id === req.session.user.id)
    return res.status(400).json({ error: 'Cannot delete yourself' });

  try {
    const { rowCount } = await getPool().query('DELETE FROM users WHERE id = $1', [id]);
    if (!rowCount) return res.status(404).json({ error: 'User not found' });
    return res.json({ ok: true });
  } catch (e) {
    return res.status(500).json({ error: e.message });
  }
});

// ── PATCH /api/auth/users/:id/password — change password ─────
router.patch('/auth/users/:id/password', requireAdmin, async (req, res) => {
  const id = parseInt(req.params.id, 10);
  const { password } = req.body || {};
  if (!password) return res.status(400).json({ error: 'password required' });

  try {
    const hash = await bcrypt.hash(password, SALT_ROUNDS);
    const { rowCount } = await getPool().query(
      'UPDATE users SET password = $1, updated_at = NOW() WHERE id = $2',
      [hash, id]
    );
    if (!rowCount) return res.status(404).json({ error: 'User not found' });
    return res.json({ ok: true });
  } catch (e) {
    return res.status(500).json({ error: e.message });
  }
});

module.exports = router;
