'use strict';

const express  = require('express');
const crypto   = require('crypto');
const router   = express.Router();
const { getPool }      = require('./db');
const { requireAdmin } = require('./middleware');

// ── Helpers ───────────────────────────────────────────────────
function generateKey() {
  // Format: osa_<32 random hex chars>  e.g. osa_a3f9c2d1...
  return 'osa_' + crypto.randomBytes(16).toString('hex');
}

function hashKey(key) {
  return crypto.createHash('sha256').update(key).digest('hex');
}

// ── GET /api/auth/api-keys — list keys for current user / all for admin ──
router.get('/auth/api-keys', async (req, res) => {
  const user = req.session?.user;
  if (!user) return res.status(401).json({ error: 'Unauthorized' });

  try {
    const pool = getPool();
    // Admin sees all keys with owner info; regular user sees only their own
    const query = user.role === 'admin'
      ? `SELECT k.id, k.name, k.key_prefix, k.last_used, k.created_at,
                u.username as owner
         FROM api_keys k JOIN users u ON u.id = k.user_id
         ORDER BY k.created_at DESC`
      : `SELECT id, name, key_prefix, last_used, created_at
         FROM api_keys WHERE user_id = $1 ORDER BY created_at DESC`;

    const { rows } = user.role === 'admin'
      ? await pool.query(query)
      : await pool.query(query, [user.id]);

    return res.json({ keys: rows });
  } catch (e) {
    return res.status(500).json({ error: e.message });
  }
});

// ── POST /api/auth/api-keys — create new key ─────────────────
router.post('/auth/api-keys', async (req, res) => {
  const user = req.session?.user;
  if (!user) return res.status(401).json({ error: 'Unauthorized' });

  const { name } = req.body || {};
  if (!name?.trim()) return res.status(400).json({ error: 'name is required' });

  try {
    const key    = generateKey();
    const hash   = hashKey(key);
    const prefix = key.slice(0, 12); // "osa_abc12345"

    await getPool().query(
      `INSERT INTO api_keys (user_id, name, key_hash, key_prefix)
       VALUES ($1, $2, $3, $4)`,
      [user.id, name.trim(), hash, prefix]
    );

    // Return the full key ONCE — never stored, never retrievable again
    return res.status(201).json({ key, prefix, name: name.trim() });
  } catch (e) {
    return res.status(500).json({ error: e.message });
  }
});

// ── DELETE /api/auth/api-keys/:id ────────────────────────────
router.delete('/auth/api-keys/:id', async (req, res) => {
  const user = req.session?.user;
  if (!user) return res.status(401).json({ error: 'Unauthorized' });

  const id = parseInt(req.params.id, 10);
  try {
    // Admin can delete any key; regular user only their own
    const query = user.role === 'admin'
      ? 'DELETE FROM api_keys WHERE id = $1'
      : 'DELETE FROM api_keys WHERE id = $1 AND user_id = $2';

    const args = user.role === 'admin' ? [id] : [id, user.id];
    const { rowCount } = await getPool().query(query, args);

    if (!rowCount) return res.status(404).json({ error: 'Key not found' });
    return res.json({ ok: true });
  } catch (e) {
    return res.status(500).json({ error: e.message });
  }
});

module.exports = router;
