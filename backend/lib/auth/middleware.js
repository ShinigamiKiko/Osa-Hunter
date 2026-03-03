'use strict';

const crypto = require('crypto');
const { getPool } = require('./db');

function hashKey(key) {
  return crypto.createHash('sha256').update(key).digest('hex');
}

// Protect all /api/* routes — allows session cookie OR X-Api-Key header
async function requireAuth(req, res, next) {
  const open = [
    '/api/auth/login',
    '/api/auth/status',
    '/api/health',
  ];
  if (open.some(p => req.path.startsWith(p))) return next();

  // 1. Session cookie
  if (req.session?.user) return next();

  // 2. X-Api-Key header
  const apiKey = req.headers['x-api-key'];
  if (apiKey && apiKey.startsWith('osa_')) {
    try {
      const hash = hashKey(apiKey);
      const { rows } = await getPool().query(
        `SELECT k.id, u.id as user_id, u.username, u.role
         FROM api_keys k JOIN users u ON u.id = k.user_id
         WHERE k.key_hash = $1`,
        [hash]
      );
      if (rows.length) {
        // Attach user to request (same shape as session.user)
        req.session = req.session || {};
        req.apiKeyUser = rows[0];
        req.user = { id: rows[0].user_id, username: rows[0].username, role: rows[0].role };
        // Update last_used async — don't await, don't block
        getPool().query('UPDATE api_keys SET last_used = NOW() WHERE id = $1', [rows[0].id])
          .catch(() => {});
        return next();
      }
    } catch (e) {
      console.error('[auth/api-key]', e.message);
    }
  }

  // 3. Unauthorized
  const wants = req.headers.accept || '';
  if (wants.includes('text/html')) return res.redirect('/login.html');
  return res.status(401).json({ error: 'Unauthorized' });
}

// Admin-only middleware — works for both session and API key auth
function requireAdmin(req, res, next) {
  const role = req.session?.user?.role || req.user?.role;
  if (role === 'admin') return next();
  return res.status(403).json({ error: 'Forbidden — admin only' });
}

module.exports = { requireAuth, requireAdmin };
