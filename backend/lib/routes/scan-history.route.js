'use strict';

// GET /api/scans/history?type=lib|dep|composer|os|img|sast
// Returns scan_cache entries for the given type, within 24h, newest first

const express = require('express');
const router  = express.Router();
const { getPool } = require('../auth/db');

const VALID_TYPES = new Set(['lib', 'dep', 'composer', 'os', 'img', 'sast']);

router.get('/scans/history', async (req, res) => {
  const { type } = req.query;

  if (!type || !VALID_TYPES.has(type))
    return res.status(400).json({ error: `type must be one of: ${[...VALID_TYPES].join(', ')}` });

  try {
    const { rows } = await getPool().query(
      `SELECT cache_key, payload, scanned_at
       FROM scan_cache
       WHERE type = $1
         AND scanned_at > NOW() - INTERVAL '24 hours'
       ORDER BY scanned_at DESC
       LIMIT 100`,
      [type]
    );

    // payload is auto-parsed from JSONB by pg
    const entries = rows.map(r => ({
      ...r.payload,
      _cachedAt: r.scanned_at,
      _cacheKey: r.cache_key,
    }));

    return res.json({ type, count: entries.length, entries });
  } catch (e) {
    console.error('[scan-history]', e.message);
    return res.status(500).json({ error: e.message });
  }
});

module.exports = router;
