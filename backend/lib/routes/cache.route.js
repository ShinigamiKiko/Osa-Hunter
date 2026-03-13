'use strict';
// DELETE /api/cache?type=dep|lib|gh|all
// Clears scan cache entries so fresh results are fetched on next scan.
const express = require('express');
const router  = express.Router();
const { getPool } = require('../auth/db');

router.delete('/cache', async (req, res) => {
  const { type } = req.query; // dep | lib | gh | (empty = all)
  const pool = getPool();
  try {
    let result;
    if (type && type !== 'all') {
      result = await pool.query('DELETE FROM scan_cache WHERE type = $1', [type]);
    } else {
      result = await pool.query('DELETE FROM scan_cache');
    }
    console.log(`[cache] cleared ${result.rowCount} entries (type=${type||'all'})`);
    res.json({ ok: true, deleted: result.rowCount, type: type || 'all' });
  } catch (e) {
    console.error('[cache] clear error:', e.message);
    res.status(500).json({ error: e.message });
  }
});

module.exports = router;
