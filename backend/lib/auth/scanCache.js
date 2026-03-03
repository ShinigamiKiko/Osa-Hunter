'use strict';

const { getPool } = require('./db');
const TTL_HOURS = 24;

class ScanError extends Error {
  constructor(status, message) {
    super(message);
    this.status = status;
  }
}

async function withCache(key, type, res, scanFn) {
  const pool = getPool();

  // 1. Try to read from cache
  try {
    const { rows } = await pool.query(
      `SELECT payload, scanned_at
       FROM scan_cache
       WHERE cache_key = $1
         AND scanned_at > NOW() - INTERVAL '${TTL_HOURS} hours'
       LIMIT 1`,
      [key]
    );
    if (rows.length) {
      const age = Math.round((Date.now() - new Date(rows[0].scanned_at)) / 60000);
      console.log(`[cache] HIT  ${key}  (${age}m old)`);
      // pg auto-parses JSONB → already a JS object
      return res.json({ ...rows[0].payload, _cached: true, _cachedAt: rows[0].scanned_at });
    }
    console.log(`[cache] MISS ${key}`);
  } catch (e) {
    // Table may not exist yet — log clearly and proceed without cache
    console.error(`[cache] READ ERROR for key "${key}":`, e.message);
  }

  // 2. Run real scan
  let result;
  try {
    result = await scanFn();
  } catch (e) {
    const status = e.status || 500;
    return res.status(status).json({ error: e.message });
  }

  // 3. Write to cache — JSON.stringify required, pg does NOT auto-serialize plain objects
  try {
    await pool.query(
      `INSERT INTO scan_cache (cache_key, type, payload, scanned_at)
       VALUES ($1, $2, $3::jsonb, NOW())
       ON CONFLICT (cache_key)
       DO UPDATE SET payload = EXCLUDED.payload, scanned_at = NOW()`,
      [key, type, JSON.stringify(result)]
    );
    console.log(`[cache] SAVE ${key}`);
  } catch (e) {
    console.error(`[cache] WRITE ERROR for key "${key}":`, e.message);
  }

  return res.json(result);
}

async function invalidate(key) {
  try {
    await getPool().query('DELETE FROM scan_cache WHERE cache_key = $1', [key]);
  } catch (e) {
    console.error('[cache] invalidate error:', e.message);
  }
}

async function purgeExpired() {
  try {
    const { rowCount } = await getPool().query(
      `DELETE FROM scan_cache WHERE scanned_at < NOW() - INTERVAL '${TTL_HOURS} hours'`
    );
    if (rowCount) console.log(`[cache] purged ${rowCount} expired entries`);
  } catch (e) {
    // Table may not exist on first boot — not fatal
    if (!e.message.includes('does not exist')) {
      console.error('[cache] purge error:', e.message);
    }
  }
}

module.exports = { withCache, invalidate, purgeExpired, ScanError };