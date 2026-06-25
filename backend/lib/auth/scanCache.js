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

  try {
    const { rows } = await pool.query(
      `SELECT payload, scanned_at
       FROM scan_cache
       WHERE cache_key = $1
         AND scanned_at > NOW() - ($2 || ' hours')::interval
       LIMIT 1`,
      [key, TTL_HOURS]
    );
    if (rows.length) {
      const age = Math.round((Date.now() - new Date(rows[0].scanned_at)) / 60000);
      console.log(`[cache] HIT  ${key}  (${age}m old)`);
      return res.json({ ...rows[0].payload, _cached: true, _cachedAt: rows[0].scanned_at });
    }
    console.log(`[cache] MISS ${key}`);
  } catch (e) {
    console.error(`[cache] READ ERROR for key "${key}":`, e.message);
  }

  let result;
  try {
    result = await scanFn();
  } catch (e) {
    const status = e.status || 500;
    return res.status(status).json({ error: e.message });
  }

  if (result != null && typeof result === 'object' && typeof result.socket !== 'undefined') {
    console.error(`[cache] scanFn returned res/ServerResponse for key "${key}" — fix error paths to throw ScanError`);
    return;
  }

  let serialized;
  try {
    serialized = JSON.stringify(result);
  } catch (e) {
    console.error(`[cache] SERIALIZE ERROR for key "${key}":`, e.message);
    return res.json(result);
  }

  try {
    await pool.query(
      `INSERT INTO scan_cache (cache_key, type, payload, scanned_at)
       VALUES ($1, $2, $3::jsonb, NOW())
       ON CONFLICT (cache_key)
       DO UPDATE SET payload = EXCLUDED.payload, scanned_at = NOW()`,
      [key, type, serialized]
    );
    console.log(`[cache] SAVE ${key}`);
  } catch (e) {
    console.error(`[cache] WRITE ERROR for key "${key}":`, e.message);
  }

  return res.json(result);
}

async function purgeExpired() {
  try {
    const { rowCount } = await getPool().query(
      `DELETE FROM scan_cache WHERE scanned_at < NOW() - ($1 || ' hours')::interval`,
      [TTL_HOURS]
    );
    if (rowCount) console.log(`[cache] purged ${rowCount} expired entries`);
  } catch (e) {
    if (!e.message.includes('does not exist')) {
      console.error('[cache] purge error:', e.message);
    }
  }
}

module.exports = { withCache, purgeExpired, ScanError };