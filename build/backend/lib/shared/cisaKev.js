'use strict';

const { CISA_URL } = require('./constants');
const { TtlCache } = require('./primitives');

// ── CISA KEV ──────────────────────────────────────────────────
let cisaCache = { set: null, ts: 0 };
async function getCisaSet() {
  if (cisaCache.set && Date.now() - cisaCache.ts < 3_600_000) return cisaCache.set;
  try {
    const r = await fetch(CISA_URL, { signal: AbortSignal.timeout(15000) });
    const d = await r.json();
    cisaCache.set = new Set((d.vulnerabilities || []).map(v => v.cveID));
    cisaCache.ts = Date.now();
    console.log('[CISA] KEV loaded:', cisaCache.set.size, 'entries');
  } catch (e) {
    console.error('[CISA] Fetch failed:', e.message);
    if (!cisaCache.set) cisaCache.set = new Set();
  }
  return cisaCache.set;
}

// 24h cache for NVD CVSS lookups
const nvdCache = new TtlCache(24 * 3_600_000);

module.exports = { getCisaSet, nvdCache };
