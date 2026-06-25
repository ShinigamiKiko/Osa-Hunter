'use strict';

async function fetchJson(url, opts = {}) {
  try {
    const r = await fetch(url, opts);
    if (!r.ok) {
      console.warn(`[fetchJson] HTTP ${r.status} from ${url}`);
      return null;
    }
    const ct = r.headers.get('content-type') || '';
    if (!ct.includes('application/json') && !ct.includes('text/json')) {
      const text = await r.text();
      console.warn(`[fetchJson] Expected JSON but got "${ct}" from ${url}: ${text.slice(0, 300)}`);
      return null;
    }
    return await r.json();
  } catch (e) {
    console.warn(`[fetchJson] error fetching ${url}:`, e.message);
    return null;
  }
}

module.exports = { fetchJson };
