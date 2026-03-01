'use strict';

class TtlCache {
  constructor(ttlMs) {
    this._map = new Map();
    this._ttlMs = ttlMs;
  }
  has(key) {
    const e = this._map.get(key);
    if (!e) return false;
    if (Date.now() > e.expiresAt) { this._map.delete(key); return false; }
    return true;
  }
  get(key) {
    return this.has(key) ? this._map.get(key).value : undefined;
  }
  set(key, value) {
    this._map.set(key, { value, expiresAt: Date.now() + this._ttlMs });
  }
}

async function pLimit(items, concurrency, fn) {
  const results = [];
  let idx = 0;
  async function worker() {
    while (idx < items.length) {
      const i = idx++;
      results[i] = await fn(items[i]);
    }
  }
  await Promise.all(Array.from({ length: Math.min(concurrency, items.length) }, worker));
  return results;
}

class RateLimiter {
  constructor(maxRequests, windowMs) {
    this._max = maxRequests;
    this._window = windowMs;
    this._log = new Map();
  }
  check(ip) {
    const now = Date.now();
    const hits = (this._log.get(ip) || []).filter(t => now - t < this._window);
    if (hits.length >= this._max) return false;
    hits.push(now);
    this._log.set(ip, hits);
    if (Math.random() < 0.01) this._cleanup(now);
    return true;
  }
  _cleanup(now) {
    for (const [ip, hits] of this._log) {
      if (hits.every(t => now - t >= this._window)) this._log.delete(ip);
    }
  }
}

module.exports = { TtlCache, pLimit, RateLimiter };
