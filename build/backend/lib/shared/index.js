// lib/shared/index.js — public shared API (barrel)
'use strict';

const constants   = require('./constants');
const validation  = require('./validation');
const primitives  = require('./primitives');
const rateLimiter = require('./rateLimit');
const cisaKev     = require('./cisaKev');
const toxicRepos  = require('./toxicRepos');
const enrichment  = require('./enrichment');

// Debug: check who exports "rateLimit"
const modules = { constants, validation, primitives, cisaKev, toxicRepos, enrichment };
for (const [name, mod] of Object.entries(modules)) {
  if ('rateLimit' in mod) {
    console.error(`[shared/index] ⚠️  "${name}" exports "rateLimit":`, typeof mod.rateLimit);
  }
}
console.log('[shared/index] rateLimiter.rateLimit:', typeof rateLimiter.rateLimit);

module.exports = {
  // bulk exports
  ...constants,
  ...validation,
  ...primitives,
  ...cisaKev,
  ...toxicRepos,
  ...enrichment,

  // explicit exports to avoid accidental overwrites
  rateLimit   : rateLimiter.rateLimit,
  trivyLimiter: rateLimiter.trivyLimiter,
  apiLimiter  : rateLimiter.apiLimiter,
  scanLimiter : rateLimiter.scanLimiter,
};

// Final check
console.log('[shared/index] final module.exports.rateLimit:', typeof module.exports.rateLimit);