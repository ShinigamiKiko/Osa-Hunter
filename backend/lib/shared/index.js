// lib/shared/index.js — public shared API (barrel)
'use strict';

const constants   = require('./constants');
const validation  = require('./validation');
const primitives  = require('./primitives');
const rateLimiter = require('./rateLimit');
const cisaKev     = require('./cisaKev');
const toxicRepos  = require('./toxicRepos');
const enrichment  = require('./enrichment');

module.exports = {
  ...constants,
  ...validation,
  ...primitives,
  ...cisaKev,
  ...toxicRepos,
  ...enrichment,

  // explicit to avoid accidental spread overwrites
  rateLimit   : rateLimiter.rateLimit,
  trivyLimiter: rateLimiter.trivyLimiter,
  apiLimiter  : rateLimiter.apiLimiter,
  scanLimiter : rateLimiter.scanLimiter,
};
