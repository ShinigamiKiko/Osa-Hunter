'use strict';
const { withCache } = require('../auth/scanCache');

const express = require('express');
const router = express.Router();

const { scanLimiter, rateLimit } = require('../shared');
const { scanComposer } = require('../services/composerScan');
const { isComposerPackageName } = require('../composer/names');

router.post('/composerscan', rateLimit(scanLimiter), async (req, res) => {
  const { name, version } = req.body || {};

  // Validate before hitting cache — avoids caching bad keys and throwing
  // inside the cache callback where errors are harder to surface cleanly.
  if (!name || typeof name !== 'string' || !name.trim())
    return res.status(400).json({ error: '"name" is required (e.g., monolog/monolog)' });
  if (!isComposerPackageName(name.trim()))
    return res.status(400).json({ error: `Invalid package name: "${name.trim()}". Expected "vendor/package" format.` });

  const _cacheKey = `composer:${name.trim()}:${(version||'').trim()||'latest'}`;
  try {
    return await withCache(_cacheKey, 'composer', res, () => scanComposer(req.body || {}));
  } catch (e) {
    console.error('[composerscan]', e);
    const status = e.statusCode || 502;
    const payload = { error: e.message || 'Composer scan failed' };
    if (e.details) payload.details = e.details;
    return res.status(status).json(payload);
  }
});

module.exports = router;
