'use strict';
const { withCache } = require('../auth/scanCache');

const express = require('express');
const router = express.Router();

const { scanLimiter, rateLimit } = require('../shared');
const { scanComposer } = require('../services/composerScan');

router.post('/composerscan', rateLimit(scanLimiter), async (req, res) => {
  const { name, version } = req.body || {};
  const _cacheKey = `composer:${(name||'').trim()}:${(version||'').trim()||'latest'}`;
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
