'use strict';

const express = require('express');
const router = express.Router();

const { scanLimiter, rateLimit } = require('../shared');
const { scanComposer } = require('../services/composerScan');

router.post('/composerscan', rateLimit(scanLimiter), async (req, res) => {
  try {
    const data = await scanComposer(req.body || {});
    return res.json(data);
  } catch (e) {
    console.error('[composerscan]', e);
    const status = e.statusCode || 502;
    const payload = { error: e.message || 'Composer scan failed' };
    if (e.details) payload.details = e.details;
    return res.status(status).json(payload);
  }
});

module.exports = router;
