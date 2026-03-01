// routes/health.js — GET /api/health, GET /api/epss/status
'use strict';
const express   = require('express');
const router    = express.Router();
const { execFile } = require('child_process');
const { EPSS_URL } = require('../shared');

router.get('/health', (req, res) => {
  execFile('trivy', ['--version'], { timeout: 5000 }, (err, stdout) => {
    res.json({
      status : 'ok',
      trivy  : !err,
      version: err ? null : (stdout.split('\n')[0] || '').trim(),
    });
  });
});

router.get('/epss/status', async (req, res) => {
  try {
    const r = await fetch(`${EPSS_URL}?cve=CVE-2021-44228`, { signal: AbortSignal.timeout(5000) });
    const d = await r.json();
    res.json({ loaded: d.total > 0, total: 270000, loadedAt: new Date(), loading: false });
  } catch {
    res.json({ loaded: false, total: 0, loadedAt: null, loading: false });
  }
});

module.exports = router;
