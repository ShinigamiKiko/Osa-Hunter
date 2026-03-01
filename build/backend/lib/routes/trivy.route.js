// routes/trivy.js — POST /api/trivy/scan
'use strict';
const express   = require('express');
const router    = express.Router();
const { execFile } = require('child_process');
const { trivyLimiter, validateImage } = require('../shared');

router.post('/trivy/scan', (req, res) => {
  const ip = req.ip || req.socket?.remoteAddress || 'unknown';
  if (!trivyLimiter.check(ip))
    return res.status(429).json({ error: 'Too many scan requests. Please wait before retrying.' });

  const { image, tag } = req.body || {};
  if (!image) return res.status(400).json({ error: 'image is required' });
  if (!validateImage(image)) return res.status(400).json({ error: 'Invalid image name' });
  if (tag && !validateImage(tag)) return res.status(400).json({ error: 'Invalid tag' });

  const fullImage = tag ? `${image}:${tag}` : `${image}:latest`;
  console.log(`[Trivy] Scanning: ${fullImage} (ip: ${ip})`);

  execFile('trivy', ['image', '--format', 'json', '--quiet', '--timeout', '10m', fullImage],
    { timeout: 600_000, maxBuffer: 50 * 1024 * 1024 },
    (err, stdout, stderr) => {
      if (err && !stdout) {
        console.error('[Trivy] Error:', stderr);
        return res.status(500).json({ error: stderr || err.message });
      }
      try { res.json(JSON.parse(stdout)); }
      catch (e) {
        console.error('[Trivy] JSON parse error:', e.message);
        res.status(500).json({ error: 'Failed to parse Trivy output' });
      }
    });
});

module.exports = router;
