// routes/libscan.js — POST /api/libscan
// OSV + EPSS + CISA KEV + NVD CVSS + PoC + Toxic — всё в одном ответе
'use strict';
const { withCache, ScanError } = require('../auth/scanCache');
const express = require('express');
const router  = express.Router();
const {
  OSV_URL, SEV_ORD, scanLimiter, rateLimit,
  checkToxic,
  osvQuery, bulkEnrich, enrichVulns, extractCVEs,
} = require('../shared');

router.post('/libscan', rateLimit(scanLimiter), async (req, res) => {
  const { name, ecosystem, version } = req.body || {};
  if (!name || typeof name !== 'string' || !name.trim())
    return res.status(400).json({ error: '"name" is required' });
  if (!ecosystem || typeof ecosystem !== 'string' || !ecosystem.trim())
    return res.status(400).json({ error: '"ecosystem" is required (e.g. npm, PyPI, Go, …)' });

  const pkg = name.trim();
  const eco = ecosystem.trim();
  const ver = (version || '').trim() || null;
  const _cacheKey = `lib:${eco}:${pkg}:${ver||'latest'}`;

  return withCache(_cacheKey, 'lib', res, async () => {
  console.log(`[libscan] ${eco}/${pkg}${ver ? '@' + ver : ''}`);

  // 1. OSV query
  let vulns;
  try {
    vulns = await osvQuery(pkg, eco, ver);
    if (!vulns) throw new Error('OSV query returned null');
  } catch (e) {
    throw new ScanError(502, `OSV query failed: ${e.message}`);
  }

  const cveIds = extractCVEs(vulns);

  // 2. Parallel enrichment
  const [toxicRes, enrichMaps] = await Promise.allSettled([
    checkToxic(pkg),
    bulkEnrich(cveIds),
  ]);

  const toxic = toxicRes.status === 'fulfilled' ? toxicRes.value : { found: false };
  const maps  = enrichMaps.status === 'fulfilled' ? enrichMaps.value : { epssMap:{}, kevSet: new Set(), cvssMap:{}, pocMap:{} };

  // 3. Enrich vulns
  const enriched = enrichVulns(vulns, maps);

  // 4. Summary
  const summary = { total: enriched.length, CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, UNKNOWN: 0 };
  for (const v of enriched) if (v.severity in summary) summary[v.severity]++;
  const topSeverity = SEV_ORD.find(s => summary[s] > 0) || 'NONE';

  return { package: pkg, ecosystem: eco, version: ver, scannedAt: new Date().toISOString(), toxic, topSeverity, summary, vulns: enriched };
  }); // withCache
});

module.exports = router;
