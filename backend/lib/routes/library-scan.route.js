// routes/libscan.js — POST /api/libscan
// OSV + EPSS + CISA KEV + NVD CVSS + PoC + Toxic — всё в одном ответе
'use strict';
const { withCache } = require('../auth/scanCache');
const express = require('express');
const router  = express.Router();
const {
  OSV_URL, scanLimiter, rateLimit,
  getCisaSet, checkToxic,
  fetchEpss, fetchCvss, fetchPocs,
  extractCVEs, parseSev, getFixed,
} = require('../shared');

const SEV_ORD = ['CRITICAL','HIGH','MEDIUM','LOW','UNKNOWN','NONE'];

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

  // 1. OSV
  let rawVulns = [];
  try {
    const body = { package: { name: pkg, ecosystem: eco } };
    if (ver) body.version = ver;
    const r = await fetch(`${OSV_URL}/query`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body), signal: AbortSignal.timeout(15000),
    });
    if (!r.ok) throw new Error(`OSV HTTP ${r.status}`);
    const d = await r.json();
    if (d.error) throw new Error(d.error);
    rawVulns = d.vulns || [];
  } catch (e) {
    return res.status(502).json({ error: `OSV query failed: ${e.message}` });
  }

  const vulns = rawVulns.map(v => ({
    ...v,
    _sev    : parseSev(v),
    _fix    : getFixed(v),
    _aliases: v.aliases || [],
    _refs   : (v.references || []).map(r => r.url),
  })).sort((a, b) => SEV_ORD.indexOf(a._sev) - SEV_ORD.indexOf(b._sev));

  const cveIds = extractCVEs(vulns);

  // 2. Parallel enrichment
  const [toxicRes, epssRes, kevRes, cvssRes, pocRes] = await Promise.allSettled([
    checkToxic(pkg),
    fetchEpss(cveIds),
    (async () => { const s = await getCisaSet(); return cveIds.filter(c => s.has(c)); })(),
    fetchCvss(cveIds),
    fetchPocs(cveIds),
  ]);

  const toxic   = toxicRes.status === 'fulfilled' ? toxicRes.value : { found: false };
  const epssMap = epssRes.status  === 'fulfilled' ? epssRes.value  : {};
  const kevSet  = new Set(kevRes.status === 'fulfilled' ? kevRes.value : []);
  const cvssMap = cvssRes.status  === 'fulfilled' ? cvssRes.value  : {};
  const pocMap  = pocRes.status   === 'fulfilled' ? pocRes.value   : {};

  // 3. Merge enrichment into vulns
  const enriched = vulns.map(v => {
    const cve = [...(v._aliases || []), v.id].find(x => x.startsWith('CVE-')) || null;
    return {
      id       : v.id,
      summary  : v.summary   || null,
      details  : v.details   || null,
      published: v.published || null,
      modified : v.modified  || null,
      severity : v._sev,
      fix      : v._fix      || null,
      aliases  : v._aliases,
      refs     : v._refs,
      cve,
      epss  : cve ? (epssMap[cve] || null) : null,
      cvss  : cve ? (cvssMap[cve] || null) : null,
      inKev : cve ? kevSet.has(cve) : false,
      pocs  : cve ? (pocMap[cve] || []) : [],
    };
  });

  // 4. Summary
  const summary = { total: enriched.length, CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, UNKNOWN: 0 };
  for (const v of enriched) if (v.severity in summary) summary[v.severity]++;
  const topSeverity = SEV_ORD.find(s => summary[s] > 0) || 'NONE';

  return { package: pkg, ecosystem: eco, version: ver, scannedAt: new Date().toISOString(), toxic, topSeverity, summary, vulns: enriched };
  }); // withCache
});

module.exports = router;