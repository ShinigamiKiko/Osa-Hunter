'use strict';

const { EPSS_URL, POC_BASE } = require('./constants');
const { pLimit } = require('./primitives');
const { nvdCache } = require('./cisaKev');

// ── NVD config — читается один раз при старте ─────────────────
const NVD_API_KEY    = process.env.NVD_API_KEY || '';
// Без ключа: 5 req/30s → concurrency 3, таймаут 10s
// С ключом:  50 req/30s → concurrency 10, таймаут 8s
const NVD_CONCURRENCY = NVD_API_KEY ? 10 : 3;
const NVD_TIMEOUT_MS  = NVD_API_KEY ? 8000 : 10000;

if (NVD_API_KEY) {
  console.log('[NVD] API key detected — high-throughput mode (concurrency 10)');
} else {
  console.log('[NVD] No API key — conservative mode (concurrency 3). Set NVD_API_KEY for faster enrichment.');
}

async function fetchEpss(cveIds) {
  if (!cveIds.length) return {};
  const results = {};
  for (let i = 0; i < cveIds.length; i += 30) {
    const chunk = cveIds.slice(i, i + 30);
    try {
      const r = await fetch(`${EPSS_URL}?cve=${chunk.join(',')}&limit=${chunk.length}`, { signal: AbortSignal.timeout(15000) });
      if (!r.ok) continue;
      const d = await r.json();
      for (const item of d.data || []) {
        results[item.cve] = { epss: parseFloat(item.epss), percentile: parseFloat(item.percentile) };
      }
    } catch {}
  }
  return results;
}

async function fetchCvss(cveIds) {
  if (!cveIds.length) return {};
  const result = {};
  await pLimit(cveIds, NVD_CONCURRENCY, async (cveId) => {
    if (nvdCache.has(cveId)) { result[cveId] = nvdCache.get(cveId); return; }
    try {
      const headers = { Accept: 'application/json' };
      if (NVD_API_KEY) headers['apiKey'] = NVD_API_KEY;
      const r = await fetch(
        `https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=${encodeURIComponent(cveId)}`,
        { signal: AbortSignal.timeout(NVD_TIMEOUT_MS), headers }
      );
      // При 429 — не кешируем null, дадим шанс следующему запросу
      if (r.status === 429) { result[cveId] = null; return; }
      if (!r.ok) { nvdCache.set(cveId, null); return; }
      const d = await r.json();
      const vuln = (d.vulnerabilities || [])[0]?.cve;
      if (!vuln) { nvdCache.set(cveId, null); return; }
      const metrics = vuln.metrics || {};
      const v3data  = (metrics.cvssMetricV31 || metrics.cvssMetricV30 || [])[0]?.cvssData;
      const v2data  = (metrics.cvssMetricV2  || [])[0]?.cvssData;
      const entry = {
        cvss3: v3data ? { score: v3data.baseScore, vector: v3data.vectorString, severity: v3data.baseSeverity, version: v3data.version } : null,
        cvss2: v2data ? { score: v2data.baseScore, vector: v2data.vectorString, severity: v2data.baseSeverity } : null,
        description: vuln.descriptions?.find(d => d.lang === 'en')?.value || null,
      };
      nvdCache.set(cveId, entry);
      result[cveId] = entry;
    } catch { nvdCache.set(cveId, null); }
  });
  for (const c of cveIds) if (!(c in result)) result[c] = nvdCache.get(c) ?? null;
  return result;
}

async function fetchPocs(cveIds) {
  if (!cveIds.length) return {};
  const result = {};
  await pLimit(cveIds, 10, async (cveId) => {
    const m = cveId.match(/CVE-(\d{4})-/);
    if (!m) { result[cveId] = []; return; }
    try {
      const r = await fetch(`${POC_BASE}/${m[1]}/${cveId}.json`, {
        signal: AbortSignal.timeout(8000),
        headers: { 'Cache-Control': 'no-cache' },
      });
      if (r.status === 404) { result[cveId] = []; return; }
      const d = await r.json();
      result[cveId] = (Array.isArray(d) ? d : [])
        .map(p => ({ name: p.full_name || p.name, url: p.html_url, stars: p.stargazers_count || 0 }))
        .sort((a, b) => b.stars - a.stars)
        .slice(0, 5);
    } catch { result[cveId] = []; }
  });
  for (const c of cveIds) if (!result[c]) result[c] = [];
  return result;
}

function extractCVEs(vulns) {
  const s = new Set();
  for (const v of vulns) {
    for (const a of v.aliases || []) if (a.startsWith('CVE-')) s.add(a);
    if (v.id?.startsWith('CVE-')) s.add(v.id);
  }
  return [...s];
}

function parseSev(v) {
  for (const s of v.severity || []) {
    const sc = parseFloat(s.score);
    if (!isNaN(sc)) {
      if (sc >= 9) return 'CRITICAL';
      if (sc >= 7) return 'HIGH';
      if (sc >= 4) return 'MEDIUM';
      return 'LOW';
    }
  }
  const db = ((v.database_specific || {}).severity || '').toUpperCase();
  return ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].includes(db) ? db : 'UNKNOWN';
}

function getFixed(v) {
  for (const a of v.affected || [])
    for (const r of a.ranges || [])
      for (const e of r.events || [])
        if (e.fixed) return e.fixed;
  return null;
}

module.exports = { fetchEpss, fetchCvss, fetchPocs, extractCVEs, parseSev, getFixed };
