'use strict';

const { OSV_URL, extractCVEs, parseSev, getFixed } = require('../shared');

const OSV_ECOSYSTEM = 'Packagist';
const SEV_ORD = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN', 'NONE'];

async function osvQueryPackagist(name, version) {
  try {
    const body = { package: { name, ecosystem: OSV_ECOSYSTEM } };
    if (version) body.version = version;

    const r = await fetch(`${OSV_URL}/query`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
      signal: AbortSignal.timeout(12000),
    });
    if (!r.ok) return [];

    const ct = r.headers.get('content-type') || '';
    if (!ct.includes('application/json') && !ct.includes('text/json')) {
      console.warn(`[osvQueryPackagist] Non-JSON response for ${name}@${version}`);
      return [];
    }

    const d = await r.json();
    return (d.vulns || [])
      .map(v => ({
        ...v,
        _sev: parseSev(v),
        _fix: getFixed(v),
        _aliases: v.aliases || [],
        _refs: (v.references || []).map(r => r.url),
      }))
      .sort((a, b) => SEV_ORD.indexOf(a._sev) - SEV_ORD.indexOf(b._sev));
  } catch {
    return [];
  }
}

function mapVulnForApi(x) {
  return {
    id: x.id,
    summary: x.summary || x.details || '',
    severity: x._sev,
    aliases: x._aliases,
    fixed: x._fix,
    refs: x._refs,
  };
}

function extractCvesFromOsv(vulns) {
  return extractCVEs(vulns);
}

module.exports = { osvQueryPackagist, mapVulnForApi, extractCvesFromOsv };
