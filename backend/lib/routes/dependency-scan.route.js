// routes/depscan.js — POST /api/depscan
// deps.dev граф + OSV + Toxic для root и каждой зависимости + EPSS/CISA/NVD/PoC
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

const DEPSDEV_URL     = 'https://api.deps.dev/v3alpha';
const DEPSDEV_SYSTEMS = new Set(['NPM','GO','PYPI','CARGO','MAVEN','NUGET']);
const SYSTEM_TO_OSV   = { NPM:'npm', GO:'Go', PYPI:'PyPI', CARGO:'crates.io', MAVEN:'Maven', NUGET:'NuGet' };
const SEV_ORD         = ['CRITICAL','HIGH','MEDIUM','LOW','UNKNOWN','NONE'];

async function depsDevGet(path) {
  const r = await fetch(`${DEPSDEV_URL}${path}`, {
    signal: AbortSignal.timeout(15000), headers: { Accept: 'application/json' },
  });
  if (!r.ok) throw new Error(`deps.dev HTTP ${r.status} for ${path}`);
  return r.json();
}

async function osvQueryDep(depName, depEco, depVer) {
  try {
    const body = { package: { name: depName, ecosystem: depEco } };
    if (depVer) body.version = depVer;
    const r = await fetch(`${OSV_URL}/query`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body), signal: AbortSignal.timeout(12000),
    });
    if (!r.ok) return [];
    const d = await r.json();
    return (d.vulns || []).map(v => ({
      ...v,
      _sev    : parseSev(v),
      _fix    : getFixed(v),
      _aliases: v.aliases || [],
      _refs   : (v.references || []).map(r => r.url),
    })).sort((a, b) => SEV_ORD.indexOf(a._sev) - SEV_ORD.indexOf(b._sev));
  } catch { return []; }
}

router.post('/depscan', rateLimit(scanLimiter), async (req, res) => {
  const { name, system, version } = req.body || {};

  if (!name || typeof name !== 'string' || !name.trim())
    return res.status(400).json({ error: '"name" is required' });
  if (!system || typeof system !== 'string')
    return res.status(400).json({ error: '"system" is required (NPM, GO, PYPI, CARGO, MAVEN, NUGET)' });

  const sys = system.trim().toUpperCase();
  if (!DEPSDEV_SYSTEMS.has(sys))
    return res.status(400).json({ error: `Unknown system "${sys}". Supported: ${[...DEPSDEV_SYSTEMS].join(', ')}` });

  const pkg    = name.trim();
  const _cacheKey = `dep:${sys}:${pkg}:${(version||'').trim()||'latest'}`;
  const osvEco = SYSTEM_TO_OSV[sys];

  return withCache(_cacheKey, 'dep', res, async () => {
  console.log(`[depscan] ${sys}/${pkg}${version ? '@' + version : ''}`);

  // 1. Resolve version
  let resolvedVersion = (version || '').trim();
  try {
    const data = await depsDevGet(`/systems/${sys.toLowerCase()}/packages/${encodeURIComponent(pkg)}`);
    if (!resolvedVersion) {
      const def = (data.versions || []).find(v => v.isDefault);
      resolvedVersion = def ? def.versionKey.version : (data.versions?.[0]?.versionKey?.version || '');
    }
  } catch (e) {
    return res.status(502).json({ error: `deps.dev package lookup failed: ${e.message}` });
  }
  if (!resolvedVersion)
    return res.status(404).json({ error: 'Could not resolve a version for this package' });

  // 2. Version details + dep graph
  let versionData, rawDeps = [];
  try {
    const encName = encodeURIComponent(pkg);
    const encVer  = encodeURIComponent(resolvedVersion);
    versionData = await depsDevGet(`/systems/${sys.toLowerCase()}/packages/${encName}/versions/${encVer}`);
    try {
      const depGraph = await depsDevGet(`/systems/${sys.toLowerCase()}/packages/${encName}/versions/${encVer}:dependencies`);
      rawDeps = depGraph.nodes || [];
    } catch (e) { console.warn('[depscan] dep graph unavailable:', e.message); }
  } catch (e) {
    return res.status(502).json({ error: `deps.dev version lookup failed: ${e.message}` });
  }

  const info = {
    description : versionData.description  || null,
    homepageUrl : versionData.homepageUrl  || null,
    licenses    : versionData.licenses     || [],
    links       : (versionData.links || []).map(l => typeof l === 'string' ? { url: l } : l),
    publishedAt : versionData.publishedAt  || null,
    isDefault   : versionData.isDefault    || false,
    isDeprecated: versionData.isDeprecated || false,
  };

  // 3. Deduplicated dep list (skip root node[0])
  const seen = new Map();
  for (const n of rawDeps.filter((_, i) => i !== 0)) {
    const vk  = n.versionKey || {};
    if (!vk.name || !vk.version) continue;
    const key = `${vk.system}:${vk.name}@${vk.version}`;
    if (!seen.has(key))
      seen.set(key, { name: vk.name, system: vk.system || sys, version: vk.version, relation: n.relation || 'INDIRECT' });
  }
  const deps = [...seen.values()];
  console.log(`[depscan] ${deps.length} deps for ${pkg}@${resolvedVersion}`);

  // 4. OSV + Toxic per dep (concurrency=6) + Toxic for root
  const { pLimit } = require('../shared');
  const scannedDeps = [];
  await pLimit(deps, 6, async (dep) => {
    const depEco = SYSTEM_TO_OSV[dep.system] || osvEco;
    const [vulns, toxic] = await Promise.all([
      osvQueryDep(dep.name, depEco, dep.version),
      checkToxic(dep.name),
    ]);
    scannedDeps.push({ ...dep, vulns, toxic });
  });

  const rootToxic  = await checkToxic(pkg);
  const orderedDeps = deps.map(d =>
    scannedDeps.find(s => s.name === d.name && s.version === d.version && s.system === d.system)
    || { ...d, vulns: [], toxic: { found: false } }
  );

  // 5. Bulk enrichment for all CVEs
  const allCVEs = [...new Set(orderedDeps.flatMap(d => extractCVEs(d.vulns)))];
  console.log(`[depscan] enriching ${allCVEs.length} unique CVEs`);

  const [epssRes, kevRes, cvssRes, pocRes] = await Promise.allSettled([
    fetchEpss(allCVEs),
    (async () => { const s = await getCisaSet(); return allCVEs.filter(c => s.has(c)); })(),
    fetchCvss(allCVEs),
    fetchPocs(allCVEs),
  ]);

  const epssMap = epssRes.status === 'fulfilled' ? epssRes.value : {};
  const kevSet  = new Set(kevRes.status === 'fulfilled' ? kevRes.value : []);
  const cvssMap = cvssRes.status === 'fulfilled' ? cvssRes.value : {};
  const pocMap  = pocRes.status  === 'fulfilled' ? pocRes.value  : {};

  // 6. Merge enrichment
  const finalDeps = orderedDeps.map(dep => {
    const enrichedVulns = dep.vulns.map(v => {
      const cve = [...(v._aliases || []), v.id].find(x => x.startsWith('CVE-')) || null;
      return {
        id      : v.id,
        summary : v.summary   || null,
        details : v.details   || null,
        published: v.published || null,
        severity: v._sev,
        fix     : v._fix      || null,
        aliases : v._aliases,
        refs    : v._refs,
        cve,
        epss  : cve ? (epssMap[cve] || null) : null,
        cvss  : cve ? (cvssMap[cve] || null) : null,
        inKev : cve ? kevSet.has(cve)         : false,
        pocs  : cve ? (pocMap[cve]  || [])    : [],
      };
    });
    const cnt = { CRITICAL:0, HIGH:0, MEDIUM:0, LOW:0, UNKNOWN:0 };
    for (const v of enrichedVulns) if (v.severity in cnt) cnt[v.severity]++;
    return {
      name       : dep.name,
      system     : dep.system,
      version    : dep.version,
      relation   : dep.relation,
      toxic      : dep.toxic,
      topSeverity: SEV_ORD.find(s => cnt[s] > 0) || 'NONE',
      vulnCount  : enrichedVulns.length,
      counts     : cnt,
      vulns      : enrichedVulns,
    };
  });

  // 7. Summary
  const summary = {
    totalDeps : finalDeps.length,
    directDeps: finalDeps.filter(d => d.relation === 'DIRECT').length,
    withVulns : finalDeps.filter(d => d.vulnCount > 0).length,
    toxic     : finalDeps.filter(d => d.toxic?.found).length,
    CRITICAL  : finalDeps.reduce((a, d) => a + d.counts.CRITICAL, 0),
    HIGH      : finalDeps.reduce((a, d) => a + d.counts.HIGH,     0),
    MEDIUM    : finalDeps.reduce((a, d) => a + d.counts.MEDIUM,   0),
    LOW       : finalDeps.reduce((a, d) => a + d.counts.LOW,      0),
  };

  return {
    package: pkg, system: sys, version: version || null,
    resolvedVersion, scannedAt: new Date().toISOString(),
    toxic: rootToxic,
    info, summary, deps: finalDeps,
  };
  }); // withCache
});

module.exports = router;
