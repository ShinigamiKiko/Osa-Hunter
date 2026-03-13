// routes/depscan.js — POST /api/depscan
// deps.dev граф + OSV + Toxic для root и каждой зависимости + EPSS/CISA/NVD/PoC
'use strict';
const { withCache, ScanError } = require('../auth/scanCache');
const express = require('express');
const router  = express.Router();
const {
  SEV_ORD, scanLimiter, rateLimit,
  checkToxic, pLimit,
  osvQuery, bulkEnrich, enrichVulns, extractCVEs,
} = require('../shared');

const DEPSDEV_URL     = 'https://api.deps.dev/v3alpha';
const DEPSDEV_SYSTEMS = new Set(['NPM','GO','PYPI','CARGO','MAVEN','NUGET']);
const SYSTEM_TO_OSV   = { NPM:'npm', GO:'Go', PYPI:'PyPI', CARGO:'crates.io', MAVEN:'Maven', NUGET:'NuGet' };
// Ecosystems where versions must be prefixed with 'v' (user may omit it)
const NEEDS_V_PREFIX  = new Set(['GO']);

function normalizeVersion(ver, sys) {
  if (!ver) return ver;
  if (NEEDS_V_PREFIX.has(sys) && !ver.startsWith('v')) return 'v' + ver;
  return ver;
}

async function depsDevGet(path) {
  const r = await fetch(`${DEPSDEV_URL}${path}`, {
    signal: AbortSignal.timeout(15000), headers: { Accept: 'application/json' },
  });
  if (!r.ok) throw new Error(`deps.dev HTTP ${r.status} for ${path}`);
  return r.json();
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

  const pkg       = name.trim();
  const osvEco    = SYSTEM_TO_OSV[sys];
  const _cacheKey = `dep:${sys}:${pkg}:${(version||'').trim()||'latest'}`;

  return withCache(_cacheKey, 'dep', res, async () => {
  console.log(`[depscan] ${sys}/${pkg}${version ? '@' + version : ''}`);

  // 1. Resolve version
  let resolvedVersion = normalizeVersion((version || '').trim(), sys);
  try {
    const data = await depsDevGet(`/systems/${sys.toLowerCase()}/packages/${encodeURIComponent(pkg)}`);
    const available = data.versions || [];
    if (!resolvedVersion) {
      const def = available.find(v => v.isDefault);
      resolvedVersion = def ? def.versionKey.version : (available[0]?.versionKey?.version || '');
    } else {
      const exists = available.some(v => v.versionKey.version === resolvedVersion);
      if (!exists && available.length > 0) {
        const latest = (available.find(v => v.isDefault) || available[available.length - 1])?.versionKey?.version;
        throw new ScanError(404,
          `Version "${resolvedVersion}" not found for ${pkg}. ` +
          (latest ? `Latest available: ${latest}` : `Try leaving the version field empty.`)
        );
      }
    }
  } catch (e) {
    if (e instanceof ScanError) throw e;
    throw new ScanError(502, `deps.dev package lookup failed: ${e.message}`);
  }
  if (!resolvedVersion)
    throw new ScanError(404, 'Could not resolve a version for this package');

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
    throw new ScanError(502, `deps.dev version lookup failed: ${e.message}`);
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

  // 4. OSV + Toxic per dep (concurrency=6) + root in parallel
  const scannedDeps = [];
  await pLimit(deps, 6, async (dep) => {
    const depEco = SYSTEM_TO_OSV[dep.system] || osvEco;
    const [vulns, toxic] = await Promise.all([
      osvQuery(dep.name, depEco, dep.version),
      checkToxic(dep.name),
    ]);
    scannedDeps.push({ ...dep, vulns, toxic });
  });

  const [rootVulns, rootToxic] = await Promise.all([
    osvQuery(pkg, osvEco, resolvedVersion),
    checkToxic(pkg),
  ]);

  const orderedDeps = deps.map(d =>
    scannedDeps.find(s => s.name === d.name && s.version === d.version && s.system === d.system)
    || { ...d, vulns: [], toxic: { found: false } }
  );

  // 5. Bulk enrichment for all CVEs
  const allCVEs = [...new Set([...extractCVEs(rootVulns), ...orderedDeps.flatMap(d => extractCVEs(d.vulns))])];
  console.log(`[depscan] enriching ${allCVEs.length} unique CVEs`);

  const maps = await bulkEnrich(allCVEs);

  // 6. Enrich root + deps
  const rootEnrichedVulns = enrichVulns(rootVulns, maps);
  const rootCounts = { CRITICAL:0, HIGH:0, MEDIUM:0, LOW:0, UNKNOWN:0 };
  for (const v of rootEnrichedVulns) if (v.severity in rootCounts) rootCounts[v.severity]++;

  const finalDeps = orderedDeps.map(dep => {
    const enrichedVulns = enrichVulns(dep.vulns, maps);
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
    rootVulnCount: rootEnrichedVulns.length,
    toxic     : finalDeps.filter(d => d.toxic?.found).length,
    CRITICAL  : rootCounts.CRITICAL + finalDeps.reduce((a, d) => a + d.counts.CRITICAL, 0),
    HIGH      : rootCounts.HIGH     + finalDeps.reduce((a, d) => a + d.counts.HIGH,     0),
    MEDIUM    : rootCounts.MEDIUM   + finalDeps.reduce((a, d) => a + d.counts.MEDIUM,   0),
    LOW       : rootCounts.LOW      + finalDeps.reduce((a, d) => a + d.counts.LOW,      0),
  };

  const rootEntry = {
    name       : pkg,
    system     : sys,
    version    : resolvedVersion,
    relation   : 'ROOT',
    toxic      : rootToxic,
    topSeverity: SEV_ORD.find(s => rootCounts[s] > 0) || 'NONE',
    vulnCount  : rootEnrichedVulns.length,
    counts     : rootCounts,
    vulns      : rootEnrichedVulns,
  };

  return {
    package: pkg, system: sys, version: version || null,
    resolvedVersion, scannedAt: new Date().toISOString(),
    toxic: rootToxic,
    info, summary, deps: [rootEntry, ...finalDeps],
  };
  }); // withCache
});

module.exports = router;
