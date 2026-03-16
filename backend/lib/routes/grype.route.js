// routes/grype.route.js — POST /api/osscan
// Scans a single OS package via grype PURL (no image pull needed)
// Returns fully enriched vulns: CVSS, EPSS, KEV, PoC, Risk
'use strict';
const { withCache } = require('../auth/scanCache');

const express      = require('express');
const router       = express.Router();
const { execFile } = require('child_process');
const {
  SEV_ORD, scanLimiter, getCisaSet,
  fetchEpss, fetchCvss, fetchPocs, fetchOsvDesc,
  calcRisk,
} = require('../shared');

// ── Distro → PURL type mapping ────────────────────────────────
const DISTRO_MAP = {
  // ns     = PURL namespace  → grype resolves vuln DB namespace from this
  // distro = grype --distro flag value (used when no distroVersion provided too)
  //
  // SUSE: grype's internal vuln DB uses "opensuse-leap:distro:opensuse-leap:15.x"
  // So the PURL namespace must also be "opensuse-leap" for grype to match it.
  // (OSV/purl-spec prefers bare "opensuse", but grype ignores that without a hit)
  ubuntu: { type: 'deb', ns: 'ubuntu',       distro: 'ubuntu'        },
  debian: { type: 'deb', ns: 'debian',       distro: 'debian'        },
  rhel:   { type: 'rpm', ns: 'redhat',       distro: 'rhel'          },
  alpine: { type: 'apk', ns: 'alpine',       distro: 'alpine'        },
  suse:   { type: 'rpm', ns: 'opensuse-leap',distro: 'opensuse-leap' },
  sles:   { type: 'rpm', ns: 'sles',          distro: 'sles'          },
};

// ── Top severity from grype matches ──────────────────────────
function topSev(matches) {
  let best = 'NONE';
  for (const m of matches) {
    const s = (m.vulnerability?.severity || 'UNKNOWN').toUpperCase();
    const si = SEV_ORD.indexOf(s);
    const bi = SEV_ORD.indexOf(best);
    if (bi === -1 || (si !== -1 && si < bi)) best = s;
  }
  return best === 'NEGLIGIBLE' ? 'LOW' : best;
}

// ── Validate package/distro inputs ───────────────────────────
function validPkg(s) { return /^[a-zA-Z0-9._+\-:@/]+$/.test(s) && s.length < 200; }
function validDistroVer(s) { return /^[a-zA-Z0-9._\-]+$/.test(s) && s.length < 50; }

router.post('/osscan', async (req, res) => {
  const ip = req.ip || req.socket?.remoteAddress || 'unknown';

  const { name, version, distro, distroVersion } = req.body || {};

  if (!name)   return res.status(400).json({ error: 'Package name is required' });
  if (!distro) return res.status(400).json({ error: 'Distro is required' });

  // Validate all inputs BEFORE hitting the cache — avoids caching invalid
  // keys and prevents cache misses on every repeated bad request.
  if (!validPkg(name))                    return res.status(400).json({ error: 'Invalid package name' });
  if (version && !validPkg(version))      return res.status(400).json({ error: 'Invalid version' });
  if (distroVersion && !validDistroVer(distroVersion)) return res.status(400).json({ error: 'Invalid distro version' });

  const dm = DISTRO_MAP[distro.toLowerCase()];
  if (!dm) return res.status(400).json({ error: `Unknown distro: ${distro}` });

  const _cacheKey = `os:${distro}:${name}:${version||'any'}`;
  return withCache(_cacheKey, 'os', res, async () => {

  // Build PURL: pkg:deb/ubuntu/openssl@3.0.2
  const purl = `pkg:${dm.type}/${dm.ns}/${encodeURIComponent(name)}${version ? '@' + version : ''}`;

  // Build --distro flag: ubuntu:22.04
  const distroFlag = distroVersion ? `${dm.distro}:${distroVersion}` : dm.distro;

  console.log(`[Grype] Scanning PURL: ${purl} --distro ${distroFlag} (ip: ${ip})`);

  // ── Run grype ─────────────────────────────────────────────
  // --add-cpes-if-none: critical for Alpine/SUSE where secdb entries may
  // not match without CPE-based fallback matching
  const args = [purl, '--distro', distroFlag, '--add-cpes-if-none', '-o', 'json', '-q'];

  try {
    const raw = await new Promise((resolve, reject) => {
      execFile('grype', args, { timeout: 120_000, maxBuffer: 20 * 1024 * 1024 }, (err, stdout, stderr) => {
        if (err && !stdout) return reject(new Error(stderr || err.message));
        resolve(stdout);
      });
    });

    let parsed;
    try { parsed = JSON.parse(raw); }
    catch { return res.status(500).json({ error: 'Failed to parse Grype output' }); }

    const matches = parsed.matches || [];

    // ── Collect CVE IDs for enrichment ────────────────────────
    const cveIds = [...new Set(
      matches
        .map(m => m.vulnerability?.id)
        .filter(id => id?.startsWith('CVE-'))
    )];

    // ── Server-side enrichment (parallel) ────────────────────
    const [epssMap, cisaSet, cvssMap, pocMap] = await Promise.all([
      fetchEpss(cveIds).catch(() => ({})),
      getCisaSet().catch(() => new Set()),
      fetchCvss(cveIds).catch(() => ({})),
      fetchPocs(cveIds).catch(() => ({})),
    ]);

    // ── Build enriched vuln list ──────────────────────────────
    // ── OSV description fallback via shared fetchOsvDesc ──────────
    const osvDescMap = {};
    const missingDescCves = cveIds.filter(id => !cvssMap[id]?.description);
    if (missingDescCves.length) {
      await Promise.all(missingDescCves.map(async id => {
        const desc = await fetchOsvDesc(id).catch(() => null);
        if (desc) osvDescMap[id] = desc;
      }));
    }

    const vulns = matches.map(m => {
      const vuln   = m.vulnerability || {};
      const art    = m.artifact    || {};
      const cveId  = vuln.id || '';
      // VEX: prefer explicit vexStatus from matchDetails, fallback to fix.state
      const vexStatus = (m.matchDetails || [])
        .map(d => d.found?.vexStatus || null)
        .find(s => s) || null;
      const fixState = vuln.fix?.state || 'unknown';

      const VEX_LABEL = {
        // OpenVEX statuses
        'not_affected':        { label:'Not Affected',        cls:'LOW',      icon:'🟢' },
        'affected':            { label:'Affected',            cls:'HIGH',     icon:'🔴' },
        'fixed':               { label:'Fixed',               cls:'LOW',      icon:'✅' },
        'under_investigation': { label:'Under Investigation', cls:'MEDIUM',   icon:'🔍' },
        // Grype fix.state fallback
        'not-fixed':           { label:'Not Fixed',           cls:'HIGH',     icon:'🔴' },
        'wont-fix':            { label:'Wont Fix',          cls:'MEDIUM',   icon:'⚠️' },
        'unknown':             { label:'Unknown',             cls:'UNKNOWN',  icon:'❓' },
      };

      const vexKey = vexStatus || fixState;
      const vex = VEX_LABEL[vexKey] || { label: vexKey, cls:'UNKNOWN', icon:'❓' };
      // Mark source so UI can show tooltip
      vex.source = vexStatus ? 'OpenVEX' : 'Grype fix.state';
      const sev    = (vuln.severity || 'UNKNOWN').toUpperCase() === 'NEGLIGIBLE'
                       ? 'LOW'
                       : (vuln.severity || 'UNKNOWN').toUpperCase();

      const fixVersions = vuln.fix?.versions || [];
      const fix = fixVersions.length ? fixVersions.join(', ') : null;

      const cvss = cvssMap[cveId] || null;
      const epss = epssMap[cveId] || null;
      const risk = calcRisk(cvss, epss);

      return {
        id:          cveId,
        severity:    sev,
        summary:     cvssMap[cveId]?.description || vuln.description || osvDescMap[cveId] || '',
        description: cvssMap[cveId]?.description || vuln.description || osvDescMap[cveId] || '',
        fix,
        fixState:    vuln.fix?.state || 'unknown',
        urls:        vuln.urls || [],
        published:   vuln.publishedDate || null,
        pkgName:     art.name    || name,
        pkgVersion:  art.version || version || '',
        pkgType:     art.type    || dm.type,
        // Enrichment
        cvss,
        epss,
        inKev: cisaSet.has(cveId),
        pocs:  pocMap[cveId] || [],
        risk,
        vex,
      };
    });

    // Sort by severity
    vulns.sort((a, b) => SEV_ORD.indexOf(a.severity) - SEV_ORD.indexOf(b.severity));

    const counts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, UNKNOWN: 0 };
    vulns.forEach(v => { if (v.severity in counts) counts[v.severity]++; });

    return {
      package:      name,
      version:      version || null,
      distro,
      distroVersion: distroVersion || null,
      topSeverity:  topSev(matches),
      vulns,
      counts,
      scannedAt:    new Date().toISOString(),
    };

  } catch (e) {
    console.error('[Grype] Error:', e.message);
    throw e; // withCache will propagate, express error handler catches
  }
  }); // withCache
});

module.exports = router;
