'use strict';

const express = require('express');
const router  = express.Router();
const fs      = require('fs');
const fsp     = fs.promises;
const path    = require('path');
const os      = require('os');
const { spawn } = require('child_process');

const {
  OSV_URL, scanLimiter, rateLimit,
  getCisaSet, checkToxic,
  fetchEpss, fetchCvss, fetchPocs,
  extractCVEs, parseSev, getFixed,
} = require('../shared');

const OSV_ECOSYSTEM = 'Packagist';
const SEV_ORD       = ['CRITICAL','HIGH','MEDIUM','LOW','UNKNOWN','NONE'];

/* ─────────────────────────────────────────────
   Helpers
───────────────────────────────────────────── */

class HttpError extends Error {
  constructor(statusCode, msg, details) {
    super(msg);
    this.statusCode = statusCode;
    this.details    = details;
  }
}

function safeJson(str, fallback = null) {
  try {
    return JSON.parse(str || '{}');
  } catch (e) {
    console.warn('[safeJson] parse failed:', e.message, '| input:', String(str).slice(0, 300));
    return fallback;
  }
}

async function fetchJson(url, opts = {}) {
  try {
    const r = await fetch(url, opts);
    if (!r.ok) {
      console.warn(`[fetchJson] HTTP ${r.status} from ${url}`);
      return null;
    }
    const ct = r.headers.get('content-type') || '';
    if (!ct.includes('application/json') && !ct.includes('text/json')) {
      const text = await r.text();
      console.warn(`[fetchJson] Expected JSON but got "${ct}" from ${url}: ${text.slice(0, 300)}`);
      return null;
    }
    return await r.json();
  } catch (e) {
    console.warn(`[fetchJson] error fetching ${url}:`, e.message);
    return null;
  }
}

function run(cmd, args, opts = {}) {
  return new Promise((resolve, reject) => {
    const p = spawn(cmd, args, { ...opts, stdio: ['ignore', 'pipe', 'pipe'] });
    let out = '', err = '';
    p.stdout.on('data', d => out += d.toString());
    p.stderr.on('data', d => err += d.toString());
    p.on('error', reject);
    p.on('close', code => {
      if (code === 0) return resolve({ out, err });
      const msg = `${cmd} ${args.join(' ')} exited ${code}: ${err || out}`;
      const e   = new Error(msg);
      e.exitCode = code;
      e.stdout   = out;
      e.stderr   = err;
      reject(e);
    });
  });
}

function normalizeVersion(v) {
  if (!v) return v;
  return String(v).trim().replace(/^v/i, '');
}

function isComposerPackageName(name) {
  return /^[a-z0-9]([_.-]?[a-z0-9]+)*\/[a-z0-9](([_.]?|-{0,2})[a-z0-9]+)*$/i.test(
    String(name || '').trim()
  );
}

function normalizeComposerConstraint(v) {
  if (v == null) return '*';
  const s0 = String(v).trim();
  if (!s0) return '*';

  const s = s0.toLowerCase();
  if (s === 'latest') return '*';

  const raw = s0.trim();

  if (
    /[~^*<>=|]/.test(raw) ||
    raw.startsWith('dev-') ||
    raw.includes('||') ||
    raw.includes('@')
  ) return raw;

  if (/^\d+\.\d+\.\d+([.-][0-9A-Za-z.-]+)?$/.test(raw)) return `==${raw}`;

  if (/^\d+(\.\d+)?$/.test(raw)) return `^${raw}`;

  return raw;
}

function classifyComposerError(pkg, constraint, errMsg) {
  const msg = String(errMsg || '');

  if (/could not find (a matching|any) package|no matching package found|package .* not found/i.test(msg)) {
    return new HttpError(404, `Пакет «${pkg}» не найден в Packagist (или версия недоступна).`);
  }

  if (/affected by security advisories|block-insecure|security advisories/i.test(msg)) {
    return new HttpError(
      409,
      `Composer заблокировал разрешение зависимостей для «${pkg}@${constraint}» из-за security advisories (Packagist audit).`,
      { kind: 'security_advisories' }
    );
  }

  if (/requires php|requires ext-|composer-runtime-api|php extension/i.test(msg)) {
    return new HttpError(
      409,
      `Не удалось разрешить «${pkg}@${constraint}»: platform requirements (версия PHP / ext-*).`,
      { kind: 'platform_requirements' }
    );
  }

  if (/Your requirements could not be resolved|conflict|cannot be resolved to an installable set/i.test(msg)) {
    return new HttpError(
      409,
      `Не удалось разрешить зависимости для «${pkg}@${constraint}»: конфликт ограничений зависимостей.`,
      { kind: 'dependency_conflict' }
    );
  }

  if (/Could not parse version constraint|Invalid version string/i.test(msg)) {
    return new HttpError(
      400,
      `Неверный constraint версии для «${pkg}»: «${constraint}». Используй, например, "3.0.0", "^3.0", "~3.0", "*" или "dev-main".`,
      { kind: 'bad_constraint' }
    );
  }

  return new HttpError(502, `Composer scan failed for «${pkg}@${constraint}».`);
}

async function osvQueryPackagist(name, version) {
  try {
    const body = { package: { name, ecosystem: OSV_ECOSYSTEM } };
    if (version) body.version = version;

    const r = await fetch(`${OSV_URL}/query`, {
      method  : 'POST',
      headers : { 'Content-Type': 'application/json' },
      body    : JSON.stringify(body),
      signal  : AbortSignal.timeout(12000),
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
        _sev    : parseSev(v),
        _fix    : getFixed(v),
        _aliases: v.aliases || [],
        _refs   : (v.references || []).map(r => r.url),
      }))
      .sort((a, b) => SEV_ORD.indexOf(a._sev) - SEV_ORD.indexOf(b._sev));
  } catch {
    return [];
  }
}

async function fetchPackagistInfo(pkg, resolvedVersion) {
  try {
    const meta = await fetchJson(
      `https://repo.packagist.org/p2/${encodeURIComponent(pkg)}.json`,
      { signal: AbortSignal.timeout(12000), headers: { Accept: 'application/json' } }
    );
    if (!meta) return null;

    const versions = meta.packages?.[pkg];
    if (!Array.isArray(versions)) return null;

    const want  = normalizeVersion(resolvedVersion);
    const entry = versions.find(v => normalizeVersion(v.version) === want) || versions[0];
    if (!entry) return null;

    return {
      name       : pkg,
      description: entry.description || null,
      homepage   : entry.homepage    || null,
      license    : Array.isArray(entry.license)
                     ? entry.license.join(', ')
                     : (entry.license || null),
      time  : entry.time           || null,
      source: entry.source?.url    || null,
    };
  } catch {
    return null;
  }
}

/* ─────────────────────────────────────────────
   Route
───────────────────────────────────────────── */

router.post('/composerscan', rateLimit(scanLimiter), async (req, res) => {
  let tmpRoot = null;

  try {
    const { name, version, ignorePlatformReqs } = req.body || {};

    /* ── Input validation ── */
    if (!name || typeof name !== 'string' || !name.trim()) {
      return res.status(400).json({ error: '"name" is required (e.g., monolog/monolog)' });
    }

    const pkg = name.trim();

    if (!isComposerPackageName(pkg)) {
      return res.status(400).json({
        error: `Неверное имя пакета: «${pkg}». Для Composer нужно "vendor/package" (например, "symfony/console").`,
      });
    }

    const constraint = normalizeComposerConstraint(version);

    console.log(`[composerscan] ${pkg}@${version || '*'} (constraint: ${constraint})`);

    /* ── Pre-check: package exists on Packagist ── */
    try {
      const checkUrl = `https://repo.packagist.org/p2/${encodeURIComponent(pkg)}.json`;
      const checkRes = await fetch(checkUrl, { signal: AbortSignal.timeout(10000) });

      if (checkRes.status === 404) {
        return res.status(404).json({ error: `Пакет «${pkg}» не найден в Packagist.` });
      }

      if (version && /^\d+\.\d+\.\d+([.-][0-9A-Za-z.-]+)?$/.test(String(version).trim())) {
        const ct = checkRes.headers.get('content-type') || '';
        if (ct.includes('application/json') || ct.includes('text/json')) {
          const meta        = safeJson(await checkRes.text(), null);
          const pkgVersions = meta?.packages?.[pkg];
          if (Array.isArray(pkgVersions)) {
            const want   = normalizeVersion(version.trim());
            const exists = pkgVersions.some(v => normalizeVersion(v.version) === want);
            if (!exists) {
              return res.status(404).json({
                error: `Версия «${version}» пакета «${pkg}» не существует в Packagist.`,
              });
            }
          }
        } else {
          console.warn(`[composerscan] packagist pre-check returned non-JSON content-type: ${ct}`);
        }
      }
    } catch (preErr) {
      console.warn('[composerscan] packagist pre-check failed:', preErr.message);
    }

    /* ── Temp workspace ── */
    tmpRoot = await fsp.mkdtemp(path.join(os.tmpdir(), 'osa-composer-'));
    const composerJsonPath = path.join(tmpRoot, 'composer.json');
    const composerLockPath = path.join(tmpRoot, 'composer.lock');

    await fsp.writeFile(composerJsonPath, JSON.stringify({
      name   : 'tmp/osa-dep-scan',
      version: '1.0.0',
      require: { [pkg]: constraint },
      'minimum-stability': 'dev',
      'prefer-stable'    : true,
      config: {
        'allow-plugins'  : false,
        'audit'          : { 'abandoned': 'ignore', 'block-insecure': false },
      },
    }, null, 2));

    const env = {
      ...process.env,
      HOME               : tmpRoot,
      COMPOSER_HOME      : path.join(tmpRoot, '.composer'),
      COMPOSER_CACHE_DIR : path.join(tmpRoot, '.composer-cache'),
      COMPOSER_NO_INTERACTION: '1',
      COMPOSER_ROOT_VERSION  : '1.0.0',
    };

    const args = [
      'update',
      '--no-interaction',
      '--no-plugins',
      '--no-scripts',
      '--no-dev',
      '--no-install',
      '--prefer-dist',
      '--no-progress',
      '--no-audit',
    ];

    if (ignorePlatformReqs !== false) {
      args.push('--ignore-platform-reqs');
    }

    /* ── Resolve versions (no install) ── */
    try {
      await run('composer', args, { cwd: tmpRoot, env });
    } catch (runErr) {
      throw classifyComposerError(pkg, constraint, runErr.message || runErr.stderr || runErr.stdout);
    }

    /* ── Parse composer.lock ── */
    const lockRaw = await fsp.readFile(composerLockPath, 'utf8').catch(() => null);
    if (!lockRaw) {
      throw new HttpError(502, 'composer.lock не был создан — зависимости не разрешены.');
    }

    const lock = safeJson(lockRaw, { packages: [], 'packages-dev': [] });
    const pkgs = [...(lock.packages || []), ...(lock['packages-dev'] || [])];

    /* ── Resolved version of root package ── */
    let resolvedVersion = null;
    try {
      const { out } = await run(
        'composer', ['show', '--locked', pkg, '--format=json'],
        { cwd: tmpRoot, env }
      );
      const j = safeJson(out, {});
      resolvedVersion = j?.versions?.[0] || j?.version || null;
    } catch { /* ignore */ }

    const resolved =
      normalizeVersion(resolvedVersion) ||
      normalizeVersion(pkgs.find(p => p.name === pkg)?.version) ||
      null;

    /* ── Dependency graph ── */
    const requiresMap   = new Map();
    const nameToVersion = new Map();

    for (const p of pkgs) {
      nameToVersion.set(p.name, normalizeVersion(p.version));
      const deps = Object.keys(p.require || {}).filter(n => !/^php$|^ext-|^lib-/i.test(n));
      requiresMap.set(p.name, deps);
    }

    // BFS from the scanned package (NOT from our fake root project)
    // Direct = packages that the scanned package directly requires
    // Transitive = everything else reachable through the graph
    const scannedPkgRequires = requiresMap.get(pkg) || [];

    const seen  = new Set();
    const q     = [{ name: pkg, depth: 0 }];
    const edges = [];

    while (q.length) {
      const { name: current, depth } = q.shift();
      if (seen.has(current)) continue;
      seen.add(current);
      const deps = requiresMap.get(current) || [];
      for (const d of deps) {
        if (nameToVersion.has(d)) { // only track deps that are actually in the lock
          edges.push([current, d]);
          if (!seen.has(d)) q.push({ name: d, depth: depth + 1 });
        }
      }
    }

    // Direct children = what the scanned package itself requires (from its own composer.json in lock)
    const directSet     = new Set(scannedPkgRequires.filter(n => nameToVersion.has(n)));
    // Transitive = everything reachable except the scanned package itself and its direct deps
    const transitiveSet = new Set([...seen].filter(n => n !== pkg && !directSet.has(n)));

    console.log(`[composerscan] ${pkg}: requires=${JSON.stringify(scannedPkgRequires)}, direct=${[...directSet]}, transitive=${[...transitiveSet].slice(0,10)}`);

    /* ── Enrich each dependency ── */
    const cisaSet = await getCisaSet();

    async function enrichOne(depName) {
      const v     = nameToVersion.get(depName) || null;
      const vulns = v ? await osvQueryPackagist(depName, v) : [];
      const cves  = extractCVEs(vulns);
      const toxic = checkToxic(depName);
      const epss  = await fetchEpss(cves);
      const cvss  = await fetchCvss(cves);
      const pocs  = await fetchPocs(cves);
      const kev   = cves.filter(id => cisaSet.has(id));

      return {
        name   : depName,
        version: v,
        toxic,
        vulns  : vulns.map(x => ({
          id      : x.id,
          summary : x.summary || x.details || '',
          severity: x._sev,
          aliases : x._aliases,
          fixed   : x._fix,
          refs    : x._refs,
        })),
        cves,
        kev,
        epss,
        cvss,
        pocs,
      };
    }

    const rootToxic = checkToxic(pkg);
    const info      = await fetchPackagistInfo(pkg, resolved);

    const rootVersionForOsv = normalizeVersion(version) || resolved;
    async function enrichRoot() {
      const v     = resolved || rootVersionForOsv;
      const vulns = rootVersionForOsv ? await osvQueryPackagist(pkg, rootVersionForOsv) : [];
      const cves  = extractCVEs(vulns);
      const toxic = rootToxic;
      const epss  = await fetchEpss(cves);
      const cvss  = await fetchCvss(cves);
      const pocs  = await fetchPocs(cves);
      const kev   = cves.filter(id => cisaSet.has(id));
      console.log(`[composerscan] root ${pkg}@${rootVersionForOsv} → ${vulns.length} vulns`);
      return {
        name   : pkg,
        version: v,
        toxic,
        vulns  : vulns.map(x => ({
          id      : x.id,
          summary : x.summary || x.details || '',
          severity: x._sev,
          aliases : x._aliases,
          fixed   : x._fix,
          refs    : x._refs,
        })),
        cves, kev, epss, cvss, pocs,
        _isRoot: true,
      };
    }

    const rootEnriched           = await enrichRoot();
    const directDepsEnriched     = await Promise.all([...directSet].sort().map(enrichOne));
    const transitiveDepsEnriched = await Promise.all([...transitiveSet].sort().map(enrichOne));
    console.log(`[composerscan] ${pkg}: root=${resolved}, direct=${directSet.size}, transitive=${transitiveSet.size}, total_pkgs=${pkgs.length}`);

    /* ── Summary ── */
    function countWithVulns(list) {
      return list.filter(d => (d.cves || []).length > 0).length;
    }

    const summary = {
      total      : directSet.size + transitiveSet.size,
      direct     : directSet.size,
      transitive : transitiveSet.size,
      withVulns  : countWithVulns([rootEnriched, ...directDepsEnriched, ...transitiveDepsEnriched]),
      resolvedVersion: resolved,
    };

    const deps = {
      root      : rootEnriched,
      direct    : directDepsEnriched,
      transitive: transitiveDepsEnriched,
      edges,
    };

    /* ── Response ── */
    return res.json({
      package         : pkg,
      system          : 'COMPOSER',
      version         : version || null,
      versionConstraint: constraint,
      resolvedVersion : resolved || null,
      scannedAt       : new Date().toISOString(),
      toxic           : rootToxic,
      info,
      summary,
      deps,
    });

  } catch (e) {
    console.error('[composerscan]', e);
    const status  = e.statusCode || 502;
    const payload = { error: e.message || 'Composer scan failed' };
    if (e.details) payload.details = e.details;
    return res.status(status).json(payload);

  } finally {
    if (tmpRoot) {
      try { await fsp.rm(tmpRoot, { recursive: true, force: true }); } catch {}
    }
  }
});

module.exports = router;