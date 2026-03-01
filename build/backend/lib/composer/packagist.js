'use strict';

const { fetchJson } = require('../utils/http');
const { safeJson } = require('../utils/json');
const { normalizeVersion } = require('./names');

async function precheckPackagist(pkg, version) {
  try {
    const checkUrl = `https://repo.packagist.org/p2/${encodeURIComponent(pkg)}.json`;
    const checkRes = await fetch(checkUrl, { signal: AbortSignal.timeout(10000) });

    if (checkRes.status === 404) {
      return { ok: false, status: 404, error: `Пакет «${pkg}» не найден в Packagist.` };
    }

    if (version && /^\d+\.\d+\.\d+([.-][0-9A-Za-z.-]+)?$/.test(String(version).trim())) {
      const ct = checkRes.headers.get('content-type') || '';
      if (ct.includes('application/json') || ct.includes('text/json')) {
        const meta = safeJson(await checkRes.text(), null);
        const pkgVersions = meta?.packages?.[pkg];
        if (Array.isArray(pkgVersions)) {
          const want = normalizeVersion(version.trim());
          const exists = pkgVersions.some(v => normalizeVersion(v.version) === want);
          if (!exists) {
            return { ok: false, status: 404, error: `Версия «${version}» пакета «${pkg}» не существует в Packagist.` };
          }
        }
      } else {
        console.warn(`[composerscan] packagist pre-check returned non-JSON content-type: ${ct}`);
      }
    }

    return { ok: true };
  } catch (e) {
    console.warn('[composerscan] packagist pre-check failed:', e.message);
    return { ok: true };
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

    const want = normalizeVersion(resolvedVersion);
    const entry = versions.find(v => normalizeVersion(v.version) === want) || versions[0];
    if (!entry) return null;

    return {
      name: pkg,
      description: entry.description || null,
      homepage: entry.homepage || null,
      license: Array.isArray(entry.license) ? entry.license.join(', ') : (entry.license || null),
      time: entry.time || null,
      source: entry.source?.url || null,
    };
  } catch {
    return null;
  }
}

module.exports = { precheckPackagist, fetchPackagistInfo };
