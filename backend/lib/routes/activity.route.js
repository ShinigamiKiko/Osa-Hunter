// routes/activity.js — POST /api/activity
'use strict';
const express = require('express');
const router  = express.Router();
const { TtlCache, apiLimiter, rateLimit } = require('../shared');

const DEPSDEV_URL  = 'https://api.deps.dev/v3alpha';
const ACTIVITY_CACHE_MAX = 2000;
const activityCache = new TtlCache(6 * 3_600_000);

// Wrap set to evict the oldest entry when cap is reached
const _actSet = activityCache.set.bind(activityCache);
activityCache.set = (key, value) => {
  if (!activityCache.has(key) && activityCache._map.size >= ACTIVITY_CACHE_MAX) {
    activityCache._map.delete(activityCache._map.keys().next().value);
  }
  _actSet(key, value);
};

async function resolveGithubRepo(name, ecosystem) {
  const sys = ecosystem?.toUpperCase();

  // 1. deps.dev
  try {
    const encSys  = (sys || 'NPM').toLowerCase();
    const encName = encodeURIComponent(name);
    const pkgData = await fetch(`${DEPSDEV_URL}/systems/${encSys}/packages/${encName}`, { signal: AbortSignal.timeout(8000), headers: { Accept: 'application/json' } });
    if (pkgData.ok) {
      const pd = await pkgData.json();
      const defVer = (pd.versions || []).find(v => v.isDefault) || pd.versions?.[0];
      if (defVer) {
        const verData = await fetch(`${DEPSDEV_URL}/systems/${encSys}/packages/${encName}/versions/${encodeURIComponent(defVer.versionKey.version)}`, { signal: AbortSignal.timeout(8000), headers: { Accept: 'application/json' } });
        if (verData.ok) {
          const vd = await verData.json();
          for (const link of vd.links || []) {
            const u = (link.url || link || '').toString();
            const m = u.match(/github\.com\/([^/]+\/[^/\s#?]+)/i);
            if (m) return { repo: m[1].replace(/\.git$/, ''), source: 'deps.dev' };
          }
        }
      }
    }
  } catch {}

  // 2. npm
  if (!sys || sys === 'NPM') {
    try {
      const r = await fetch(`https://registry.npmjs.org/${encodeURIComponent(name)}/latest`, { signal: AbortSignal.timeout(8000) });
      if (r.ok) {
        const d = await r.json();
        const m = (d.repository?.url || d.homepage || '').match(/github\.com\/([^/]+\/[^/\s#?.]+)/i);
        if (m) return { repo: m[1].replace(/\.git$/, ''), source: 'npm' };
      }
    } catch {}
  }

  // 3. PyPI
  if (sys === 'PYPI') {
    try {
      const r = await fetch(`https://pypi.org/pypi/${encodeURIComponent(name)}/json`, { signal: AbortSignal.timeout(8000) });
      if (r.ok) {
        const d = await r.json();
        const urls = Object.values(d.info?.project_urls || {});
        for (const u of [d.info?.home_page, ...urls]) {
          const m = (u || '').match(/github\.com\/([^/]+\/[^/\s#?.]+)/i);
          if (m) return { repo: m[1].replace(/\.git$/, ''), source: 'pypi' };
        }
      }
    } catch {}
  }

  return null;
}

router.post('/activity', rateLimit(apiLimiter), async (req, res) => {
  const { name, ecosystem } = req.body || {};
  if (!name) return res.status(400).json({ error: '"name" required' });

  const cacheKey = `act:${(ecosystem||'').toLowerCase()}:${name.toLowerCase()}`;
  if (activityCache.has(cacheKey)) return res.json(activityCache.get(cacheKey));

  try {
    const resolved = await resolveGithubRepo(name, ecosystem);
    if (!resolved) {
      const result = { found: false, lastCommit: null, repoUrl: null, source: null };
      activityCache.set(cacheKey, result);
      return res.json(result);
    }

    const { repo, source } = resolved;
    const repoUrl = `https://github.com/${repo}`;
    const headers = { Accept: 'application/vnd.github+json', 'User-Agent': 'OSAGuard/1.0' };
    if (process.env.GITHUB_TOKEN) headers['Authorization'] = `Bearer ${process.env.GITHUB_TOKEN}`;

    const r = await fetch(`https://api.github.com/repos/${repo}/commits?per_page=1`, { signal: AbortSignal.timeout(10000), headers });
    if (!r.ok) {
      const isRateLimit = r.status === 403 || r.status === 429;
      const result = { found: true, lastCommit: null, repoUrl, source, rateLimited: isRateLimit, error: `GitHub ${r.status}` };
      if (!isRateLimit) activityCache.set(cacheKey, result);
      return res.json(result);
    }

    const commits    = await r.json();
    const lastCommit = commits[0]?.commit?.committer?.date || commits[0]?.commit?.author?.date || null;
    const result     = { found: true, lastCommit, repoUrl, source };
    activityCache.set(cacheKey, result);
    res.json(result);
  } catch (e) {
    const result = { found: false, lastCommit: null, repoUrl: null, source: null, error: e.message };
    activityCache.set(cacheKey, result);
    res.json(result);
  }
});

module.exports = router;
