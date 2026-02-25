const express = require('express');
const cors = require('cors');
const path = require('path');
const { execFile } = require('child_process');

const app = express();

// ── Security headers ──────────────────────────────────────────
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  res.setHeader('Referrer-Policy', 'no-referrer');
  next();
});

// ── CORS ──────────────────────────────────────────────────────
app.use(cors({ origin: process.env.CORS_ORIGIN || '*' }));

// ── Body size limit (prevent large payload DoS) ───────────────
app.use(express.json({ limit: '64kb' }));
app.use(express.static(path.join(__dirname, 'frontend/public')));

const EPSS_URL = 'https://api.first.org/data/v1/epss';
const OSV_URL  = 'https://api.osv.dev/v1';
const CISA_URL = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json';
const POC_BASE = 'https://raw.githubusercontent.com/nomi-sec/PoC-in-GitHub/master';

// ── Input validation helpers ──────────────────────────────────
const MAX_PKG_NAME  = 214; // npm max package name length
const MAX_CVE_BATCH = 100;
const CVE_RE = /^CVE-\d{4}-\d{4,}$/i;

function validatePkgName(name) {
  return typeof name === 'string' && name.length > 0 && name.length <= MAX_PKG_NAME;
}

function validateCveBatch(cves) {
  if (!Array.isArray(cves) || !cves.length) return null;
  const clean = cves.filter(c => typeof c === 'string' && CVE_RE.test(c)).slice(0, MAX_CVE_BATCH);
  return clean.length ? clean : null;
}

// ── Утилиты ───────────────────────────────────────────────────

/** TTL-кэш: хранит { value, expiresAt } */
class TtlCache {
  constructor(ttlMs) {
    this._map   = new Map();
    this._ttlMs = ttlMs;
  }
  has(key) {
    const e = this._map.get(key);
    if (!e) return false;
    if (Date.now() > e.expiresAt) { this._map.delete(key); return false; }
    return true;
  }
  get(key) {
    return this.has(key) ? this._map.get(key).value : undefined;
  }
  set(key, value) {
    this._map.set(key, { value, expiresAt: Date.now() + this._ttlMs });
  }
}

/** Ограничитель параллельных промисов */
async function pLimit(items, concurrency, fn) {
  const results = [];
  let idx = 0;
  async function worker() {
    while (idx < items.length) {
      const i = idx++;
      results[i] = await fn(items[i]);
    }
  }
  const workers = Array.from({ length: Math.min(concurrency, items.length) }, worker);
  await Promise.all(workers);
  return results;
}

/** Простой rate-limiter (sliding window) */
class RateLimiter {
  constructor(maxRequests, windowMs) {
    this._max    = maxRequests;
    this._window = windowMs;
    this._log    = new Map(); // ip -> [timestamps]
  }
  check(ip) {
    const now  = Date.now();
    const hits = (this._log.get(ip) || []).filter(t => now - t < this._window);
    if (hits.length >= this._max) return false;
    hits.push(now);
    this._log.set(ip, hits);
    // Периодически чистим старые IP (раз в 5 мин)
    if (Math.random() < 0.01) this._cleanup(now);
    return true;
  }
  _cleanup(now) {
    for (const [ip, hits] of this._log) {
      if (hits.every(t => now - t >= this._window)) this._log.delete(ip);
    }
  }
}

const trivyLimiter = new RateLimiter(
  parseInt(process.env.TRIVY_RATE_LIMIT  || '5'),
  parseInt(process.env.TRIVY_RATE_WINDOW || '60000')
);

// General API rate limiter: 120 req/min per IP (covers OSV, EPSS, CISA, PoC, NVD)
const apiLimiter = new RateLimiter(
  parseInt(process.env.API_RATE_LIMIT  || '120'),
  parseInt(process.env.API_RATE_WINDOW || '60000')
);

// Heavy scan endpoints: 20 req/min per IP
const scanLimiter = new RateLimiter(
  parseInt(process.env.SCAN_RATE_LIMIT  || '20'),
  parseInt(process.env.SCAN_RATE_WINDOW || '60000')
);

// Middleware factory
function rateLimit(limiter) {
  return (req, res, next) => {
    const ip = req.headers['x-forwarded-for']?.split(',')[0].trim() || req.socket.remoteAddress || 'unknown';
    if (!limiter.check(ip)) return res.status(429).json({ error: 'Rate limit exceeded. Please wait before retrying.' });
    next();
  };
}

/** Валидация docker-образа — только безопасные символы */
const IMAGE_RE = /^[a-z0-9\-_./:@]+$/i;
function validateImage(image) {
  return typeof image === 'string' && image.length > 0 && image.length < 512 && IMAGE_RE.test(image);
}

// ── CISA KEV cache ────────────────────────────────────────────
let cisaCache = { set: null, ts: 0 };
async function getCisaSet() {
  if (cisaCache.set && Date.now() - cisaCache.ts < 3_600_000) return cisaCache.set;
  try {
    const r = await fetch(CISA_URL, { signal: AbortSignal.timeout(15000) });
    const d = await r.json();
    cisaCache.set = new Set((d.vulnerabilities || []).map(v => v.cveID));
    cisaCache.ts  = Date.now();
    console.log('[CISA] KEV loaded:', cisaCache.set.size, 'entries');
  } catch (e) {
    console.error('[CISA] Fetch failed:', e.message);
    if (!cisaCache.set) cisaCache.set = new Set();
  }
  return cisaCache.set;
}

// ── NVD CVSS cache с TTL (24 ч) ───────────────────────────────
const nvdCache = new TtlCache(24 * 3_600_000);

// ── Health ────────────────────────────────────────────────────
app.get('/api/health', (req, res) => {
  execFile('trivy', ['--version'], { timeout: 5000 }, (err, stdout) => {
    res.json({
      status : 'ok',
      trivy  : !err,
      version: err ? null : (stdout.split('\n')[0] || '').trim(),
    });
  });
});

// ── OSV query (validated — не open proxy) ─────────────────────
app.post('/api/osv/query', rateLimit(apiLimiter), async (req, res) => {
  // Accept only known OSV query shapes: { package, version } or { commit }
  const { package: pkg, version, commit, purl } = req.body || {};
  if (!pkg && !commit && !purl) return res.status(400).json({ error: 'package, commit, or purl required' });
  if (pkg && typeof pkg !== 'object') return res.status(400).json({ error: 'package must be an object' });
  if (version && typeof version !== 'string') return res.status(400).json({ error: 'invalid version' });

  const body = {};
  if (pkg)     body.package = { name: String(pkg.name || '').slice(0, MAX_PKG_NAME), ecosystem: String(pkg.ecosystem || '').slice(0, 50) };
  if (version) body.version = String(version).slice(0, 100);
  if (commit)  body.commit  = String(commit).slice(0, 40);
  if (purl)    body.purl    = String(purl).slice(0, 256);

  try {
    const r = await fetch(`${OSV_URL}/query`, {
      method : 'POST',
      headers: { 'Content-Type': 'application/json' },
      body   : JSON.stringify(body),
      signal : AbortSignal.timeout(15000),
    });
    res.json(await r.json());
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ── EPSS ─────────────────────────────────────────────────────
app.post('/api/epss', rateLimit(apiLimiter), async (req, res) => {
  const cves = validateCveBatch(req.body?.cves);
  if (!cves) return res.json({ data: {} });
  try {
    const results = {};
    for (let i = 0; i < cves.length; i += 30) {
      const chunk = cves.slice(i, i + 30);
      const url   = `${EPSS_URL}?cve=${chunk.join(',')}&limit=${chunk.length}`;
      console.log('[EPSS] Fetching:', url);
      const r = await fetch(url, { signal: AbortSignal.timeout(15000) });
      if (!r.ok) { console.error('[EPSS] HTTP', r.status); continue; }
      const d = await r.json();
      console.log('[EPSS] Got', d.data?.length, 'results for', chunk.length, 'CVEs');
      for (const item of d.data || [])
        results[item.cve] = { epss: parseFloat(item.epss), percentile: parseFloat(item.percentile) };
    }
    res.json({ data: results });
  } catch (e) {
    console.error('[EPSS] Error:', e.message);
    res.status(500).json({ error: e.message });
  }
});

// ── EPSS status ───────────────────────────────────────────────
app.get('/api/epss/status', async (req, res) => {
  try {
    const r = await fetch(`${EPSS_URL}?cve=CVE-2021-44228`, { signal: AbortSignal.timeout(5000) });
    const d = await r.json();
    res.json({ loaded: d.total > 0, total: 270000, loadedAt: new Date(), loading: false });
  } catch (e) {
    res.json({ loaded: false, total: 0, loadedAt: null, loading: false });
  }
});

// ── Trivy scan ────────────────────────────────────────────────
app.post('/api/trivy/scan', (req, res) => {
  // Rate limit по IP
  const ip = req.ip || req.socket.remoteAddress || 'unknown';
  if (!trivyLimiter.check(ip)) {
    return res.status(429).json({ error: 'Too many scan requests. Please wait before retrying.' });
  }

  const { image, tag } = req.body;

  // Валидация входных данных
  if (!image) return res.status(400).json({ error: 'image is required' });
  if (!validateImage(image)) return res.status(400).json({ error: 'Invalid image name' });
  if (tag && !validateImage(tag)) return res.status(400).json({ error: 'Invalid tag' });

  const fullImage = tag ? `${image}:${tag}` : `${image}:latest`;
  console.log(`[Trivy] Scanning: ${fullImage} (ip: ${ip})`);

  const args = ['image', '--format', 'json', '--quiet', '--timeout', '10m', fullImage];

  execFile('trivy', args, { timeout: 600_000, maxBuffer: 50 * 1024 * 1024 }, (err, stdout, stderr) => {
    if (err && !stdout) {
      console.error('[Trivy] Error:', stderr);
      return res.status(500).json({ error: stderr || err.message });
    }
    try {
      res.json(JSON.parse(stdout));
    } catch (e) {
      console.error('[Trivy] JSON parse error:', e.message, stdout.slice(0, 200));
      res.status(500).json({ error: 'Failed to parse Trivy output' });
    }
  });
});

// ── CISA KEV check ───────────────────────────────────────────
app.post('/api/cisa/check', rateLimit(apiLimiter), async (req, res) => {
  const cves = validateCveBatch(req.body?.cves);
  if (!cves) return res.json({ inKev: [] });
  try {
    const kevSet = await getCisaSet();
    res.json({ inKev: cves.filter(c => kevSet.has(c)) });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ── PoC-in-GitHub check (concurrency = 10) ───────────────────
app.post('/api/poc/check', rateLimit(apiLimiter), async (req, res) => {
  const cves = validateCveBatch(req.body?.cves);
  if (!cves) return res.json({ pocs: {} });

  const result = {};

  await pLimit(cves, 10, async (cveId) => {
    const m = cveId.match(/CVE-(\d{4})-/);
    if (!m) { result[cveId] = []; return; }
    const year = m[1];
    try {
      const r = await fetch(`${POC_BASE}/${year}/${cveId}.json`, {
        signal : AbortSignal.timeout(8000),
        headers: { 'Cache-Control': 'no-cache' },
      });
      if (r.status === 404) { result[cveId] = []; return; }
      const d = await r.json();
      result[cveId] = (Array.isArray(d) ? d : [])
        .map(p => ({ name: p.full_name || p.name, url: p.html_url, stars: p.stargazers_count || 0, desc: p.description || '' }))
        .sort((a, b) => b.stars - a.stars)
        .slice(0, 5);
    } catch (e) {
      result[cveId] = [];
    }
  });

  for (const c of cves) if (!result[c]) result[c] = [];
  res.json({ pocs: result });
});

// ── NVD CVSS (TTL-кэш 24 ч, concurrency = 5) ─────────────────
app.post('/api/nvd/cvss', rateLimit(apiLimiter), async (req, res) => {
  const cves = validateCveBatch(req.body?.cves);
  if (!cves) return res.json({ data: {} });

  const result = {};

  await pLimit(cves, 5, async (cveId) => {
    if (nvdCache.has(cveId)) { result[cveId] = nvdCache.get(cveId); return; }
    try {
      const r = await fetch(
        `https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=${encodeURIComponent(cveId)}`,
        { signal: AbortSignal.timeout(10000), headers: { Accept: 'application/json' } }
      );
      if (!r.ok) { nvdCache.set(cveId, null); return; }
      const d    = await r.json();
      const vuln = (d.vulnerabilities || [])[0]?.cve;
      if (!vuln) { nvdCache.set(cveId, null); return; }
      const metrics = vuln.metrics || {};
      const v3data  = (metrics.cvssMetricV31 || metrics.cvssMetricV30 || [])[0]?.cvssData;
      const v2data  = (metrics.cvssMetricV2  || [])[0]?.cvssData;
      const entry   = {
        cvss3: v3data ? { score: v3data.baseScore, vector: v3data.vectorString, severity: v3data.baseSeverity, version: v3data.version } : null,
        cvss2: v2data ? { score: v2data.baseScore, vector: v2data.vectorString, severity: v2data.baseSeverity } : null,
      };
      nvdCache.set(cveId, entry);
      result[cveId] = entry;
    } catch (e) {
      nvdCache.set(cveId, null);
    }
  });

  for (const c of cves) if (!(c in result)) result[c] = nvdCache.get(c) ?? null;
  res.json({ data: result });
});

// ── Toxic-Repos check ─────────────────────────────────────────
const TOXIC_URL = 'https://raw.githubusercontent.com/toxic-repos/toxic-repos/main/data/json/toxic-repos.json';
let toxicCache = { list: null, ts: 0 };

async function getToxicList() {
  if (toxicCache.list && Date.now() - toxicCache.ts < 3_600_000) return toxicCache.list;
  try {
    const r = await fetch(TOXIC_URL, { signal: AbortSignal.timeout(15000) });
    if (!r.ok) throw new Error(`HTTP ${r.status}`);
    const data = await r.json();
    toxicCache = { list: data, ts: Date.now() };
    console.log('[TOXIC] Loaded', data.length, 'entries');
    return data;
  } catch (e) {
    console.error('[TOXIC] Load failed:', e.message);
    return toxicCache.list || [];
  }
}

app.post('/api/toxic/check', rateLimit(apiLimiter), async (req, res) => {
  const { name } = req.body || {};
  if (!validatePkgName(name)) return res.json({ found: false });
  try {
    const list   = await getToxicList();
    const needle = name.toLowerCase();
    const matches = list.filter(entry => {
      const n = (entry.name || '').toLowerCase();
      return n === needle || n.endsWith('/' + needle) || n === needle.replace(/^@[^/]+\//, '');
    });
    if (!matches.length) return res.json({ found: false });
    const m = matches[0];
    res.json({ found: true, problem_type: m.problem_type, description: m.description, commit_link: m.commit_link, name: m.name });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ── /api/libscan — all-in-one library intelligence endpoint ──
//
// POST /api/libscan
// Body: { name, ecosystem, version? }
//   name       — package name (e.g. "lodash")
//   ecosystem  — OSV ecosystem string (e.g. "npm", "PyPI", "Go", …)
//   version    — optional version string
//
// Returns a single enriched object with every piece of data the UI shows:
//   package, ecosystem, version, scannedAt
//   toxic         — { found, problem_type, description, commit_link, name }
//   vulns[]       — OSV vulns, each enriched with:
//                     epss   { epss, percentile }
//                     cvss   { cvss3, cvss2 }
//                     inKev  boolean
//                     pocs[] { name, url, stars, desc }
//                     aliases, fix, refs, severity
//   summary       — { total, CRITICAL, HIGH, MEDIUM, LOW, UNKNOWN }
//
app.post('/api/libscan', rateLimit(scanLimiter), async (req, res) => {
  const { name, ecosystem, version } = req.body || {};

  if (!name || typeof name !== 'string' || !name.trim())
    return res.status(400).json({ error: '"name" is required' });
  if (!ecosystem || typeof ecosystem !== 'string' || !ecosystem.trim())
    return res.status(400).json({ error: '"ecosystem" is required (e.g. npm, PyPI, Go, …)' });

  const pkg     = name.trim();
  const eco     = ecosystem.trim();
  const ver     = (version || '').trim() || null;

  console.log(`[libscan] ${eco}/${pkg}${ver ? '@' + ver : ''}`);

  // ── helpers ───────────────────────────────────────────────
  const SEV_ORD = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN', 'NONE'];

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
    if (['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].includes(db)) return db;
    return 'UNKNOWN';
  }

  function getFixed(v) {
    for (const a of v.affected || [])
      for (const r of a.ranges || [])
        for (const e of r.events || [])
          if (e.fixed) return e.fixed;
    return null;
  }

  function extractCVEs(vulns) {
    const s = new Set();
    for (const v of vulns) {
      for (const a of v.aliases || []) if (a.startsWith('CVE-')) s.add(a);
      if (v.id.startsWith('CVE-')) s.add(v.id);
    }
    return [...s];
  }

  // ── 1. OSV query ─────────────────────────────────────────
  let rawVulns = [];
  try {
    const body = { package: { name: pkg, ecosystem: eco } };
    if (ver) body.version = ver;
    const r = await fetch(`${OSV_URL}/query`, {
      method : 'POST',
      headers: { 'Content-Type': 'application/json' },
      body   : JSON.stringify(body),
      signal : AbortSignal.timeout(15000),
    });
    if (!r.ok) throw new Error(`OSV HTTP ${r.status}`);
    const d = await r.json();
    if (d.error) throw new Error(d.error);
    rawVulns = d.vulns || [];
  } catch (e) {
    return res.status(502).json({ error: `OSV query failed: ${e.message}` });
  }

  // Annotate vulns with computed fields
  const vulns = rawVulns.map(v => ({
    ...v,
    _sev    : parseSev(v),
    _fix    : getFixed(v),
    _aliases: v.aliases || [],
    _refs   : (v.references || []).map(r => r.url),
  })).sort((a, b) => SEV_ORD.indexOf(a._sev) - SEV_ORD.indexOf(b._sev));

  const cveIds = [...new Set(extractCVEs(vulns))];

  // ── 2. Parallel enrichment ────────────────────────────────
  const [
    toxicResult,
    epssResult,
    cisaResult,
    cvssResult,
    pocResult,
  ] = await Promise.allSettled([

    // Toxic-repos
    (async () => {
      const list   = await getToxicList();
      const needle = pkg.toLowerCase();
      const matches = list.filter(entry => {
        const n = (entry.name || '').toLowerCase();
        return n === needle || n.endsWith('/' + needle) || n === needle.replace(/^@[^/]+\//, '');
      });
      if (!matches.length) return { found: false };
      const m = matches[0];
      return {
        found       : true,
        problem_type: m.problem_type,
        description : m.description,
        commit_link : m.commit_link,
        name        : m.name,
      };
    })(),

    // EPSS
    (async () => {
      if (!cveIds.length) return {};
      const results = {};
      for (let i = 0; i < cveIds.length; i += 30) {
        const chunk = cveIds.slice(i, i + 30);
        const url   = `${EPSS_URL}?cve=${chunk.join(',')}&limit=${chunk.length}`;
        const r = await fetch(url, { signal: AbortSignal.timeout(15000) });
        if (!r.ok) continue;
        const d = await r.json();
        for (const item of d.data || [])
          results[item.cve] = { epss: parseFloat(item.epss), percentile: parseFloat(item.percentile) };
      }
      return results;
    })(),

    // CISA KEV
    (async () => {
      if (!cveIds.length) return [];
      const kevSet = await getCisaSet();
      return cveIds.filter(c => kevSet.has(c));
    })(),

    // NVD CVSS
    (async () => {
      if (!cveIds.length) return {};
      const result = {};
      await pLimit(cveIds, 5, async (cveId) => {
        if (nvdCache.has(cveId)) { result[cveId] = nvdCache.get(cveId); return; }
        try {
          const r = await fetch(
            `https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=${encodeURIComponent(cveId)}`,
            { signal: AbortSignal.timeout(10000), headers: { Accept: 'application/json' } }
          );
          if (!r.ok) { nvdCache.set(cveId, null); return; }
          const d    = await r.json();
          const vuln = (d.vulnerabilities || [])[0]?.cve;
          if (!vuln) { nvdCache.set(cveId, null); return; }
          const metrics = vuln.metrics || {};
          const v3data  = (metrics.cvssMetricV31 || metrics.cvssMetricV30 || [])[0]?.cvssData;
          const v2data  = (metrics.cvssMetricV2  || [])[0]?.cvssData;
          const entry   = {
            cvss3: v3data ? { score: v3data.baseScore, vector: v3data.vectorString, severity: v3data.baseSeverity, version: v3data.version } : null,
            cvss2: v2data ? { score: v2data.baseScore, vector: v2data.vectorString, severity: v2data.baseSeverity } : null,
          };
          nvdCache.set(cveId, entry);
          result[cveId] = entry;
        } catch { nvdCache.set(cveId, null); }
      });
      for (const c of cveIds) if (!(c in result)) result[c] = nvdCache.get(c) ?? null;
      return result;
    })(),

    // PoC-in-GitHub
    (async () => {
      if (!cveIds.length) return {};
      const result = {};
      await pLimit(cveIds, 10, async (cveId) => {
        const m = cveId.match(/CVE-(\d{4})-/);
        if (!m) { result[cveId] = []; return; }
        const year = m[1];
        try {
          const r = await fetch(`${POC_BASE}/${year}/${cveId}.json`, {
            signal : AbortSignal.timeout(8000),
            headers: { 'Cache-Control': 'no-cache' },
          });
          if (r.status === 404) { result[cveId] = []; return; }
          const d = await r.json();
          result[cveId] = (Array.isArray(d) ? d : [])
            .map(p => ({ name: p.full_name || p.name, url: p.html_url, stars: p.stargazers_count || 0, desc: p.description || '' }))
            .sort((a, b) => b.stars - a.stars)
            .slice(0, 5);
        } catch { result[cveId] = []; }
      });
      for (const c of cveIds) if (!result[c]) result[c] = [];
      return result;
    })(),
  ]);

  // Unwrap settled results safely
  const toxic    = toxicResult.status === 'fulfilled'  ? toxicResult.value  : { found: false, error: toxicResult.reason?.message };
  const epssMap  = epssResult.status  === 'fulfilled'  ? epssResult.value   : {};
  const kevList  = cisaResult.status  === 'fulfilled'  ? cisaResult.value   : [];
  const cvssMap  = cvssResult.status  === 'fulfilled'  ? cvssResult.value   : {};
  const pocMap   = pocResult.status   === 'fulfilled'  ? pocResult.value    : {};
  const kevSet   = new Set(kevList);

  // ── 3. Merge enrichment into each vuln ───────────────────
  const enriched = vulns.map(v => {
    const cve   = [...(v._aliases || []), v.id].find(x => x.startsWith('CVE-')) || null;
    return {
      id         : v.id,
      summary    : v.summary    || null,
      details    : v.details    || null,
      published  : v.published  || null,
      modified   : v.modified   || null,
      severity   : v._sev,
      fix        : v._fix       || null,
      aliases    : v._aliases,
      refs       : v._refs,
      cve        : cve,
      epss       : cve ? (epssMap[cve] || null) : null,
      cvss       : cve ? (cvssMap[cve] || null) : null,
      inKev      : cve ? kevSet.has(cve)         : false,
      pocs       : cve ? (pocMap[cve]  || [])    : [],
      affected   : v.affected   || [],
    };
  });

  // ── 4. Summary counters ───────────────────────────────────
  const summary = { total: enriched.length, CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, UNKNOWN: 0 };
  for (const v of enriched) { if (v.severity in summary) summary[v.severity]++; }
  const topSeverity = SEV_ORD.find(s => summary[s] > 0) || 'NONE';

  res.json({
    package      : pkg,
    ecosystem    : eco,
    version      : ver,
    scannedAt    : new Date().toISOString(),
    toxic,
    topSeverity,
    summary,
    vulns        : enriched,
  });
});

// ── /api/depscan — Google Open Source Insights (deps.dev) ────
//
// POST /api/depscan
// Body: { name, system, version? }
//   name    — package name (e.g. "django")
//   system  — NPM | GO | PYPI | CARGO | MAVEN | NUGET
//   version — optional; if omitted, latest stable is resolved
//
// Returns:
//   package, system, version, resolvedVersion, scannedAt
//   info        — { description, homepageUrl, licenses, links }
//   deps[]      — direct + transitive deps, each with:
//                   name, system, version, relation (DIRECT|INDIRECT)
//                   vulns[]  — same shape as /api/libscan vulns
//                   toxic    — { found, … }
//                   epss / cvss / inKev / pocs per vuln
//   summary     — { totalDeps, directDeps, withVulns, CRITICAL,HIGH,MEDIUM,LOW }
//
const DEPSDEV_URL = 'https://api.deps.dev/v3alpha';

// Supported systems for deps.dev
const DEPSDEV_SYSTEMS = new Set(['NPM','GO','PYPI','CARGO','MAVEN','NUGET']);

// OSV ecosystem map from deps.dev system
const SYSTEM_TO_OSV = {
  NPM   : 'npm',
  GO    : 'Go',
  PYPI  : 'PyPI',
  CARGO : 'crates.io',
  MAVEN : 'Maven',
  NUGET : 'NuGet',
};

async function depsDevGet(path) {
  const r = await fetch(`${DEPSDEV_URL}${path}`, {
    signal : AbortSignal.timeout(15000),
    headers: { Accept: 'application/json' },
  });
  if (!r.ok) throw new Error(`deps.dev HTTP ${r.status} for ${path}`);
  return r.json();
}

app.post('/api/depscan', rateLimit(scanLimiter), async (req, res) => {
  const { name, system, version } = req.body || {};

  if (!name || typeof name !== 'string' || !name.trim())
    return res.status(400).json({ error: '"name" is required' });
  if (!system || typeof system !== 'string')
    return res.status(400).json({ error: '"system" is required (NPM, GO, PYPI, CARGO, MAVEN, NUGET)' });

  const sys = system.trim().toUpperCase();
  if (!DEPSDEV_SYSTEMS.has(sys))
    return res.status(400).json({ error: `Unknown system "${sys}". Supported: ${[...DEPSDEV_SYSTEMS].join(', ')}` });

  const pkg = name.trim();
  const osvEco = SYSTEM_TO_OSV[sys];

  console.log(`[depscan] ${sys}/${pkg}${version ? '@' + version : ''}`);

  // ── 1. Resolve version ───────────────────────────────────
  let resolvedVersion = (version || '').trim();
  let pkgInfo = null;
  try {
    const encName = encodeURIComponent(pkg);
    const data = await depsDevGet(`/systems/${sys.toLowerCase()}/packages/${encName}`);
    pkgInfo = data;
    if (!resolvedVersion) {
      // pick latest default version
      const def = (data.versions || []).find(v => v.isDefault);
      resolvedVersion = def ? def.versionKey.version : (data.versions?.[0]?.versionKey?.version || '');
    }
  } catch(e) {
    return res.status(502).json({ error: `deps.dev package lookup failed: ${e.message}` });
  }

  if (!resolvedVersion)
    return res.status(404).json({ error: 'Could not resolve a version for this package' });

  // ── 2. Get version details + dependency graph ─────────────
  let versionData = null;
  let rawDeps = [];
  try {
    const encName = encodeURIComponent(pkg);
    const encVer  = encodeURIComponent(resolvedVersion);
    versionData = await depsDevGet(`/systems/${sys.toLowerCase()}/packages/${encName}/versions/${encVer}`);

    // Fetch dependency graph
    try {
      const depGraph = await depsDevGet(`/systems/${sys.toLowerCase()}/packages/${encName}/versions/${encVer}:dependencies`);
      rawDeps = depGraph.nodes || [];
    } catch(e) {
      console.warn('[depscan] dep graph unavailable:', e.message);
      rawDeps = [];
    }
  } catch(e) {
    return res.status(502).json({ error: `deps.dev version lookup failed: ${e.message}` });
  }

  // Build info block — fields from GetVersion response
  // licenses[] is string[], links[] has {label, url}, advisories[] for known vulns
  const info = {
    description : versionData.description  || null,
    homepageUrl : versionData.homepageUrl  || null,
    licenses    : versionData.licenses     || [],
    links       : (versionData.links       || []).map(l => typeof l === 'string' ? { url: l } : l),
    publishedAt : versionData.publishedAt  || null,
    isDefault   : versionData.isDefault    || false,
    isDeprecated: versionData.isDeprecated || false,
  };

  // ── 3. Build deduplicated dep list (skip root itself) ─────
  // nodes[0] is always the root package itself
  const depNodes = rawDeps.filter((n, i) => {
    if (i === 0) return false; // root
    const vk = n.versionKey || {};
    return vk.name && vk.version;
  });

  // Deduplicate by name+version
  const seen = new Map();
  for (const n of depNodes) {
    const vk  = n.versionKey;
    const key = `${vk.system}:${vk.name}@${vk.version}`;
    if (!seen.has(key)) {
      seen.set(key, {
        name    : vk.name,
        system  : vk.system || sys,
        version : vk.version,
        relation: n.relation || 'INDIRECT', // DIRECT or INDIRECT
      });
    }
  }
  const deps = [...seen.values()];
  console.log(`[depscan] ${deps.length} deps found for ${pkg}@${resolvedVersion}`);

  // ── helpers (same as libscan) ─────────────────────────────
  const SEV_ORD = ['CRITICAL','HIGH','MEDIUM','LOW','UNKNOWN','NONE'];
  function parseSev(v) {
    for (const s of v.severity || []) {
      const sc = parseFloat(s.score);
      if (!isNaN(sc)) {
        if (sc >= 9) return 'CRITICAL'; if (sc >= 7) return 'HIGH';
        if (sc >= 4) return 'MEDIUM'; return 'LOW';
      }
    }
    const db = ((v.database_specific || {}).severity || '').toUpperCase();
    return ['CRITICAL','HIGH','MEDIUM','LOW'].includes(db) ? db : 'UNKNOWN';
  }
  function getFixed(v) {
    for (const a of v.affected || [])
      for (const r of a.ranges || [])
        for (const e of r.events || [])
          if (e.fixed) return e.fixed;
    return null;
  }
  function extractCVEs(vulns) {
    const s = new Set();
    for (const v of vulns) {
      for (const a of v.aliases || []) if (a.startsWith('CVE-')) s.add(a);
      if (v.id.startsWith('CVE-')) s.add(v.id);
    }
    return [...s];
  }

  // ── 4. OSV + Toxic for each dep (concurrency = 6) ─────────
  const toxicList  = await getToxicList();

  function toxicCheck(pkgName) {
    const needle  = pkgName.toLowerCase();
    const matches = toxicList.filter(entry => {
      const n = (entry.name || '').toLowerCase();
      return n === needle || n.endsWith('/' + needle) || n === needle.replace(/^@[^/]+\//, '');
    });
    if (!matches.length) return { found: false };
    const m = matches[0];
    return { found: true, problem_type: m.problem_type, description: m.description, commit_link: m.commit_link, name: m.name };
  }

  // OSV query per dep
  async function fetchOsvForDep(dep) {
    try {
      const depEco = SYSTEM_TO_OSV[dep.system] || osvEco;
      const body = { package: { name: dep.name, ecosystem: depEco } };
      if (dep.version) body.version = dep.version;
      const r = await fetch(`${OSV_URL}/query`, {
        method:'POST', headers:{'Content-Type':'application/json'},
        body: JSON.stringify(body), signal: AbortSignal.timeout(12000),
      });
      if (!r.ok) return [];
      const d = await r.json();
      return (d.vulns || []).map(v => ({
        ...v, _sev: parseSev(v), _fix: getFixed(v),
        _aliases: v.aliases || [], _refs: (v.references || []).map(r => r.url),
      })).sort((a,b) => SEV_ORD.indexOf(a._sev) - SEV_ORD.indexOf(b._sev));
    } catch { return []; }
  }

  // Scan deps in parallel batches of 6
  const scannedDeps = [];
  await pLimit(deps, 6, async (dep) => {
    const [vulns, toxic] = await Promise.all([
      fetchOsvForDep(dep),
      Promise.resolve(toxicCheck(dep.name)),
    ]);
    scannedDeps.push({ ...dep, vulns, toxic });
  });

  // Keep original order
  const orderedDeps = deps.map(d =>
    scannedDeps.find(s => s.name === d.name && s.version === d.version && s.system === d.system) || { ...d, vulns: [], toxic: { found: false } }
  );

  // ── 5. Bulk enrichment: EPSS / CISA / NVD / PoC ──────────
  // Collect all unique CVEs across all deps
  const allCVEs = [...new Set(orderedDeps.flatMap(d => extractCVEs(d.vulns)))];
  console.log(`[depscan] enriching ${allCVEs.length} unique CVEs`);

  const [epssResult, cisaResult, cvssResult, pocResult] = await Promise.allSettled([
    // EPSS
    (async () => {
      if (!allCVEs.length) return {};
      const results = {};
      for (let i = 0; i < allCVEs.length; i += 30) {
        const chunk = allCVEs.slice(i, i + 30);
        try {
          const r = await fetch(`${EPSS_URL}?cve=${chunk.join(',')}&limit=${chunk.length}`, { signal: AbortSignal.timeout(15000) });
          if (!r.ok) continue;
          const d = await r.json();
          for (const item of d.data || [])
            results[item.cve] = { epss: parseFloat(item.epss), percentile: parseFloat(item.percentile) };
        } catch {}
      }
      return results;
    })(),
    // CISA
    (async () => {
      if (!allCVEs.length) return [];
      const kevSet = await getCisaSet();
      return allCVEs.filter(c => kevSet.has(c));
    })(),
    // NVD CVSS
    (async () => {
      if (!allCVEs.length) return {};
      const result = {};
      await pLimit(allCVEs, 5, async (cveId) => {
        if (nvdCache.has(cveId)) { result[cveId] = nvdCache.get(cveId); return; }
        try {
          const r = await fetch(`https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=${encodeURIComponent(cveId)}`,
            { signal: AbortSignal.timeout(10000), headers: { Accept: 'application/json' } });
          if (!r.ok) { nvdCache.set(cveId, null); return; }
          const d = await r.json();
          const vuln = (d.vulnerabilities || [])[0]?.cve;
          if (!vuln) { nvdCache.set(cveId, null); return; }
          const metrics = vuln.metrics || {};
          const v3data = (metrics.cvssMetricV31 || metrics.cvssMetricV30 || [])[0]?.cvssData;
          const v2data = (metrics.cvssMetricV2 || [])[0]?.cvssData;
          const entry = {
            cvss3: v3data ? { score: v3data.baseScore, vector: v3data.vectorString, severity: v3data.baseSeverity, version: v3data.version } : null,
            cvss2: v2data ? { score: v2data.baseScore, vector: v2data.vectorString, severity: v2data.baseSeverity } : null,
          };
          nvdCache.set(cveId, entry); result[cveId] = entry;
        } catch { nvdCache.set(cveId, null); }
      });
      for (const c of allCVEs) if (!(c in result)) result[c] = nvdCache.get(c) ?? null;
      return result;
    })(),
    // PoC
    (async () => {
      if (!allCVEs.length) return {};
      const result = {};
      await pLimit(allCVEs, 10, async (cveId) => {
        const m = cveId.match(/CVE-(\d{4})-/);
        if (!m) { result[cveId] = []; return; }
        try {
          const r = await fetch(`${POC_BASE}/${m[1]}/${cveId}.json`, { signal: AbortSignal.timeout(8000), headers: { 'Cache-Control':'no-cache' } });
          if (r.status === 404) { result[cveId] = []; return; }
          const d = await r.json();
          result[cveId] = (Array.isArray(d) ? d : [])
            .map(p => ({ name: p.full_name || p.name, url: p.html_url, stars: p.stargazers_count || 0, desc: p.description || '' }))
            .sort((a,b) => b.stars - a.stars).slice(0, 5);
        } catch { result[cveId] = []; }
      });
      for (const c of allCVEs) if (!result[c]) result[c] = [];
      return result;
    })(),
  ]);

  const epssMap = epssResult.status === 'fulfilled' ? epssResult.value : {};
  const kevSet2 = new Set(cisaResult.status === 'fulfilled' ? cisaResult.value : []);
  const cvssMap = cvssResult.status === 'fulfilled' ? cvssResult.value : {};
  const pocMap  = pocResult.status  === 'fulfilled' ? pocResult.value  : {};

  // ── 6. Merge enrichment into each dep's vulns ─────────────
  const finalDeps = orderedDeps.map(dep => {
    const enrichedVulns = dep.vulns.map(v => {
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
        inKev : cve ? kevSet2.has(cve)        : false,
        pocs  : cve ? (pocMap[cve]  || [])    : [],
      };
    });
    const cnt = { CRITICAL:0, HIGH:0, MEDIUM:0, LOW:0, UNKNOWN:0 };
    for (const v of enrichedVulns) if (v.severity in cnt) cnt[v.severity]++;
    return {
      name    : dep.name,
      system  : dep.system,
      version : dep.version,
      relation: dep.relation,
      toxic   : dep.toxic,
      topSeverity: SEV_ORD.find(s => cnt[s] > 0) || 'NONE',
      vulnCount: enrichedVulns.length,
      counts  : cnt,
      vulns   : enrichedVulns,
    };
  });

  // ── 7. Global summary ─────────────────────────────────────
  const summary = {
    totalDeps  : finalDeps.length,
    directDeps : finalDeps.filter(d => d.relation === 'DIRECT').length,
    withVulns  : finalDeps.filter(d => d.vulnCount > 0).length,
    toxic      : finalDeps.filter(d => d.toxic?.found).length,
    CRITICAL   : finalDeps.reduce((a,d) => a + d.counts.CRITICAL, 0),
    HIGH       : finalDeps.reduce((a,d) => a + d.counts.HIGH,     0),
    MEDIUM     : finalDeps.reduce((a,d) => a + d.counts.MEDIUM,   0),
    LOW        : finalDeps.reduce((a,d) => a + d.counts.LOW,      0),
  };

  res.json({
    package        : pkg,
    system         : sys,
    version        : version || null,
    resolvedVersion,
    scannedAt      : new Date().toISOString(),
    info,
    summary,
    deps           : finalDeps,
  });
});

// ── /api/activity — library last-commit activity ─────────────
//
// POST /api/activity
// Body: { name, ecosystem }
//   Tries to resolve a GitHub repo for the package via:
//   1. deps.dev links (sourceRepo field)
//   2. npm registry (repository.url)
//   3. PyPI JSON API (info.project_urls)
//   Then hits GitHub API for latest commit date.
//
// Returns:
//   { found: bool, lastCommit: ISO string | null, repoUrl: string | null, source: string }
//
const activityCache = new TtlCache(6 * 3_600_000); // 6h TTL

async function resolveGithubRepo(name, ecosystem) {
  const sys = ecosystem?.toUpperCase();

  // ── 1. Try deps.dev links ────────────────────────────────────
  try {
    const encSys  = (sys || 'NPM').toLowerCase();
    const encName = encodeURIComponent(name);
    // Get default version first
    const pkgData = await fetch(
      `${DEPSDEV_URL}/systems/${encSys}/packages/${encName}`,
      { signal: AbortSignal.timeout(8000), headers: { Accept: 'application/json' } }
    );
    if (pkgData.ok) {
      const pd = await pkgData.json();
      const defVer = (pd.versions || []).find(v => v.isDefault) || pd.versions?.[0];
      if (defVer) {
        const verData = await fetch(
          `${DEPSDEV_URL}/systems/${encSys}/packages/${encName}/versions/${encodeURIComponent(defVer.versionKey.version)}`,
          { signal: AbortSignal.timeout(8000), headers: { Accept: 'application/json' } }
        );
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

  // ── 2. npm registry ──────────────────────────────────────────
  if (!sys || sys === 'NPM') {
    try {
      const r = await fetch(
        `https://registry.npmjs.org/${encodeURIComponent(name)}/latest`,
        { signal: AbortSignal.timeout(8000) }
      );
      if (r.ok) {
        const d = await r.json();
        const repoUrl = d.repository?.url || d.homepage || '';
        const m = repoUrl.match(/github\.com\/([^/]+\/[^/\s#?.]+)/i);
        if (m) return { repo: m[1].replace(/\.git$/, ''), source: 'npm' };
      }
    } catch {}
  }

  // ── 3. PyPI ──────────────────────────────────────────────────
  if (sys === 'PYPI') {
    try {
      const r = await fetch(
        `https://pypi.org/pypi/${encodeURIComponent(name)}/json`,
        { signal: AbortSignal.timeout(8000) }
      );
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

app.post('/api/activity', rateLimit(apiLimiter), async (req, res) => {
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

    // Fetch latest commit from default branch
    const headers = { Accept: 'application/vnd.github+json', 'User-Agent': 'OSAGuard/1.0' };
    if (process.env.GITHUB_TOKEN) headers['Authorization'] = `Bearer ${process.env.GITHUB_TOKEN}`;

    const r = await fetch(
      `https://api.github.com/repos/${repo}/commits?per_page=1`,
      { signal: AbortSignal.timeout(10000), headers }
    );

    if (!r.ok) {
      const isRateLimit = r.status === 403 || r.status === 429;
      // Don't cache rate limit errors — retry next time
      const result = { found: true, lastCommit: null, repoUrl, source, rateLimited: isRateLimit, error: `GitHub ${r.status}` };
      if (!isRateLimit) activityCache.set(cacheKey, result);
      return res.json(result);
    }

    const commits = await r.json();
    const lastCommit = commits[0]?.commit?.committer?.date || commits[0]?.commit?.author?.date || null;

    const result = { found: true, lastCommit, repoUrl, source };
    activityCache.set(cacheKey, result);
    res.json(result);
  } catch (e) {
    const result = { found: false, lastCommit: null, repoUrl: null, source: null, error: e.message };
    activityCache.set(cacheKey, result);
    res.json(result);
  }
});

// ── Глобальный обработчик ошибок ─────────────────────────────
app.use((err, req, res, _next) => {
  console.error('[Unhandled]', err);
  res.status(500).json({ error: 'Internal server error' });
});

const PORT = process.env.PORT || 3001;
app.listen(PORT, () => console.log(`OSVGuard → http://localhost:${PORT}`));
