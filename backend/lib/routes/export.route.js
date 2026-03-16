// routes/export.route.js — POST /api/export/pdf
'use strict';

const express = require('express');
const router = express.Router();
const fs = require('fs');
const nodePath = require('path');

const { scanLimiter, rateLimit } = require('../shared');
const { buildLibReportHtml, buildImgReportHtml, buildDepReportHtml, buildOsReportHtml, buildSastReportHtml } = require('../pdf');

// Load osa.png as base64 once at startup for PDF embedding
let OSA_PNG_B64 = '';
try {
  const imgFile = nodePath.join(__dirname, '../../frontend/public/assets/osa.png');
  OSA_PNG_B64 = fs.readFileSync(imgFile).toString('base64');
} catch (e) {
  console.warn('[export] osa.png not found:', e.message);
}

// Auth is already verified by requireAuth middleware before this route is
// reached. The internal fetch must forward credentials so the downstream
// route handlers don't reject the request with 401.
// We prefer req.ip over X-Forwarded-For to avoid spoofing — the rate
// limiter on sub-routes uses req.ip as well, so the internal call is
// counted against the same bucket as the outer request.
async function internalPostJson(pathname, body, req) {
  const port = process.env.PORT || 3001;

  const headers = { 'Content-Type': 'application/json' };
  // Forward whichever auth mechanism the original request used
  if (req.headers['x-api-key']) {
    headers['x-api-key'] = req.headers['x-api-key'];
  } else if (req.headers.cookie) {
    headers['cookie'] = req.headers.cookie;
  }

  const r = await fetch(`http://localhost:${port}/api/${pathname}`, {
    method: 'POST',
    headers,
    body: JSON.stringify(body || {}),
  });
  const data = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(data.error || `${pathname} failed`);
  return data;
}

async function enrichTrivyVulns(trivyResult) {
  const allV = [];
  (trivyResult.Results || []).forEach(t => (t.Vulnerabilities || []).forEach(v => allV.push(v)));
  const cveIds = [...new Set(allV.map(v => v.VulnerabilityID).filter(x => x?.startsWith('CVE-')))];

  const { fetchEpss, fetchCvss, fetchPocs, getCisaSet } = require('../shared');
  const [epssMap, kevArr, cvssMap, pocMap] = await Promise.all([
    fetchEpss(cveIds),
    getCisaSet().then(s => cveIds.filter(c => s.has(c))).catch(() => []),
    fetchCvss(cveIds),
    fetchPocs(cveIds),
  ]);
  const kevSet = new Set(kevArr);

  const enrichedVulns = allV.map(v => ({
    ...v,
    epss: epssMap[v.VulnerabilityID] || null,
    inKev: kevSet.has(v.VulnerabilityID),
    pocs: pocMap[v.VulnerabilityID] || [],
    cvss: cvssMap[v.VulnerabilityID] || null,
  }));

  const counts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, UNKNOWN: 0 };
  enrichedVulns.forEach(v => {
    const s = String(v.Severity || 'UNKNOWN').toUpperCase();
    if (s in counts) counts[s]++;
  });

  return { vulns: enrichedVulns, counts };
}

router.post('/export/pdf', rateLimit(scanLimiter), async (req, res) => {
  const { type, params } = req.body || {};
  if (!type || !params) return res.status(400).json({ error: '"type" and "params" required' });
  if (!['lib', 'img', 'dep', 'os', 'sast'].includes(type)) return res.status(400).json({ error: 'type must be lib | img | dep | os | sast' });

  let puppeteer;
  try { puppeteer = require('puppeteer'); }
  catch { return res.status(503).json({ error: 'Puppeteer not installed' }); }

  // ── 1. Get enriched scan payload ─────────────────────────────
  let scan;
  try {
    if (type === 'lib') {
      const { name, ecosystem, version, desc, ecoLabel, ecoLogo } = params;
      if (!name || !ecosystem) return res.status(400).json({ error: 'lib scan requires name + ecosystem' });

      const data = await internalPostJson('libscan', { name, ecosystem, version }, req);
      const actData = await internalPostJson('activity', { name, ecosystem: ecoLabel || ecosystem }, req).catch(() => null);
      scan = { ...data, desc, ecoLabel: ecoLabel || ecosystem, ecoLogo: ecoLogo || '📦', activity: actData };

    } else if (type === 'img') {
      const { image, tag, desc } = params;
      if (!image) return res.status(400).json({ error: 'img scan requires image' });

      const data = await internalPostJson('trivy/scan', { image, tag: tag || 'latest', desc }, req);
      const enriched = await enrichTrivyVulns(data);
      scan = { image, tag: tag || 'latest', desc, ...enriched, scannedAt: new Date().toISOString() };

    } else if (type === 'dep') {
      // dep — already enriched on frontend; do not re-scan
      const { scanData } = params;
      if (!scanData) return res.status(400).json({ error: 'dep export requires params.scanData' });
      scan = scanData;
      console.log('[PDF dep] using pre-enriched scan, package:', scan.package, 'deps:', scan.deps?.length);

    } else if (type === 'os') {
      // os — pre-enriched grype scan data from frontend
      const { scanData } = params;
      if (!scanData) return res.status(400).json({ error: 'os export requires params.scanData' });
      scan = scanData;
      console.log('[PDF os] using pre-enriched scan, package:', scan.package, 'vulns:', scan.vulns?.length);

    } else if (type === 'sast') {
      // sast — pre-scanned github findings from frontend
      const { scanData } = params;
      if (!scanData) return res.status(400).json({ error: 'sast export requires params.scanData' });
      scan = scanData;
      console.log('[PDF sast] repo:', scan.repo, 'findings:', scan.findings?.length);
    }
  } catch (e) {
    return res.status(502).json({ error: 'Scan failed: ' + e.message });
  }

  // ── 2. Build HTML ────────────────────────────────────────────
  let html;
  try {
    const ctx = { osaPngB64: OSA_PNG_B64 };
    if      (type === 'lib')  html = buildLibReportHtml(scan, ctx);
    else if (type === 'img')  html = buildImgReportHtml(scan, ctx);
    else if (type === 'dep')  html = buildDepReportHtml(scan, ctx);
    else if (type === 'os')   html = buildOsReportHtml(scan, ctx);
    else                      html = buildSastReportHtml(scan, ctx);
  } catch (e) {
    console.error('[PDF build error]', e.stack || e.message);
    return res.status(500).json({ error: 'Failed to build report: ' + e.message });
  }

  // ── 3. Puppeteer → PDF ───────────────────────────────────────
  let browser;
  try {
    browser = await puppeteer.launch({
      headless: 'new',
      executablePath: process.env.PUPPETEER_EXECUTABLE_PATH || undefined,
      protocolTimeout: 120000,
      args: [
        '--no-sandbox',
        '--disable-setuid-sandbox',
        '--disable-dev-shm-usage',
        '--disable-gpu',
        '--disable-web-security',
      ],
      timeout: 60000,
    });

    const page = await browser.newPage();
    await page.setDefaultNavigationTimeout(120000);
    await page.setDefaultTimeout(120000);
    await page.setContent(html, { waitUntil: 'domcontentloaded', timeout: 60000 });
    await new Promise(r => setTimeout(r, 300));

    const pdf = await page.pdf({
      format: 'A4',
      printBackground: true,
      margin: { top: '0', right: '0', bottom: '0', left: '0' },
    });

    const nameSlug = s => (s||'scan').replace(/[^a-z0-9]/gi, '-').toLowerCase();
    const name =
      type === 'lib'  ? `osa-lib-${nameSlug(scan.package || scan.pkg)}` :
      type === 'img'  ? `osa-img-${nameSlug(scan.image)}-${scan.tag||'latest'}` :
      type === 'dep'  ? `osa-dep-${nameSlug(scan.package)}` :
      type === 'os'   ? `osa-os-${nameSlug(scan.package || scan.image)}` :
                        `osa-sast-${nameSlug(scan.repo)}`;

    res.set({
      'Content-Type': 'application/pdf',
      'Content-Disposition': `attachment; filename="${name}.pdf"`,
      'Content-Length': pdf.length,
    });
    res.send(pdf);
  } catch (e) {
    console.error('[PDF export]', e.message);
    res.status(500).json({ error: 'PDF generation failed: ' + e.message });
  } finally {
    if (browser) await browser.close().catch(() => {});
  }
});

module.exports = router;
