// routes/export.route.js — POST /api/export/pdf
'use strict';

const express = require('express');
const router = express.Router();
const fs = require('fs');
const nodePath = require('path');

const { scanLimiter, rateLimit } = require('../shared');
const { buildLibReportHtml, buildImgReportHtml, buildDepReportHtml } = require('../pdf');

// Load osa.png as base64 once at startup for PDF embedding
let OSA_PNG_B64 = '';
try {
  const imgFile = nodePath.join(__dirname, '../../frontend/public/assets/osa.png');
  OSA_PNG_B64 = fs.readFileSync(imgFile).toString('base64');
} catch (e) {
  console.warn('[export] osa.png not found:', e.message);
}

async function internalPostJson(pathname, body) {
  const port = process.env.PORT || 3001;
  const r = await fetch(`http://localhost:${port}/api/${pathname}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
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
  if (!['lib', 'img', 'dep'].includes(type)) return res.status(400).json({ error: 'type must be lib | img | dep' });

  let puppeteer;
  try { puppeteer = require('puppeteer'); }
  catch { return res.status(503).json({ error: 'Puppeteer not installed' }); }

  // ── 1. Get enriched scan payload ─────────────────────────────
  let scan;
  try {
    if (type === 'lib') {
      const { name, ecosystem, version, desc, ecoLabel, ecoLogo } = params;
      if (!name || !ecosystem) return res.status(400).json({ error: 'lib scan requires name + ecosystem' });

      const data = await internalPostJson('libscan', { name, ecosystem, version });
      const actData = await internalPostJson('activity', { name, ecosystem: ecoLabel || ecosystem }).catch(() => null);
      scan = { ...data, desc, ecoLabel: ecoLabel || ecosystem, ecoLogo: ecoLogo || '📦', activity: actData };

    } else if (type === 'img') {
      const { image, tag, desc } = params;
      if (!image) return res.status(400).json({ error: 'img scan requires image' });

      const data = await internalPostJson('trivy/scan', { image, tag: tag || 'latest', desc });
      const enriched = await enrichTrivyVulns(data);
      scan = { image, tag: tag || 'latest', desc, ...enriched, scannedAt: new Date().toISOString() };

    } else {
      // dep — already enriched on frontend; do not re-scan
      const { scanData } = params;
      if (!scanData) return res.status(400).json({ error: 'dep export requires params.scanData' });
      scan = scanData;
      console.log('[PDF dep] using pre-enriched scan, package:', scan.package, 'deps:', scan.deps?.length);
    }
  } catch (e) {
    return res.status(502).json({ error: 'Scan failed: ' + e.message });
  }

  // ── 2. Build HTML ────────────────────────────────────────────
  let html;
  try {
    const ctx = { osaPngB64: OSA_PNG_B64 };
    if (type === 'lib') html = buildLibReportHtml(scan, ctx);
    else if (type === 'img') html = buildImgReportHtml(scan, ctx);
    else html = buildDepReportHtml(scan, ctx);
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

    const name = type === 'lib'
      ? `osa-lib-${(scan.package || scan.pkg || 'scan').replace(/[^a-z0-9]/gi, '-')}`
      : type === 'img'
        ? `osa-img-${(scan.image || 'scan').replace(/[^a-z0-9]/gi, '-')}-${scan.tag || 'latest'}`
        : `osa-dep-${(scan.package || 'scan').replace(/[^a-z0-9]/gi, '-')}`;

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
