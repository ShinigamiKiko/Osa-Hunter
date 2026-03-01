'use strict';

const { sevBadge, epssBar, cvssLine, activityLine, toxicLine } = require('./style');
const { vulnRows } = require('./rows');
const { buildBaseHtml } = require('./base');

function buildLibReportHtml(scan, { osaPngB64 = '' } = {}) {
  const pkg = scan.package || scan.pkg || scan.name || 'Library';
  const eco = scan.ecosystem || scan.ecoLabel || 'Unknown';
  const desc = scan.desc || '';

  const counts = scan.counts || { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, UNKNOWN: 0, NONE: 0 };
  const topSev = Object.entries(counts).sort((a, b) => b[1] - a[1])[0]?.[0] || 'NONE';

  const vulns = scan.vulns || scan.vulnerabilities || [];
  const kevHits = vulns.filter(v => v.inKev).length;
  const pocHits = vulns.filter(v => (v.pocs || []).length).length;

  const sections = [];

  sections.push(`<div class="section">
    <div class="section-h"><div class="section-title">Package</div></div>
    <div class="section-body">
      <div style="display:flex;justify-content:space-between;gap:12px;flex-wrap:wrap">
        <div>
          <div style="font-size:18px;font-weight:900;color:#e5e7eb">${pkg}</div>
          <div style="margin-top:5px;color:#8a9ab0;font-size:12px">Ecosystem: <b style="color:#e5e7eb">${eco}</b></div>
          ${scan.version ? `<div style="margin-top:5px;color:#8a9ab0;font-size:12px">Version: <b style="color:#e5e7eb">${scan.version}</b></div>` : ''}
        </div>
        <div style="min-width:240px">
          ${activityLine(scan.activity)}
          <div style="margin-top:6px">${toxicLine(scan.toxic)}</div>
        </div>
      </div>
    </div>
  </div>`);

  sections.push(`<div class="section">
    <div class="section-h"><div class="section-title">Vulnerabilities</div></div>
    <div class="section-body">
      <table>
        <thead><tr>
          <th style="text-align:left;padding:10px 14px;color:#8a9ab0;font-size:11px">ID</th>
          <th style="text-align:left;padding:10px 14px;color:#8a9ab0;font-size:11px">Details</th>
          <th style="text-align:left;padding:10px 14px;color:#8a9ab0;font-size:11px">Severity</th>
        </tr></thead>
        <tbody>${vulnRows(vulns)}</tbody>
      </table>
    </div>
  </div>`);

  sections.push(`<div class="section">
    <div class="section-h"><div class="section-title">Enrichment</div></div>
    <div class="section-body" style="display:flex;gap:18px;flex-wrap:wrap">
      <div style="min-width:220px">
        <div style="color:#8a9ab0;font-size:11px">Top CVSS</div>
        <div style="margin-top:6px">${cvssLine(scan.topCvss)}</div>
      </div>
      <div style="min-width:220px">
        <div style="color:#8a9ab0;font-size:11px">Top EPSS</div>
        <div style="margin-top:6px">${epssBar(scan.topEpss)}</div>
      </div>
      <div style="min-width:220px">
        <div style="color:#8a9ab0;font-size:11px">Overall Severity</div>
        <div style="margin-top:6px">${sevBadge(topSev)}</div>
      </div>
    </div>
  </div>`);

  return buildBaseHtml({
    title: `${pkg}`,
    subtitle: `${eco}`,
    scannedAt: scan.scannedAt || new Date().toISOString(),
    topSev,
    counts,
    kevHits,
    pocHits,
    desc,
    sections,
    osaPngB64,
  });
}

module.exports = { buildLibReportHtml };
