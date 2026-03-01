'use strict';

const { EXPORT_SEV_COLORS } = require('./style');
const { compactVulnRow } = require('./rows');
const { buildBaseHtml } = require('./base');

function buildImgReportHtml(scan, { osaPngB64 = '' } = {}) {
  const image = scan.image || 'Image';
  const tag = scan.tag || 'latest';
  const desc = scan.desc || '';

  const counts = scan.counts || { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, UNKNOWN: 0 };
  const topSev = Object.entries(counts).sort((a, b) => b[1] - a[1])[0]?.[0] || 'NONE';

  const vulns = scan.vulns || [];
  const kevHits = vulns.filter(v => v.inKev).length;
  const pocHits = vulns.filter(v => (v.pocs || []).length).length;

  const sections = [];

  sections.push(`<div class="section">
    <div class="section-h"><div class="section-title">Container</div></div>
    <div class="section-body">
      <div style="font-size:18px;font-weight:900;color:#e5e7eb">${image}:${tag}</div>
      ${desc ? `<div style="margin-top:8px;color:#cbd5e1;font-size:12px">${desc}</div>` : ''}
    </div>
  </div>`);

  sections.push(`<div class="section">
    <div class="section-h"><div class="section-title">Vulnerabilities (compact)</div>
      <div style="font-size:11px;color:#8a9ab0">${vulns.length} findings</div>
    </div>
    <div class="section-body">
      <table>
        <thead><tr>
          <th style="text-align:left;padding:10px 10px;color:#8a9ab0;font-size:11px">ID</th>
          <th style="text-align:center;padding:10px 10px;color:#8a9ab0;font-size:11px">Sev</th>
          <th style="text-align:center;padding:10px 10px;color:#8a9ab0;font-size:11px">CVSS</th>
          <th style="text-align:center;padding:10px 10px;color:#8a9ab0;font-size:11px">EPSS</th>
          <th style="text-align:left;padding:10px 10px;color:#8a9ab0;font-size:11px">Summary</th>
        </tr></thead>
        <tbody>${vulns.map(compactVulnRow).join('')}</tbody>
      </table>
    </div>
  </div>`);

  const extraStats = `<div class="summary-row" style="margin-top:10px">
    ${Object.entries(counts).map(([s, c]) => {
      const sc = EXPORT_SEV_COLORS[s] || EXPORT_SEV_COLORS.UNKNOWN;
      return `<span class="stat-chip" style="border-color:${sc.border}"><b style="color:${sc.text}">${c}</b> ${s}</span>`;
    }).join('')}
  </div>`;

  return buildBaseHtml({
    title: 'Container Image Scan',
    subtitle: `${image}:${tag}`,
    scannedAt: scan.scannedAt || new Date().toISOString(),
    topSev,
    counts,
    kevHits,
    pocHits,
    desc,
    extraStats,
    sections,
    osaPngB64,
  });
}

module.exports = { buildImgReportHtml };
