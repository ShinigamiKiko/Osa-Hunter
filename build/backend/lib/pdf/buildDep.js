'use strict';

const { EXPORT_SEV_COLORS } = require('./style');
const { compactVulnRow } = require('./rows');
const { buildBaseHtml } = require('./base');

function buildDepReportHtml(scan, { osaPngB64 = '' } = {}) {
  const pkg = scan.package || 'Dependency Scan';
  const desc = scan.desc || '';

  const summary = scan.summary || {};
  const counts = summary.counts || summary || { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, UNKNOWN: 0, NONE: 0 };
  const topSev = Object.entries(counts).sort((a, b) => b[1] - a[1])[0]?.[0] || 'NONE';

  const deps = scan.deps || [];

  let kevHits = 0;
  let pocHits = 0;
  for (const d of deps) {
    for (const v of d.vulns || []) {
      if (v.inKev) kevHits++;
      if ((v.pocs || []).length) pocHits++;
    }
  }

  const sections = [];
  sections.push(`<div class="section">
    <div class="section-h"><div class="section-title">Package</div></div>
    <div class="section-body">
      <div style="font-size:18px;font-weight:900;color:#e5e7eb">${pkg}</div>
      ${scan.version ? `<div style="margin-top:6px;color:#8a9ab0;font-size:12px">Version: <b style="color:#e5e7eb">${scan.version}</b></div>` : ''}
      ${scan.deps ? `<div style="margin-top:6px;color:#8a9ab0;font-size:12px">Dependencies: <b style="color:#e5e7eb">${scan.deps.length}</b></div>` : ''}
      ${desc ? `<div style="margin-top:10px;color:#cbd5e1;font-size:12px">${desc}</div>` : ''}
    </div>
  </div>`);

  const rows = deps.map((d, idx) => {
    const name = d.name || d.package || 'dep';
    const ver = d.version || '';
    const vulns = d.vulns || [];
    const rowBg = idx % 2 === 0 ? '#07090f' : '#0b0f16';
    const top = vulns[0];
    const sev = (top?._sev || top?.severity || top?.Severity || 'NONE');
    const sevUp = String(sev).toUpperCase();
    const sc = EXPORT_SEV_COLORS[sevUp] || EXPORT_SEV_COLORS.UNKNOWN;

    const sub = vulns.slice(0, 5).map(compactVulnRow).join('');

    return `<div class="section" style="margin-top:16px">
      <div class="section-h">
        <div class="section-title">${name}${ver ? ` <span style=\"color:#8a9ab0;font-weight:700\">@${ver}</span>` : ''}</div>
        <div style="font-size:11px;color:${sc.text};font-weight:900">${sevUp}</div>
      </div>
      <div class="section-body">
        ${!vulns.length ? '<div style="color:#34d399">✅ No vulns</div>' : `
        <table>
          <thead><tr>
            <th style="text-align:left;padding:10px 10px;color:#8a9ab0;font-size:11px">ID</th>
            <th style="text-align:center;padding:10px 10px;color:#8a9ab0;font-size:11px">Sev</th>
            <th style="text-align:center;padding:10px 10px;color:#8a9ab0;font-size:11px">CVSS</th>
            <th style="text-align:center;padding:10px 10px;color:#8a9ab0;font-size:11px">EPSS</th>
            <th style="text-align:left;padding:10px 10px;color:#8a9ab0;font-size:11px">Summary</th>
          </tr></thead>
          <tbody>${sub}</tbody>
        </table>`}
      </div>
    </div>`;
  }).join('');

  sections.push(rows);

  const extraStats = `<div class="summary-row" style="margin-top:10px">
    ${Object.entries(counts).map(([s, c]) => {
      const sc = EXPORT_SEV_COLORS[s] || EXPORT_SEV_COLORS.UNKNOWN;
      return `<span class=\"stat-chip\" style=\"border-color:${sc.border}\"><b style=\"color:${sc.text}\">${c}</b> ${s}</span>`;
    }).join('')}
  </div>`;

  return buildBaseHtml({
    title: 'Dependency Scan',
    subtitle: `${pkg}`,
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

module.exports = { buildDepReportHtml };
