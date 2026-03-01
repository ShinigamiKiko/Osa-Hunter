'use strict';

const { EXPORT_SEV_COLORS, epssBar, cvssLine, pocLinks } = require('./style');

// Compact vuln rows for lib/img — fast render, no heavy text blocks
function compactVulnRow(v, i) {
  const SC = EXPORT_SEV_COLORS;
  const cveId = v.cve || v.VulnerabilityID || v.id || '';
  const raw = v._sev || v.severity || v.Severity || 'UNKNOWN';
  const sev = (typeof raw === 'string' && !raw.startsWith('[')) ? raw.toUpperCase() : 'UNKNOWN';
  const sc = SC[sev] || SC.UNKNOWN;
  const cvss3 = v.cvss?.cvss3;
  const epss = v.epss;
  const fix = v.fix || v._fix || v.FixedVersion || '';
  const sum = String(v.summary || v.Title || v.Description || '').slice(0, 100);
  const kev = v.inKev
    ? '<span style="background:#3d0a0a;border:1px solid #ff3b30;color:#ff3b30;font-size:8px;font-weight:700;padding:1px 5px;border-radius:3px;margin-right:3px">KEV</span>'
    : '';
  const poc = (v.pocs || []).length
    ? `<span style="background:#2d1800;border:1px solid #ff9500;color:#ff9500;font-size:8px;font-weight:700;padding:1px 5px;border-radius:3px">PoC×${v.pocs.length}</span>`
    : '';
  const bg = i % 2 === 0 ? '#07090f' : '#0b0f16';
  const epssStr = epss
    ? `<span style="color:${epss.epss >= 0.1 ? '#ff4444' : epss.epss >= 0.01 ? '#fbbf24' : '#34d399'};font-weight:600">${(epss.epss * 100).toFixed(2)}%</span>`
    : '<span style="color:#5a6478">—</span>';
  const cvssStr = cvss3
    ? `<span style="color:${cvss3.score >= 9 ? '#ff4444' : cvss3.score >= 7 ? '#ff8c32' : cvss3.score >= 4 ? '#fbbf24' : '#34d399'};font-weight:700">${cvss3.score}</span>`
    : '<span style="color:#5a6478">—</span>';
  const nvdUrl = cveId.startsWith('CVE-') ? `https://nvd.nist.gov/vuln/detail/${cveId}` : '';
  return `<tr style="background:${bg};border-bottom:1px solid #111820">
    <td style="padding:7px 10px;font-family:monospace;font-size:11px;min-width:145px">
      ${nvdUrl ? `<a href="${nvdUrl}" style="color:#5ef0c8;text-decoration:none;display:block">${cveId}</a>` : `<span style="color:#5ef0c8">${cveId}</span>`}
      <div style="margin-top:3px">${kev}${poc}</div>
      ${fix ? `<div style="color:#34d399;font-size:10px;margin-top:2px">→ ${fix}</div>` : ''}
    </td>
    <td style="padding:7px 10px;text-align:center;white-space:nowrap">
      <span style="background:${sc.bg};border:1px solid ${sc.border};color:${sc.text};font-size:9px;font-weight:700;padding:2px 7px;border-radius:3px">${sev}</span>
    </td>
    <td style="padding:7px 10px;text-align:center;font-size:11px">${cvssStr}</td>
    <td style="padding:7px 10px;text-align:center;font-size:11px">${epssStr}</td>
    <td style="padding:7px 10px;font-size:11px;color:#8a9ab0">${sum}</td>
  </tr>`;
}

function vulnRows(vulns) {
  if (!vulns || !vulns.length) {
    return '<tr><td colspan="6" style="text-align:center;color:#34d399;padding:18px;font-size:13px">✅ No vulnerabilities found</td></tr>';
  }
  return vulns.map((v, i) => {
    const cveId = v.cve || v.id || v.VulnerabilityID || '';
    const osvId = v.id || '';
    const fixed = v.fix || v._fix || v.FixedVersion || '';
    const kev = v.inKev
      ? '<span style="background:#3d0a0a;border:1px solid #ff3b30;color:#ff3b30;font-size:9px;font-weight:700;padding:1px 6px;border-radius:3px;margin-right:3px">🔥 KEV</span>'
      : '';
    const poc = (v.pocs || []).length
      ? `<span style="background:#2d1800;border:1px solid #ff9500;color:#ff9500;font-size:9px;font-weight:700;padding:1px 6px;border-radius:3px">💥 PoC×${v.pocs.length}</span>`
      : '';
    const raw = v._sev || v.severity || v.Severity || 'UNKNOWN';
    const sev = (typeof raw === 'string' && !raw.startsWith('[')) ? raw.toUpperCase() : 'UNKNOWN';
    const summary = v.summary || v.Title || v.Description || 'No description';
    const details = v.details || v.Description || '';
    const nvdLink = cveId.startsWith('CVE-') ? `https://nvd.nist.gov/vuln/detail/${cveId}` : '';
    const osvLink = osvId ? `https://osv.dev/vulnerability/${osvId}` : '';
    const rowBg = i % 2 === 0 ? '#07090f' : '#0b0f16';
    const detailsId = `vd-${i}`;
    return `<tr style="background:${rowBg};border-bottom:1px solid #111820">
      <td style="padding:12px 14px;vertical-align:top">
        <div style="font-family:monospace;font-size:12px;font-weight:800;color:#5ef0c8">${cveId || osvId}</div>
        <div style="margin-top:6px">${kev}${poc}</div>
        <div style="margin-top:6px">${fixed ? `<span style="color:#34d399;font-size:11px;font-weight:600">Fixed: ${fixed}</span>` : ''}</div>
        <div style="margin-top:8px">${cvssLine(v.cvss)}</div>
        <div style="margin-top:6px">${epssBar(v.epss)}</div>
      </td>
      <td style="padding:12px 14px;vertical-align:top">
        <div style="color:#e5e7eb;font-size:12px;font-weight:700">${summary}</div>
        ${details ? `<div id="${detailsId}" style="color:#8a9ab0;font-size:11px;margin-top:6px;line-height:1.35">${String(details).slice(0, 450)}</div>` : ''}
        <div style="margin-top:8px">${pocLinks(v.pocs)}</div>
        <div style="margin-top:10px;display:flex;gap:10px;flex-wrap:wrap">
          ${nvdLink ? `<a href="${nvdLink}" style="color:#5ef0c8;font-size:11px;text-decoration:none">NVD</a>` : ''}
          ${osvLink ? `<a href="${osvLink}" style="color:#5ef0c8;font-size:11px;text-decoration:none">OSV</a>` : ''}
        </div>
      </td>
      <td style="padding:12px 14px;vertical-align:top">${sev}</td>
    </tr>`;
  }).join('');
}

module.exports = { compactVulnRow, vulnRows };
