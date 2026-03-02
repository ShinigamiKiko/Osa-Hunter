'use strict';
const { epssCell, cvssCell, badges, fixCell, sevBadge } = require('./style');

// ── Standard vuln table thead ─────────────────────────────────
function vulnThead(hasPackage) {
  const pkgTh = hasPackage ? '<th class="col-pkg">Package</th>' : '';
  return `<thead><tr>
    <th class="col-id">CVE / ID</th>
    ${pkgTh}
    <th class="col-sev">Severity</th>
    <th class="col-cvss" style="text-align:center">CVSS</th>
    <th class="col-epss" style="text-align:center">EPSS</th>
    <th class="col-fix">Fix</th>
    <th>Description</th>
  </tr></thead>`;
}

// ── Single vuln table row ─────────────────────────────────────
function vulnRow(v, idx, pkgHtml) {
  const cveId = v.cve || v.VulnerabilityID || v.id || '';
  const raw   = v._sev || v.severity || v.Severity || 'UNKNOWN';
  const sev   = (typeof raw === 'string' && !raw.startsWith('[')) ? raw.toUpperCase() : 'UNKNOWN';
  const nvdUrl  = cveId.startsWith('CVE-') ? `https://nvd.nist.gov/vuln/detail/${cveId}` : '';
  const osvUrl  = (!cveId.startsWith('CVE-') && cveId) ? `https://osv.dev/vulnerability/${cveId}` : '';
  const summary = String(v.summary || v.Title || v.Description || '').slice(0, 160);
  const rowBg   = idx % 2 === 0 ? '' : '';   // handled by CSS nth-child

  return `<tr>
    <td class="col-id">
      ${nvdUrl ? `<a class="vuln-id" href="${nvdUrl}">${cveId}</a>` : `<span class="vuln-id">${cveId}</span>`}
      <div>${badges(v)}</div>
    </td>
    ${pkgHtml ? `<td class="col-pkg">${pkgHtml}</td>` : ''}
    <td class="col-sev">${sevBadge(sev)}</td>
    <td class="col-cvss" style="text-align:center">${cvssCell(v.cvss)}</td>
    <td class="col-epss" style="text-align:center">${epssCell(v.epss)}</td>
    <td class="col-fix">${fixCell(v)}</td>
    <td>
      <div class="vuln-desc">${summary}</div>
      <div class="vuln-links">
        ${nvdUrl ? `<a href="${nvdUrl}">NVD ↗</a>` : ''}
        ${osvUrl ? `<a href="${osvUrl}">OSV ↗</a>` : ''}
      </div>
    </td>
  </tr>`;
}

// ── Vuln rows for lib / img ───────────────────────────────────
function vulnRows(vulns) {
  if (!vulns || !vulns.length) {
    return '<tr><td colspan="6" style="text-align:center;color:#34d399;padding:18px;font-size:13px">✅ No vulnerabilities found</td></tr>';
  }
  return vulns.map((v, i) => vulnRow(v, i, '')).join('');
}

// ── Vuln rows for OS scan (includes Package column) ───────────
function vulnRowsOs(vulns) {
  if (!vulns || !vulns.length) {
    return '<tr><td colspan="7" style="text-align:center;color:#34d399;padding:18px;font-size:13px">✅ No vulnerabilities found</td></tr>';
  }
  return vulns.map((v, i) => {
    const pkgName = v.PkgName || v.pkgName || v.package || '';
    const pkgVer  = v.InstalledVersion || v.installedVersion || v.version || '';
    const pkgHtml = pkgName
      ? `<span class="pkg-cell-name">${pkgName}</span>${pkgVer ? `<span class="pkg-cell-ver">${pkgVer}</span>` : ''}`
      : '';
    return vulnRow(v, i, pkgHtml);
  }).join('');
}

module.exports = { vulnThead, vulnRow, vulnRows, vulnRowsOs };
