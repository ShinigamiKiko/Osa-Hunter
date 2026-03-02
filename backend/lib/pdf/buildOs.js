'use strict';
const { wrapHtml, buildHeader, buildChips, buildAlerts, buildFooter } = require('./style');
const { vulnThead, vulnRowsOs } = require('./rows');

function buildOsReportHtml(scan, { osaPngB64 = '' } = {}) {
  const pkg     = scan.package || scan.image || 'OS Scan';
  const ver     = scan.version || '';
  const distro  = scan.distro || '';
  const distroV = scan.distroVersion || '';
  const vulns   = scan.vulns || [];
  const counts  = scan.counts || {};
  const topSev  = ['CRITICAL','HIGH','MEDIUM','LOW'].find(s => (counts[s]||0) > 0) || 'NONE';
  const kevHits = vulns.filter(v => v.inKev).length;
  const pocHits = vulns.filter(v => (v.pocs||[]).length).length;
  const date    = new Date(scan.scannedAt || Date.now()).toLocaleString('en-US', { year:'numeric', month:'short', day:'2-digit', hour:'2-digit', minute:'2-digit' });

  const distroStr = distro ? `${distro}${distroV ? ' ' + distroV : ''}` : '';
  const extraChip = distroStr ? `<div class="chip"><b>Distro:</b> ${distroStr}</div>` : '';

  const header = buildHeader({
    logo: osaPngB64,
    title: 'OS Package Scan',
    sub: `${pkg}${ver ? ' · ' + ver : ''}`,
    sev: topSev,
    meta: `Scanned: ${date}${distroStr ? ' · ' + distroStr : ''}`,
  });

  const chips  = buildChips(counts, kevHits, pocHits, extraChip);
  const alerts = buildAlerts(kevHits, pocHits, null);

  const section = `<div class="section">
    <div class="sec-hdr">
      <span class="sec-title">Vulnerabilities</span>
      <span class="sec-count">${vulns.length} finding${vulns.length !== 1 ? 's' : ''}</span>
    </div>
    <table>${vulnThead(true)}<tbody>${vulnRowsOs(vulns)}</tbody></table>
  </div>`;

  return wrapHtml(header + chips + alerts + section + buildFooter(date));
}

module.exports = { buildOsReportHtml };
