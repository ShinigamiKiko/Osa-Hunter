'use strict';
const { activityLine, toxicLine, wrapHtml, buildHeader, buildChips, buildAlerts, buildFooter } = require('./style');
const { vulnThead, vulnRows } = require('./rows');

function buildLibReportHtml(scan, { osaPngB64 = '' } = {}) {
  const pkg  = scan.package || scan.pkg || scan.name || 'Library';
  const eco  = scan.ecosystem || scan.ecoLabel || 'Unknown';
  const ver  = scan.version || '';
  const desc = scan.desc || '';

  const vulns   = scan.vulns || scan.vulnerabilities || [];
  const counts  = scan.counts || scan.summary || {};
  const topSev  = ['CRITICAL','HIGH','MEDIUM','LOW'].find(s => (counts[s]||0) > 0) || 'NONE';
  const kevHits = vulns.filter(v => v.inKev).length;
  const pocHits = vulns.filter(v => (v.pocs||[]).length).length;
  const date    = new Date(scan.scannedAt || Date.now()).toLocaleString('en-US', { year:'numeric', month:'short', day:'2-digit', hour:'2-digit', minute:'2-digit' });

  const right = activityLine(scan.activity) + toxicLine(scan.toxic);

  const header = buildHeader({
    logo: osaPngB64,
    title: pkg,
    sub: `${eco}${ver ? ' · ' + ver : ''}`,
    sev: topSev,
    meta: `Scanned: ${date}${desc ? ' · ' + desc : ''}`,
    right,
  });

  const chips  = buildChips(counts, kevHits, pocHits);
  const alerts = buildAlerts(kevHits, pocHits, scan.toxic);

  const section = `<div class="section">
    <div class="sec-hdr">
      <span class="sec-title">Vulnerabilities</span>
      <span class="sec-count">${vulns.length} finding${vulns.length !== 1 ? 's' : ''}</span>
    </div>
    <table>${vulnThead(false)}<tbody>${vulnRows(vulns)}</tbody></table>
  </div>`;

  const footer = buildFooter(date);

  return wrapHtml(header + chips + alerts + section + footer);
}

module.exports = { buildLibReportHtml };
