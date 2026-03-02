'use strict';
const { wrapHtml, buildHeader, buildChips, buildAlerts, buildFooter, sevBadge } = require('./style');
const { vulnThead, vulnRows } = require('./rows');

function buildDepReportHtml(scan, { osaPngB64 = '' } = {}) {
  const pkg    = scan.package || 'Dependency Scan';
  const ver    = scan.version || '';
  const sys    = scan.system || '';
  const desc   = scan.desc || '';
  const deps   = scan.deps || [];
  const summary = scan.summary || {};

  // counts may live in summary.counts or directly in summary
  const counts = summary.CRITICAL != null ? summary : (summary.counts || {});
  const topSev = ['CRITICAL','HIGH','MEDIUM','LOW'].find(s => (counts[s]||0) > 0) || 'NONE';

  let kevHits = 0, pocHits = 0;
  deps.forEach(d => (d.vulns||[]).forEach(v => {
    if (v.inKev) kevHits++;
    if ((v.pocs||[]).length) pocHits++;
  }));

  const date = new Date(scan.scannedAt || Date.now()).toLocaleString('en-US', { year:'numeric', month:'short', day:'2-digit', hour:'2-digit', minute:'2-digit' });

  const extraChip = `<div class="chip"><b>${deps.length}</b> deps</div>`;
  const header = buildHeader({
    logo: osaPngB64,
    title: 'Dependency Scan',
    sub: `${pkg}${ver ? ' · ' + ver : ''}${sys ? ' · ' + sys : ''}`,
    sev: topSev,
    meta: `Scanned: ${date} · ${deps.length} dependencies${desc ? ' · ' + desc : ''}`,
  });

  const chips  = buildChips(counts, kevHits, pocHits, extraChip);
  const alerts = buildAlerts(kevHits, pocHits, scan.toxic);

  // One section per dep that has vulns
  const vulnDeps = deps.filter(d => (d.vulns||[]).length > 0);
  const cleanDeps = deps.filter(d => !(d.vulns||[]).length);

  const depSections = vulnDeps.map(d => {
    const name    = d.name || d.package || 'dep';
    const dver    = d.version || '';
    const rel     = (d.relation||'').toUpperCase();
    const isDirect = rel === 'DIRECT';
    const topD    = (d.vulns||[])[0];
    const dsev    = (topD?._sev || topD?.severity || 'UNKNOWN').toUpperCase();
    return `<div class="section">
      <div class="dep-hdr">
        <div>
          <span style="font-family:monospace;font-size:12px;font-weight:700;color:#e5e7eb">${name}</span>
          ${dver ? `<span style="font-family:monospace;font-size:12px;color:#8a9ab0"> @${dver}</span>` : ''}
          <span class="dep-rel${isDirect ? ' direct' : ''}">${isDirect ? 'DIRECT' : 'INDIRECT'}</span>
        </div>
        ${sevBadge(dsev)}
      </div>
      <table>${vulnThead(false)}<tbody>${vulnRows(d.vulns||[])}</tbody></table>
    </div>`;
  }).join('');

  const cleanSection = cleanDeps.length ? `<div class="section" style="margin-top:12px">
    <div class="sec-hdr"><span class="sec-title">Clean dependencies</span><span class="sec-count">${cleanDeps.length}</span></div>
    <div style="padding:12px 16px;display:flex;flex-wrap:wrap;gap:8px">
      ${cleanDeps.map(d => `<span style="font-family:monospace;font-size:11px;background:#0d1219;border:1px solid #1a2030;padding:3px 10px;border-radius:999px;color:#34d399">${d.name||''}${d.version ? '@'+d.version : ''}</span>`).join('')}
    </div>
  </div>` : '';

  return wrapHtml(header + chips + alerts + depSections + cleanSection + buildFooter(date));
}

module.exports = { buildDepReportHtml };
