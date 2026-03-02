'use strict';

// ── Shared CSS used by ALL report builders ────────────────────
const BASE_CSS = `
*{box-sizing:border-box;-webkit-print-color-adjust:exact;print-color-adjust:exact}
html,body{margin:0;padding:0;background:#0a0c12;color:#e5e7eb;font-family:Inter,system-ui,-apple-system,Segoe UI,Roboto,sans-serif}
.report{width:100%;background:#07090f}
.rpt-header{background:#0b0f18;border-bottom:1px solid #1a2030;padding:28px 32px;display:flex;align-items:flex-start;justify-content:space-between;gap:24px}
.rpt-brand{display:flex;align-items:center;gap:10px;margin-bottom:14px}
.rpt-brand img{width:36px;height:36px;border-radius:8px;object-fit:contain}
.rpt-brand-name{font-size:11px;font-weight:800;letter-spacing:.1em;color:#5ef0c8;text-transform:uppercase}
.rpt-title{font-size:26px;font-weight:900;line-height:1.1;color:#fff;margin:0 0 4px}
.rpt-sub{font-size:13px;color:#8a9ab0;margin:0 0 4px;font-family:monospace}
.rpt-meta{font-size:11px;color:#5a6478;margin-top:8px}
.rpt-right{text-align:right;min-width:200px;flex-shrink:0}
.rpt-sev{display:inline-block;padding:3px 12px;border-radius:6px;font-size:11px;font-weight:800;letter-spacing:.06em;margin-top:8px}
.rpt-sev.CRITICAL{background:#2d0a0a;border:1px solid #ff4444;color:#ff4444}
.rpt-sev.HIGH{background:#2d1500;border:1px solid #ff8c32;color:#ff8c32}
.rpt-sev.MEDIUM{background:#2a2000;border:1px solid #fbbf24;color:#fbbf24}
.rpt-sev.LOW,.rpt-sev.NONE{background:#0a2018;border:1px solid #34d399;color:#34d399}
.rpt-sev.UNKNOWN{background:#111827;border:1px solid #5a6478;color:#5a6478}
.chips{display:flex;gap:8px;flex-wrap:wrap;padding:16px 32px;border-bottom:1px solid #1a2030;background:#080b10}
.chip{display:inline-flex;align-items:center;gap:7px;background:#0d1219;border:1px solid #1a2030;border-radius:999px;padding:6px 14px;font-size:12px;color:#cbd5e1}
.chip b{color:#e5e7eb;font-size:13px}
.chip.crit{border-color:#ff4444}.chip.crit b{color:#ff4444}
.chip.high{border-color:#ff8c32}.chip.high b{color:#ff8c32}
.chip.med{border-color:#fbbf24}.chip.med b{color:#fbbf24}
.chip.low{border-color:#34d399}.chip.low b{color:#34d399}
.chip.kev{border-color:#ff3b30;background:#1a0808}.chip.kev b{color:#ff3b30}
.chip.poc{border-color:#ff9500;background:#1a0e00}.chip.poc b{color:#ff9500}
.alerts{display:flex;gap:10px;flex-wrap:wrap;padding:12px 32px;background:#080b10;border-bottom:1px solid #1a2030}
.alert{display:flex;align-items:center;gap:8px;padding:7px 13px;border-radius:8px;font-size:12px;font-weight:600}
.alert.kev{background:#1a0808;border:1px solid #ff3b30;color:#ff3b30}
.alert.poc{background:#1a0a00;border:1px solid #ff9500;color:#ff9500}
.alert.toxic{background:#1a0a1a;border:1px solid #c084fc;color:#c084fc}
.alert.clean{background:#051a0f;border:1px solid #34d399;color:#34d399}
.section{margin:20px 32px;background:#0b0f18;border:1px solid #1a2030;border-radius:12px;overflow:hidden}
.sec-hdr{padding:12px 16px;background:#0e1420;border-bottom:1px solid #1a2030;display:flex;align-items:center;justify-content:space-between}
.sec-title{font-size:12px;font-weight:800;letter-spacing:.05em;text-transform:uppercase;color:#8a9ab0}
.sec-count{font-size:11px;color:#5a6478}
table{width:100%;border-collapse:collapse;table-layout:fixed}
thead th{padding:10px 14px;font-size:10px;font-weight:700;letter-spacing:.05em;text-transform:uppercase;color:#5a6478;background:#080b10;text-align:left;white-space:nowrap;overflow:hidden}
tbody tr{border-bottom:1px solid #111820}
tbody tr:last-child{border-bottom:none}
tbody tr:nth-child(even){background:#080b10}
tbody tr:nth-child(odd){background:#0b0f18}
td{padding:10px 14px;vertical-align:top;font-size:12px;overflow:hidden}
.col-id{width:145px}
.col-pkg{width:140px}
.col-sev{width:88px}
.col-cvss{width:60px}
.col-epss{width:82px}
.col-fix{width:115px}
.vuln-id{font-family:monospace;font-size:11px;font-weight:800;color:#5ef0c8;display:block;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.vuln-id a{color:#5ef0c8;text-decoration:none}
.badge{display:inline-block;font-size:8px;font-weight:800;padding:1px 5px;border-radius:3px;margin-top:3px;margin-right:2px}
.badge.kev{background:#3d0a0a;border:1px solid #ff3b30;color:#ff3b30}
.badge.poc{background:#2d1800;border:1px solid #ff9500;color:#ff9500}
.fix-val{color:#34d399;font-size:10px;font-family:monospace;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;display:block}
.no-fix{color:#5a6478;font-size:10px}
.sev{display:inline-block;padding:2px 8px;border-radius:4px;font-size:9px;font-weight:800;letter-spacing:.04em;white-space:nowrap}
.sev.CRITICAL{background:#2d0a0a;border:1px solid #ff4444;color:#ff4444}
.sev.HIGH{background:#2d1500;border:1px solid #ff8c32;color:#ff8c32}
.sev.MEDIUM{background:#2a2000;border:1px solid #fbbf24;color:#fbbf24}
.sev.LOW{background:#0a2018;border:1px solid #34d399;color:#34d399}
.sev.UNKNOWN{background:#111827;border:1px solid #5a6478;color:#5a6478}
.score-crit{color:#ff4444;font-weight:700;font-size:12px}
.score-high{color:#ff8c32;font-weight:700;font-size:12px}
.score-med{color:#fbbf24;font-weight:700;font-size:12px}
.score-low{color:#34d399;font-weight:700;font-size:12px}
.score-none{color:#5a6478;font-size:12px}
.vuln-desc{color:#8a9ab0;font-size:11px;line-height:1.4;display:-webkit-box;-webkit-line-clamp:2;-webkit-box-orient:vertical;overflow:hidden}
.vuln-links{margin-top:4px;display:flex;gap:8px}
.vuln-links a{color:#5ef0c8;font-size:10px;text-decoration:none;opacity:.7}
.pkg-cell-name{font-family:monospace;font-size:11px;font-weight:700;color:#e5e7eb;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;display:block}
.pkg-cell-ver{font-family:monospace;font-size:10px;color:#5a6478;display:block;margin-top:1px}
.dep-hdr{padding:10px 16px;background:#0b0f18;border-bottom:1px solid #1a2030;display:flex;align-items:center;justify-content:space-between}
.dep-rel{font-size:10px;padding:1px 7px;border-radius:10px;background:#0e1420;border:1px solid #1a2030;color:#8a9ab0;margin-left:8px}
.dep-rel.direct{border-color:#5ef0c8;color:#5ef0c8}
.finding-row{padding:12px 16px;border-bottom:1px solid #111820;display:flex;align-items:flex-start;gap:12px}
.finding-row:last-child{border-bottom:none}
.finding-row:nth-child(even){background:#080b10}
.finding-vbar{width:3px;border-radius:2px;flex-shrink:0;margin-top:2px;align-self:stretch;min-height:16px}
.finding-vbar.CRITICAL{background:#ff4444}
.finding-vbar.HIGH{background:#ff8c32}
.finding-vbar.MEDIUM{background:#fbbf24}
.finding-vbar.LOW{background:#34d399}
.finding-vbar.UNKNOWN{background:#5a6478}
.finding-body{flex:1;min-width:0}
.finding-rule{font-family:monospace;font-size:11px;font-weight:700;color:#a78bfa;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.finding-file{font-family:monospace;font-size:10px;color:#5a6478;margin-top:2px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.finding-desc{font-size:11px;color:#8a9ab0;margin-top:5px;line-height:1.4;display:-webkit-box;-webkit-line-clamp:2;-webkit-box-orient:vertical;overflow:hidden}
.finding-code{margin-top:6px;background:#0d1117;border:1px solid #1a2030;border-radius:5px;padding:5px 10px;font-family:monospace;font-size:10px;color:#e6edf3;white-space:pre;overflow:hidden;text-overflow:ellipsis}
.finding-cwe{font-size:9px;color:#5a6478;margin-top:4px}
.rpt-footer{padding:14px 32px;border-top:1px solid #1a2030;background:#07090f;display:flex;justify-content:space-between;align-items:center;margin-top:8px}
.rpt-footer span{font-size:10px;color:#5a6478}
`;

function sevBadge(sev) {
  const s = (sev||'UNKNOWN').toUpperCase();
  return `<span class="sev ${s}">${s}</span>`;
}
function scoreClass(n) {
  if (n >= 9) return 'score-crit';
  if (n >= 7) return 'score-high';
  if (n >= 4) return 'score-med';
  if (n > 0)  return 'score-low';
  return 'score-none';
}
function epssCell(epss) {
  if (!epss || epss.epss == null) return '<span class="score-none">—</span>';
  const pct = (epss.epss * 100).toFixed(2);
  const cls = epss.epss >= 0.1 ? 'score-crit' : epss.epss >= 0.01 ? 'score-med' : 'score-low';
  return `<span class="${cls}">${pct}%</span>`;
}
function cvssCell(cvss) {
  const score = cvss?.cvss3?.score;
  if (score == null) return '<span class="score-none">—</span>';
  return `<span class="${scoreClass(score)}">${score}</span>`;
}
function badges(v) {
  let out = '';
  if (v.inKev) out += '<span class="badge kev">🔥 KEV</span>';
  if ((v.pocs||[]).length) out += `<span class="badge poc">💥 PoC×${v.pocs.length}</span>`;
  return out;
}
function fixCell(v) {
  const fix = v.fix || v._fix || v.FixedVersion || '';
  return fix ? `<span class="fix-val">→ ${fix}</span>` : '<span class="no-fix">No fix yet</span>';
}
function activityLine(activity) {
  if (!activity || !activity.found || !activity.lastCommit) return '';
  const date = new Date(activity.lastCommit);
  const days = Math.floor((Date.now() - date) / 86400000);
  const years = Math.floor(days / 365);
  const age = days < 1 ? 'today' : days < 7 ? `${days}d ago` : days < 60 ? `${Math.floor(days/7)}w ago` : years >= 1 ? `${years}y ago` : `${Math.floor(days/30)}mo ago`;
  const stale = years >= 2;
  const color = stale ? '#ff8c32' : '#34d399';
  const label = stale ? '⚠ Possibly stale' : '● Active';
  const dateStr = date.toLocaleDateString('en-US', { year:'numeric', month:'short', day:'numeric' });
  return `<div style="font-size:12px;color:${color}">${label} · last commit ${age} · ${dateStr}</div>`;
}
function toxicLine(toxic) {
  if (!toxic || !toxic.found) return '<div style="font-size:12px;color:#34d399;margin-top:6px">✅ Not in toxic-repos</div>';
  const labels = { ddos:'DDoS tool', hostile_actions:'Hostile actions', political_slogan:'Political slogan', malware:'Malware', ip_blocking:'IP blocking' };
  const label = labels[toxic.problem_type] || toxic.problem_type || 'Toxic';
  const desc = toxic.description ? ` — ${toxic.description.slice(0,100)}` : '';
  return `<div style="font-size:12px;color:#c084fc;font-weight:600;margin-top:6px">☠ Toxic: ${label}${desc}</div>`;
}
function wrapHtml(bodyHtml) {
  return `<!doctype html><html><head><meta charset="utf-8"/><style>${BASE_CSS}</style></head><body><div class="report">${bodyHtml}</div></body></html>`;
}
function buildHeader({ logo, title, sub, sev, meta, right = '' }) {
  const sevHtml = sev && sev !== 'NONE' ? `<span class="rpt-sev ${sev}">${sev}</span>` : '';
  return `<div class="rpt-header">
    <div>
      <div class="rpt-brand">${logo ? `<img src="data:image/png;base64,${logo}" alt="OSA"/>` : ''}<span class="rpt-brand-name">OSA Hunter</span></div>
      <div class="rpt-title">${title}</div>
      ${sub ? `<div class="rpt-sub">${sub}</div>` : ''}
      ${sevHtml}
      <div class="rpt-meta">${meta}</div>
    </div>
    ${right ? `<div class="rpt-right">${right}</div>` : ''}
  </div>`;
}
function buildChips(counts, kevHits, pocHits, extra) {
  const CLS = { CRITICAL:'crit', HIGH:'high', MEDIUM:'med', LOW:'low', UNKNOWN:'' };
  let html = ['CRITICAL','HIGH','MEDIUM','LOW','UNKNOWN']
    .filter(s => (counts||{})[s])
    .map(s => `<div class="chip ${CLS[s]}"><b>${counts[s]}</b> ${s}</div>`).join('');
  if (kevHits) html += `<div class="chip kev"><b>${kevHits}</b> in CISA KEV</div>`;
  if (pocHits) html += `<div class="chip poc"><b>${pocHits}</b> with PoC</div>`;
  if (extra)   html += extra;
  return `<div class="chips">${html || '<div class="chip low"><b>✅</b> Clean</div>'}</div>`;
}
function buildAlerts(kevHits, pocHits, toxic) {
  const rows = [];
  if (kevHits)      rows.push(`<div class="alert kev">🔥 ${kevHits} CVE${kevHits>1?'s':''} found in CISA KEV — actively exploited in the wild</div>`);
  if (pocHits)      rows.push(`<div class="alert poc">💥 ${pocHits} CVE${pocHits>1?'s':''} with public PoC on GitHub</div>`);
  if (toxic?.found) rows.push(`<div class="alert toxic">☠ Toxic repository — ${toxic.problem_type||'unknown issue'}</div>`);
  if (!rows.length) rows.push(`<div class="alert clean">✅ No active exploits or toxic flags detected</div>`);
  return `<div class="alerts">${rows.join('')}</div>`;
}
function buildFooter(date) {
  return `<div class="rpt-footer"><span>OSA Hunter — Vulnerability Scanner</span><span>Generated ${date}</span></div>`;
}

module.exports = { BASE_CSS, sevBadge, scoreClass, epssCell, cvssCell, badges, fixCell, activityLine, toxicLine, wrapHtml, buildHeader, buildChips, buildAlerts, buildFooter };
