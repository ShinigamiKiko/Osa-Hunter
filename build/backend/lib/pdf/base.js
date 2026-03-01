'use strict';

function buildBaseHtml({
  title,
  subtitle,
  scannedAt,
  topSev,
  counts,
  kevHits,
  pocHits,
  desc,
  extraStats = '',
  sections,
  osaPngB64 = '',
}) {
  const date = new Date(scannedAt || Date.now()).toLocaleString('en-US', { year: 'numeric', month: 'short', day: '2-digit', hour: '2-digit', minute: '2-digit' });

  const pills = Object.entries(counts || {})
    .filter(([, c]) => c > 0)
    .map(([s, c]) => `<span class="stat-chip"><b>${c}</b> ${s}</span>`)
    .join('');

  return `<!doctype html><html><head><meta charset="utf-8"/>
  <style>
  html,body{margin:0;padding:0;background:#05070d;color:#e5e7eb;font-family:Inter,system-ui,-apple-system,Segoe UI,Roboto,Ubuntu,Cantarell,Arial,sans-serif}
  .page{width:210mm;min-height:297mm;padding:28px 26px;box-sizing:border-box}
  .cover{display:flex;justify-content:space-between;align-items:flex-start;gap:20px;margin-bottom:18px}
  .brand{display:flex;align-items:center;gap:10px}
  .brand-name{font-weight:800;letter-spacing:.06em;font-size:12px;color:#5ef0c8}
  .cover-title{font-size:28px;font-weight:900;line-height:1.1;margin:10px 0 4px}
  .cover-sub{color:#8a9ab0;font-size:14px;margin-top:4px}
  .cover-desc{margin-top:10px;color:#cbd5e1;font-size:12px;line-height:1.4;max-width:640px}
  .cover-meta{margin-top:12px;color:#5a6478;font-size:11px}
  .top-sev{display:inline-block;margin-top:10px;background:#2d0a0a;border:1px solid #ff4444;color:#ff4444;font-weight:800;font-size:10px;letter-spacing:.06em;padding:3px 9px;border-radius:6px}
  .summary-row{display:flex;gap:10px;flex-wrap:wrap;margin:18px 0 18px}
  .stat-chip{display:inline-flex;gap:6px;align-items:center;background:#0b0f16;border:1px solid #111820;border-radius:999px;padding:6px 10px;font-size:12px;color:#cbd5e1}
  .stat-chip b{color:#e5e7eb}
  .section{margin:14px 0 18px;background:#07090f;border:1px solid #111820;border-radius:12px;overflow:hidden}
  .section-h{padding:12px 14px;background:#0b0f16;border-bottom:1px solid #111820;display:flex;justify-content:space-between;align-items:center}
  .section-title{font-weight:900;font-size:13px;letter-spacing:.02em}
  .section-body{padding:14px}
  table{width:100%;border-collapse:collapse}
  .footer{margin-top:16px;color:#5a6478;font-size:10px;display:flex;justify-content:space-between}
  .kev-box span{color:#e5e7eb;font-weight:800}
  </style></head><body><div class="page">
    <div class="cover">
      <div>
        <div class="brand">
          ${osaPngB64 ? `<img src="data:image/png;base64,${osaPngB64}" width="34" height="34" style="flex-shrink:0;border-radius:6px;object-fit:contain"/>` : ''}
          <div class="brand-name">OSA Hunter</div>
        </div>
        <div class="cover-title">${title}</div>
        ${topSev !== 'NONE' ? `<span class="top-sev">${topSev}</span>` : ''}
      </div>
      <div class="cover-sub">${subtitle}</div>
      ${desc ? `<div class="cover-desc">${desc}</div>` : ''}
      <div class="cover-meta">Scanned: ${date}</div>
      ${extraStats}
    </div>
    <div class="summary-row">
      ${pills || '<span class="stat-chip" style="color:#34d399">✅ Clean — no vulnerabilities found</span>'}
    </div>
    ${kevHits || pocHits ? `
    <div class="kev-box" style="margin-bottom:20px;display:flex;gap:20px;flex-wrap:wrap">
      ${kevHits ? `<div>🔥 <span>${kevHits} CVE${kevHits > 1 ? 's' : ''}</span> found in <span>CISA KEV</span> — actively exploited in the wild</div>` : ''}
      ${pocHits ? `<div>💥 <span>${pocHits} CVE${pocHits > 1 ? 's' : ''}</span> with <span>public PoC</span> on GitHub</div>` : ''}
    </div>` : ''}
    ${(sections || []).join('')}
    <div class="footer">
      <span>OSA Hunter — Vulnerability Scanner</span>
      <span>Generated ${date}</span>
    </div>
  </div></body></html>`;
}

module.exports = { buildBaseHtml };
