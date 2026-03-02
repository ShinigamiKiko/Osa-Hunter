'use strict';
const { wrapHtml, buildHeader, buildChips, buildAlerts, buildFooter, sevBadge, epssCell, cvssCell } = require('./style');

const SEV_W = { CRITICAL:4, HIGH:3, MEDIUM:2, LOW:1, UNKNOWN:0 };

// Extra CSS for image scan card rows
const EXTRA_CSS = `
.pkg-section{margin:20px 32px;background:#0b0f18;border:1px solid #1a2030;border-radius:12px;overflow:hidden}
.pkg-hdr{padding:11px 16px;background:#0e1420;border-bottom:1px solid #1a2030;display:flex;align-items:center;gap:10px}
.pkg-hdr-vbar{width:3px;border-radius:2px;flex-shrink:0;height:28px}
.pkg-hdr-vbar.CRITICAL{background:#ff4444}
.pkg-hdr-vbar.HIGH{background:#ff8c32}
.pkg-hdr-vbar.MEDIUM{background:#fbbf24}
.pkg-hdr-vbar.LOW{background:#34d399}
.pkg-hdr-vbar.UNKNOWN{background:#5a6478}
.pkg-hdr-name{font-family:monospace;font-size:13px;font-weight:700;color:#e5e7eb}
.pkg-hdr-ver{font-family:monospace;font-size:12px;color:#8a9ab0;margin-left:4px}
.pkg-hdr-fix{font-family:monospace;font-size:11px;color:#34d399;margin-left:10px}
.cve-row{display:flex;align-items:flex-start;gap:10px;padding:9px 16px;border-bottom:1px solid #111820}
.cve-row:last-child{border-bottom:none}
.cve-row:nth-child(even){background:#080b10}
.cve-vbar{width:3px;border-radius:2px;flex-shrink:0;min-height:16px;align-self:stretch;margin-top:2px}
.cve-vbar.CRITICAL{background:#ff4444}
.cve-vbar.HIGH{background:#ff8c32}
.cve-vbar.MEDIUM{background:#fbbf24}
.cve-vbar.LOW{background:#34d399}
.cve-vbar.UNKNOWN{background:#5a6478}
.cve-id{font-family:monospace;font-size:11px;font-weight:800;color:#5ef0c8;flex-shrink:0;width:130px;white-space:nowrap}
.cve-id a{color:#5ef0c8;text-decoration:none}
.cve-lib{font-family:monospace;font-size:10px;color:#a78bfa;flex-shrink:0;background:rgba(167,139,250,.08);border:1px solid rgba(167,139,250,.25);border-radius:4px;padding:1px 7px;max-width:160px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.cve-badges{display:flex;gap:3px;flex-shrink:0}
.cve-desc{font-size:11px;color:#8a9ab0;flex:1;line-height:1.4;overflow:hidden;display:-webkit-box;-webkit-line-clamp:2;-webkit-box-orient:vertical}
.cve-meta{flex-shrink:0;text-align:right;min-width:90px}
.cve-scores{font-size:10px;color:#5a6478;margin-top:3px;white-space:nowrap}
.badge{display:inline-block;font-size:8px;font-weight:800;padding:1px 5px;border-radius:3px}
.badge.kev{background:#3d0a0a;border:1px solid #ff3b30;color:#ff3b30}
.badge.poc{background:#2d1800;border:1px solid #ff9500;color:#ff9500}
.fix-val{color:#34d399;font-family:monospace;font-size:10px;display:block;margin-top:2px}
`;

function buildImgReportHtml(scan, { osaPngB64 = '' } = {}) {
  const image   = scan.image || 'Image';
  const tag     = scan.tag   || 'latest';
  const desc    = scan.desc  || '';
  const vulns   = scan.vulns || [];
  const counts  = scan.counts || {};
  const topSev  = ['CRITICAL','HIGH','MEDIUM','LOW'].find(s => (counts[s]||0) > 0) || 'NONE';
  const kevHits = vulns.filter(v => v.inKev).length;
  const pocHits = vulns.filter(v => (v.pocs||[]).length).length;
  const date    = new Date(scan.scannedAt || Date.now()).toLocaleString('en-US', { year:'numeric', month:'short', day:'2-digit', hour:'2-digit', minute:'2-digit' });

  // ── Group by PkgName ─────────────────────────────────────────
  const groups = new Map();
  for (const v of vulns) {
    const pkg = v.PkgName || v.pkgName || 'unknown';
    if (!groups.has(pkg)) groups.set(pkg, { vulns:[], topW:0, counts:{CRITICAL:0,HIGH:0,MEDIUM:0,LOW:0,UNKNOWN:0} });
    const g = groups.get(pkg);
    g.vulns.push(v);
    const s = (v.Severity || v.severity || 'UNKNOWN').toUpperCase();
    if (s in g.counts) g.counts[s]++;
    g.topW = Math.max(g.topW, SEV_W[s] || 0);
  }

  const sorted = [...groups.entries()].sort((a, b) =>
    b[1].topW !== a[1].topW ? b[1].topW - a[1].topW : b[1].vulns.length - a[1].vulns.length
  );
  for (const [, g] of sorted)
    g.vulns.sort((a, b) => (SEV_W[(b.Severity||b.severity||'UNKNOWN').toUpperCase()]||0) - (SEV_W[(a.Severity||a.severity||'UNKNOWN').toUpperCase()]||0));

  // ── Build sections ────────────────────────────────────────────
  const groupSections = sorted.map(([pkgName, g]) => {
    const topSevG  = ['CRITICAL','HIGH','MEDIUM','LOW'].find(s => g.counts[s]) || 'UNKNOWN';
    const pills    = ['CRITICAL','HIGH','MEDIUM','LOW'].filter(s => g.counts[s])
      .map(s => `<span class="sev ${s}" style="font-size:9px;padding:1px 6px">${g.counts[s]}</span>`).join('');
    const ver      = g.vulns[0]?.InstalledVersion || g.vulns[0]?.installedVersion || '';
    const fixedVer = g.vulns.find(v => v.FixedVersion || v.fixedVersion)?.FixedVersion ||
                     g.vulns.find(v => v.FixedVersion || v.fixedVersion)?.fixedVersion || '';

    const cveRows = g.vulns.map(v => {
      const sev     = (v.Severity || v.severity || 'UNKNOWN').toUpperCase();
      const cveId   = v.VulnerabilityID || v.cve || v.id || '';
      const nvdUrl  = cveId.startsWith('CVE-') ? `https://nvd.nist.gov/vuln/detail/${cveId}` : '';
      const title   = v.Title || v.summary || v.Description || '';
      const libVer  = v.InstalledVersion || v.installedVersion || ver;
      const fix     = v.FixedVersion || v.fixedVersion || v.fix || '';
      const kevBadge = v.inKev ? '<span class="badge kev">🔥 KEV</span>' : '';
      const pocBadge = (v.pocs||[]).length ? `<span class="badge poc">💥 PoC×${v.pocs.length}</span>` : '';
      const cvss3   = v.cvss?.cvss3?.score;
      const epssVal = v.epss?.epss;
      const cvssStr = cvss3 != null ? `CVSS ${cvss3}` : '';
      const epssStr = epssVal != null ? `EPSS ${(epssVal*100).toFixed(1)}%` : '';
      const scores  = [cvssStr, epssStr].filter(Boolean).join(' · ');

      return `<div class="cve-row">
        <div class="cve-vbar ${sev}"></div>
        <div class="cve-id">${nvdUrl ? `<a href="${nvdUrl}">${cveId}</a>` : cveId}</div>
        <span class="cve-lib">${pkgName}${libVer ? ' '+libVer : ''}</span>
        <div class="cve-badges">${kevBadge}${pocBadge}</div>
        <div class="cve-desc">
          ${title ? `<div style="color:#e5e7eb;font-weight:600;font-size:11px;margin-bottom:2px">${title.slice(0,120)}</div>` : ''}
          ${fix ? `<span class="fix-val">→ ${fix}</span>` : ''}
        </div>
        <div class="cve-meta">
          <span class="sev ${sev}">${sev}</span>
          ${scores ? `<div class="cve-scores">${scores}</div>` : ''}
        </div>
      </div>`;
    }).join('');

    return `<div class="pkg-section">
      <div class="pkg-hdr">
        <div class="pkg-hdr-vbar ${topSevG}"></div>
        <span class="pkg-hdr-name">${pkgName}</span>
        ${ver      ? `<span class="pkg-hdr-ver">@${ver}</span>` : ''}
        ${fixedVer ? `<span class="pkg-hdr-fix">→ ${fixedVer}</span>` : ''}
        <div style="margin-left:auto;display:flex;align-items:center;gap:6px">
          ${pills}
          <span style="font-size:11px;color:#5a6478">${g.vulns.length} CVE${g.vulns.length>1?'s':''}</span>
        </div>
      </div>
      ${cveRows}
    </div>`;
  }).join('');

  const header = buildHeader({
    logo: osaPngB64,
    title: 'Container Image Scan',
    sub: `${image}:${tag}`,
    sev: topSev,
    meta: `Scanned: ${date} · ${vulns.length} findings across ${sorted.length} package${sorted.length!==1?'s':''}${desc ? ' · '+desc : ''}`,
  });

  const chips  = buildChips(counts, kevHits, pocHits);
  const alerts = buildAlerts(kevHits, pocHits, null);
  const empty  = '<div style="text-align:center;padding:60px;color:#34d399;font-size:14px">🐳 No vulnerabilities found — this image is clean!</div>';

  // Inject extra CSS into wrapHtml output
  const base = wrapHtml(header + chips + alerts + (vulns.length ? groupSections : empty) + buildFooter(date));
  return base.replace('</style>', EXTRA_CSS + '</style>');
}

module.exports = { buildImgReportHtml };
