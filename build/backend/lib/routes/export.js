// routes/export.js — POST /api/export/pdf
'use strict';
const express  = require('express');
const router   = express.Router();
const fs       = require('fs');
const nodePath = require('path');
const { scanLimiter, rateLimit, fetchEpss, fetchCvss, fetchPocs } = require('../shared');

// Load osa.png as base64 once at startup for PDF embedding
let OSA_PNG_B64 = '';
try {
  const imgFile = nodePath.join(__dirname, '../../frontend/public/assets/osa.png');
  OSA_PNG_B64 = fs.readFileSync(imgFile).toString('base64');
} catch(e) { console.warn('[export] osa.png not found:', e.message); }

const EXPORT_SEV_COLORS = {
  CRITICAL : { bg:'#2d0a0a', border:'#ff4444', text:'#ff4444' },
  HIGH     : { bg:'#2d1500', border:'#ff8c32', text:'#ff8c32' },
  MEDIUM   : { bg:'#2a2000', border:'#fbbf24', text:'#fbbf24' },
  LOW      : { bg:'#0a2018', border:'#34d399', text:'#34d399' },
  NONE     : { bg:'#0a2018', border:'#34d399', text:'#34d399' },
  UNKNOWN  : { bg:'#111827', border:'#5a6478', text:'#5a6478' },
};

function sevBadge(sev) {
  const c = EXPORT_SEV_COLORS[sev] || EXPORT_SEV_COLORS.UNKNOWN;
  return `<span style="display:inline-block;padding:2px 10px;border-radius:4px;font-size:11px;font-weight:700;letter-spacing:.06em;background:${c.bg};border:1px solid ${c.border};color:${c.text}">${sev}</span>`;
}

function epssBar(epss) {
  if (!epss) return '<span style="color:#5a6478;font-size:11px">—</span>';
  const pct = (epss.epss * 100).toFixed(2);
  const color = epss.epss >= .1 ? '#ff4444' : epss.epss >= .01 ? '#fbbf24' : '#34d399';
  return `<span style="font-size:12px;color:${color};font-weight:600">${pct}%</span><span style="color:#5a6478;font-size:10px;margin-left:5px">(${(epss.percentile*100).toFixed(0)}th pct)</span>`;
}

function cvssLine(cvss) {
  if (!cvss || !cvss.cvss3) return '<span style="color:#5a6478;font-size:11px">—</span>';
  const s = cvss.cvss3.score;
  const color = s >= 9 ? '#ff4444' : s >= 7 ? '#ff8c32' : s >= 4 ? '#fbbf24' : '#34d399';
  return `<span style="color:${color};font-weight:700;font-size:13px">${s}</span><span style="color:#5a6478;font-size:10px;margin-left:4px">CVSSv${cvss.cvss3.version||3}</span>`;
}

// Compact vuln rows for lib/img — fast render, no heavy text blocks
function compactVulnRow(v, i) {
  const SC = EXPORT_SEV_COLORS;
  const cveId = v.cve || v.VulnerabilityID || v.id || '';
  const raw   = v._sev || v.severity || v.Severity || 'UNKNOWN';
  const sev   = (typeof raw==='string'&&!raw.startsWith('[')) ? raw.toUpperCase() : 'UNKNOWN';
  const sc    = SC[sev] || SC.UNKNOWN;
  const cvss3 = v.cvss?.cvss3;
  const epss  = v.epss;
  const fix   = v.fix || v._fix || v.FixedVersion || '';
  const sum   = String(v.summary || v.Title || v.Description || '').slice(0, 100);
  const kev   = v.inKev ? '<span style="background:#3d0a0a;border:1px solid #ff3b30;color:#ff3b30;font-size:8px;font-weight:700;padding:1px 5px;border-radius:3px;margin-right:3px">KEV</span>' : '';
  const poc   = (v.pocs||[]).length ? `<span style="background:#2d1800;border:1px solid #ff9500;color:#ff9500;font-size:8px;font-weight:700;padding:1px 5px;border-radius:3px">PoC×${v.pocs.length}</span>` : '';
  const bg    = i%2===0 ? '#07090f' : '#0b0f16';
  const epssStr = epss ? `<span style="color:${epss.epss>=.1?'#ff4444':epss.epss>=.01?'#fbbf24':'#34d399'};font-weight:600">${(epss.epss*100).toFixed(2)}%</span>` : '<span style="color:#5a6478">—</span>';
  const cvssStr = cvss3 ? `<span style="color:${cvss3.score>=9?'#ff4444':cvss3.score>=7?'#ff8c32':cvss3.score>=4?'#fbbf24':'#34d399'};font-weight:700">${cvss3.score}</span>` : '<span style="color:#5a6478">—</span>';
  const nvdUrl  = cveId.startsWith('CVE-') ? `https://nvd.nist.gov/vuln/detail/${cveId}` : '';
  return `<tr style="background:${bg};border-bottom:1px solid #111820">
    <td style="padding:7px 10px;font-family:monospace;font-size:11px;min-width:145px">
      ${nvdUrl?`<a href="${nvdUrl}" style="color:#5ef0c8;text-decoration:none;display:block">${cveId}</a>`:`<span style="color:#5ef0c8">${cveId}</span>`}
      <div style="margin-top:3px">${kev}${poc}</div>
      ${fix?`<div style="color:#34d399;font-size:10px;margin-top:2px">→ ${fix}</div>`:''}
    </td>
    <td style="padding:7px 10px;text-align:center;white-space:nowrap">
      <span style="background:${sc.bg};border:1px solid ${sc.border};color:${sc.text};font-size:9px;font-weight:700;padding:2px 7px;border-radius:3px">${sev}</span>
    </td>
    <td style="padding:7px 10px;text-align:center;font-size:11px">${cvssStr}</td>
    <td style="padding:7px 10px;text-align:center;font-size:11px">${epssStr}</td>
    <td style="padding:7px 10px;font-size:11px;color:#8a9ab0">${sum}</td>
  </tr>`;
}

function activityLine(activity) {
  if (!activity || !activity.found || !activity.lastCommit) return '';
  const date  = new Date(activity.lastCommit);
  const days  = Math.floor((Date.now() - date) / 86400000);
  const years = Math.floor(days / 365);
  const age   = days < 1 ? 'today' : days < 7 ? `${days}d ago` : days < 60 ? `${Math.floor(days/7)}w ago` : years >= 1 ? `${years}y ago` : `${Math.floor(days/30)}mo ago`;
  const stale = years >= 2;
  const color = stale ? '#ff8c32' : '#34d399';
  const label = stale ? '⚠ Possibly stale' : '● Active';
  const dateStr = date.toLocaleDateString('en-US',{year:'numeric',month:'short',day:'numeric'});
  const repoLink = activity.repoUrl ? ` <a href="${activity.repoUrl}" style="color:${color};opacity:.7;font-size:10px;text-decoration:none">↗ repo</a>` : '';
  return `<span style="font-size:11px;color:${color}">${label} · last commit ${age} · ${dateStr}</span>${repoLink}`;
}

function toxicLine(toxic) {
  if (!toxic || !toxic.found) return '<span style="color:#34d399;font-size:11px">✅ Not in toxic-repos</span>';
  const labels = { ddos:'DDoS tool', hostile_actions:'Hostile actions', political_slogan:'Political slogan', malware:'Malware', ip_blocking:'IP blocking' };
  const label  = labels[toxic.problem_type] || toxic.problem_type || 'Toxic';
  const desc   = toxic.description ? ` — ${toxic.description.slice(0,120)}` : '';
  return `<span style="color:#ff3b30;font-size:11px;font-weight:600">☠ Toxic: ${label}${desc}</span>`;
}

function pocLinks(pocs) {
  if (!pocs || !pocs.length) return '<span style="color:#34d399;font-size:11px">No public PoC found</span>';
  return pocs.slice(0,3).map(p =>
    `<a href="${p.url}" style="display:inline-block;background:#2d1800;border:1px solid #ff9500;color:#ff9500;font-size:10px;font-weight:700;padding:1px 7px;border-radius:3px;text-decoration:none;margin-right:4px">💥 ${p.name} ⭐${p.stars}</a>`
  ).join('');
}

function vulnRows(vulns) {
  if (!vulns || !vulns.length) return '<tr><td colspan="6" style="text-align:center;color:#34d399;padding:18px;font-size:13px">✅ No vulnerabilities found</td></tr>';
  return vulns.map((v, i) => {
    const cveId   = v.cve || v.id || v.VulnerabilityID || '';
    const osvId   = v.id || '';
    const fixed   = v.fix || v._fix || v.FixedVersion || '';
    const kev     = v.inKev ? '<span style="background:#3d0a0a;border:1px solid #ff3b30;color:#ff3b30;font-size:9px;font-weight:700;padding:1px 6px;border-radius:3px;margin-right:3px">🔥 KEV</span>' : '';
    const poc     = (v.pocs||[]).length ? `<span style="background:#2d1800;border:1px solid #ff9500;color:#ff9500;font-size:9px;font-weight:700;padding:1px 6px;border-radius:3px">💥 PoC×${v.pocs.length}</span>` : '';
    const raw     = v._sev || v.severity || v.Severity || 'UNKNOWN';
    const sev     = (typeof raw === 'string' && !raw.startsWith('[')) ? raw.toUpperCase() : 'UNKNOWN';
    const summary = v.summary || v.Title || v.Description || 'No description';
    const details = v.details || v.Description || '';
    const nvdLink = cveId.startsWith('CVE-') ? `https://nvd.nist.gov/vuln/detail/${cveId}` : '';
    const osvLink = osvId ? `https://osv.dev/vulnerability/${osvId}` : '';
    const rowBg   = i % 2 === 0 ? '#07090f' : '#0b0f16';
    const detailsId = `vd-${i}`;
    return `
    <tr style="background:${rowBg};border-bottom:2px solid #0f1219">
      <td style="padding:12px;vertical-align:top;min-width:155px">
        ${nvdLink ? `<a href="${nvdLink}" style="font-size:12px;color:#5ef0c8;font-family:monospace;font-weight:700;text-decoration:none;display:block;margin-bottom:2px">${cveId} ↗</a>` : `<span style="font-size:12px;color:#5ef0c8;font-family:monospace;font-weight:700;display:block;margin-bottom:2px">${cveId}</span>`}
        ${osvId && osvId !== cveId ? `<a href="${osvLink}" style="font-size:10px;color:#5a6478;text-decoration:none">${osvId}</a>` : ''}
        <div style="margin-top:4px">${kev}${poc}</div>
        ${fixed ? `<div style="margin-top:6px;font-size:11px;color:#34d399;font-weight:600">→ Fix: ${fixed}</div>` : ''}
        ${v.published ? `<div style="font-size:10px;color:#5a6478;margin-top:4px">${new Date(v.published||v.PublishedDate).toLocaleDateString('en-US',{year:'numeric',month:'short',day:'numeric'})}</div>` : ''}
      </td>
      <td style="padding:12px;vertical-align:top;text-align:center;min-width:80px">${sevBadge(sev)}</td>
      <td style="padding:12px;vertical-align:top;text-align:center;min-width:90px">${cvssLine(v.cvss||null)}</td>
      <td style="padding:12px;vertical-align:top;text-align:center;min-width:80px">${epssBar(v.epss||null)}</td>
      <td style="padding:12px;vertical-align:top;font-size:11px;color:#9ab;min-width:220px;max-width:300px">
        <div style="font-weight:600;color:#c8d8e8;margin-bottom:4px">${String(summary).slice(0,160)}${summary.length>160?'…':''}</div>
        ${details && details !== summary ? `<div style="color:#7a8a9a;font-size:10px;line-height:1.5;margin-top:3px">${String(details).slice(0,300)}${details.length>300?'…':''}</div>` : ''}
        <div style="margin-top:5px">${pocLinks(v.pocs||[])}</div>
      </td>
      <td style="padding:12px;vertical-align:top;min-width:120px">
        ${v.inKev ? '<div style="font-size:10px;color:#ff3b30;font-weight:700;margin-bottom:3px">🔥 In CISA KEV</div>' : ''}
        ${v.cvss?.cvss3?.vector ? `<div style="font-size:9px;color:#5a6478;word-break:break-all;margin-bottom:3px;font-family:monospace">${v.cvss.cvss3.vector}</div>` : ''}
        ${(v.refs||v._refs||[]).slice(0,2).map(u=>`<a href="${u}" style="display:block;font-size:9px;color:#5a6478;word-break:break-all;text-decoration:none;margin-bottom:2px">${u.slice(0,55)}…</a>`).join('')}
      </td>
    </tr>`;
  }).join('');
}


function buildLibReportHtml(scan) {
  const cnt = { CRITICAL:0,HIGH:0,MEDIUM:0,LOW:0,UNKNOWN:0 };
  (scan.vulns||[]).forEach(v => { const raw = v._sev||v.severity||'UNKNOWN'; const s = (typeof raw==='string'&&!raw.startsWith('[')) ? raw : 'UNKNOWN'; if(s in cnt) cnt[s]++; });
  const topSev  = ['CRITICAL','HIGH','MEDIUM','LOW'].find(s=>cnt[s]) || 'NONE';
  const kevHits = (scan.vulns||[]).filter(v=>v.inKev).length;
  const pocHits = (scan.vulns||[]).filter(v=>(v.pocs||[]).length).length;
  const toxic   = scan.toxic;
  const activity= scan.activity;

  const extraStats = `
    <div style="display:flex;flex-wrap:wrap;gap:8px;margin-top:8px">
      <span style="font-size:11px;background:#0f1219;border:1px solid #1a2130;border-radius:5px;padding:3px 10px">${toxicLine(toxic)}</span>
      ${activity ? `<span style="font-size:11px;background:#0f1219;border:1px solid #1a2130;border-radius:5px;padding:3px 10px">${activityLine(activity)}</span>` : ''}
    </div>`;

  return buildBaseHtml({
    title     : `${scan.pkg || scan.package}${scan.ver||scan.version ? ' @ v'+(scan.ver||scan.version) : ''}`,
    subtitle  : `${scan.ecoLabel||scan.ecosystem||''} · Library Scan`,
    scannedAt : scan.scannedAt,
    topSev, counts: cnt, kevHits, pocHits,
    desc      : scan.desc,
    extraStats,
    sections  : [`
      <h2 style="font-size:13px;font-weight:700;color:#e8f0f8;margin:28px 0 12px;letter-spacing:.06em;text-transform:uppercase">Vulnerabilities (${(scan.vulns||[]).length})</h2>
      <table style="width:100%;border-collapse:collapse;font-size:11px">
        <thead><tr style="background:#0f1219;border-bottom:2px solid #1a2130">
          <th style="padding:8px 10px;text-align:left;color:#5a6478;font-size:9px;letter-spacing:.08em;font-weight:500">CVE / ID</th>
          <th style="padding:8px 10px;color:#5a6478;font-size:9px;letter-spacing:.08em;font-weight:500;text-align:center">SEV</th>
          <th style="padding:8px 10px;color:#5a6478;font-size:9px;letter-spacing:.08em;font-weight:500;text-align:center">CVSS</th>
          <th style="padding:8px 10px;color:#5a6478;font-size:9px;letter-spacing:.08em;font-weight:500;text-align:center">EPSS</th>
          <th style="padding:8px 10px;text-align:left;color:#5a6478;font-size:9px;letter-spacing:.08em;font-weight:500">Summary</th>
        </tr></thead>
        <tbody>${(scan.vulns||[]).map((v,i)=>compactVulnRow(v,i)).join('')}</tbody>
      </table>`]
  });
}

function buildImgReportHtml(scan) {
  const cnt = { CRITICAL: scan.counts?.CRITICAL||0, HIGH: scan.counts?.HIGH||0, MEDIUM: scan.counts?.MEDIUM||0, LOW: scan.counts?.LOW||0, UNKNOWN: scan.counts?.UNKNOWN||0 };
  const topSev = ['CRITICAL','HIGH','MEDIUM','LOW'].find(s=>cnt[s]) || 'NONE';
  const kevHits = (scan.vulns||[]).filter(v=>v.inKev).length;
  const pocHits = (scan.vulns||[]).filter(v=>(v.pocs||[]).length).length;

  // Group by target
  const byTarget = {};
  (scan.vulns||[]).forEach(v => {
    const t = v.Target || v.PkgName || 'Unknown';
    if (!byTarget[t]) byTarget[t] = [];
    byTarget[t].push(v);
  });

  const sections = Object.entries(byTarget).map(([target, vulns]) => `
    <h2 style="font-size:12px;font-weight:700;color:#4da6ff;margin:24px 0 10px;letter-spacing:.05em;text-transform:uppercase;border-bottom:1px solid #1a2130;padding-bottom:7px">📦 ${target} (${vulns.length})</h2>
    <table style="width:100%;border-collapse:collapse;font-size:12px">
      <thead><tr style="background:#0f1219;border-bottom:1px solid #1a2130">
        <th style="padding:9px 12px;text-align:left;color:#5a6478;font-size:10px;letter-spacing:.08em;font-weight:500">CVE</th>
        <th style="padding:9px 12px;color:#5a6478;font-size:10px;letter-spacing:.08em;font-weight:500">SEV</th>
        <th style="padding:9px 12px;color:#5a6478;font-size:10px;letter-spacing:.08em;font-weight:500">CVSS</th>
        <th style="padding:9px 12px;color:#5a6478;font-size:10px;letter-spacing:.08em;font-weight:500">EPSS</th>
        <th style="padding:9px 12px;text-align:left;color:#5a6478;font-size:10px;letter-spacing:.08em;font-weight:500">Package / Summary</th>
        <th style="padding:9px 12px;color:#5a6478;font-size:10px;letter-spacing:.08em;font-weight:500">Fix</th>
      </tr></thead>
      <tbody>${vulns.map(v => {
        const sev = String(v.Severity||v.severity||'UNKNOWN').toUpperCase();
        const summary = v.Title||v.Description||v.summary||'';
        const pkg = v.PkgName ? `<div style="color:#5ef0c8;font-size:10px;margin-bottom:2px">${v.PkgName} ${v.InstalledVersion||''}</div>` : '';
        const kev = v.inKev ? '<span style="background:#3d0a0a;border:1px solid #ff3b30;color:#ff3b30;font-size:9px;font-weight:700;padding:1px 5px;border-radius:3px;margin-right:2px">🔥 KEV</span>' : '';
        const poc = (v.pocs||[]).length ? `<span style="background:#2d1800;border:1px solid #ff9500;color:#ff9500;font-size:9px;font-weight:700;padding:1px 5px;border-radius:3px">💥 PoC</span>` : '';
        return `<tr style="border-bottom:1px solid #1a2130">
          <td style="padding:9px 12px;vertical-align:top">
            <div style="font-size:11px;color:#5ef0c8;font-family:monospace;font-weight:600">${v.VulnerabilityID||v.cve||v.id||'—'}</div>
            <div style="margin-top:2px">${kev}${poc}</div>
          </td>
          <td style="padding:9px 12px;vertical-align:top;text-align:center">${sevBadge(sev)}</td>
          <td style="padding:9px 12px;vertical-align:top;text-align:center">${cvssLine(v.cvss||null)}</td>
          <td style="padding:9px 12px;vertical-align:top;text-align:center">${epssBar(v.epss||null)}</td>
          <td style="padding:9px 12px;vertical-align:top;font-size:11px;color:#9ab;max-width:260px">${pkg}${String(summary).slice(0,100)}${summary.length>100?'…':''}</td>
          <td style="padding:9px 12px;vertical-align:top;font-size:11px;color:#34d399">${v.FixedVersion||v.fix||'—'}</td>
        </tr>`;
      }).join('')}</tbody>
    </table>`);

  return buildBaseHtml({
    title     : `${scan.image}:${scan.tag}`,
    subtitle  : 'Docker Image Scan',
    scannedAt : scan.scannedAt,
    topSev,
    counts    : cnt,
    kevHits,
    pocHits,
    desc      : scan.desc,
    sections
  });
}

function buildDepReportHtml(scan) {
  const sm  = scan.summary || {};
  const cnt = { CRITICAL:sm.CRITICAL||0, HIGH:sm.HIGH||0, MEDIUM:sm.MEDIUM||0, LOW:sm.LOW||0, UNKNOWN:0 };
  const topSev  = ['CRITICAL','HIGH','MEDIUM','LOW'].find(s=>cnt[s]) || 'NONE';
  const allVulns = (scan.deps||[]).flatMap(d=>d.vulns||[]);
  const kevHits  = allVulns.filter(v=>v.inKev).length;
  const pocHits  = allVulns.filter(v=>(v.pocs||[]).length).length;
  const SEV_W   = {CRITICAL:4,HIGH:3,MEDIUM:2,LOW:1,UNKNOWN:0};
  const SC      = EXPORT_SEV_COLORS;

  const directDeps     = (scan.deps||[]).filter(d=>d.relation==='DIRECT');
  const transitiveDeps = (scan.deps||[]).filter(d=>d.relation!=='DIRECT');

  // Full enriched vuln block — one per CVE, like lib-scan PDF
  function vulnBlock(v) {
    const cveId  = v.cve || v.id || '';
    const sev    = String(v.severity||'UNKNOWN').toUpperCase();
    const sc     = SC[sev] || SC.UNKNOWN;
    const cvss3  = v.cvss?.cvss3;
    const epss   = v.epss;
    const kev    = v.inKev ? '<span style="background:#3d0a0a;border:1px solid #ff3b30;color:#ff3b30;font-size:8px;font-weight:700;padding:1px 6px;border-radius:3px">KEV</span> ' : '';
    const poc    = (v.pocs||[]).length ? `<span style="background:#2d1800;border:1px solid #ff9500;color:#ff9500;font-size:8px;font-weight:700;padding:1px 6px;border-radius:3px">PoC x${v.pocs.length}</span>` : '';
    const epssStr = epss ? `${(epss.epss*100).toFixed(2)}% <span style="color:#5a6478;font-size:10px">(${(epss.percentile*100).toFixed(0)}th pct)</span>` : '—';
    const epssColor = epss ? (epss.epss>=.1?'#ff4444':epss.epss>=.01?'#fbbf24':'#34d399') : '#5a6478';
    const cvssScore = cvss3?.score;
    const cvssColor = cvssScore ? (cvssScore>=9?'#ff4444':cvssScore>=7?'#ff8c32':cvssScore>=4?'#fbbf24':'#34d399') : '#5a6478';
    const pocLinks  = (v.pocs||[]).slice(0,2).map(p=>`<a href="${p.url}" style="color:#ff9500;font-size:10px;text-decoration:none;display:inline-block;margin-right:8px">${p.name} ⭐${p.stars}</a>`).join('');

    return `<div style="margin-bottom:10px;padding:10px 14px;background:#090d14;border:1px solid ${sc.border};border-left:3px solid ${sc.border};border-radius:0 6px 6px 0">
      <div style="display:flex;align-items:flex-start;gap:10px;margin-bottom:6px">
        <div style="flex:1">
          <span style="font-family:monospace;font-size:12px;font-weight:700;color:#5ef0c8">${cveId.startsWith('CVE-')?`<a href="https://nvd.nist.gov/vuln/detail/${cveId}" style="color:#5ef0c8;text-decoration:none">${cveId}</a>`:cveId}</span>
          <span style="color:#5a6478;font-size:10px;margin-left:8px">${v.id!==cveId?v.id:''}</span>
          <span style="margin-left:8px">${kev}${poc}</span>
        </div>
        <span style="background:${sc.bg};border:1px solid ${sc.border};color:${sc.text};font-size:10px;font-weight:700;padding:2px 10px;border-radius:4px;white-space:nowrap">${sev}</span>
      </div>
      ${v.summary ? `<div style="color:#c0cde0;font-size:11px;margin-bottom:8px;line-height:1.5">${String(v.summary).slice(0,200)}${v.summary.length>200?'…':''}</div>` : ''}
      <div style="display:grid;grid-template-columns:80px 1fr 80px 1fr;gap:4px 12px;font-size:10px">
        <span style="color:#5a6478">CVSS</span>
        <span style="color:${cvssColor};font-weight:700">${cvssScore ? `${cvssScore} (v${cvss3.version||3})` : '—'}</span>
        <span style="color:#5a6478">EPSS</span>
        <span style="color:${epssColor};font-weight:600">${epssStr}</span>
        ${v.fix ? `<span style="color:#5a6478">Fixed in</span><span style="color:#34d399;font-weight:600">${v.fix}</span>` : ''}
        ${v.published ? `<span style="color:#5a6478">Published</span><span style="color:#8a9ab0">${new Date(v.published).toLocaleDateString('en-US',{year:'numeric',month:'short',day:'numeric'})}</span>` : ''}
      </div>
      ${pocLinks ? `<div style="margin-top:6px">${pocLinks}</div>` : ''}
    </div>`;
  }

  // One lib entry: header + its vulns listed below
  function libEntry(dep) {
    const isToxic  = dep.toxic?.found;
    const sorted   = [...(dep.vulns||[])].sort((a,b)=>(SEV_W[String(b.severity||'').toUpperCase()]||0)-(SEV_W[String(a.severity||'').toUpperCase()]||0));
    const depTopSev = sorted.length ? String(sorted[0].severity||'UNKNOWN').toUpperCase() : 'NONE';
    const tc = SC[depTopSev] || SC.UNKNOWN;
    const toxicLabel = isToxic ? (() => {
      const labels = {ddos:'DDoS tool',hostile_actions:'Hostile actions',political_slogan:'Political slogan',malware:'Malware',ip_blocking:'IP blocking'};
      return labels[dep.toxic.problem_type] || dep.toxic.problem_type || 'Toxic';
    })() : '';

    return `<div style="margin-bottom:18px;page-break-inside:avoid">
      <!-- lib header -->
      <div style="display:flex;align-items:center;gap:8px;padding:8px 14px;background:#0d1117;border:1px solid ${sorted.length?tc.border:'#1a2130'};border-radius:7px ${sorted.length?'7px 0 0':'7px 7px 7px'}">
        <span style="width:3px;height:20px;border-radius:2px;background:${sorted.length?tc.border:'#2a3a4a'};flex-shrink:0"></span>
        <span style="font-size:13px;font-weight:700;color:#fff">${dep.name}</span>
        <span style="color:#5a6478;font-size:11px">v${dep.version}</span>
        ${isToxic ? `<span style="background:rgba(255,59,48,.15);border:1px solid rgba(255,59,48,.4);color:#ff3b30;font-size:9px;font-weight:700;padding:1px 6px;border-radius:3px">☠ ${toxicLabel}</span>` : ''}
        <span style="margin-left:auto;color:#5a6478;font-size:10px">${sorted.length ? `${sorted.length} vuln${sorted.length!==1?'s':''}` : '<span style="color:#34d399">✓ clean</span>'}</span>
      </div>
      ${sorted.length
        ? `<div style="border:1px solid #1a2130;border-top:none;border-radius:0 0 7px 7px;padding:8px 8px 2px">${sorted.map(v=>vulnBlock(v)).join('')}</div>`
        : ''
      }
      ${isToxic && dep.toxic.description ? `<div style="padding:6px 14px;background:rgba(255,59,48,.06);border:1px solid rgba(255,59,48,.2);border-top:none;border-radius:0 0 7px 7px;font-size:10px;color:#ff8888">${dep.toxic.description.slice(0,180)}</div>` : ''}
    </div>`;
  }

  // Section block: Direct or Transitive
  function depSection(deps, label, isTransitive) {
    if (!deps.length) return '';
    const accentColor = isTransitive ? '#3b82f6' : '#a78bfa';
    const sectionCnt  = {CRITICAL:0,HIGH:0,MEDIUM:0,LOW:0};
    deps.forEach(d=>(d.vulns||[]).forEach(v=>{const s=String(v.severity||'').toUpperCase();if(s in sectionCnt)sectionCnt[s]++;}));
    const groupTopSev = ['CRITICAL','HIGH','MEDIUM','LOW'].find(s=>sectionCnt[s])||'NONE';
    const borderColor = groupTopSev!=='NONE' ? (SC[groupTopSev]?.border||accentColor) : accentColor;
    const pills = ['CRITICAL','HIGH','MEDIUM','LOW'].filter(s=>sectionCnt[s])
      .map(s=>`<span style="background:${SC[s].bg};border:1px solid ${SC[s].border};color:${SC[s].text};font-size:9px;font-weight:700;padding:1px 8px;border-radius:3px">${sectionCnt[s]} ${s}</span>`).join(' ');

    // Sort: toxic first, then by severity, then clean
    const sorted = [...deps].sort((a,b)=>{
      if(a.toxic?.found !== b.toxic?.found) return a.toxic?.found ? -1 : 1;
      const wa = Math.max(0,...(a.vulns||[]).map(v=>SEV_W[String(v.severity||'').toUpperCase()]||0));
      const wb = Math.max(0,...(b.vulns||[]).map(v=>SEV_W[String(v.severity||'').toUpperCase()]||0));
      return wb - wa;
    });

    return `<div style="margin-bottom:32px">
      <div style="display:flex;align-items:center;gap:10px;padding:10px 16px;background:#0a0d12;border:1px solid ${borderColor};border-radius:8px;margin-bottom:14px">
        <span style="font-size:11px;font-weight:700;padding:3px 12px;border-radius:5px;
          background:${isTransitive?'rgba(59,130,246,.12)':'rgba(167,139,250,.12)'};
          border:1px solid ${isTransitive?'rgba(59,130,246,.4)':'rgba(167,139,250,.4)'};
          color:${accentColor}">${isTransitive ? 'Transitive' : 'Direct'}</span>
        <span style="font-size:14px;font-weight:700;color:#fff">${label}</span>
        <span style="color:#5a6478;font-size:11px">(${deps.length} packages)</span>
        <span style="margin-left:auto;display:flex;gap:5px;align-items:center">
          ${pills || '<span style="color:#34d399;font-size:10px;font-weight:600">✅ all clean</span>'}
        </span>
      </div>
      ${sorted.map(dep => libEntry(dep)).join('')}
    </div>`;
  }

  const sections = [
    depSection(directDeps,    'Direct Dependencies',    false),
    depSection(transitiveDeps,'Transitive Dependencies', true),
  ].filter(Boolean);

  if (!sections.length) sections.push('<div style="text-align:center;padding:50px;color:#34d399;font-size:14px">No dependencies found</div>');

  return buildBaseHtml({
    title     : `${scan.package||''} v${scan.resolvedVersion||''}`,
    subtitle  : `${scan.system||''} · Dependency Scan`,
    scannedAt : scan.scannedAt || new Date().toISOString(),
    topSev, counts: cnt, kevHits, pocHits,
    desc      : scan.desc,
    extraStats: `<div style="display:flex;gap:8px;margin-top:8px;flex-wrap:wrap">
      <div class="stat-chip">Total: <strong>${sm.totalDeps||0}</strong></div>
      <div class="stat-chip" style="color:#a78bfa">Direct: <strong>${sm.directDeps||0}</strong></div>
      <div class="stat-chip" style="color:#3b82f6">Transitive: <strong>${(sm.totalDeps||0)-(sm.directDeps||0)}</strong></div>
      <div class="stat-chip" style="color:#ff8c32">With vulns: <strong>${sm.withVulns||0}</strong></div>
      ${sm.toxic ? `<div class="stat-chip" style="color:#ff3b30">Toxic: <strong>${sm.toxic}</strong></div>` : ''}
    </div>`,
    sections
  });
}

function buildBaseHtml({ title, subtitle, scannedAt, topSev, counts, kevHits, pocHits, desc, extraStats='', sections }) {
  const sevColor = EXPORT_SEV_COLORS[topSev] || EXPORT_SEV_COLORS.UNKNOWN;
  const date = new Date(scannedAt).toLocaleString('en-US',{year:'numeric',month:'short',day:'numeric',hour:'2-digit',minute:'2-digit'});
  const pills = ['CRITICAL','HIGH','MEDIUM','LOW'].filter(s=>counts[s])
    .map(s => { const c=EXPORT_SEV_COLORS[s]; return `<span style="background:${c.bg};border:1px solid ${c.border};color:${c.text};padding:4px 12px;border-radius:5px;font-size:12px;font-weight:700">${counts[s]} ${s}</span>`; }).join('');

  return `<!DOCTYPE html><html><head><meta charset="UTF-8"/>
  <style>
    *{box-sizing:border-box;margin:0;padding:0}
    body{background:#07090f;color:#e8f0f8;font-family:'Courier New',Courier,monospace;font-size:13px;line-height:1.6;-webkit-print-color-adjust:exact;print-color-adjust:exact}
    .page{max-width:1000px;margin:0 auto;padding:48px 44px}
    .cover{display:flex;align-items:flex-start;gap:20px;padding-bottom:28px;border-bottom:1px solid #1a2130;margin-bottom:28px}
    .cover-badge{width:52px;height:52px;border-radius:12px;background:rgba(94,240,200,.08);border:1px solid rgba(94,240,200,.2);display:flex;align-items:center;justify-content:center;font-size:22px;flex-shrink:0}
    .cover-info{flex:1}
    .cover-title{font-family:system-ui,-apple-system,'Segoe UI',sans-serif;font-size:22px;font-weight:800;color:#fff;letter-spacing:-.01em}
    .cover-sub{font-size:11px;color:#5a6478;letter-spacing:.08em;text-transform:uppercase;margin-top:3px}
    .cover-desc{font-size:12px;color:#8a9ab0;margin-top:5px}
    .cover-meta{font-size:10px;color:#5a6478;margin-top:6px}
    .cover-top{display:flex;align-items:center;gap:10px;margin-bottom:10px}
    .top-sev{padding:5px 16px;border-radius:6px;font-size:13px;font-weight:700;letter-spacing:.04em;background:${sevColor.bg};border:1px solid ${sevColor.border};color:${sevColor.text}}
    .stat-chip{background:#0f1219;border:1px solid #1a2130;border-radius:6px;padding:5px 12px;font-size:11px;color:#8a9ab0}
    .summary-row{display:flex;gap:10px;flex-wrap:wrap;margin-bottom:18px}
    .kev-box{background:#1a0505;border:1px solid #3d0a0a;border-radius:8px;padding:10px 16px;font-size:11px}
    .kev-box span{color:#ff3b30;font-weight:700}
    .brand{display:flex;align-items:center;gap:8px;margin-bottom:36px;padding-bottom:16px;border-bottom:1px solid #0f1219}
    .brand-name{font-family:system-ui,-apple-system,'Segoe UI',sans-serif;font-size:14px;font-weight:800;color:#fff;letter-spacing:.04em;text-transform:uppercase}
    .brand-name em{color:#5ef0c8;font-style:normal}
    .footer{margin-top:40px;padding-top:16px;border-top:1px solid #1a2130;display:flex;justify-content:space-between;font-size:10px;color:#5a6478}
    table{width:100%}
  </style>
  </head><body><div class="page">
    <div class="brand">
      ${OSA_PNG_B64 ? `<img src="data:image/png;base64,${OSA_PNG_B64}" width="34" height="34" style="flex-shrink:0;border-radius:6px;object-fit:contain"/>` : ''}
      <span class="brand-name">OSA <em>HUNTER</em></span>
      <span style="font-size:10px;color:#5a6478;letter-spacing:.1em;margin-left:4px">VULN SCANNER · SECURITY REPORT</span>
    </div>    </div>
    <div class="cover">
      <div class="cover-badge">🔍</div>
      <div class="cover-info">
        <div class="cover-top">
          <div class="cover-title">${title}</div>
          ${topSev !== 'NONE' ? `<span class="top-sev">${topSev}</span>` : ''}
        </div>
        <div class="cover-sub">${subtitle}</div>
        ${desc ? `<div class="cover-desc">${desc}</div>` : ''}
        <div class="cover-meta">Scanned: ${date}</div>
        ${extraStats}
      </div>
    </div>
    <div class="summary-row">
      ${pills || '<span class="stat-chip" style="color:#34d399">✅ Clean — no vulnerabilities found</span>'}
    </div>
    ${kevHits || pocHits ? `
    <div class="kev-box" style="margin-bottom:20px;display:flex;gap:20px;flex-wrap:wrap">
      ${kevHits ? `<div>🔥 <span>${kevHits} CVE${kevHits>1?'s':''}</span> found in <span>CISA KEV</span> — actively exploited in the wild</div>` : ''}
      ${pocHits ? `<div>💥 <span>${pocHits} CVE${pocHits>1?'s':''}</span> with <span>public PoC</span> on GitHub</div>` : ''}
    </div>` : ''}
    ${sections.join('')}
    <div class="footer">
      <span>OSA Hunter — Vulnerability Scanner</span>
      <span>Generated ${date}</span>
    </div>
  </div></body></html>`;
}

router.post('/export/pdf', rateLimit(scanLimiter), async (req, res) => {
  const { type, params } = req.body || {};
  if (!type || !params) return res.status(400).json({ error: '"type" and "params" required' });
  if (!['lib','img','dep'].includes(type)) return res.status(400).json({ error: 'type must be lib | img | dep' });

  let puppeteer;
  try { puppeteer = require('puppeteer'); }
  catch { return res.status(503).json({ error: 'Puppeteer not installed' }); }

  // ── 1. Re-run full enriched scan internally ──────────────────
  let scan;
  try {
    if (type === 'lib') {
      const { name, ecosystem, version, desc, ecoLabel, ecoLogo } = params;
      if (!name || !ecosystem) return res.status(400).json({ error: 'lib scan requires name + ecosystem' });

      // Call our own /api/libscan logic by making internal fetch
      const r = await fetch(`http://localhost:${process.env.PORT||3001}/api/libscan`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name, ecosystem, version }),
      });
      const data = await r.json();
      if (!r.ok) throw new Error(data.error || 'libscan failed');

      // Add activity info
      const actR = await fetch(`http://localhost:${process.env.PORT||3001}/api/activity`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name, ecosystem: ecoLabel || ecosystem }),
      }).catch(() => null);
      const actData = actR ? await actR.json().catch(() => null) : null;

      scan = { ...data, desc, ecoLabel: ecoLabel || ecosystem, ecoLogo: ecoLogo || '📦', activity: actData };

    } else if (type === 'img') {
      const { image, tag, desc } = params;
      if (!image) return res.status(400).json({ error: 'img scan requires image' });

      const r = await fetch(`http://localhost:${process.env.PORT||3001}/api/trivy/scan`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ image, tag: tag || 'latest', desc }),
      });
      const data = await r.json();
      if (!r.ok) throw new Error(data.error || 'trivy scan failed');

      // Enrich trivy vulns with EPSS/KEV/PoC
      const allV = [];
      (data.Results || []).forEach(t => (t.Vulnerabilities || []).forEach(v => allV.push(v)));
      const cveIds = [...new Set(allV.map(v => v.VulnerabilityID).filter(x => x?.startsWith('CVE-')))];

      const { fetchEpss, fetchCvss, fetchPocs, getCisaSet } = require('../shared');
      const [epssMap, kevArr, cvssMap, pocMap] = await Promise.all([
        fetchEpss(cveIds),
        getCisaSet().then(s => cveIds.filter(c => s.has(c))).catch(() => []),
        fetchCvss(cveIds),
        fetchPocs(cveIds),
      ]);
      const kevSet = new Set(kevArr);

      const enrichedVulns = allV.map(v => ({
        ...v,
        epss  : epssMap[v.VulnerabilityID] || null,
        inKev : kevSet.has(v.VulnerabilityID),
        pocs  : pocMap[v.VulnerabilityID] || [],
        cvss  : cvssMap[v.VulnerabilityID] || null,
      }));

      const counts = { CRITICAL:0, HIGH:0, MEDIUM:0, LOW:0, UNKNOWN:0 };
      enrichedVulns.forEach(v => { const s = String(v.Severity||'UNKNOWN').toUpperCase(); if(s in counts) counts[s]++; });

      scan = { image, tag: tag||'latest', desc, vulns: enrichedVulns, counts, scannedAt: new Date().toISOString() };

    } else {
      // dep — data already fully enriched on frontend, send it directly
      // (re-scanning would take 30-60s for large packages)
      const { scanData } = params;
      if (!scanData) return res.status(400).json({ error: 'dep export requires params.scanData' });
      scan = scanData;
      console.log('[PDF dep] using pre-enriched scan, package:', scan.package, 'deps:', scan.deps?.length);
    }
  } catch(e) {
    return res.status(502).json({ error: 'Scan failed: ' + e.message });
  }

  // ── 2. Build HTML ────────────────────────────────────────────
  let html;
  try {
    if (type === 'lib') html = buildLibReportHtml(scan);
    else if (type === 'img') html = buildImgReportHtml(scan);
    else html = buildDepReportHtml(scan);
  } catch(e) {
    console.error('[PDF build error]', e.stack || e.message);
    if (scan) {
      console.error('[PDF build] scan keys:', Object.keys(scan));
      console.error('[PDF build] scan.package:', scan.package, 'scan.deps count:', scan.deps?.length, 'scan.summary:', JSON.stringify(scan.summary));
      if (scan.deps?.length) {
        const first = scan.deps[0];
        console.error('[PDF build] first dep keys:', Object.keys(first), 'vulns:', first.vulns?.length);
        if (first.vulns?.length) console.error('[PDF build] first vuln keys:', Object.keys(first.vulns[0]));
      }
    } else {
      console.error('[PDF build] scan is null/undefined');
    }
    return res.status(500).json({ error: 'Failed to build report: ' + e.message });
  }

  // ── 3. Puppeteer → PDF ───────────────────────────────────────
  let browser;
  try {
    browser = await puppeteer.launch({
      headless: 'new',
      executablePath: process.env.PUPPETEER_EXECUTABLE_PATH || undefined,
      protocolTimeout: 120000,
      args: [
        '--no-sandbox',
        '--disable-setuid-sandbox',
        '--disable-dev-shm-usage',
        '--disable-gpu',
        '--disable-web-security',
      ],
      timeout: 60000,
    });
    const page = await browser.newPage();
    await page.setDefaultNavigationTimeout(120000);
    await page.setDefaultTimeout(120000);
    await page.setContent(html, { waitUntil: 'domcontentloaded', timeout: 60000 });
    // Small wait for any inline rendering to settle
    await new Promise(r => setTimeout(r, 300));
    const pdf = await page.pdf({
      format         : 'A4',
      printBackground: true,
      margin         : { top:'0', right:'0', bottom:'0', left:'0' },
    });

    const name = type === 'lib'
      ? `osa-lib-${(scan.package||scan.pkg||'scan').replace(/[^a-z0-9]/gi,'-')}`
      : type === 'img'
      ? `osa-img-${(scan.image||'scan').replace(/[^a-z0-9]/gi,'-')}-${scan.tag||'latest'}`
      : `osa-dep-${(scan.package||'scan').replace(/[^a-z0-9]/gi,'-')}`;

    res.set({
      'Content-Type'       : 'application/pdf',
      'Content-Disposition': `attachment; filename="${name}.pdf"`,
      'Content-Length'     : pdf.length,
    });
    res.send(pdf);
  } catch(e) {
    console.error('[PDF export]', e.message);
    res.status(500).json({ error: 'PDF generation failed: ' + e.message });
  } finally {
    if (browser) await browser.close().catch(()=>{});
  }
});



module.exports = router;
