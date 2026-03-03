// ui-os-scan.js — OS Packages Scan (powered by Grype)
// Rendering 1:1 with image scan: groups, enrichment, CVSS/NVD/EPSS/Risk/KEV/PoC

const OS_DISTROS = [
  { id:'ubuntu', label:'Ubuntu', logo:'🟠' },
  { id:'debian', label:'Debian', logo:'🌀' },
  { id:'rhel',   label:'RHEL',   logo:'🎩' },
  { id:'alpine', label:'Alpine', logo:'🏔️' },
  { id:'suse',   label:'SUSE',   logo:'🦎' },
];

let osScans       = safeLoad('es_os', []);
let selOsDistro   = null;
let currentOsScan = null;
const saveOs      = () => safeSave('es_os', osScans);

// ── MODAL ─────────────────────────────────────────────────────
function renderOsDistros(){
  document.getElementById('osDistroGrid').innerHTML = OS_DISTROS.map(d =>
    `<button class="eco-btn${selOsDistro===d.id?' on':''}" onclick="pickOsDistro('${d.id}')">
      <div class="eco-logo">${d.logo}</div><div class="eco-name">${d.label}</div>
    </button>`).join('');
}
function pickOsDistro(id){ selOsDistro=id; renderOsDistros(); }

function openOsModal(){
  selOsDistro=null;
  ['osDesc','osPkg','osPkgVer','osDistroVer'].forEach(id=>document.getElementById(id).value='');
  document.getElementById('osmerr').style.display='none';
  setBtn('btnOsGo',false,'▶ Scan');
  renderOsDistros();
  document.getElementById('osModal').style.display='flex';
  setTimeout(()=>document.getElementById('osPkg').focus(),160);
}
function closeOsModal(){ document.getElementById('osModal').style.display='none'; }

// ── SCAN ─────────────────────────────────────────────────────
async function doOsScan(){
  const distro    = OS_DISTROS.find(d=>d.id===selOsDistro);
  const pkg       = document.getElementById('osPkg').value.trim();
  const pkgVer    = document.getElementById('osPkgVer').value.trim();
  const distroVer = document.getElementById('osDistroVer').value.trim();
  const desc      = document.getElementById('osDesc').value.trim();
  document.getElementById('osmerr').style.display='none';
  if(!distro) return showErr('osmerr','Select a distribution');
  if(!pkg)    return showErr('osmerr','Enter a package name');
  setBtn('btnOsGo',true);
  try{
    const r=await fetch('/api/osscan',{method:'POST',headers:{'Content-Type':'application/json'},
      body:JSON.stringify({name:pkg,version:pkgVer||undefined,distro:distro.id,distroVersion:distroVer||undefined})});
    const data=await r.json();
    if(!r.ok) throw new Error(data.error||`Error ${r.status}`);
    const _ck = `os:${distro.id}:${pkg}:${pkgVer||'any'}`;
    const ckIdx = osScans.findIndex(s => s._cacheKey === _ck);
    if (ckIdx !== -1) osScans.splice(ckIdx, 1);
    osScans.unshift({
      id:Date.now(), _cacheKey:_ck,
      pkg,pkgVer,distro:distro.id,distroLabel:distro.label,distroLogo:distro.logo,
      distroVer,desc,vulns:data.vulns||[],counts:data.counts||{},
      topSev:data.topSeverity||'NONE',scannedAt:data.scannedAt||new Date().toISOString(),
    });
    if(osScans.length>30) osScans=osScans.slice(0,30);
    saveOs();closeOsModal();updateOsBadge();navTo('os-list');
  }catch(e){ showErr('osmerr',e.message||'Scan failed'); }
  setBtn('btnOsGo',false,'▶ Scan');
}

// ── BADGE ─────────────────────────────────────────────────────
function updateOsBadge(){
  const b=document.getElementById('osBadge');
  if(osScans.length){b.style.display='';b.textContent=osScans.length;}
  else b.style.display='none';
}

// ── LIST ──────────────────────────────────────────────────────
async function renderOsList(){
  if (!window._histLoaded_os) {
    window._histLoaded_os = true;
    try {
      const r = await fetch('/api/scans/history?type=os', {credentials:'same-origin'});
      if (r.ok) {
        const {entries=[]} = await r.json();
        const existing = new Set(osScans.map(s=>s._cacheKey||String(s.id)));
        const DM = {ubuntu:'🟠 Ubuntu',debian:'🌀 Debian',rhel:'🎩 RHEL',alpine:'🏔️ Alpine',suse:'🦎 SUSE'};
        for (const e of entries) {
          if (existing.has(e._cacheKey)) continue;
          const [logo,label] = (DM[e.distro]||'🐧 '+e.distro).split(' ');
          osScans.push({
            id:e._cacheKey, _cacheKey:e._cacheKey,
            pkg:e.package, pkgVer:e.version||'',
            distro:e.distro, distroLabel:label||e.distro, distroLogo:logo||'🐧',
            distroVer:e.distroVersion||'', desc:'',
            vulns:e.vulns||[], counts:e.counts||{},
            topSev:e.topSeverity||'NONE', scannedAt:e.scannedAt||e._cachedAt,
          });
          existing.add(e._cacheKey);
        }
        osScans.sort((a,b)=>new Date(b.scannedAt||0)-new Date(a.scannedAt||0));
        saveOs(); updateOsBadge();
      }
    } catch(e) { console.warn('[history] os:', e.message); }
  }
  updateOsBadge();
  const el=document.getElementById('osListContent');
  if(!osScans.length){
    el.innerHTML=`<div class="empty">${_emptyRadar()}
      <h2>No OS scans yet</h2>
      <p>Scan an OS package for known vulnerabilities across Ubuntu, Debian, RHEL, Alpine and SUSE — powered by Grype</p>
      <button class="btn-primary" style="background:#f97316" onclick="openOsModal()">+ Add scan</button>
    </div>`;
    _initEmptyRadar();return;
  }
  el.innerHTML=`
    <div style="display:flex;justify-content:flex-end;margin-bottom:14px">
      <button class="btn-secondary" onclick="openOsModal()">+ Add scan</button>
      <button class="btn-secondary" onclick="if(confirm('Clear all OS scans?')){osScans=[];saveOs();updateOsBadge();renderOsList()}">Clear all</button>
    </div>
    <div class="tbl-wrap"><table class="tbl">
      <thead><tr><th>Package</th><th>Description</th><th>Distribution</th><th>Version</th><th>Top Severity</th><th>Findings</th><th>Scanned</th><th style="width:28px"></th></tr></thead>
      <tbody>${osScans.map((s,i)=>{
        const counts=s.counts||{};
        const pills=['CRITICAL','HIGH','MEDIUM','LOW'].filter(sv=>counts[sv])
          .map(sv=>`<span class="sev ${sv}" style="font-size:9px;padding:2px 6px">${counts[sv]} ${sv}</span>`).join(' ');
        const vulnLen=(s.vulns||[]).length;
        return`<tr class="row" onclick="navTo('os-detail',{scan:osScans[${i}]})">
          <td><div style="display:flex;align-items:center;gap:9px">
            <div style="flex-shrink:0;font-size:20px;line-height:1">${s.distroLogo}</div>
            <div class="row-name">${esc(s.pkg)}</div>
          </div></td>
          <td><div class="row-desc">${esc(s.desc||'—')}</div></td>
          <td><span style="font-size:13px;color:var(--muted2)">${esc(s.distroLabel)}${s.distroVer?' <span style="color:var(--muted)">'+esc(s.distroVer)+'</span>':''}</span></td>
          <td><span class="row-ver">${s.pkgVer?'v'+esc(s.pkgVer):'any'}</span></td>
          <td><span class="sev ${s.topSev}">${s.topSev}</span></td>
          <td>${vulnLen===0?'<span style="color:var(--l);font-size:11px">✓ clean</span>':(pills||`<span style="color:var(--muted)">${vulnLen}</span>`)}</td>
          <td style="color:var(--muted);font-size:10px;white-space:nowrap">${fmtDate(s.scannedAt)}</td>
          <td><button onclick="event.stopPropagation();osScans.splice(${i},1);saveOs();updateOsBadge();renderOsList()"
            style="background:none;border:none;color:var(--muted);cursor:pointer;font-size:13px;padding:3px 5px;border-radius:4px"
            onmouseover="this.style.color='var(--c)'" onmouseout="this.style.color='var(--muted)'">✕</button></td>
        </tr>`;
      }).join('')}
      </tbody>
    </table></div>`;
}

// ── DETAIL ────────────────────────────────────────────────────
function renderOsDetail(scan){
  currentOsScan=scan;
  const el=document.getElementById('osDetailContent');
  const distroInfo=OS_DISTROS.find(d=>d.id===scan.distro)||{logo:'🐧',label:scan.distro};
  const vulns=scan.vulns||[];
  const counts=scan.counts||{};
  const chips=['CRITICAL','HIGH','MEDIUM','LOW'].filter(sv=>counts[sv])
    .map(sv=>`<span class="sev ${sv}">${counts[sv]} ${sv}</span>`).join('');
  const SEV_W={CRITICAL:4,HIGH:3,MEDIUM:2,LOW:1,UNKNOWN:0};

  // Group by package
  const groups=new Map();
  for(const v of vulns){
    const pkg=v.pkgName||scan.pkg;
    if(!groups.has(pkg)) groups.set(pkg,{vulns:[],topW:0,counts:{CRITICAL:0,HIGH:0,MEDIUM:0,LOW:0,UNKNOWN:0}});
    const g=groups.get(pkg);
    g.vulns.push(v);
    const sev=(v.severity||'UNKNOWN').toUpperCase();
    if(sev in g.counts) g.counts[sev]++;
    g.topW=Math.max(g.topW,SEV_W[sev]||0);
  }
  const sorted=[...groups.entries()].sort((a,b)=>{
    if(b[1].topW!==a[1].topW) return b[1].topW-a[1].topW;
    return b[1].vulns.length-a[1].vulns.length;
  });
  for(const [,g] of sorted)
    g.vulns.sort((a,b)=>(SEV_W[b.severity]||0)-(SEV_W[a.severity]||0));

  let gvi=0;
  const groupHtml=sorted.map(([pkgName,g])=>{
    const topSevG=['CRITICAL','HIGH','MEDIUM','LOW'].find(s=>g.counts[s])||'UNKNOWN';
    const pills=['CRITICAL','HIGH','MEDIUM','LOW'].filter(sv=>g.counts[sv])
      .map(sv=>`<span class="sev ${sv}" style="font-size:9px;padding:1px 6px">${g.counts[sv]}</span>`).join('');
    const pkgVerSpan=g.vulns[0]?.pkgVersion?`<span style="color:var(--muted);font-size:11px;margin-left:6px">v${esc(g.vulns[0].pkgVersion)}</span>`:'';
    const fixedVer=g.vulns.find(v=>v.fix)?.fix;
    const fixTag=fixedVer?`<span class="fix-tag" style="font-size:10px">→ ${esc(fixedVer)}</span>`:'';
    const cards=g.vulns.map(v=>osVulnCardHtml(v,gvi++)).join('');
    return`<div class="pkg-group" style="margin-bottom:20px">
      <div class="pkg-group-hdr" onclick="toggleOsPkgGroup(this)" style="display:flex;align-items:center;gap:10px;padding:11px 16px;background:var(--s2);border:1px solid var(--br);border-radius:11px;cursor:pointer;transition:background .13s;user-select:none;margin-bottom:0" onmouseover="this.style.background='var(--s3)'" onmouseout="this.style.background='var(--s2)'">
        <div class="vbar ${topSevG}" style="height:28px"></div>
        <div style="flex:1;min-width:0"><span style="font-size:14px;font-weight:600;color:#fff">${esc(pkgName)}</span>${pkgVerSpan}${fixTag?'<span style="margin-left:8px">'+fixTag+'</span>':''}</div>
        <div style="display:flex;align-items:center;gap:6px">${pills}<span style="font-size:11px;color:var(--muted);margin-left:4px">${g.vulns.length} CVE${g.vulns.length>1?'s':''}</span><span class="pkg-chev" style="color:var(--muted);font-size:10px;transition:transform .18s;margin-left:4px">▼</span></div>
      </div>
      <div class="pkg-group-body" style="display:none;margin-top:2px">${cards}</div>
    </div>`;
  }).join('');

  window._lastOsScan = scan;
  el.innerHTML=`
    <div class="detail-header">
      <div class="detail-icon" style="background:rgba(249,115,22,.1);border:1px solid rgba(249,115,22,.25);font-size:22px;display:flex;align-items:center;justify-content:center;width:56px;height:56px;border-radius:14px;flex-shrink:0">${distroInfo.logo}</div>
      <div class="detail-info">
        <div class="detail-name">${esc(scan.pkg)}${scan.pkgVer?` <span style="color:var(--muted);font-size:15px;font-weight:400">v${esc(scan.pkgVer)}</span>`:''}</div>
        <div class="detail-sub">${esc(distroInfo.label)}${scan.distroVer?' '+esc(scan.distroVer):''}${scan.desc?' · '+esc(scan.desc):''} · ${vulns.length} vulnerabilit${vulns.length===1?'y':'ies'} across ${sorted.length} package${sorted.length!==1?'s':''} · scanned ${fmtDate(scan.scannedAt)}</div>
      </div>
      <div class="detail-chips">${chips||'<span class="sev NONE">✅ CLEAN</span>'}</div>
      <div style="margin-left:auto;flex-shrink:0">${exportBtnHtml('os','__OS_SCAN__')}</div>
    </div>
    ${vulns.length===0?'<div style="text-align:center;padding:60px;color:var(--l);font-size:14px">🛡️ No vulnerabilities found — this package is clean!</div>':groupHtml}`;

  const fb=el.querySelector('.pkg-group-body'),fc=el.querySelector('.pkg-chev');
  if(fb){fb.style.display='block';if(fc)fc.style.transform='rotate(180deg)';}

}

function osVulnCardHtml(v,vi){
  const sev=(v.severity||'UNKNOWN').toUpperCase();
  const cveId=v.id||'';
  const title=v.summary||v.description||'No description';

  // Pre-render enrichment (all data already on v from server)
  const cvss3=v.cvss?.cvss3;
  const cvssInline=cvss3?(()=>{const cls=cvss3.score>=9?'CRITICAL':cvss3.score>=7?'HIGH':cvss3.score>=4?'MEDIUM':'LOW';return`<span class="sev ${cls}" style="font-size:9px;padding:1px 6px">${cvss3.score}</span>`;})():'';
  let eb='';
  if(v.vex) eb+=`<span title="VEX: ${v.vex.label}" style="background:rgba(94,240,200,.15);border:1px solid rgba(94,240,200,.4);color:var(--accent);font-size:9px;font-weight:700;padding:2px 6px;border-radius:4px;margin-right:3px">VEX</span>`;
  if(v.vex) eb+=`<span title="${v.vex.source||'VEX'}: ${v.vex.label}" class="sev ${v.vex.cls}" style="font-size:9px;padding:1px 6px;margin-right:3px">${v.vex.icon||''} ${v.vex.label}</span>`;
  if(v.inKev) eb+=`<span title="CISA KEV" style="background:#ff3b30;color:#fff;font-size:9px;font-weight:700;padding:2px 6px;border-radius:4px;margin-right:3px">🔥 KEV</span>`;
  if((v.pocs||[]).length) eb+=`<span title="${v.pocs.length} PoC(s)" style="background:#ff9500;color:#000;font-size:9px;font-weight:700;padding:2px 6px;border-radius:4px;margin-right:3px">💥 PoC×${v.pocs.length}</span>`;
  const risk=v.risk;
  const riskBadge=risk?`<span class="sev ${risk.label}" style="font-size:9px;padding:1px 7px" title="Risk score">⚡${risk.score}</span>`:'';

  return`<div class="vi" id="osvi-${vi}">
    <div class="vi-hdr" onclick="toggleOsVI(${vi})">
      <div class="vbar ${sev}"></div>
      <div class="vi-id">${esc(cveId)}</div>
      <div class="vi-sum">${esc(title.length>80?title.slice(0,80)+'…':title)}</div>
      <span class="enrich-badges">${eb}${cvssInline}${riskBadge}</span>
      <span class="vi-sev ${sev}">${sev}</span>
      <span class="vi-chev">▼</span>
    </div>
    <div class="vi-body" id="osvib-${vi}" style="display:none">
      <div class="vgrid">
        <span class="vk">CVE ID</span><span class="vv"><a href="https://nvd.nist.gov/vuln/detail/${esc(cveId)}" target="_blank" rel="noopener">${esc(cveId)} ↗</a></span>
        <span class="vk">Package</span><span class="vv" style="color:#fff;font-weight:500">${esc(v.pkgName||'—')}</span>
        <span class="vk">Installed</span><span class="vv" style="color:var(--muted)">${esc(v.pkgVersion||'—')}</span>
        ${v.fix?`<span class="vk">Fixed in</span><span class="vv"><span class="fix-tag">→ ${esc(v.fix)}</span></span>`:''}
        ${v.description?`<span class="vk">Description</span><span class="vv" style="white-space:pre-wrap;line-height:1.55" id="osdesc-${vi}">${esc(v.description.slice(0,480))}${v.description.length>480?`<button data-full="${esc(v.description)}" onclick="expandOsDesc(${vi},this)" style="background:none;border:none;color:var(--accent);cursor:pointer;font-size:11px;padding:0;text-decoration:underline;margin-left:2px">… show more</button>`:''}</span>`:''}
        ${v.published?`<span class="vk">Published</span><span class="vv">${new Date(v.published).toLocaleDateString('en-US',{year:'numeric',month:'short',day:'numeric'})}</span>`:''}
        ${(v.urls||[]).length?`<span class="vk">Reference</span><span class="vv"><a href="${esc(safeUrl(v.urls[0]))}" target="_blank" rel="noopener">${esc(v.urls[0].length>60?v.urls[0].slice(0,60)+'…':v.urls[0])}</a></span>`:''}
        <span class="vk">CVSS</span><span class="vv">${_osCvssHtml(v.cvss)}</span>
        <span class="vk">NVD Score</span><span class="vv">${_osNvdScoreHtml(v.cvss)}</span>
        <span class="vk">EPSS</span><span class="vv">${_osEpssHtml(v.epss)}</span>
        <span class="vk">Risk Score</span><span class="vv">${_osRiskHtml(v.risk)}</span>
        <span class="vk">CISA KEV</span><span class="vv">${kevBadge(v.inKev)}</span>
        <span class="vk">PoC (GitHub)</span><span class="vv">${pocBadge(v.pocs||[])}</span>
        ${v.vex?`
        <span class="vk">VEX Status</span>
        <span class="vv">
          <span class="sev ${v.vex.cls}" style="font-size:11px">${v.vex.icon} ${v.vex.label}</span>
          <span style="color:var(--muted);font-size:10px;margin-left:8px">via ${v.vex.source||'Grype'}</span>
        </span>`:''}
        ${v.vex?`<span class="vk">VEX Status</span><span class="vv">${_osVexHtml(v.vex)}</span>`:''}
      </div>
    </div>
  </div>`;
}

// ── Render helpers ────────────────────────────────────────────
function _osCvssHtml(cvss){
  if(!cvss||(!cvss.cvss3&&!cvss.cvss2)) return '<span style="color:var(--muted);font-size:11px">not in NVD</span>';
  let out='';
  if(cvss.cvss3){const s=cvss.cvss3.score,cls=s>=9?'CRITICAL':s>=7?'HIGH':s>=4?'MEDIUM':'LOW';out+=`<span class="sev ${cls}" style="font-size:10px;padding:2px 7px;margin-right:5px">${s} ${cvss.cvss3.severity||cls}</span><span style="color:var(--muted);font-size:10px;margin-right:10px">CVSSv${cvss.cvss3.version||3}</span>`;}
  if(cvss.cvss2){const s=cvss.cvss2.score,cls=s>=7?'HIGH':s>=4?'MEDIUM':'LOW';out+=`<span class="sev ${cls}" style="font-size:10px;padding:2px 7px;margin-right:5px;opacity:.7">${s}</span><span style="color:var(--muted);font-size:10px">CVSSv2</span>`;}
  return out;
}
function _osNvdScoreHtml(cvss){
  if(!cvss?.cvss3) return '<span style="color:var(--muted);font-size:11px">not in NVD</span>';
  const s=cvss.cvss3.score,cls=s>=9?'CRITICAL':s>=7?'HIGH':s>=4?'MEDIUM':'LOW';
  return`<span class="sev ${cls}">${s}</span><span style="color:var(--muted);font-size:11px;margin-left:6px">${cvss.cvss3.vector||''}</span>`;
}
function _osEpssHtml(epss){
  if(!epss) return '<span style="color:var(--muted);font-size:11px">not found</span>';
  const pct=(epss.epss*100).toFixed(2),cls=epss.epss>=.1?'hi':epss.epss>=.01?'mi':'';
  return`<div class="epss-row"><span class="epss-pct ${cls}">${pct}%</span><div class="epss-bar"><div class="epss-fill ${cls}" style="width:${Math.min(epss.epss*500,100)}%"></div></div><span style="font-size:10px;color:var(--muted)">${(epss.percentile*100).toFixed(0)}th pct</span></div>`;
}
function _osRiskHtml(risk){
  if(!risk) return '<span style="color:var(--muted);font-size:11px">—</span>';
  const bgCol=risk.label==='CRITICAL'?'var(--c)':risk.label==='HIGH'?'var(--h)':risk.label==='MEDIUM'?'var(--m)':'var(--l)';
  return`<div class="epss-row"><span class="sev ${risk.label}" style="font-size:10px;padding:2px 8px">${risk.score}/100</span><div class="epss-bar"><div class="epss-fill" style="width:${risk.score}%;background:${bgCol}"></div></div><span style="font-size:10px;color:var(--muted)">60% CVSS · 40% EPSS</span></div>`;
}

// ── Toggle ────────────────────────────────────────────────────
function toggleOsPkgGroup(hdr){
  const body=hdr.nextElementSibling,chev=hdr.querySelector('.pkg-chev');
  if(!body)return;
  const open=body.style.display!=='none';
  body.style.display=open?'none':'block';
  if(chev)chev.style.transform=open?'':'rotate(180deg)';
}
function toggleOsVI(vi){
  const el=document.getElementById('osvi-'+vi),body=document.getElementById('osvib-'+vi);
  if(!el||!body)return;
  const open=el.classList.contains('open');
  el.classList.toggle('open',!open);
  body.style.display=open?'none':'block';
}
function expandOsDesc(vi,btn){
  const el=document.getElementById('osdesc-'+vi);
  if(el) el.textContent=btn.getAttribute('data-full');
}

function _osVexHtml(vex){
  if(!vex) return '<span style="color:var(--muted);font-size:11px">—</span>';
  const cols={LOW:'var(--l)',HIGH:'var(--h)',MEDIUM:'var(--m)',UNKNOWN:'var(--u)',CRITICAL:'var(--c)'};
  const col=cols[vex.cls]||'var(--muted)';
  return`<span style="display:inline-flex;align-items:center;gap:5px;font-size:11px;font-weight:600;padding:3px 10px;border-radius:6px;border:1px solid ${col};color:${col};background:${col.replace(')',', .1)').replace('var(--','rgba(').replace(')',',1)')}">🔖 ${vex.label}</span>`;
}

document.addEventListener('keydown',e=>{
  const m=document.getElementById('osModal');
  if(m?.style.display!=='none'){
    if(e.key==='Escape') closeOsModal();
    if(e.key==='Enter')  doOsScan();
  }
});
