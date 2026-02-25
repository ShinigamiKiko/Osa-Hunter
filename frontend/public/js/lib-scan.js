// ── LIB SCAN CONFIG ──────────────────────────────────────────
const ECOS = [
  {id:'npm',       label:'npm',   logo:'📦', osv:'npm'},
  {id:'pypi',      label:'PyPI',  logo:'🐍', osv:'PyPI'},
  {id:'go',        label:'Go',    logo:'🐹', osv:'Go'},
  {id:'crates',    label:'Rust',  logo:'🦀', osv:'crates.io'},
  {id:'maven',     label:'Maven', logo:'☕', osv:'Maven'},
  {id:'rubygems',  label:'Ruby',  logo:'💎', osv:'RubyGems'},
  {id:'nuget',     label:'NuGet', logo:'🔷', osv:'NuGet'},
  {id:'packagist', label:'PHP',   logo:'🐘', osv:'Packagist'},
];

let libScans = safeLoad('es_lib', []);
let selEco = null;
const saveLib = () => safeSave('es_lib', libScans);

// ── SEVERITY UTILS ───────────────────────────────────────────
function parseSev(v){
  for(const s of v.severity||[]){ const sc=parseFloat(s.score);
    if(!isNaN(sc)){ if(sc>=9)return'CRITICAL'; if(sc>=7)return'HIGH'; if(sc>=4)return'MEDIUM'; return'LOW'; }}
  const db=((v.database_specific||{}).severity||'').toUpperCase();
  if(['CRITICAL','HIGH','MEDIUM','LOW'].includes(db)) return db;
  return'UNKNOWN';
}
function topSev(vs){ if(!vs?.length)return'NONE'; for(const s of SEV_ORD)if(vs.some(v=>v._sev===s))return s; return'NONE'; }
function getFixed(v){ for(const a of v.affected||[])for(const r of a.ranges||[])for(const e of r.events||[])if(e.fixed)return e.fixed; return null; }
function extractCVEs(vulns){ const s=new Set(); for(const v of vulns){for(const a of v._aliases||[])if(a.startsWith('CVE-'))s.add(a); if(v.id.startsWith('CVE-'))s.add(v.id);} return[...s]; }

// ── MODAL ────────────────────────────────────────────────────
function renderEcos(){
  document.getElementById('ecoGrid').innerHTML=ECOS.map(e=>`
    <button class="eco-btn${selEco===e.id?' on':''}" onclick="pickEco('${e.id}')">
      <div class="eco-logo">${e.logo}</div><div class="eco-name">${e.label}</div>
    </button>`).join('');
}
function pickEco(id){ selEco=id; renderEcos(); }

function openLibModal(){
  selEco=null; ['fDesc','fPkg','fVer'].forEach(id=>document.getElementById(id).value='');
  document.getElementById('lmerr').style.display='none';
  setBtn('btnLibGo',false,'▶ Scan'); renderEcos();
  document.getElementById('libModal').style.display='flex';
  setTimeout(()=>document.getElementById('fPkg').focus(),160);
}
function closeLibModal(){ document.getElementById('libModal').style.display='none'; }

// ── SCAN ─────────────────────────────────────────────────────
async function doLibScan(){
  const eco=ECOS.find(e=>e.id===selEco);
  const pkg=document.getElementById('fPkg').value.trim();
  const ver=document.getElementById('fVer').value.trim();
  const desc=document.getElementById('fDesc').value.trim();
  document.getElementById('lmerr').style.display='none';
  if(!eco) return showErr('lmerr','Select an ecosystem');
  if(!pkg) return showErr('lmerr','Enter a package name');
  setBtn('btnLibGo',true);
  try{
    const body={package:{name:pkg,ecosystem:eco.osv}}; if(ver) body.version=ver;
    const r=await fetch('/api/osv/query',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});
    if(!r.ok) throw new Error(`OSV error ${r.status}`);
    const data=await r.json(); if(data.error) throw new Error(data.error);
    const vulns=(data.vulns||[]).map(v=>({...v,_sev:parseSev(v),_fix:getFixed(v),
      _aliases:v.aliases||[],_refs:(v.references||[]).map(r=>r.url)}))
      .sort((a,b)=>SEV_ORD.indexOf(a._sev)-SEV_ORD.indexOf(b._sev));
    const epssMap=await fetchEPSS(extractCVEs(vulns));
    libScans.unshift({id:Date.now(),pkg,ver,eco:eco.id,ecoLabel:eco.label,ecoLogo:eco.logo,
      desc,vulns,epssMap,topSev:topSev(vulns),scannedAt:new Date().toISOString()});
    saveLib(); closeLibModal(); updateLibBadge(); navTo('lib-list');
  }catch(e){ showErr('lmerr',e.message||'Request failed'); }
  setBtn('btnLibGo',false,'▶ Scan');
}

// ── BADGE ────────────────────────────────────────────────────
function updateLibBadge(){
  const b=document.getElementById('libBadge');
  if(libScans.length){ b.style.display=''; b.textContent=libScans.length; }
  else b.style.display='none';
}

// ── LIST PAGE ─────────────────────────────────────────────────
function renderLibList(){
  updateLibBadge();
  const el=document.getElementById('libListContent');
  if(!libScans.length){
    el.innerHTML=`<div class="empty">
      ${_emptyRadar()}
      <h2>No scans yet</h2>
      <p>Add a library to check for known vulnerabilities via OSV database with EPSS enrichment</p>
      <button class="btn-primary" onclick="openLibModal()">+ Add library</button>
    </div>`;
    _initEmptyRadar();
    return;
  }
  el.innerHTML=`
    <div style="display:flex;justify-content:flex-end;margin-bottom:14px">
      <button class="btn-secondary" onclick="if(confirm('Clear all?')){libScans=[];saveLib();updateLibBadge();renderLibList()}">Clear all</button>
    </div>
    <div class="tbl-wrap">
      <table class="tbl">
        <thead><tr>
          <th>Package</th><th>Description</th><th>Version</th>
          <th>Top Severity</th><th>Findings</th><th>Scanned</th><th style="width:28px"></th>
        </tr></thead>
        <tbody>
          ${libScans.map((s,i)=>{
            const cnt={}; s.vulns.forEach(v=>{cnt[v._sev]=(cnt[v._sev]||0)+1;});
            const pills=['CRITICAL','HIGH','MEDIUM','LOW'].filter(sv=>cnt[sv])
              .map(sv=>`<span class="sev ${sv}" style="font-size:9px;padding:2px 6px">${cnt[sv]} ${sv}</span>`).join(' ');
            return`<tr class="row" onclick="navTo('lib-detail',{scan:libScans[${i}]})">
              <td><div class="row-name">${esc(s.pkg)}</div><div class="row-eco">${s.ecoLogo} ${s.ecoLabel}</div></td>
              <td><div class="row-desc">${esc(s.desc||'—')}</div></td>
              <td><span class="row-ver">${s.ver?'v'+esc(s.ver):'any'}</span></td>
              <td><span class="sev ${s.topSev}">${s.topSev}</span></td>
              <td>${s.vulns.length===0?'<span style="color:var(--l);font-size:11px">✓ clean</span>':(pills||`<span style="color:var(--muted)">${s.vulns.length}</span>`)}</td>
              <td style="color:var(--muted);font-size:10px;white-space:nowrap">${fmtDate(s.scannedAt)}</td>
              <td><button onclick="event.stopPropagation();libScans.splice(${i},1);saveLib();updateLibBadge();renderLibList()"
                style="background:none;border:none;color:var(--muted);cursor:pointer;font-size:13px;padding:3px 5px;border-radius:4px"
                onmouseover="this.style.color='var(--c)'" onmouseout="this.style.color='var(--muted)'">✕</button></td>
            </tr>`;
          }).join('')}
        </tbody>
      </table>
    </div>`;
}

// ── DETAIL PAGE ───────────────────────────────────────────────
function renderLibDetail(s){
  const cnt={}; s.vulns.forEach(v=>{cnt[v._sev]=(cnt[v._sev]||0)+1;});
  const el=document.getElementById('libDetailContent');
  el.innerHTML=`
    <div class="detail-header">
      <div class="detail-icon green" style="font-size:22px">${s.ecoLogo}</div>
      <div class="detail-info">
        <div class="detail-name">${esc(s.pkg)}${s.ver?' <span style="color:var(--muted);font-size:14px;font-weight:400">v'+esc(s.ver)+'</span>':''}</div>
        <div class="detail-sub">${esc(s.ecoLabel)} · ${esc(s.desc||'No description')} · scanned ${fmtDate(s.scannedAt)}</div>
        <div style="display:flex;flex-wrap:wrap;align-items:center;gap:6px;margin-top:6px">
          <div id="toxicBadge"><span style="font-size:11px;color:var(--muted)">⏳ Checking toxic-repos…</span></div>
          <div id="activityBadge"><span style="font-size:11px;color:var(--muted)">⏳ Checking activity…</span></div>
        </div>
      </div>
      <div class="detail-chips">
        ${s.vulns.length===0
          ?'<span class="sev NONE">✅ CLEAN</span>'
          :['CRITICAL','HIGH','MEDIUM','LOW'].filter(sv=>cnt[sv]).map(sv=>`<span class="sev ${sv}">${cnt[sv]} ${sv}</span>`).join('')}
      </div>
    </div>
    ${s.vulns.length===0
      ?'<div style="text-align:center;padding:60px;color:var(--l);font-size:14px">🛡️ No vulnerabilities found — this package version is clean!</div>'
      :`<div id="vulnCards">${s.vulns.map((v,vi)=>vulnCardHtml(s,v,vi)).join('')}</div>`}`;
  if(s.vulns.length) enrichVulns('lib', s.vulns.map(v=>[...(v._aliases||[]),v.id]).flat().filter(x=>x.startsWith('CVE-')));
  checkToxic(s.pkg);
  checkActivity('activityBadge', s.pkg, s.ecoLabel);
}

function vulnCardHtml(s,v,vi){
  const cveId=[...(v._aliases||[]),v.id].find(x=>x.startsWith('CVE-'))||v.id;
  return`<div class="vi" id="vi-${vi}">
    <div class="vi-hdr" onclick="toggleVI(${vi})">
      <div class="vbar ${v._sev}"></div>
      <div class="vi-id">
        ${(()=>{const cve=(v._aliases||[]).find(a=>a.startsWith('CVE-'));return cve?`<a href="https://nvd.nist.gov/vuln/detail/${esc(cve)}" target="_blank" onclick="event.stopPropagation()" style="color:var(--accent);font-weight:700;font-size:11px;text-decoration:none" title="Open in NVD">${esc(cve)} ↗</a><span style="color:var(--muted);font-size:10px;margin:0 5px">/</span>`:''})()}
        <span style="opacity:.7">${esc(v.id)}</span>
        <span class="vi-cvss-inline" id="cvss-hdr-lib-${cveId}"></span>
      </div>
      <div class="vi-sum">${esc(v.summary||'No summary')}</div>
      <span class="enrich-badges" id="eb-lib-${cveId}"></span>
      <span class="vi-sev ${v._sev}">${v._sev}</span>
      <span class="vi-chev">▼</span>
    </div>
    <div class="vi-body" id="vib-${vi}">
      <div class="vgrid">
        <span class="vk">OSV ID</span><span class="vv"><a href="https://osv.dev/vulnerability/${esc(v.id)}" target="_blank">${esc(v.id)} ↗</a></span>
        <span class="vk">CVSS</span><span class="vv" id="cvss-lib-${cveId}"><span style="color:var(--muted);font-size:11px">loading…</span></span>
        <span class="vk">EPSS</span><span class="vv" id="epss-lib-${cveId}"><span style="color:var(--muted);font-size:11px">loading…</span></span>
        ${v.details?`<span class="vk">Details</span><span class="vv" style="white-space:pre-wrap" id="det-${vi}">${esc(v.details.slice(0,480))}${v.details.length>480?`<span id="det-dots-${vi}"> <button data-full="${esc(v.details)}" onclick="expandDet(${vi},this)" style="background:none;border:none;color:var(--accent);cursor:pointer;font-size:11px;padding:0;text-decoration:underline">… show more</button></span>`:''}</span>`:''}
        ${v._fix?`<span class="vk">Fixed in</span><span class="vv"><span class="fix-tag">→ ${esc(v._fix)}</span></span>`:''}
        ${v.published?`<span class="vk">Published</span><span class="vv">${new Date(v.published).toLocaleDateString('en-US',{year:'numeric',month:'short',day:'numeric'})}</span>`:''}
        ${(v._refs||[]).length?`<span class="vk">References</span><span class="vv" style="line-height:2">${v._refs.slice(0,4).map(u=>{const su=safeUrl(u);return su==='#'?'':`<a href="${esc(su)}" target="_blank" rel="noopener noreferrer">${esc(u.length>60?u.slice(0,60)+'…':u)}</a>`;}).filter(Boolean).join('<br/>')}</span>`:''}
        <span class="vk">CISA KEV</span><span class="vv" id="kev-lib-${cveId}"><span style="color:var(--muted);font-size:11px">loading…</span></span>
        <span class="vk">PoC (GitHub)</span><span class="vv" id="poc-lib-${cveId}"><span style="color:var(--muted);font-size:11px">loading…</span></span>
      </div>
    </div>
  </div>`;
}

function expandDet(vi,btn){
  const el=document.getElementById('det-'+vi);
  const dots=document.getElementById('det-dots-'+vi);
  if(!el||!dots) return;
  dots.remove(); el.textContent=btn.getAttribute('data-full');
}

function toggleVI(vi){
  const el=document.getElementById('vi-'+vi);
  const body=document.getElementById('vib-'+vi);
  if(!el||!body) return;
  const open=el.classList.contains('open');
  el.classList.toggle('open',!open);
  body.style.display=open?'none':'block';
}

// keyboard shortcuts for lib modal
document.addEventListener('keydown',e=>{
  if(e.key==='Escape'&&document.getElementById('libModal').style.display!=='none') closeLibModal();
  if(e.key==='Enter' &&document.getElementById('libModal').style.display!=='none') doLibScan();
});
