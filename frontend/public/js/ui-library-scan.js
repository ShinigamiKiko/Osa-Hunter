// lib-scan.js — Library Scan
// Scan → /api/libscan → получаем полностью обогащённые данные (EPSS, CVSS, KEV, PoC, Toxic)
const ECOS=[
  {id:'npm',      label:'npm',   logo:'📦',osv:'npm'},
  {id:'pypi',     label:'PyPI',  logo:'🐍',osv:'PyPI'},
  {id:'go',       label:'Go',    logo:'🐹',osv:'Go'},
  {id:'crates',   label:'Rust',  logo:'🦀',osv:'crates.io'},
  {id:'maven',    label:'Maven', logo:'☕',osv:'Maven'},
  {id:'rubygems', label:'Ruby',  logo:'💎',osv:'RubyGems'},
  {id:'nuget',    label:'NuGet', logo:'🔷',osv:'NuGet'},
  {id:'packagist',label:'PHP',   logo:'🐘',osv:'Packagist'},
];

let libScans=safeLoad('es_lib',[]);
let selEco=null;
const saveLib=()=>safeSave('es_lib',libScans);

function renderEcos(){
  document.getElementById('ecoGrid').innerHTML=ECOS.map(e=>`
    <button class="eco-btn${selEco===e.id?' on':''}" onclick="pickEco('${e.id}')">
      <div class="eco-logo">${e.logo}</div><div class="eco-name">${e.label}</div>
    </button>`).join('');
}
function pickEco(id){selEco=id;renderEcos();}

function openLibModal(){
  selEco=null;['fDesc','fPkg','fVer'].forEach(id=>document.getElementById(id).value='');
  document.getElementById('lmerr').style.display='none';
  setBtn('btnLibGo',false,'▶ Scan');renderEcos();
  document.getElementById('libModal').style.display='flex';
  setTimeout(()=>document.getElementById('fPkg').focus(),160);
}
function closeLibModal(){document.getElementById('libModal').style.display='none';}

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
    const r=await fetch('/api/libscan',{method:'POST',headers:{'Content-Type':'application/json'},
      body:JSON.stringify({name:pkg,ecosystem:eco.osv,version:ver||undefined})});
    if(!r.ok) throw new Error(`Server error ${r.status}`);
    const data=await r.json();
    if(data.error) throw new Error(data.error);
    // /api/libscan возвращает vulns с severity, fix, aliases, refs, epss, cvss, inKev, pocs
    // Маппим в _sev/_fix/_aliases/_refs для совместимости с render кодом
    const vulns=(data.vulns||[]).map(v=>({...v,_sev:v.severity,_fix:v.fix,_aliases:v.aliases||[],_refs:v.refs||[]}));
    libScans.unshift({
      id:Date.now(),pkg:data.package,ver:data.version||'',
      eco:eco.id,ecoLabel:eco.label,ecoLogo:eco.logo,
      desc,vulns,toxic:data.toxic,topSev:data.topSeverity||'NONE',scannedAt:data.scannedAt,
    });
    saveLib();closeLibModal();updateLibBadge();navTo('lib-list');
  }catch(e){showErr('lmerr',e.message||'Request failed');}
  setBtn('btnLibGo',false,'▶ Scan');
}

function updateLibBadge(){
  const b=document.getElementById('libBadge');
  if(libScans.length){b.style.display='';b.textContent=libScans.length;}
  else b.style.display='none';
}

function renderLibList(){
  updateLibBadge();
  const el=document.getElementById('libListContent');
  if(!libScans.length){
    el.innerHTML=`<div class="empty">${_emptyRadar()}<h2>No scans yet</h2><p>Add a library to check for known vulnerabilities via OSV database with EPSS enrichment</p><button class="btn-primary" onclick="openLibModal()">+ Add library</button></div>`;
    _initEmptyRadar();return;
  }
  el.innerHTML=`
    <div style="display:flex;justify-content:flex-end;margin-bottom:14px">
      <button class="btn-secondary" onclick="if(confirm('Clear all?')){libScans=[];saveLib();updateLibBadge();renderLibList()}">Clear all</button>
    </div>
    <div class="tbl-wrap"><table class="tbl">
      <thead><tr><th>Package</th><th>Description</th><th>Version</th><th>Top Severity</th><th>Findings</th><th>Scanned</th><th style="width:28px"></th></tr></thead>
      <tbody>${libScans.map((s,i)=>{
        const cnt={};s.vulns.forEach(v=>{const sv=v._sev||v.severity||'UNKNOWN';cnt[sv]=(cnt[sv]||0)+1;});
        const pills=['CRITICAL','HIGH','MEDIUM','LOW'].filter(sv=>cnt[sv])
          .map(sv=>`<span class="sev ${sv}" style="font-size:9px;padding:2px 6px">${cnt[sv]} ${sv}</span>`).join(' ');
        const isToxic=s.toxic?.found;
        return`<tr class="row" onclick="navTo('lib-detail',{scan:libScans[${i}]})">
          <td>
            <div class="row-name" style="font-size:17px">${esc(s.pkg)}</div>
            <div style="display:flex;align-items:center;gap:5px;margin-top:2px">
              <div class="row-eco">${s.ecoLogo} ${s.ecoLabel}</div>
              ${isToxic?`<span style="background:rgba(255,59,48,.15);border:1px solid rgba(255,59,48,.4);color:#ff3b30;font-size:9px;font-weight:700;padding:1px 5px;border-radius:3px">☠ TOXIC</span>`:''}
            </div>
          </td>
          <td><div class="row-desc">${esc(s.desc||'—')}</div></td>
          <td><span class="row-ver">${s.ver?'v'+esc(s.ver):'any'}</span></td>
          <td><span class="sev ${s.topSev}">${s.topSev}</span></td>
          <td>${s.vulns.length===0?'<span style="color:var(--l);font-size:11px">✓ clean</span>':(pills||`<span style="color:var(--muted)">${s.vulns.length}</span>`)}</td>
          <td style="color:var(--muted);font-size:10px;white-space:nowrap">${fmtDate(s.scannedAt)}</td>
          <td><button onclick="event.stopPropagation();libScans.splice(${i},1);saveLib();updateLibBadge();renderLibList()"
            style="background:none;border:none;color:var(--muted);cursor:pointer;font-size:13px;padding:3px 5px;border-radius:4px"
            onmouseover="this.style.color='var(--c)'" onmouseout="this.style.color='var(--muted)'">✕</button></td>
        </tr>`;
      }).join('')}</tbody>
    </table></div>`;
}

function renderLibDetail(s){
  const cnt={};s.vulns.forEach(v=>{const sv=v._sev||v.severity||'UNKNOWN';cnt[sv]=(cnt[sv]||0)+1;});
  const el=document.getElementById('libDetailContent');
  el.innerHTML=`
    <div class="detail-header">
      <div class="detail-icon green" style="font-size:22px">${s.ecoLogo}</div>
      <div class="detail-info">
        <div class="detail-name" style="font-size:27px">${esc(s.pkg)}${s.ver?` <span style="color:var(--muted);font-size:20px;font-weight:400">v${esc(s.ver)}</span>`:''}</div>
        <div class="detail-sub">${esc(s.ecoLabel)} · ${esc(s.desc||'No description')} · scanned ${fmtDate(s.scannedAt)}</div>
        <div style="display:flex;flex-wrap:wrap;align-items:center;gap:6px;margin-top:6px">
          ${_toxicBadgeHtml(s.toxic)}
          <div id="activityBadge"><span style="font-size:11px;color:var(--muted)">⏳ Checking activity…</span></div>
        </div>
      </div>
      <div class="detail-chips" style="display:flex;flex-direction:column;align-items:flex-end;gap:8px">
        <div style="display:flex;flex-wrap:wrap;gap:6px;justify-content:flex-end">
          ${s.vulns.length===0?'<span class="sev NONE">✅ CLEAN</span>':['CRITICAL','HIGH','MEDIUM','LOW'].filter(sv=>cnt[sv]).map(sv=>`<span class="sev ${sv}">${cnt[sv]} ${sv}</span>`).join('')}
        </div>
        ${exportBtnHtml('lib',{name:s.pkg,ecosystem:s.eco,version:s.ver||'',desc:s.desc||'',ecoLabel:s.ecoLabel||'',ecoLogo:s.ecoLogo||''})}
      </div>
    </div>
    ${s.vulns.length===0
      ?'<div style="text-align:center;padding:60px;color:var(--l);font-size:14px">🛡️ No vulnerabilities found — this package version is clean!</div>'
      :`<div id="vulnCards">${s.vulns.map((v,vi)=>vulnCardHtml(s,v,vi)).join('')}</div>`}`;
  if(s.vulns.length) renderStoredEnrichment(s.vulns,'lib');
  checkActivity('activityBadge',s.pkg,s.ecoLabel);
}

function vulnCardHtml(s,v,vi){
  const cveId=[...(v._aliases||v.aliases||[]),(v.cve||v.id)].find(x=>x?.startsWith('CVE-'))||v.id;
  const sev=v._sev||v.severity||'UNKNOWN';
  return`<div class="vi" id="vi-${vi}">
    <div class="vi-hdr" onclick="toggleVI(${vi})">
      <div class="vbar ${sev}"></div>
      <div class="vi-id">
        ${cveId.startsWith('CVE-')?`<a href="https://nvd.nist.gov/vuln/detail/${esc(cveId)}" target="_blank" onclick="event.stopPropagation()" style="color:var(--accent);font-weight:700;font-size:14px;text-decoration:none">${esc(cveId)} ↗</a><span style="color:var(--muted);font-size:12px;margin:0 5px">/</span>`:''}
        <span style="opacity:.7;font-size:14px">${esc(v.id)}</span>
        <span class="vi-cvss-inline" id="cvss-hdr-lib-${cveId}"></span>
      </div>
      <div class="vi-sum">${esc(v.summary||'No summary')}</div>
      <span class="enrich-badges" id="eb-lib-${cveId}"></span>
      <span class="vi-sev ${sev}">${sev}</span>
      <span class="vi-chev">▼</span>
    </div>
    <div class="vi-body" id="vib-${vi}">
      <div class="vgrid">
        <span class="vk">OSV ID</span><span class="vv"><a href="https://osv.dev/vulnerability/${esc(v.id)}" target="_blank">${esc(v.id)} ↗</a></span>
        <span class="vk">CVSS</span><span class="vv" id="cvss-lib-${cveId}"></span>
        <span class="vk">NVD Score</span><span class="vv" id="nvd-lib-${cveId}"><span style="color:var(--muted);font-size:11px">loading…</span></span>
        <span class="vk">EPSS</span><span class="vv" id="epss-lib-${cveId}"></span>
        ${v.details?`<span class="vk">Details</span><span class="vv" style="white-space:pre-wrap" id="det-${vi}">${esc(v.details.slice(0,480))}${v.details.length>480?`<span id="det-dots-${vi}"> <button data-full="${esc(v.details)}" onclick="expandDet(${vi},this)" style="background:none;border:none;color:var(--accent);cursor:pointer;font-size:11px;padding:0;text-decoration:underline">… show more</button></span>`:''}</span>`:''}
        ${(v._fix||v.fix)?`<span class="vk">Fixed in</span><span class="vv"><span class="fix-tag">→ ${esc(v._fix||v.fix)}</span></span>`:''}
        ${v.published?`<span class="vk">Published</span><span class="vv">${new Date(v.published).toLocaleDateString('en-US',{year:'numeric',month:'short',day:'numeric'})}</span>`:''}
        ${(v._refs||v.refs||[]).length?`<span class="vk">References</span><span class="vv" style="line-height:2">${(v._refs||v.refs).slice(0,4).map(u=>`<a href="${esc(safeUrl(u))}" target="_blank" rel="noopener noreferrer">${esc(u.length>60?u.slice(0,60)+'…':u)}</a>`).filter(Boolean).join('<br/>')}</span>`:''}
        <span class="vk">CISA KEV</span><span class="vv" id="kev-lib-${cveId}"></span>
        <span class="vk">PoC (GitHub)</span><span class="vv" id="poc-lib-${cveId}"></span>
      </div>
    </div>
  </div>`;
}

function expandDet(vi,btn){
  const el=document.getElementById('det-'+vi);
  const dots=document.getElementById('det-dots-'+vi);
  if(!el||!dots)return;
  dots.remove();el.textContent=btn.getAttribute('data-full');
}
function toggleVI(vi){
  const el=document.getElementById('vi-'+vi);
  const body=document.getElementById('vib-'+vi);
  if(!el||!body)return;
  const open=el.classList.contains('open');
  el.classList.toggle('open',!open);
  body.style.display=open?'none':'block';
}

document.addEventListener('keydown',e=>{
  if(e.key==='Escape'&&document.getElementById('libModal').style.display!=='none') closeLibModal();
  if(e.key==='Enter' &&document.getElementById('libModal').style.display!=='none') doLibScan();
});
