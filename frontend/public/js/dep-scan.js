// ── DEP SCAN CONFIG ───────────────────────────────────────────
const DEP_SYSTEMS = [
  { id:'NPM',   label:'npm',   logo:'📦', hint:'express, lodash…' },
  { id:'PYPI',  label:'PyPI',  logo:'🐍', hint:'django, requests…' },
  { id:'GO',    label:'Go',    logo:'🐹', hint:'github.com/gin-gonic/gin' },
  { id:'CARGO', label:'Rust',  logo:'🦀', hint:'tokio, serde…' },
  { id:'MAVEN', label:'Maven', logo:'☕', hint:'com.google.guava:guava' },
  { id:'NUGET', label:'NuGet', logo:'🔷', hint:'Newtonsoft.Json…' },
];

let depScans  = safeLoad('es_dep', []);
let selDepSys = null;
let currentDepScan = null;

const saveDep = () => safeSave('es_dep', depScans);

// ── MODAL ─────────────────────────────────────────────────────
function renderDepEcos(){
  document.getElementById('depEcoGrid').innerHTML=DEP_SYSTEMS.map(e=>`
    <button class="eco-btn${selDepSys===e.id?' on':''}" onclick="pickDepSys('${e.id}')">
      <div class="eco-logo">${e.logo}</div><div class="eco-name">${e.label}</div>
    </button>`).join('');
}
function pickDepSys(id){ selDepSys=id; renderDepEcos(); }

function openDepModal(){
  selDepSys=null; ['dDesc','dPkg','dVer'].forEach(id=>document.getElementById(id).value='');
  document.getElementById('dmerr').style.display='none';
  setBtn('btnDepGo',false,'▶ Scan'); renderDepEcos();
  document.getElementById('depModal').style.display='flex';
  setTimeout(()=>document.getElementById('dPkg').focus(),160);
}
function closeDepModal(){ document.getElementById('depModal').style.display='none'; }

// ── SCAN ─────────────────────────────────────────────────────
async function doDepScan(){
  const sys  = selDepSys;
  const pkg  = document.getElementById('dPkg').value.trim();
  const ver  = document.getElementById('dVer').value.trim();
  const desc = document.getElementById('dDesc').value.trim();
  document.getElementById('dmerr').style.display='none';
  if(!sys) return showErr('dmerr','Select a package system');
  if(!pkg) return showErr('dmerr','Enter a package name');
  setBtn('btnDepGo',true,'Scanning…');
  try{
    const r=await fetch('/api/depscan',{method:'POST',headers:{'Content-Type':'application/json'},
      body:JSON.stringify({name:pkg,system:sys,version:ver||undefined})});
    const data=await r.json();
    if(!r.ok) throw new Error(data.error||`Error ${r.status}`);
    const scan={...data,desc,id:Date.now()};
    depScans.unshift(scan);
    if(depScans.length>20) depScans=depScans.slice(0,20);
    saveDep(); closeDepModal(); updateDepBadge();
    navTo('dep-detail',{scan});
  }catch(e){ showErr('dmerr',e.message||'Scan failed'); }
  setBtn('btnDepGo',false,'▶ Scan');
}

// ── BADGE ─────────────────────────────────────────────────────
function updateDepBadge(){
  const b=document.getElementById('depBadge');
  if(depScans.length){ b.style.display=''; b.textContent=depScans.length; }
  else b.style.display='none';
}

// ── LIST PAGE ─────────────────────────────────────────────────
function renderDepList(){
  updateDepBadge();
  const el=document.getElementById('depListContent');
  if(!depScans.length){
    el.innerHTML=`<div class="empty">
      ${_emptyRadar()}
      <h2>No dependency scans yet</h2>
      <p>Scan a package to map its full dependency tree and check every dep for vulnerabilities, toxic repos and EPSS scores</p>
      <button class="btn-primary" style="background:#a78bfa" onclick="openDepModal()">+ Add scan</button>
    </div>`;
    _initEmptyRadar();
    return;
  }
  el.innerHTML=`
    <div style="display:flex;justify-content:flex-end;margin-bottom:14px">
      <button class="btn-secondary" onclick="if(confirm('Clear all dep scans?')){depScans=[];saveDep();updateDepBadge();renderDepList()}">Clear all</button>
    </div>
    <div class="tbl-wrap">
      <table class="tbl">
        <thead><tr>
          <th>Package</th><th>Description</th><th>System</th>
          <th>Version</th><th>Deps</th><th>Vulns</th><th>Toxic</th><th>Scanned</th><th style="width:28px"></th>
        </tr></thead>
        <tbody>
          ${depScans.map((s,i)=>{
            const sysInfo=DEP_SYSTEMS.find(x=>x.id===s.system)||{logo:'📦',label:s.system};
            const pills=['CRITICAL','HIGH','MEDIUM','LOW'].filter(sv=>s.summary[sv])
              .map(sv=>`<span class="sev ${sv}" style="font-size:9px;padding:2px 6px">${s.summary[sv]} ${sv}</span>`).join(' ');
            return`<tr class="row" onclick="currentDepScan=depScans[${i}];navTo('dep-detail',{scan:depScans[${i}]})">
              <td><div style="display:flex;align-items:center;gap:8px">
                <span style="font-size:18px">${sysInfo.logo}</span>
                <div><div class="row-name">${esc(s.package)}</div></div>
              </div></td>
              <td><div class="row-desc">${esc(s.desc||'—')}</div></td>
              <td><span style="font-size:10px;color:var(--muted2)">${sysInfo.label}</span></td>
              <td><span class="row-ver">${esc(s.resolvedVersion||'—')}</span></td>
              <td><span style="font-size:12px;color:var(--text)">${s.summary.totalDeps}</span>
                  <span style="font-size:10px;color:var(--muted)"> (${s.summary.directDeps} direct)</span></td>
              <td>${s.summary.withVulns===0
                ?'<span style="color:var(--l);font-size:11px">✓ clean</span>'
                :(pills||`<span style="color:var(--muted)">${s.summary.withVulns}</span>`)}</td>
              <td>${s.summary.toxic>0
                ?`<span style="color:#ff3b30;font-size:11px">☠ ${s.summary.toxic}</span>`
                :'<span style="color:var(--l);font-size:11px">✓</span>'}</td>
              <td style="color:var(--muted);font-size:10px;white-space:nowrap">${fmtDate(s.scannedAt)}</td>
              <td><button onclick="event.stopPropagation();depScans.splice(${i},1);saveDep();renderDepList()"
                style="background:none;border:none;color:var(--muted);cursor:pointer;font-size:13px;padding:3px 5px;border-radius:4px"
                onmouseover="this.style.color='var(--c)'" onmouseout="this.style.color='var(--muted)'">✕</button></td>
            </tr>`;
          }).join('')}
        </tbody>
      </table>
    </div>`;
}

// ── DETAIL PAGE ───────────────────────────────────────────────
function renderDepDetail(scan){
  currentDepScan=scan;
  const el=document.getElementById('depDetailContent');
  const sysInfo=DEP_SYSTEMS.find(x=>x.id===scan.system)||{logo:'📦',label:scan.system};
  const sm=scan.summary;
  const chips=['CRITICAL','HIGH','MEDIUM','LOW'].filter(sv=>sm[sv])
    .map(sv=>`<span class="sev ${sv}">${sm[sv]} ${sv}</span>`).join('');

  const infoStrip=scan.info?(()=>{
    const parts=[];
    if(scan.info.licenses?.length) parts.push(`📄 ${scan.info.licenses.filter(Boolean).join(', ')}`);
    if(scan.info.homepageUrl) parts.push(`<a href="${esc(scan.info.homepageUrl)}" target="_blank" style="color:var(--accent);text-decoration:none">🌐 Homepage ↗</a>`);
    if(scan.info.publishedAt) parts.push(`📅 ${new Date(scan.info.publishedAt).toLocaleDateString('en-US',{year:'numeric',month:'short',day:'numeric'})}`);
    if(!parts.length) return'';
    return`<div style="display:flex;flex-wrap:wrap;gap:14px;font-size:11px;color:var(--muted);
      background:var(--s1);border:1px solid var(--br);border-radius:10px;
      padding:11px 18px;margin-bottom:16px">${parts.join('')}</div>`;
  })():'';

  const direct  =scan.deps.filter(d=>d.relation==='DIRECT');
  const indirect=scan.deps.filter(d=>d.relation!=='DIRECT');

  function depRow(dep){
    const isToxic=dep.toxic?.found;
    const c=dep.counts||{};
    const depIdx=scan.deps.indexOf(dep);
    return`<tr class="row" onclick="openDepPkg(${depIdx})">
      <td><div style="display:flex;align-items:center;gap:7px">
        <div class="row-name">${esc(dep.name)}</div>
        ${isToxic?`<span title="${esc(dep.toxic.problem_type||'toxic')}" style="background:rgba(255,59,48,.15);border:1px solid rgba(255,59,48,.4);color:#ff3b30;font-size:9px;font-weight:700;padding:1px 5px;border-radius:4px">☠ TOXIC</span>`:''}
      </div></td>
      <td><span class="row-ver">${esc(dep.version)}</span></td>
      <td style="text-align:center">${(c.CRITICAL)?`<span class="sev CRITICAL" style="font-size:10px;padding:2px 8px">${c.CRITICAL}</span>`:'<span style="color:var(--muted);font-size:12px">—</span>'}</td>
      <td style="text-align:center">${(c.HIGH)?`<span class="sev HIGH" style="font-size:10px;padding:2px 8px">${c.HIGH}</span>`:'<span style="color:var(--muted);font-size:12px">—</span>'}</td>
      <td style="color:var(--muted);font-size:11px;text-align:center">${dep.vulnCount||'<span style="color:var(--l)">✓</span>'}</td>
    </tr>`;
  }

  function depTable(deps,title,color){
    if(!deps.length) return'';
    return`<div style="margin-bottom:20px">
      <div style="font-size:11px;letter-spacing:.08em;color:${color};text-transform:uppercase;margin-bottom:8px;font-weight:600">${title} (${deps.length})</div>
      <div class="tbl-wrap"><table class="tbl">
        <thead><tr>
          <th>Package</th><th>Version</th>
          <th style="text-align:center;color:var(--c)">Critical</th>
          <th style="text-align:center;color:var(--h)">High</th>
          <th style="text-align:center">Total vulns</th>
        </tr></thead>
        <tbody>${deps.map(d=>depRow(d)).join('')}</tbody>
      </table></div>
    </div>`;
  }

  el.innerHTML=`
    <div class="detail-header" style="cursor:pointer;transition:border-color .18s"
      onclick="openDepPkg(-1)"
      onmouseover="this.style.borderColor='rgba(167,139,250,.5)'"
      onmouseout="this.style.borderColor='var(--br)'">
      <div class="detail-icon" style="background:rgba(167,139,250,.1);border:1px solid rgba(167,139,250,.25);font-size:24px;display:flex;align-items:center;justify-content:center">${sysInfo.logo}</div>
      <div class="detail-info" style="flex:1">
        <div class="detail-name">${esc(scan.package)} <span style="color:var(--muted);font-size:14px;font-weight:400">v${esc(scan.resolvedVersion)}</span></div>
        <div class="detail-sub">${sysInfo.label} · ${esc(scan.desc||'No description')} · scanned ${fmtDate(scan.scannedAt)}</div>
        <div style="display:flex;gap:14px;margin-top:5px;font-size:11px;color:var(--muted)">
          <span>📦 ${sm.totalDeps} total deps</span>
          <span style="color:#a78bfa">⬆ ${sm.directDeps} direct</span>
          ${sm.withVulns?`<span style="color:var(--h)">⚠ ${sm.withVulns} with vulns</span>`:'<span style="color:var(--l)">✓ no vulns</span>'}
          ${sm.toxic?`<span style="color:#ff3b30">☠ ${sm.toxic} toxic</span>`:''}
        </div>
        <div style="display:flex;flex-wrap:wrap;align-items:center;gap:6px;margin-top:6px" onclick="event.stopPropagation()">
          <div id="depDetailActivityBadge"><span style="font-size:11px;color:var(--muted)">⏳ Checking activity…</span></div>
        </div>
      </div>
      <div style="display:flex;flex-direction:column;align-items:flex-end;gap:8px;flex-shrink:0">
        <div class="detail-chips">${chips||'<span class="sev NONE">✅ CLEAN</span>'}</div>
        <span style="font-size:11px;color:#a78bfa;display:flex;align-items:center;gap:4px">View vulnerabilities →</span>
      </div>
    </div>
    ${infoStrip}
    ${depTable(direct,  '⬆ Direct dependencies',     '#a78bfa')}
    ${depTable(indirect,'↳ Transitive dependencies','var(--muted)')}
    ${!direct.length&&!indirect.length?'<div style="text-align:center;padding:60px;color:var(--muted);font-size:14px">No dependencies found in the graph.</div>':''}`;

  window._currentDepScanDeps=scan.deps;
  window._currentDepScanRoot={
    name:scan.package, system:scan.system, version:scan.resolvedVersion,
    relation:'ROOT', toxic:{found:false},
    topSeverity:['CRITICAL','HIGH','MEDIUM','LOW'].find(s=>sm[s]>0)||'NONE',
    vulnCount:sm.CRITICAL+sm.HIGH+sm.MEDIUM+sm.LOW,
    counts:{CRITICAL:sm.CRITICAL,HIGH:sm.HIGH,MEDIUM:sm.MEDIUM,LOW:sm.LOW,UNKNOWN:0},
    vulns:[],
  };
  checkActivity('depDetailActivityBadge', scan.package, scan.system);
}

function openDepPkg(idx){
  const dep=idx===-1?window._currentDepScanRoot:window._currentDepScanDeps[idx];
  if(!dep) return;
  navTo('dep-pkg',{dep,scan:currentDepScan,backScan:currentDepScan});
}

// ── SINGLE DEP PAGE ───────────────────────────────────────────
function renderDepPkg(dep, scan){
  const el=document.getElementById('depPkgContent');
  const sysInfo=DEP_SYSTEMS.find(x=>x.id===(dep.system||scan?.system))||{logo:'📦',label:dep.system};
  const cnt=dep.counts||{};
  const chips=['CRITICAL','HIGH','MEDIUM','LOW'].filter(sv=>cnt[sv])
    .map(sv=>`<span class="sev ${sv}">${cnt[sv]} ${sv}</span>`).join('');

  function toxicBadgeHtml(toxic){
    if(!toxic?.found) return`<span style="display:inline-flex;align-items:center;gap:5px;font-size:10px;background:rgba(52,199,89,.1);color:#34c759;border:1px solid rgba(52,199,89,.3);padding:2px 9px;border-radius:12px">✅ Toxic repos: not found</span>`;
    const TOXIC_LABELS={ddos:'DDoS tool',hostile_actions:'Hostile actions',political_slogan:'Political slogan',malware:'Malware',ip_blocking:'IP blocking'};
    const label=TOXIC_LABELS[toxic.problem_type]||toxic.problem_type||'Toxic';
    const fullDesc=toxic.description||'';
    const short=fullDesc.length>60;
    const preview=short?fullDesc.slice(0,60):fullDesc;
    const moreBtn=short?`<button onclick="this.parentElement.querySelector('.toxic-full').style.display='inline';this.remove()" style="background:none;border:none;color:inherit;opacity:.75;cursor:pointer;font-size:10px;padding:0;text-decoration:underline;margin-left:2px">…</button><span class="toxic-full" style="display:none">${esc(fullDesc.slice(60))}</span>`:'';
    return`<span style="display:inline-flex;align-items:center;flex-wrap:wrap;gap:4px;font-size:10px;background:rgba(255,59,48,.12);color:#ff3b30;border:1px solid rgba(255,59,48,.35);padding:3px 10px;border-radius:12px">☠ <strong>Toxic: ${esc(label)}</strong>${fullDesc?' — '+esc(preview)+moreBtn:''}</span>`;
  }

  el.innerHTML=`
    <div class="detail-header">
      <div class="detail-icon" style="background:rgba(167,139,250,.1);border:1px solid rgba(167,139,250,.25);font-size:22px;display:flex;align-items:center;justify-content:center">${sysInfo.logo}</div>
      <div class="detail-info">
        <div class="detail-name">${esc(dep.name)} <span style="color:var(--muted);font-size:14px;font-weight:400">v${esc(dep.version)}</span></div>
        <div class="detail-sub">${sysInfo.label}${dep.relation&&dep.relation!=='ROOT'?` · <span style="color:${dep.relation==='DIRECT'?'#a78bfa':'var(--muted)'}">${dep.relation}</span> · from ${esc(scan?.package||'—')}`:''}</div>
        <div style="display:flex;flex-wrap:wrap;align-items:center;gap:6px;margin-top:6px">
          <div>${toxicBadgeHtml(dep.toxic)}</div>
          <div id="depPkgActivityBadge"><span style="font-size:11px;color:var(--muted)">⏳ Checking activity…</span></div>
        </div>
      </div>
      <div class="detail-chips">${dep.vulns?.length===0?'<span class="sev NONE">✅ CLEAN</span>':chips}</div>
    </div>
    ${dep.vulns?.length===0
      ?(dep.relation==='ROOT'
        ?'<div style="text-align:center;padding:60px;color:var(--l);font-size:15px">🛡️ No vulnerabilities found in this library!</div>'
        :'<div style="text-align:center;padding:60px;color:var(--l);font-size:15px">🛡️ No vulnerabilities found for this dependency!</div>')
      :`<div id="depPkgVulnCards">${(dep.vulns||[]).map((v,vi)=>depVulnCardHtml(dep,v,vi)).join('')}</div>`}`;

  if(dep.vulns?.length) enrichDepPkgVulns(dep.vulns);
  checkActivity('depPkgActivityBadge', dep.name, dep.system||scan?.system);
}

function depVulnCardHtml(dep,v,vi){
  const cveId=[...(v.aliases||[]),v.id].find(x=>x.startsWith('CVE-'))||v.id;
  return`<div class="vi" id="dpvi-${vi}">
    <div class="vi-hdr" onclick="toggleDPVI(${vi})">
      <div class="vbar ${v.severity}"></div>
      <div class="vi-id">
        ${cveId.startsWith('CVE-')?`<a href="https://nvd.nist.gov/vuln/detail/${esc(cveId)}" target="_blank" onclick="event.stopPropagation()" style="color:var(--accent);font-weight:700;font-size:11px;text-decoration:none">${esc(cveId)} ↗</a><span style="color:var(--muted);font-size:10px;margin:0 5px">/</span>`:''}
        <span style="opacity:.7">${esc(v.id)}</span>
        <span class="vi-cvss-inline" id="dpvcvss-${vi}"></span>
      </div>
      <div class="vi-sum">${esc(v.summary||'No summary')}</div>
      <span class="enrich-badges" id="dpveb-${vi}"></span>
      <span class="vi-sev ${v.severity}">${v.severity}</span>
      <span class="vi-chev">▼</span>
    </div>
    <div class="vi-body" id="dpvib-${vi}">
      <div class="vgrid">
        <span class="vk">OSV ID</span><span class="vv"><a href="https://osv.dev/vulnerability/${esc(v.id)}" target="_blank">${esc(v.id)} ↗</a></span>
        <span class="vk">CVSS</span><span class="vv" id="dpvcvssv-${vi}">${v.cvss?cvssHtml(v.cvss):'<span style="color:var(--muted);font-size:11px">loading…</span>'}</span>
        <span class="vk">EPSS</span><span class="vv" id="dpvepss-${vi}">${v.epss?epssHtml(v.epss):'<span style="color:var(--muted);font-size:11px">loading…</span>'}</span>
        ${v.details?`<span class="vk">Details</span><span class="vv" style="white-space:pre-wrap">${esc(v.details.slice(0,480))}${v.details.length>480?'…':''}</span>`:''}
        ${v.fix?`<span class="vk">Fixed in</span><span class="vv"><span class="fix-tag">→ ${esc(v.fix)}</span></span>`:''}
        ${v.published?`<span class="vk">Published</span><span class="vv">${new Date(v.published).toLocaleDateString('en-US',{year:'numeric',month:'short',day:'numeric'})}</span>`:''}
        ${(v.refs||[]).length?`<span class="vk">References</span><span class="vv" style="line-height:2">${v.refs.slice(0,4).map(u=>{const su=safeUrl(u);return su==='#'?'':`<a href="${esc(su)}" target="_blank" rel="noopener noreferrer">${esc(u.length>60?u.slice(0,60)+'…':u)}</a>`;}).filter(Boolean).join('<br/>')}</span>`:''}
        <span class="vk">CISA KEV</span><span class="vv" id="dpvkev-${vi}">${kevBadge(v.inKev)}</span>
        <span class="vk">PoC (GitHub)</span><span class="vv" id="dpvpoc-${vi}">${pocBadge(v.pocs||[])}</span>
      </div>
    </div>
  </div>`;
}

function toggleDPVI(vi){
  const el=document.getElementById('dpvi-'+vi);
  const body=document.getElementById('dpvib-'+vi);
  if(!el||!body) return;
  const open=el.classList.contains('open');
  el.classList.toggle('open',!open);
  body.style.display=open?'none':'block';
}

function enrichDepPkgVulns(vulns){
  vulns.forEach((v,vi)=>{
    const cvssEl=document.getElementById('dpvcvssv-'+vi);
    if(cvssEl) cvssEl.innerHTML=cvssHtml(v.cvss);
    const cvssHdrEl=document.getElementById('dpvcvss-'+vi);
    if(cvssHdrEl&&v.cvss?.cvss3){
      const s=v.cvss.cvss3.score;
      const cls=s>=9?'CRITICAL':s>=7?'HIGH':s>=4?'MEDIUM':'LOW';
      cvssHdrEl.innerHTML=`<span class="sev ${cls}" style="font-size:9px;padding:1px 6px">${s}</span>`;
    }
    const epssEl=document.getElementById('dpvepss-'+vi);
    if(epssEl) epssEl.innerHTML=epssHtml(v.epss);
    const kevEl=document.getElementById('dpvkev-'+vi);
    if(kevEl) kevEl.innerHTML=kevBadge(v.inKev);
    const pocEl=document.getElementById('dpvpoc-'+vi);
    if(pocEl) pocEl.innerHTML=pocBadge(v.pocs||[]);
    const eb=document.getElementById('dpveb-'+vi);
    if(eb){
      let hb='';
      if(v.inKev) hb+=`<span title="CISA Known Exploited" style="background:#ff3b30;color:#fff;font-size:9px;font-weight:700;padding:2px 6px;border-radius:4px;margin-right:3px">🔥 KEV</span>`;
      if(v.pocs?.length) hb+=`<span title="${v.pocs.length} PoC(s)" style="background:#ff9500;color:#000;font-size:9px;font-weight:700;padding:2px 6px;border-radius:4px;margin-right:3px">💥 PoC×${v.pocs.length}</span>`;
      eb.innerHTML=hb;
    }
  });
}

// keyboard shortcuts for dep modal
document.addEventListener('keydown',e=>{
  if(e.key==='Escape'&&document.getElementById('depModal').style.display!=='none') closeDepModal();
  if(e.key==='Enter' &&document.getElementById('depModal').style.display!=='none') doDepScan();
});
