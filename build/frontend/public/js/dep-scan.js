// Open a library scan directly from dep-scan (click on transitive/direct package names)
async function openLibFromDep(ev, systemId, name, version){
  try{
    if(ev) ev.stopPropagation();
    const map = {
      'NPM':      { ecoId:'npm',      osv:'npm',        label:'npm',       logo:'📦' },
      'PYPI':     { ecoId:'pypi',     osv:'PyPI',       label:'PyPI',      logo:'🐍' },
      'GO':       { ecoId:'go',       osv:'Go',         label:'Go',        logo:'🐹' },
      'CARGO':    { ecoId:'crates',   osv:'crates.io',  label:'Rust',      logo:'🦀' },
      'MAVEN':    { ecoId:'maven',    osv:'Maven',      label:'Maven',     logo:'☕' },
      'NUGET':    { ecoId:'nuget',    osv:'NuGet',      label:'NuGet',     logo:'💠' },
      'RUBYGEMS': { ecoId:'rubygems', osv:'RubyGems',   label:'RubyGems',  logo:'💎' },
      'COMPOSER': { ecoId:'composer', osv:'Packagist',  label:'Composer',  logo:'🐘' },
    };
    const eco = map[systemId] || map[(systemId||'').toUpperCase()];
    if(!eco) throw new Error('Unknown ecosystem for lib jump: '+systemId);
    const r = await fetch('/api/libscan', {
      method:'POST', headers:{'Content-Type':'application/json'},
      body: JSON.stringify({ name, ecosystem: eco.osv, version: (version||'').trim() })
    });
    const data = await r.json();
    if(!r.ok) throw new Error(data?.error || 'libscan failed');
    const vulns = (data.vulns||[]).map(v=>({...v,_sev:v.severity,_fix:v.fix,_aliases:v.aliases||[],_refs:v.refs||[]}));
    window.libScans = window.libScans || [];
    window.libScans.unshift({
      id:Date.now(), pkg:data.package, ver:data.version||'',
      eco:eco.ecoId, ecoLabel:eco.label, ecoLogo:eco.logo, desc:'',
      vulns, toxic:data.toxic, topSev:data.topSeverity||'NONE', scannedAt:data.scannedAt,
    });
    if(typeof window.saveLib === 'function') window.saveLib();
    navTo('lib-detail', { scan: window.libScans[0] });
  }catch(e){
    console.error(e);
    alert(e.message || 'Failed to open library');
  }
}

// ── DEP SCAN CONFIG ───────────────────────────────────────────
const DEP_SYSTEMS = [
  { id:'NPM',      label:'npm',      logo:'📦', hint:'express, lodash…' },
  { id:'PYPI',     label:'PyPI',     logo:'🐍', hint:'django, requests…' },
  { id:'GO',       label:'Go',       logo:'🐹', hint:'github.com/gin-gonic/gin' },
  { id:'CARGO',    label:'Rust',     logo:'🦀', hint:'tokio, serde…' },
  { id:'MAVEN',    label:'Maven',    logo:'☕', hint:'com.google.guava:guava' },
  { id:'NUGET',    label:'NuGet',    logo:'🔷', hint:'Newtonsoft.Json…' },
  { id:'COMPOSER', label:'Composer', logo:'🐘', hint:'monolog/monolog' },
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
  selDepSys=null;
  ['dDesc','dPkg','dVer'].forEach(id=>document.getElementById(id).value='');
  document.getElementById('dmerr').style.display='none';
  setBtn('btnDepGo',false,'▶ Scan');
  renderDepEcos();
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
    const ep = (sys==='COMPOSER') ? '/api/composerscan' : '/api/depscan';
    const payload = (sys==='COMPOSER')
      ? { name:pkg, version:ver||undefined }
      : { name:pkg, system:sys, version:ver||undefined };
    const r=await fetch(ep,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(payload)});
    const data=await r.json();
    if(!r.ok) throw new Error(data.error||`Error ${r.status}`);
    // Normalize composerscan response → same shape as depscan
    // composerscan returns deps:{direct:[],transitive:[]} — convert to flat array with relation/counts fields
    if(sys==='COMPOSER' && data.deps && !Array.isArray(data.deps)){
      const normDeps=(list,relation)=>(list||[]).map(d=>{
        // composerscan stores epss/cvss/pocs/kev as {CVE-xxx: value} objects, not arrays
        const epssMap = d.epss||{};  // { 'CVE-xxx': {epss, percentile} }
        const cvssMap = d.cvss||{};  // { 'CVE-xxx': {cvss3, cvss2} }
        const pocsMap = d.pocs||{};  // { 'CVE-xxx': [...] }
        const kevSet  = new Set(d.kev||[]);

        const vulns=(d.vulns||[]).map(v=>{
          const cveId=[...(v.aliases||[]),v.id].find(x=>x&&x.startsWith('CVE-'))||null;
          return {
            ...v,
            fix     : v.fixed||v.fix||null,
            severity: v.severity||'UNKNOWN',
            aliases : v.aliases||[],
            refs    : v.refs||[],
            epss    : cveId ? (epssMap[cveId]||null) : null,
            cvss    : cveId ? (cvssMap[cveId]||null) : null,
            pocs    : cveId ? (pocsMap[cveId]||[])   : [],
            inKev   : cveId ? kevSet.has(cveId)       : false,
          };
        });
        const cnt={CRITICAL:0,HIGH:0,MEDIUM:0,LOW:0,UNKNOWN:0};
        vulns.forEach(v=>{const s=(v.severity||'UNKNOWN').toUpperCase();if(s in cnt)cnt[s]++;});
        const topSev=['CRITICAL','HIGH','MEDIUM','LOW'].find(s=>cnt[s]>0)||'NONE';
        return{...d,relation,vulns,counts:cnt,topSeverity:topSev,system:data.system||'COMPOSER',toxic:d.toxic||{found:false}};
      });
      // root — отдельное поле, не входит в direct/transitive
      console.log('[dep-scan] raw deps from server:', {
        hasRoot: !!data.deps.root,
        directCount: (data.deps.direct||[]).length,
        transitiveCount: (data.deps.transitive||[]).length,
        transitiveNames: (data.deps.transitive||[]).map(d=>d.name).slice(0,5),
      });
      const rootNorm = data.deps.root ? normDeps([data.deps.root], 'ROOT') : [];
      data.deps=[
        ...rootNorm,
        ...normDeps(data.deps.direct,     'DIRECT'),
        ...normDeps(data.deps.transitive,  'INDIRECT'),
      ];
      console.log('[dep-scan] after normalize:', data.deps.map(d=>d.name+':'+d.relation));
      // Recount severity totals from normalized deps (composerscan doesn't include them in summary)
      const sevTotals={CRITICAL:0,HIGH:0,MEDIUM:0,LOW:0};
      data.deps.forEach(d=>(d.vulns||[]).forEach(v=>{const s=(v.severity||'').toUpperCase();if(s in sevTotals)sevTotals[s]++;}));
      const toxicCount=data.deps.filter(d=>d.toxic?.found).length;
      const sm=data.summary||{};
      data.summary={
        ...sm,
        totalDeps : sm.total   ??sm.totalDeps  ??data.deps.length,
        directDeps: sm.direct  ??sm.directDeps ??data.deps.filter(d=>d.relation==='DIRECT').length,
        CRITICAL  : sevTotals.CRITICAL,
        HIGH      : sevTotals.HIGH,
        MEDIUM    : sevTotals.MEDIUM,
        LOW       : sevTotals.LOW,
        toxic     : toxicCount,
        withVulns : data.deps.filter(d=>(d.vulns||[]).length>0).length,
      };
    }
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
    <div class="tbl-wrap"><table class="tbl">
      <thead><tr>
        <th>Package</th><th>Description</th><th>System</th>
        <th>Version</th><th>Deps</th><th>Vulns</th><th>Toxic</th><th>Scanned</th><th style="width:28px"></th>
      </tr></thead>
      <tbody>
        ${depScans.map((s,i)=>{
          const sysInfo=DEP_SYSTEMS.find(x=>x.id===s.system)||{logo:'📦',label:s.system};
          const pills=['CRITICAL','HIGH','MEDIUM','LOW'].filter(sv=>s.summary[sv])
            .map(sv=>`<span class="sev ${sv}" style="font-size:9px;padding:2px 6px">${s.summary[sv]} ${sv}</span>`).join(' ');
          const vulnCell  = s.summary.withVulns===0 ? '<span style="color:var(--l);font-size:11px">&#10003; clean</span>' : (pills||`<span style="color:var(--muted)">${s.summary.withVulns}</span>`);
          const toxicCell = s.summary.toxic>0 ? `<span style="color:#ff3b30;font-size:11px">&#9760; ${s.summary.toxic}</span>` : '<span style="color:var(--l);font-size:11px">&#10003;</span>';
          const toxicBadge= s.toxic?.found ? '<span style="background:rgba(255,59,48,.15);border:1px solid rgba(255,59,48,.4);color:#ff3b30;font-size:9px;font-weight:700;padding:1px 5px;border-radius:3px;margin-top:2px;display:inline-block">&#9760; TOXIC</span>' : '';
          return `<tr class="row" onclick="currentDepScan=depScans[${i}];navTo('dep-detail',{scan:depScans[${i}]})">
            <td><div style="display:flex;align-items:center;gap:8px">
              <span style="font-size:18px">${sysInfo.logo}</span>
              <div><div class="row-name" style="font-size:17px">${esc(s.package)}</div>${toxicBadge}</div>
            </div></td>
            <td><div class="row-desc">${esc(s.desc||'—')}</div></td>
            <td><span style="font-size:10px;color:var(--muted2)">${sysInfo.label}</span></td>
            <td><span class="row-ver">${esc(s.resolvedVersion||'—')}</span></td>
            <td><span style="font-size:12px;color:var(--text)">${s.summary.totalDeps}</span>
                <span style="font-size:10px;color:var(--muted)"> (${s.summary.directDeps} direct)</span></td>
            <td>${vulnCell}</td>
            <td>${toxicCell}</td>
            <td style="color:var(--muted);font-size:10px;white-space:nowrap">${fmtDate(s.scannedAt)}</td>
            <td><button onclick="event.stopPropagation();depScans.splice(${i},1);saveDep();renderDepList()"
              style="background:none;border:none;color:var(--muted);cursor:pointer;font-size:13px;padding:3px 5px;border-radius:4px"
              onmouseover="this.style.color='var(--c)'" onmouseout="this.style.color='var(--muted)'">&#10005;</button></td>
          </tr>`;
        }).join('')}
      </tbody>
    </table></div>`;
}

// ── TOGGLES ───────────────────────────────────────────────────
function toggleDepSection(key){
  const body=document.getElementById('depsec-body-'+key);
  const chev=document.getElementById('depsec-chev-'+key);
  if(!body) return;
  const open=body.style.display!=='none';
  body.style.display=open?'none':'block';
  if(chev) chev.style.transform=open?'':'rotate(180deg)';
}

function toggleDepCard(depIdx){
  const body=document.getElementById('dcard-body-'+depIdx);
  const chev=document.getElementById('dcard-chev-'+depIdx);
  if(!body) return;
  const open=body.style.display!=='none';
  body.style.display=open?'none':'block';
  if(chev) chev.style.transform=open?'':'rotate(180deg)';
  if(!open && body.dataset.enriched!=='1'){
    body.dataset.enriched='1';
    const dep=window._currentDepScanDeps?.[depIdx];
    if(dep?.vulns?.length) _enrichDepCardVulns(dep.vulns, depIdx);
  }
}

function toggleDepVI(depIdx, vi){
  const el  =document.getElementById('dvi-'+depIdx+'-'+vi);
  const body=document.getElementById('dvib-'+depIdx+'-'+vi);
  if(!el||!body) return;
  const open=el.classList.contains('open');
  el.classList.toggle('open',!open);
  body.style.display=open?'none':'block';
}

function _enrichDepCardVulns(vulns, depIdx){
  vulns.forEach((v,vi)=>{
    const cvssVEl=document.getElementById('dvicvssv-'+depIdx+'-'+vi);
    if(cvssVEl) cvssVEl.innerHTML=cvssHtml(v.cvss);
    const cvssHEl=document.getElementById('dvicvss-'+depIdx+'-'+vi);
    if(cvssHEl&&v.cvss?.cvss3){
      const s=v.cvss.cvss3.score;
      const cls=s>=9?'CRITICAL':s>=7?'HIGH':s>=4?'MEDIUM':'LOW';
      cvssHEl.innerHTML=`<span class="sev ${cls}" style="font-size:9px;padding:1px 6px">${s}</span>`;
    }
    const epssEl=document.getElementById('dviepss-'+depIdx+'-'+vi);
    if(epssEl) epssEl.innerHTML=epssHtml(v.epss);
    const kevEl=document.getElementById('dvikev-'+depIdx+'-'+vi);
    if(kevEl) kevEl.innerHTML=kevBadge(v.inKev);
    const pocEl=document.getElementById('dvipoc-'+depIdx+'-'+vi);
    if(pocEl) pocEl.innerHTML=pocBadge(v.pocs||[]);
    const eb=document.getElementById('dvieb-'+depIdx+'-'+vi);
    if(eb){
      let hb='';
      if(v.inKev)    hb+=`<span title="CISA KEV" style="background:#ff3b30;color:#fff;font-size:9px;font-weight:700;padding:2px 6px;border-radius:4px;margin-right:3px">&#128293; KEV</span>`;
      if(v.pocs?.length) hb+=`<span title="${v.pocs.length} PoC(s)" style="background:#ff9500;color:#000;font-size:9px;font-weight:700;padding:2px 6px;border-radius:4px">&#128165; PoC&#215;${v.pocs.length}</span>`;
      eb.innerHTML=hb;
    }
  });
}

// ── DETAIL PAGE ───────────────────────────────────────────────
function renderDepDetail(scan){
  window._lastDepScan=scan;
  currentDepScan=scan;
  const el=document.getElementById('depDetailContent');
  const sysInfo=DEP_SYSTEMS.find(x=>x.id===scan.system)||{logo:'📦',label:scan.system};
  const sm=scan.summary;
  const chips=['CRITICAL','HIGH','MEDIUM','LOW'].filter(sv=>sm[sv])
    .map(sv=>`<span class="sev ${sv}">${sm[sv]} ${sv}</span>`).join('');

  // Универсальная классификация: root / direct / transitive
  const allDeps  = Array.isArray(scan.deps) ? scan.deps : [];
  const rootDep  = allDeps.find(d=>d.relation==='ROOT') || null;
  const rootName = rootDep?.name || scan.package;
  const direct   = allDeps.filter(d=>d.relation==='DIRECT'   && d.name!==rootName);
  const indirect = allDeps.filter(d=>d.relation==='INDIRECT'  && d.name!==rootName);

  // Пересчитываем счётчики из реальных отфильтрованных массивов
  const directCount     = direct.length;
  const transitiveCount = indirect.length;
  const totalCount      = directCount + transitiveCount;

  function depMiniVulnRow(v, vi, depIdx){
    const cveId=[...(v.aliases||[]),v.id].find(x=>x.startsWith('CVE-'))||v.id;
    const sev=v.severity||'UNKNOWN';
    const cveLink=cveId.startsWith('CVE-')
      ?`<a href="https://nvd.nist.gov/vuln/detail/${esc(cveId)}" target="_blank" onclick="event.stopPropagation()" style="color:var(--accent);font-weight:700;font-size:11px;text-decoration:none">${esc(cveId)} &#8599;</a><span style="color:var(--muted);font-size:10px;margin:0 5px">/</span>`
      :'';
    const fixRow=v.fix?`<span class="vk">Fixed in</span><span class="vv"><span class="fix-tag">&#8594; ${esc(v.fix)}</span></span>`:'';
    const descText = v.details||v.summary||'';
    const detRow=descText?`<span class="vk">Description</span><span class="vv" style="white-space:pre-wrap;line-height:1.5">${esc(descText.slice(0,500))}${descText.length>500?'&#8230;':''}</span>`:'';
    const nvdScore = v.cvss?.cvss3?.score||null;
    const nvdSev   = nvdScore ? (nvdScore>=9?'CRITICAL':nvdScore>=7?'HIGH':nvdScore>=4?'MEDIUM':'LOW') : null;
    const nvdRow   = nvdScore ? `<span class="vk">NVD Score</span><span class="vv"><span class="sev ${nvdSev}" style="font-size:10px;padding:1px 7px">${nvdScore}</span> <span style="color:var(--muted);font-size:10px">${v.cvss.cvss3.vector||''}</span></span>` : '';
    return`<div class="vi" id="dvi-${depIdx}-${vi}">
      <div class="vi-hdr" onclick="toggleDepVI(${depIdx},${vi})">
        <div class="vbar ${sev}"></div>
        <div class="vi-id">
          ${cveLink}
          <span style="opacity:.7">${esc(v.id)}</span>
          <span id="dvicvss-${depIdx}-${vi}"></span>
        </div>
        <div class="vi-sum">${esc(v.summary||'No summary')}</div>
        <span class="enrich-badges" id="dvieb-${depIdx}-${vi}"></span>
        <span class="vi-sev ${sev}">${sev}</span>
        <span class="vi-chev">&#9660;</span>
      </div>
      <div class="vi-body" id="dvib-${depIdx}-${vi}" style="display:none">
        <div class="vgrid">
          <span class="vk">CVSS</span><span class="vv" id="dvicvssv-${depIdx}-${vi}">${v.cvss?cvssHtml(v.cvss):'—'}</span>
          ${nvdRow}
          <span class="vk">EPSS</span><span class="vv" id="dviepss-${depIdx}-${vi}">${v.epss?epssHtml(v.epss):'—'}</span>
          ${fixRow}${detRow}
          <span class="vk">CISA KEV</span><span class="vv" id="dvikev-${depIdx}-${vi}">${kevBadge(v.inKev)}</span>
          <span class="vk">PoC</span><span class="vv" id="dvipoc-${depIdx}-${vi}">${pocBadge(v.pocs||[])}</span>
        </div>
      </div>
    </div>`;
  }

  function depPkgCard(dep, depIdx){
    const isToxic =dep.toxic?.found;
    const topSev  =dep.topSeverity||(['CRITICAL','HIGH','MEDIUM','LOW'].find(s=>(dep.counts||{})[s])||'NONE');
    const pills   =['CRITICAL','HIGH','MEDIUM','LOW'].filter(k=>(dep.counts||{})[k])
      .map(k=>`<span class="sev ${k}" style="font-size:9px;padding:1px 6px">${dep.counts[k]}</span>`).join('');
    const fixVer  =dep.vulns?.find(v=>v.fix)?.fix;
    const cveCount=dep.vulns?.length||0;

    const cleanBadge ='<span class="sev NONE" style="font-size:9px;padding:1px 6px">&#10003;</span>';
    const noCvesDiv  ='<div style="padding:16px 20px;color:var(--l);font-size:12px">&#x2705; No vulnerabilities found</div>';
    const toxicBadge =isToxic?'<span style="background:rgba(255,59,48,.15);border:1px solid rgba(255,59,48,.4);color:#ff3b30;font-size:9px;font-weight:700;padding:1px 5px;border-radius:4px;margin-left:8px">&#9760; TOXIC</span>':'';
    const fixBadge   =fixVer?`<span class="fix-tag" style="margin-left:8px;font-size:10px">&#8594; ${esc(fixVer)}</span>`:'';
    const cveLabel   =cveCount?`<span style="font-size:11px;color:var(--muted);margin-left:4px">${cveCount} CVE${cveCount>1?'s':''}</span>`:'';
    const vulnsBody  =cveCount?(dep.vulns||[]).map((v,vi)=>depMiniVulnRow(v,vi,depIdx)).join(''):noCvesDiv;
    const sysId      =esc(scan.system);
    const depName    =esc(dep.name);
    const depVer     =esc(dep.version||'');

    return`<div class="pkg-group" style="margin-bottom:12px">
      <div style="display:flex;align-items:stretch;background:var(--s2);border:1px solid var(--br);border-radius:11px;overflow:hidden">
        <div class="pkg-group-hdr" onclick="toggleDepCard(${depIdx})"
          style="flex:1;display:flex;align-items:center;gap:10px;padding:11px 16px;cursor:pointer;transition:background .13s;user-select:none"
          onmouseover="this.style.background='var(--s3)'" onmouseout="this.style.background=''">
          <div class="vbar ${topSev}" style="height:28px"></div>
          <div style="flex:1;min-width:0">
            <a href="javascript:void(0)" onclick="openLibFromDep(event,'${sysId}','${depName}','${depVer}')"
              style="font-size:13px;font-weight:700;color:#fff;text-decoration:none"
              onmouseover="this.style.textDecoration='underline'" onmouseout="this.style.textDecoration='none'">${esc(dep.name)}</a>
            <span style="color:var(--muted);font-size:11px;margin-left:7px">v${esc(dep.version)}</span>
            ${fixBadge}${toxicBadge}
          </div>
          <div style="display:flex;align-items:center;gap:6px">
            ${cveCount?pills:cleanBadge}
            ${cveLabel}
            <span class="pkg-chev" id="dcard-chev-${depIdx}" style="color:var(--muted);font-size:10px;transition:transform .18s;margin-left:4px">&#9660;</span>
          </div>
        </div>
        <button onclick="openDepPkg(${depIdx})"
          style="flex-shrink:0;width:42px;background:rgba(167,139,250,.07);border:none;border-left:1px solid var(--br);color:#a78bfa;font-size:14px;cursor:pointer;transition:background .13s;display:flex;align-items:center;justify-content:center"
          onmouseover="this.style.background='rgba(167,139,250,.18)'" onmouseout="this.style.background='rgba(167,139,250,.07)'"
          title="Open detail">&#8594;</button>
      </div>
      <div id="dcard-body-${depIdx}" class="pkg-group-body" style="display:none;margin-top:2px">${vulnsBody}</div>
    </div>`;
  }

  function depSection(deps, label, isTransitive, key){
    const cnt={CRITICAL:0,HIGH:0,MEDIUM:0,LOW:0};
    deps.forEach(d=>(d.vulns||[]).forEach(v=>{const s=(v.severity||'').toUpperCase();if(s in cnt)cnt[s]++;}));
    const pills=['CRITICAL','HIGH','MEDIUM','LOW'].filter(k=>cnt[k])
      .map(k=>`<span class="sev ${k}" style="font-size:9px;padding:1px 6px">${cnt[k]}</span>`).join('');
    const accent=isTransitive?'#3b82f6':'#a78bfa';
    const rgb   =isTransitive?'59,130,246':'167,139,250';
    const bgTag =isTransitive?'rgba(59,130,246,.12)':'rgba(167,139,250,.12)';
    const brTag =isTransitive?'rgba(59,130,246,.35)':'rgba(167,139,250,.35)';
    const tag   =isTransitive?'&#8627; Transitive':'&#8679; Direct';
    const clean ='<span style="color:var(--l);font-size:11px">&#x2705; all clean</span>';

    const emptyBody = !deps.length
      ? `<div style="text-align:center;padding:40px 20px;color:var(--muted);font-size:13px">
           ${isTransitive ? '&#128065; No transitive dependencies found' : '&#128065; No direct dependencies found'}
         </div>`
      : '';

    return`<div style="margin-bottom:20px">
      <div onclick="toggleDepSection('${key}')"
        style="display:flex;align-items:center;gap:10px;padding:9px 14px;border-left:3px solid ${accent};background:rgba(${rgb},.06);border-radius:0 8px 8px 0;cursor:pointer;user-select:none;transition:background .13s"
        onmouseover="this.style.background='rgba(${rgb},.12)'"
        onmouseout="this.style.background='rgba(${rgb},.06)'">
        <span style="font-size:11px;font-weight:700;padding:2px 9px;border-radius:5px;background:${bgTag};border:1px solid ${brTag};color:${accent}">${tag}</span>
        <span style="font-size:13px;font-weight:600;color:#fff">${esc(label)}</span>
        <span style="color:var(--muted);font-size:11px">(${deps.length})</span>
        <span style="margin-left:auto;display:flex;gap:5px;align-items:center">
          ${deps.length ? (pills||clean) : '<span style="color:var(--muted);font-size:11px">&mdash; empty</span>'}
          <span id="depsec-chev-${key}" style="color:var(--muted);font-size:10px;transition:transform .18s;margin-left:6px;transform:rotate(180deg)">&#9660;</span>
        </span>
      </div>
      <div id="depsec-body-${key}" style="display:block;margin-top:8px">
        ${deps.length ? deps.map(d=>depPkgCard(d,allDeps.indexOf(d))).join('') : emptyBody}
      </div>
    </div>`;
  }

  // Root package own vulns (from enrichRoot)
  const rootVulns = rootDep?.vulns||[];
  const rootCnt   = rootDep?.counts||{};
  const rootChips = ['CRITICAL','HIGH','MEDIUM','LOW'].filter(sv=>rootCnt[sv])
    .map(sv=>`<span class="sev ${sv}">${rootCnt[sv]} ${sv}</span>`).join('');

  const chipsHtml = rootChips||chips||'<span class="sev NONE">&#x2705; CLEAN</span>';
  const exportBtn      =(typeof exportBtnHtml==='function')?exportBtnHtml('dep','__DEP_SCAN__'):'';

  // Root package vuln section
  const rootPills = ['CRITICAL','HIGH','MEDIUM','LOW'].filter(k=>rootCnt[k])
    .map(k=>`<span class="sev ${k}" style="font-size:9px;padding:1px 6px">${rootCnt[k]}</span>`).join('');
  const rootVulnsHtml = rootVulns.length===0
    ? ''
    : `<div style="margin-bottom:20px">
        <div onclick="toggleDepSection('root')"
          style="display:flex;align-items:center;gap:10px;padding:9px 14px;border-left:3px solid #ff3b30;background:rgba(255,59,48,.06);border-radius:0 8px 8px 0;cursor:pointer;user-select:none;transition:background .13s"
          onmouseover="this.style.background='rgba(255,59,48,.12)'"
          onmouseout="this.style.background='rgba(255,59,48,.06)'">
          <span style="font-size:11px;font-weight:700;padding:2px 9px;border-radius:5px;background:rgba(255,59,48,.12);border:1px solid rgba(255,59,48,.35);color:#ff3b30">&#9888; Own Vulnerabilities</span>
          <span style="font-size:13px;font-weight:600;color:#fff">${esc(scan.package)}</span>
          <span style="color:var(--muted);font-size:11px">(${rootVulns.length})</span>
          <span style="margin-left:auto;display:flex;gap:5px;align-items:center">
            ${rootPills}
            <span id="depsec-chev-root" style="color:var(--muted);font-size:10px;transition:transform .18s;margin-left:6px;transform:rotate(180deg)">&#9660;</span>
          </span>
        </div>
        <div id="depsec-body-root" style="display:block;margin-top:8px">
          ${rootVulns.map((v,vi)=>depMiniVulnRow(v,vi,-1)).join('')}
        </div>
      </div>`;

  const noVulnsHtml    =sm.withVulns
    ?`<span style="color:var(--h)">&#9888; ${sm.withVulns} with vulns</span>`
    :'<span style="color:var(--l)">&#10003; no vulns</span>';
  const emptyHtml=(!direct.length&&!indirect.length)
    ?'<div style="text-align:center;padding:60px;color:var(--muted);font-size:14px">No dependencies found in the graph.</div>'
    :'';

  el.innerHTML=`
    <div class="detail-header" style="cursor:pointer;transition:border-color .18s"
      onclick="openDepPkg(-1)"
      onmouseover="this.style.borderColor='rgba(167,139,250,.5)'"
      onmouseout="this.style.borderColor='var(--br)'">
      <div class="detail-icon green" style="font-size:22px">${sysInfo.logo}</div>
      <div class="detail-info" style="flex:1">
        <div class="detail-name" style="font-size:27px">
          ${esc(scan.package)} <span style="color:var(--muted);font-size:15px;font-weight:400">v${esc(scan.resolvedVersion)}</span>
          <span class="dep-hdr-stats" style="margin-left:10px;font-size:11px;color:var(--muted);font-weight:500;display:inline-flex;gap:10px;align-items:center">
            <span>&#128230; ${totalCount} total</span>
            <span style="color:#a78bfa">&#8679; ${directCount} direct</span>
            <span style="color:#3b82f6">&#8681; ${transitiveCount} transitive</span>
            ${noVulnsHtml}
          </span>
        </div>
        <div class="detail-sub">${sysInfo.label} &middot; ${esc(scan.desc||'No description')} &middot; scanned ${fmtDate(scan.scannedAt)}</div>
        <div style="display:flex;flex-wrap:wrap;align-items:center;gap:6px;margin-top:6px" onclick="event.stopPropagation()">
          ${_toxicBadgeHtml(scan.toxic)}
          <div id="depDetailActivityBadge"><span style="font-size:11px;color:var(--muted)">&#9203; Checking activity&#8230;</span></div>
        </div>
      </div>
      <div class="detail-chips" style="display:flex;flex-direction:column;align-items:flex-end;gap:8px;flex-shrink:0" onclick="event.stopPropagation()">
        <div style="display:flex;flex-wrap:wrap;gap:6px;justify-content:flex-end">${chipsHtml}</div>
        ${exportBtn}
      </div>
    </div>
    ${rootVulnsHtml}
    ${depSection(direct,   'Direct Dependencies',    false,'direct')}
    ${depSection(indirect, 'Transitive Dependencies', true, 'transitive')}
    ${emptyHtml}`;

  window._currentDepScanDeps=allDeps;
  window._currentDepScanRoot = rootDep || {
    name:scan.package, system:scan.system, version:scan.resolvedVersion,
    relation:'ROOT', toxic:scan.toxic||{found:false},
    topSeverity:['CRITICAL','HIGH','MEDIUM','LOW'].find(s=>rootCnt[s]>0)||'NONE',
    vulnCount:(rootCnt.CRITICAL||0)+(rootCnt.HIGH||0)+(rootCnt.MEDIUM||0)+(rootCnt.LOW||0),
    counts:rootCnt,
    vulns:rootVulns,
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
  const sysInfo=DEP_SYSTEMS.find(x=>x.id===(dep.system||scan?.system))||{logo:'📦',label:dep.system||'Unknown'};
  const cnt=dep.counts||{};
  const chips=['CRITICAL','HIGH','MEDIUM','LOW'].filter(sv=>cnt[sv])
    .map(sv=>`<span class="sev ${sv}">${cnt[sv]} ${sv}</span>`).join('');

  function toxicBadgeHtml(toxic){
    if(!toxic?.found) return '<span style="display:inline-flex;align-items:center;gap:5px;font-size:10px;background:rgba(52,199,89,.1);color:#34c759;border:1px solid rgba(52,199,89,.3);padding:2px 9px;border-radius:12px">&#x2705; Toxic repos: not found</span>';
    const LABELS={ddos:'DDoS tool',hostile_actions:'Hostile actions',political_slogan:'Political slogan',malware:'Malware',ip_blocking:'IP blocking'};
    const label=LABELS[toxic.problem_type]||toxic.problem_type||'Toxic';
    const fullDesc=toxic.description||'';
    const preview=fullDesc.length>60?fullDesc.slice(0,60):fullDesc;
    const moreBtn=fullDesc.length>60
      ?`<button onclick="this.parentElement.querySelector('.toxic-full').style.display='inline';this.remove()" style="background:none;border:none;color:inherit;opacity:.75;cursor:pointer;font-size:10px;padding:0;text-decoration:underline;margin-left:2px">&#8230;</button><span class="toxic-full" style="display:none">${esc(fullDesc.slice(60))}</span>`
      :'';
    return`<span style="display:inline-flex;align-items:center;flex-wrap:wrap;gap:4px;font-size:10px;background:rgba(255,59,48,.12);color:#ff3b30;border:1px solid rgba(255,59,48,.35);padding:3px 10px;border-radius:12px">&#9760; <strong>Toxic: ${esc(label)}</strong>${fullDesc?' — '+esc(preview)+moreBtn:''}</span>`;
  }

  const chipsOrClean=dep.vulns?.length===0?'<span class="sev NONE">&#x2705; CLEAN</span>':chips;
  const relationHtml=(dep.relation&&dep.relation!=='ROOT')
    ?` &middot; <span style="color:${dep.relation==='DIRECT'?'#a78bfa':'var(--muted)'}">${dep.relation}</span> &middot; from ${esc(scan?.package||'—')}`
    :'';
  const emptyMsg=dep.relation==='ROOT'
    ?'<div style="text-align:center;padding:60px;color:var(--l);font-size:15px">&#x1F6E1;&#xFE0F; No vulnerabilities found in this library!</div>'
    :'<div style="text-align:center;padding:60px;color:var(--l);font-size:15px">&#x1F6E1;&#xFE0F; No vulnerabilities found for this dependency!</div>';
  const vulnsHtml=dep.vulns?.length===0
    ?emptyMsg
    :`<div id="depPkgVulnCards">${(dep.vulns||[]).map((v,vi)=>depVulnCardHtml(dep,v,vi)).join('')}</div>`;

  el.innerHTML=`
    <div class="detail-header">
      <div class="detail-icon" style="background:rgba(167,139,250,.1);border:1px solid rgba(167,139,250,.25);font-size:22px;display:flex;align-items:center;justify-content:center">${sysInfo.logo}</div>
      <div class="detail-info">
        <div class="detail-name" style="font-size:24px">${esc(dep.name)} <span style="color:var(--muted);font-size:15px;font-weight:400">v${esc(dep.version)}</span></div>
        <div class="detail-sub">${sysInfo.label}${relationHtml}</div>
        <div style="display:flex;flex-wrap:wrap;align-items:center;gap:6px;margin-top:6px">
          <div>${toxicBadgeHtml(dep.toxic)}</div>
          <div id="depPkgActivityBadge"><span style="font-size:11px;color:var(--muted)">&#9203; Checking activity&#8230;</span></div>
        </div>
      </div>
      <div class="detail-chips">${chipsOrClean}</div>
    </div>
    ${vulnsHtml}`;

  if(dep.vulns?.length) enrichDepPkgVulns(dep.vulns);
  checkActivity('depPkgActivityBadge', dep.name, dep.system||scan?.system);
}

function depVulnCardHtml(dep,v,vi){
  const cveId=[...(v.aliases||[]),v.id].find(x=>x.startsWith('CVE-'))||v.id;
  const cveLink=cveId.startsWith('CVE-')
    ?`<a href="https://nvd.nist.gov/vuln/detail/${esc(cveId)}" target="_blank" onclick="event.stopPropagation()" style="color:var(--accent);font-weight:700;font-size:11px;text-decoration:none">${esc(cveId)} &#8599;</a><span style="color:var(--muted);font-size:10px;margin:0 5px">/</span>`
    :'';
  const loading='<span style="color:var(--muted);font-size:11px">loading&#8230;</span>';
  const fixRow =v.fix?`<span class="vk">Fixed in</span><span class="vv"><span class="fix-tag">&#8594; ${esc(v.fix)}</span></span>`:'';
  const descText2=v.details||v.summary||'';
  const detRow =descText2?`<span class="vk">Description</span><span class="vv" style="white-space:pre-wrap;line-height:1.5">${esc(descText2.slice(0,500))}${descText2.length>500?'&#8230;':''}</span>`:'';
  const nvdScore2=v.cvss?.cvss3?.score||null;
  const nvdSev2  =nvdScore2?(nvdScore2>=9?'CRITICAL':nvdScore2>=7?'HIGH':nvdScore2>=4?'MEDIUM':'LOW'):null;
  const nvdRow2  =nvdScore2?`<span class="vk">NVD Score</span><span class="vv"><span class="sev ${nvdSev2}" style="font-size:10px;padding:1px 7px">${nvdScore2}</span> <span style="color:var(--muted);font-size:10px">${v.cvss.cvss3.vector||''}</span></span>`:'';
  const pubRow =v.published?`<span class="vk">Published</span><span class="vv">${new Date(v.published).toLocaleDateString('en-US',{year:'numeric',month:'short',day:'numeric'})}</span>`:'';
  const refsRow=(v.refs||[]).length
    ?`<span class="vk">References</span><span class="vv" style="line-height:2">${v.refs.slice(0,4).map(u=>{const su=safeUrl(u);return su==='#'?'':`<a href="${esc(su)}" target="_blank" rel="noopener noreferrer">${esc(u.length>60?u.slice(0,60)+'&#8230;':u)}</a>`;}).filter(Boolean).join('<br/>')}</span>`
    :'';
  return`<div class="vi" id="dpvi-${vi}">
    <div class="vi-hdr" onclick="toggleDPVI(${vi})">
      <div class="vbar ${v.severity}"></div>
      <div class="vi-id">
        ${cveLink}
        <span style="opacity:.7">${esc(v.id)}</span>
        <span class="vi-cvss-inline" id="dpvcvss-${vi}"></span>
      </div>
      <div class="vi-sum">${esc(v.summary||'No summary')}</div>
      <span class="enrich-badges" id="dpveb-${vi}"></span>
      <span class="vi-sev ${v.severity}">${v.severity}</span>
      <span class="vi-chev">&#9660;</span>
    </div>
    <div class="vi-body" id="dpvib-${vi}">
      <div class="vgrid">
        <span class="vk">OSV ID</span><span class="vv"><a href="https://osv.dev/vulnerability/${esc(v.id)}" target="_blank">${esc(v.id)} &#8599;</a></span>
        <span class="vk">CVSS</span><span class="vv" id="dpvcvssv-${vi}">${v.cvss?cvssHtml(v.cvss):loading}</span>
        ${nvdRow2}
        <span class="vk">EPSS</span><span class="vv" id="dpvepss-${vi}">${v.epss?epssHtml(v.epss):loading}</span>
        ${detRow}${fixRow}${pubRow}${refsRow}
        <span class="vk">CISA KEV</span><span class="vv" id="dpvkev-${vi}">${kevBadge(v.inKev)}</span>
        <span class="vk">PoC (GitHub)</span><span class="vv" id="dpvpoc-${vi}">${pocBadge(v.pocs||[])}</span>
      </div>
    </div>
  </div>`;
}

function toggleDPVI(vi){
  const el  =document.getElementById('dpvi-'+vi);
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
      if(v.inKev)    hb+=`<span title="CISA Known Exploited" style="background:#ff3b30;color:#fff;font-size:9px;font-weight:700;padding:2px 6px;border-radius:4px;margin-right:3px">&#128293; KEV</span>`;
      if(v.pocs?.length) hb+=`<span title="${v.pocs.length} PoC(s)" style="background:#ff9500;color:#000;font-size:9px;font-weight:700;padding:2px 6px;border-radius:4px;margin-right:3px">&#128165; PoC&#215;${v.pocs.length}</span>`;
      eb.innerHTML=hb;
    }
  });
}

document.addEventListener('keydown',e=>{
  if(e.key==='Escape'&&document.getElementById('depModal').style.display!=='none') closeDepModal();
  if(e.key==='Enter' &&document.getElementById('depModal').style.display!=='none') doDepScan();
});