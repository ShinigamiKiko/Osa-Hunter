// Split from 50-pages.js to keep files smaller. Logic unchanged.

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
