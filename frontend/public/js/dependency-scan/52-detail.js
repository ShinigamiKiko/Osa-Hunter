// Split from 50-pages.js to keep files smaller. Logic unchanged.

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
              style="font-size:17px;font-weight:700;color:#fff;text-decoration:none"
              onmouseover="this.style.textDecoration='underline'" onmouseout="this.style.textDecoration='none'">${esc(dep.name)}</a>
            <span style="color:var(--muted);font-size:14px;margin-left:7px">${esc(dep.version)}</span>
            ${fixBadge}${toxicBadge}
          </div>
          <div style="display:flex;align-items:center;gap:6px">
            ${cveCount?pills:cleanBadge}
            ${cveLabel}
            <span class="pkg-chev" id="dcard-chev-${depIdx}" style="color:var(--muted);font-size:10px;transition:transform .18s;margin-left:4px">&#9660;</span>
          </div>
        </div>

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

  // Root package vuln section — always rendered; green when clean, red when has vulns
  const rootPills = ['CRITICAL','HIGH','MEDIUM','LOW'].filter(k=>rootCnt[k])
    .map(k=>`<span class="sev ${k}" style="font-size:9px;padding:1px 6px">${rootCnt[k]}</span>`).join('');
  const rootIsClean  = rootVulns.length === 0;
  const rootAccent   = rootIsClean ? '#34c759'            : '#ff3b30';
  const rootRgb      = rootIsClean ? '52,199,89'          : '255,59,48';
  const rootTagBg    = rootIsClean ? 'rgba(52,199,89,.12)' : 'rgba(255,59,48,.12)';
  const rootTagBr    = rootIsClean ? 'rgba(52,199,89,.35)' : 'rgba(255,59,48,.35)';
  const rootTagIcon  = rootIsClean ? '&#x2705;'           : '&#9888;';
  const rootRight    = rootIsClean
    ? `<span style="color:#34c759;font-size:11px">&#x2705; clean</span>`
    : rootPills;
  const rootBodyHtml = rootIsClean
    ? `<div style="padding:16px 20px;color:var(--l);font-size:12px">&#x2705; No own vulnerabilities found</div>`
    : rootVulns.map((v,vi)=>depMiniVulnRow(v,vi,-1)).join('');
  const rootVulnsHtml = `<div style="margin-bottom:20px">
      <div onclick="toggleDepSection('root')"
        style="display:flex;align-items:center;gap:10px;padding:9px 14px;border-left:3px solid ${rootAccent};background:rgba(${rootRgb},.06);border-radius:0 8px 8px 0;cursor:pointer;user-select:none;transition:background .13s"
        onmouseover="this.style.background='rgba(${rootRgb},.12)'"
        onmouseout="this.style.background='rgba(${rootRgb},.06)'">
        <span style="font-size:11px;font-weight:700;padding:2px 9px;border-radius:5px;background:${rootTagBg};border:1px solid ${rootTagBr};color:${rootAccent}">${rootTagIcon} Own Vulnerabilities</span>
        <span style="font-size:13px;font-weight:600;color:#fff">${esc(scan.package)}</span>
        <span style="color:var(--muted);font-size:11px">(${rootVulns.length})</span>
        <span style="margin-left:auto;display:flex;gap:5px;align-items:center">
          ${rootRight}
          <span id="depsec-chev-root" style="color:var(--muted);font-size:10px;transition:transform .18s;margin-left:6px;transform:rotate(180deg)">&#9660;</span>
        </span>
      </div>
      <div id="depsec-body-root" style="display:block;margin-top:8px">
        ${rootBodyHtml}
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
          ${esc(scan.package)} <span style="color:var(--muted);font-size:15px;font-weight:400">${esc(scan.resolvedVersion)}</span>
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
