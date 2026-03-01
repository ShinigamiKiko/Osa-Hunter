// Split from 50-pages.js to keep files smaller. Logic unchanged.

function openDepPkg(idx){
  const dep=idx===-1?window._currentDepScanRoot:window._currentDepScanDeps[idx];
  if(!dep) return;
  navTo('dep-pkg',{dep,scan:currentDepScan,backScan:currentDepScan});
}

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
