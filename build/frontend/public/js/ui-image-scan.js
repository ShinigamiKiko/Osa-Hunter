// ── IMAGE SCAN ───────────────────────────────────────────────
let imgScans = safeLoad('es_img', []);
const saveImg = () => safeSave('es_img', imgScans);

function whaleSmallSvg(){ return`<span style="font-size:22px;line-height:1">🐋</span>`; }

async function doImageScan(){
  const image=document.getElementById('imgName').value.trim();
  const tag  =document.getElementById('imgTag').value.trim()||'latest';
  const desc =document.getElementById('imgDesc').value.trim();
  document.getElementById('imgErr').style.display='none';
  if(!image){ showErr('imgErr','Enter an image name'); return; }
  setBtn('btnImgScan',true,'Scanning...');
  try{
    const r=await fetch('/api/trivy/scan',{method:'POST',
      headers:{'Content-Type':'application/json'},body:JSON.stringify({image,tag,desc})});
    const data=await r.json();
    if(!r.ok) throw new Error(data.error||`Error ${r.status}`);
    const results=data.Results||[];
    const allV=[]; results.forEach(t=>(t.Vulnerabilities||[]).forEach(v=>allV.push(v)));
    allV.sort((a,b)=>SEV_ORD.indexOf((a.Severity||'UNKNOWN').toUpperCase())-SEV_ORD.indexOf((b.Severity||'UNKNOWN').toUpperCase()));
    const counts={CRITICAL:0,HIGH:0,MEDIUM:0,LOW:0,UNKNOWN:0};
    allV.forEach(v=>{ const s=(v.Severity||'UNKNOWN').toUpperCase(); if(s in counts) counts[s]++; });
    const scan={id:Date.now(),image,tag,desc,vulns:allV,counts,scannedAt:new Date().toISOString()};
    imgScans.unshift(scan);
    if(imgScans.length>20) imgScans=imgScans.slice(0,20);
    saveImg(); navTo('img-list');
  }catch(e){ showErr('imgErr',e.message||'Scan failed. Is Trivy running?'); }
  setBtn('btnImgScan',false,'Scan Image');
}

// ── LIST PAGE ─────────────────────────────────────────────────
function renderImgList(){
  const el=document.getElementById('imgListContent');
  if(!imgScans.length){
    el.innerHTML=`<div class="empty">
      <div class="empty-rings"><div class="ering"></div><div class="ering"></div><div class="ering"></div><div class="ering-c">🐋</div></div>
      <h2>No image scans yet</h2>
      <p>Scan a Docker image to see vulnerability results</p>
      <button class="btn-primary blue-btn" onclick="navTo('img-form')">+ New scan</button>
    </div>`; return;
  }
  el.innerHTML=`
    <div style="display:flex;justify-content:flex-end;margin-bottom:14px">
      <button class="btn-secondary" onclick="if(confirm('Clear all image scans?')){imgScans=[];saveImg();renderImgList()}">Clear all</button>
    </div>
    <div class="tbl-wrap">
      <table class="tbl">
        <thead><tr>
          <th>Image</th><th>Description</th><th>Tag</th>
          <th>Top Severity</th><th>Findings</th><th>Scanned</th><th style="width:28px"></th>
        </tr></thead>
        <tbody>
          ${imgScans.map((s,i)=>{
            const topS=['CRITICAL','HIGH','MEDIUM','LOW'].find(sv=>s.counts[sv])||'NONE';
            const pills=['CRITICAL','HIGH','MEDIUM','LOW'].filter(sv=>s.counts[sv])
              .map(sv=>`<span class="sev ${sv}" style="font-size:9px;padding:2px 6px">${s.counts[sv]} ${sv}</span>`).join(' ');
            return`<tr class="row" onclick="navTo('img-detail',{scan:imgScans[${i}]})">
              <td><div style="display:flex;align-items:center;gap:9px">
                <div style="flex-shrink:0">${whaleSmallSvg()}</div>
                <div class="row-name">${esc(s.image)}</div>
              </div></td>
              <td><div class="row-desc">${esc(s.desc||'—')}</div></td>
              <td><span class="row-ver">${esc(s.tag)}</span></td>
              <td><span class="sev ${topS}">${topS}</span></td>
              <td>${s.vulns.length===0
                ?'<span style="color:var(--l);font-size:11px">✓ clean</span>'
                :(pills||`<span style="color:var(--muted)">${s.vulns.length}</span>`)}</td>
              <td style="color:var(--muted);font-size:10px;white-space:nowrap">${fmtDate(s.scannedAt)}</td>
              <td><button onclick="event.stopPropagation();imgScans.splice(${i},1);saveImg();renderImgList()"
                style="background:none;border:none;color:var(--muted);cursor:pointer;font-size:13px;padding:3px 5px;border-radius:4px"
                onmouseover="this.style.color='var(--c)'" onmouseout="this.style.color='var(--muted)'">✕</button></td>
            </tr>`;
          }).join('')}
        </tbody>
      </table>
    </div>`;
}

// ── DETAIL PAGE ───────────────────────────────────────────────
function renderImgDetail(s){
  const el=document.getElementById('imgDetailContent');
  const chips=['CRITICAL','HIGH','MEDIUM','LOW'].filter(sv=>s.counts[sv])
    .map(sv=>`<span class="sev ${sv}">${s.counts[sv]} ${sv}</span>`).join('');

  const SEV_W = {CRITICAL:4,HIGH:3,MEDIUM:2,LOW:1,UNKNOWN:0};

  // ── Group vulns by package name ──────────────────────────────
  const groups = new Map(); // pkgName → {vulns[], topW, counts{}}
  for(const v of (s.vulns||[])){
    const pkg = v.PkgName||'unknown';
    if(!groups.has(pkg)) groups.set(pkg, {vulns:[], topW:0, counts:{CRITICAL:0,HIGH:0,MEDIUM:0,LOW:0,UNKNOWN:0}});
    const g = groups.get(pkg);
    g.vulns.push(v);
    const sev = (v.Severity||'UNKNOWN').toUpperCase();
    if(sev in g.counts) g.counts[sev]++;
    g.topW = Math.max(g.topW, SEV_W[sev]||0);
  }

  // Sort groups: first by topSev desc, then by total vuln count desc
  const sorted = [...groups.entries()].sort((a,b)=>{
    if(b[1].topW !== a[1].topW) return b[1].topW - a[1].topW;
    return b[1].vulns.length - a[1].vulns.length;
  });

  // Sort vulns inside each group by severity
  for(const [,g] of sorted)
    g.vulns.sort((a,b)=>(SEV_W[(b.Severity||'UNKNOWN').toUpperCase()]||0) - (SEV_W[(a.Severity||'UNKNOWN').toUpperCase()]||0));

  // Assign global indices for toggleIVI
  let globalVi = 0;
  const groupHtml = sorted.map(([pkgName, g])=>{
    const topSev = ['CRITICAL','HIGH','MEDIUM','LOW'].find(s=>g.counts[s])||'UNKNOWN';
    const pills = ['CRITICAL','HIGH','MEDIUM','LOW'].filter(sv=>g.counts[sv])
      .map(sv=>`<span class="sev ${sv}" style="font-size:9px;padding:1px 6px">${g.counts[sv]}</span>`).join('');
    const pkgVer = g.vulns[0]?.InstalledVersion ? `<span style="color:var(--muted);font-size:11px;margin-left:6px">v${esc(g.vulns[0].InstalledVersion)}</span>` : '';
    const fixedVer= g.vulns.find(v=>v.FixedVersion)?.FixedVersion;
    const fixTag  = fixedVer ? `<span class="fix-tag" style="font-size:10px">→ ${esc(fixedVer)}</span>` : '';

    const cardsHtml = g.vulns.map(v=>{
      const vi = globalVi++;
      return imgVulnCardHtml(v, vi);
    }).join('');

    return `<div class="pkg-group" style="margin-bottom:20px">
      <div class="pkg-group-hdr" onclick="togglePkgGroup(this)" style="
        display:flex;align-items:center;gap:10px;
        padding:11px 16px;
        background:var(--s2);border:1px solid var(--br);border-radius:11px;
        cursor:pointer;transition:background .13s;user-select:none;
        margin-bottom:0" onmouseover="this.style.background='var(--s3)'" onmouseout="this.style.background='var(--s2)'">
        <div class="vbar ${topSev}" style="height:28px"></div>
        <div style="flex:1;min-width:0">
          <span style="font-size:14px;font-weight:600;color:#fff">${esc(pkgName)}</span>
          ${pkgVer}${fixTag?'<span style="margin-left:8px">'+fixTag+'</span>':''}
        </div>
        <div style="display:flex;align-items:center;gap:6px">
          ${pills}
          <span style="font-size:11px;color:var(--muted);margin-left:4px">${g.vulns.length} CVE${g.vulns.length>1?'s':''}</span>
          <span class="pkg-chev" style="color:var(--muted);font-size:10px;transition:transform .18s;margin-left:4px">▼</span>
        </div>
      </div>
      <div class="pkg-group-body" style="display:none;margin-top:2px">
        ${cardsHtml}
      </div>
    </div>`;
  }).join('');

  el.innerHTML=`
    <div class="detail-header">
      <div class="detail-icon blue" style="display:flex;align-items:center;justify-content:center">${whaleSmallSvg()}</div>
      <div class="detail-info">
        <div class="detail-name">${esc(s.image)}:${esc(s.tag)}</div>
        <div class="detail-sub">${s.vulns.length} vulnerabilit${s.vulns.length===1?'y':'ies'} across ${sorted.length} package${sorted.length!==1?'s':''}${s.desc?' · '+esc(s.desc):''}  ·  scanned ${fmtDate(s.scannedAt)}</div>
      </div>
      <div class="detail-chips" style="display:flex;flex-direction:column;align-items:flex-end;gap:8px">
        <div style="display:flex;flex-wrap:wrap;gap:6px;justify-content:flex-end">
          ${chips||'<span class="sev NONE">✅ CLEAN</span>'}
        </div>
        ${exportBtnHtml('img', {image:s.image,tag:s.tag||'latest',desc:s.desc||''})}
      </div>
    </div>
    ${s.vulns.length===0
      ?'<div style="text-align:center;padding:60px;color:var(--l);font-size:14px">🐳 No vulnerabilities found — this image is clean!</div>'
      :groupHtml}`;

  // Expand first group automatically
  const firstBody = el.querySelector('.pkg-group-body');
  const firstChev = el.querySelector('.pkg-chev');
  if(firstBody){ firstBody.style.display='block'; if(firstChev) firstChev.style.transform='rotate(180deg)'; }

  if(s.vulns.length){
    // Normalize Trivy vuln objects so renderStoredEnrichment can fill CVSS/NVD/EPSS/KEV/PoC
    s.vulns.forEach(v=>{
      if(!v.id) v.id = v.VulnerabilityID || '';
      if(!v.aliases) v.aliases = [v.VulnerabilityID].filter(Boolean);
      // Map Trivy CVSS → internal format {cvss3:{score,vector}, cvss2:{score,vector}}
      if(!v.cvss && v.CVSS){
        const nvd = v.CVSS.nvd || v.CVSS.NVD || Object.values(v.CVSS)[0] || {};
        const cvss = {};
        if(nvd.V3Score != null) cvss.cvss3 = { score: nvd.V3Score, vector: nvd.V3Vector || '', version: '3' };
        if(nvd.V2Score != null) cvss.cvss2 = { score: nvd.V2Score, vector: nvd.V2Vector || '' };
        if(cvss.cvss3 || cvss.cvss2) v.cvss = cvss;
      }
    });
    renderStoredEnrichment(s.vulns, 'img');
  }
}

function togglePkgGroup(hdr){
  const body = hdr.nextElementSibling;
  const chev = hdr.querySelector('.pkg-chev');
  if(!body) return;
  const open = body.style.display !== 'none';
  body.style.display = open ? 'none' : 'block';
  if(chev) chev.style.transform = open ? '' : 'rotate(180deg)';
}

function imgVulnCardHtml(v,vi){
  const sev=(v.Severity||'UNKNOWN').toUpperCase();
  const cveId=v.VulnerabilityID||'';
  const title=v.Title||v.Description||'No description';
  return`<div class="vi" id="ivi-${vi}">
    <div class="vi-hdr" onclick="toggleIVI(${vi})">
      <div class="vbar ${sev}"></div>
      <div class="vi-id">
        ${cveId.startsWith('CVE-')?`<a href="https://nvd.nist.gov/vuln/detail/${esc(cveId)}" target="_blank" onclick="event.stopPropagation()" style="color:var(--accent);font-weight:700;font-size:11px;text-decoration:none">${esc(cveId)} &#8599;</a>`:`<span style="opacity:.7">${esc(cveId)}</span>`}
        <span class="vi-cvss-inline" id="cvss-hdr-img-${cveId}"></span>
      </div>
      <div class="vi-sum">${esc(title.length>80?title.slice(0,80)+'…':title)}</div>
      <span class="enrich-badges" id="eb-img-${cveId}"></span>
      <span class="vi-sev ${sev}">${sev}</span>
      <span class="vi-chev">▼</span>
    </div>
    <div class="vi-body" id="ivib-${vi}" style="display:none">
      <div class="vgrid">
        <span class="vk">CVE ID</span><span class="vv"><a href="https://avd.aquasec.com/nvd/${esc(cveId.toLowerCase())}" target="_blank">${esc(cveId)} ↗</a></span>
        <span class="vk">Package</span><span class="vv" style="color:#fff;font-weight:500">${esc(v.PkgName||'—')}</span>
        <span class="vk">Installed</span><span class="vv" style="color:var(--muted)">${esc(v.InstalledVersion||'—')}</span>
        ${v.FixedVersion?`<span class="vk">Fixed in</span><span class="vv"><span class="fix-tag">→ ${esc(v.FixedVersion)}</span></span>`:''}
        ${v.Title?`<span class="vk">Title</span><span class="vv">${esc(v.Title)}</span>`:''}
        ${v.Description?`<span class="vk">Description</span><span class="vv" style="white-space:pre-wrap" id="idesc-${vi}">${esc(v.Description.slice(0,480))}${v.Description.length>480?`<span id="idesc-dots-${vi}"> <button data-full="${esc(v.Description)}" onclick="expandIDesc(${vi},this)" style="background:none;border:none;color:var(--accent);cursor:pointer;font-size:11px;padding:0;text-decoration:underline">… show more</button></span>`:''}</span>`:''}
        ${v.PublishedDate?`<span class="vk">Published</span><span class="vv">${new Date(v.PublishedDate).toLocaleDateString('en-US',{year:'numeric',month:'short',day:'numeric'})}</span>`:''}
        ${v.PrimaryURL?`<span class="vk">Reference</span><span class="vv"><a href="${esc(safeUrl(v.PrimaryURL))}" target="_blank" rel="noopener noreferrer">${esc(v.PrimaryURL.length>60?v.PrimaryURL.slice(0,60)+'…':v.PrimaryURL)}</a></span>`:''}
        <span class="vk">CVSS</span><span class="vv" id="cvss-img-${cveId}"><span style="color:var(--muted);font-size:11px">loading…</span></span>
        <span class="vk">NVD Score</span><span class="vv" id="nvd-img-${cveId}"><span style="color:var(--muted);font-size:11px">loading…</span></span>
        <span class="vk">EPSS</span><span class="vv" id="epss-img-${cveId}"><span style="color:var(--muted);font-size:11px">loading…</span></span>
        <span class="vk">CISA KEV</span><span class="vv" id="kev-img-${cveId}"><span style="color:var(--muted);font-size:11px">loading…</span></span>
        <span class="vk">PoC (GitHub)</span><span class="vv" id="poc-img-${cveId}"><span style="color:var(--muted);font-size:11px">loading…</span></span>
      </div>
    </div>
  </div>`;
}

function expandIDesc(vi,btn){
  const el=document.getElementById('idesc-'+vi);
  const dots=document.getElementById('idesc-dots-'+vi);
  if(!el||!dots) return;
  dots.remove(); el.textContent=btn.getAttribute('data-full');
}

function toggleIVI(vi){
  const el=document.getElementById('ivi-'+vi);
  const body=document.getElementById('ivib-'+vi);
  if(!el||!body) return;
  const open=el.classList.contains('open');
  el.classList.toggle('open',!open);
  body.style.display=open?'none':'block';
}
