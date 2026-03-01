// Split from 50-pages.js to keep files smaller. Logic unchanged.

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
