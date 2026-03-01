// enrich.js — render helpers для данных обогащения (CVSS, EPSS, KEV, PoC)
// Данные приходят уже готовые из /api/libscan и /api/depscan — API вызовов нет

function cvssHtml(entry){
  if(!entry||(!entry.cvss3&&!entry.cvss2))
    return '<span style="color:var(--muted);font-size:11px">not in NVD</span>';
  let out='';
  if(entry.cvss3){
    const s=entry.cvss3.score,cls=s>=9?'CRITICAL':s>=7?'HIGH':s>=4?'MEDIUM':'LOW';
    out+=`<span class="sev ${cls}" style="font-size:10px;padding:2px 7px;margin-right:5px">${s} ${entry.cvss3.severity||cls}</span><span style="color:var(--muted);font-size:10px;margin-right:10px">CVSSv${entry.cvss3.version||3}</span>`;
  }
  if(entry.cvss2){
    const s=entry.cvss2.score,cls=s>=7?'HIGH':s>=4?'MEDIUM':'LOW';
    out+=`<span class="sev ${cls}" style="font-size:10px;padding:2px 7px;margin-right:5px;opacity:.7">${s}</span><span style="color:var(--muted);font-size:10px">CVSSv2</span>`;
  }
  return out;
}

function epssHtml(score){
  if(!score) return '<span style="color:var(--muted);font-size:11px">not found</span>';
  const pct=(score.epss*100).toFixed(2);
  const cls=score.epss>=.1?'hi':score.epss>=.01?'mi':'';
  return `<div class="epss-row">
    <span class="epss-pct ${cls}">${pct}%</span>
    <div class="epss-bar"><div class="epss-fill ${cls}" style="width:${Math.min(score.epss*500,100)}%"></div></div>
    <span style="font-size:10px;color:var(--muted)">${(score.percentile*100).toFixed(0)}th pct</span>
  </div>`;
}

function kevBadge(found){
  if(found)
    return `<span style="display:inline-flex;align-items:center;gap:4px;background:rgba(255,59,48,.15);border:1px solid #ff3b30;color:#ff3b30;font-size:11px;font-weight:600;padding:3px 10px;border-radius:6px">🔥 Found in CISA KEV — actively exploited</span>`;
  return `<span style="display:inline-flex;align-items:center;gap:4px;background:rgba(52,199,89,.1);border:1px solid rgba(52,199,89,.5);color:#34c759;font-size:11px;font-weight:600;padding:3px 10px;border-radius:6px">✅ Not in CISA KEV</span>`;
}

function pocBadge(pocs){
  if(!pocs||!pocs.length)
    return `<span style="display:inline-flex;align-items:center;gap:4px;background:rgba(52,199,89,.1);border:1px solid rgba(52,199,89,.5);color:#34c759;font-size:11px;font-weight:600;padding:3px 10px;border-radius:6px">✅ No public PoC found</span>`;
  return pocs.map(p=>
    `<a href="${p.url}" target="_blank" style="display:inline-flex;align-items:center;gap:5px;background:rgba(255,149,0,.12);border:1px solid #ff9500;color:#ff9500;font-size:11px;font-weight:600;padding:3px 10px;border-radius:6px;text-decoration:none;margin-right:4px;margin-bottom:3px">💥 ${esc(p.name)} ⭐${p.stars}</a>`
  ).join('');
}

// Рендерит обогащение прямо из объектов вулнов (данные уже в scan)
function renderStoredEnrichment(vulns, scope){
  for(const v of vulns){
    const cveId=[...(v._aliases||v.aliases||[]),(v._sev?v.id:v.cve)||v.id].find(x=>x?.startsWith('CVE-'))||v.cve||v.id;

    const cvssHdr=document.getElementById(`cvss-hdr-${scope}-${cveId}`);
    if(cvssHdr&&v.cvss?.cvss3){
      const s=v.cvss.cvss3.score,cls=s>=9?'CRITICAL':s>=7?'HIGH':s>=4?'MEDIUM':'LOW';
      cvssHdr.innerHTML=`<span class="sev ${cls}" style="font-size:9px;padding:1px 6px">${s}</span>`;
    }

    const eb=document.getElementById(`eb-${scope}-${cveId}`);
    if(eb){
      let h='';
      if(v.inKev) h+=`<span title="CISA Known Exploited" style="background:#ff3b30;color:#fff;font-size:9px;font-weight:700;padding:2px 6px;border-radius:4px;margin-right:3px">🔥 KEV</span>`;
      if((v.pocs||[]).length) h+=`<span title="${v.pocs.length} PoC(s)" style="background:#ff9500;color:#000;font-size:9px;font-weight:700;padding:2px 6px;border-radius:4px;margin-right:3px">💥 PoC×${v.pocs.length}</span>`;
      eb.innerHTML=h;
    }

    const cvssEl=document.getElementById(`cvss-${scope}-${cveId}`);
    if(cvssEl) cvssEl.innerHTML=cvssHtml(v.cvss);

    const nvdEl=document.getElementById(`nvd-${scope}-${cveId}`);
    if(nvdEl){
      if(v.cvss?.cvss3){
        const s=v.cvss.cvss3.score,cls=s>=9?'CRITICAL':s>=7?'HIGH':s>=4?'MEDIUM':'LOW';
        nvdEl.innerHTML=`<span class="sev ${cls}" style="font-size:10px;padding:1px 7px">${s}</span><span style="color:var(--muted);font-size:10px;margin-left:7px">${v.cvss.cvss3.vector||''}</span>`;
      } else {
        nvdEl.innerHTML='<span style="color:var(--muted);font-size:11px">not in NVD</span>';
      }
    }

    const epssEl=document.getElementById(`epss-${scope}-${cveId}`);
    if(epssEl) epssEl.innerHTML=epssHtml(v.epss);

    const kevEl=document.getElementById(`kev-${scope}-${cveId}`);
    if(kevEl) kevEl.innerHTML=kevBadge(v.inKev);

    const pocEl=document.getElementById(`poc-${scope}-${cveId}`);
    if(pocEl) pocEl.innerHTML=pocBadge(v.pocs||[]);
  }
}
