// ── ENRICHMENT BADGES ────────────────────────────────────────
function cvssHtml(entry){
  if(!entry||(!entry.cvss3&&!entry.cvss2)) return '<span style="color:var(--muted);font-size:11px">not in NVD</span>';
  let out='';
  if(entry.cvss3){
    const s=entry.cvss3.score;
    const cls=s>=9?'CRITICAL':s>=7?'HIGH':s>=4?'MEDIUM':'LOW';
    out+=`<span class="sev ${cls}" style="font-size:10px;padding:2px 7px;margin-right:5px">${s} ${entry.cvss3.severity||cls}</span><span style="color:var(--muted);font-size:10px;margin-right:10px">CVSSv${entry.cvss3.version||3}</span>`;
  }
  if(entry.cvss2){
    const s=entry.cvss2.score;
    const cls=s>=7?'HIGH':s>=4?'MEDIUM':'LOW';
    out+=`<span class="sev ${cls}" style="font-size:10px;padding:2px 7px;margin-right:5px;opacity:.7">${s}</span><span style="color:var(--muted);font-size:10px">CVSSv2</span>`;
  }
  return out;
}

function kevBadge(found){
  if(found) return `<span style="display:inline-flex;align-items:center;gap:4px;background:rgba(255,59,48,.15);border:1px solid #ff3b30;color:#ff3b30;font-size:11px;font-weight:600;padding:3px 10px;border-radius:6px">🔥 Found in CISA KEV — actively exploited</span>`;
  return `<span style="display:inline-flex;align-items:center;gap:4px;background:rgba(52,199,89,.1);border:1px solid rgba(52,199,89,.5);color:#34c759;font-size:11px;font-weight:600;padding:3px 10px;border-radius:6px">✅ Not in CISA KEV</span>`;
}

function pocBadge(pocs){
  if(!pocs||!pocs.length) return `<span style="display:inline-flex;align-items:center;gap:4px;background:rgba(52,199,89,.1);border:1px solid rgba(52,199,89,.5);color:#34c759;font-size:11px;font-weight:600;padding:3px 10px;border-radius:6px">✅ No public PoC found</span>`;
  return pocs.map(p=>`<a href="${esc(safeUrl(p.url))}" target="_blank" rel="noopener noreferrer" style="display:inline-flex;align-items:center;gap:5px;background:rgba(255,149,0,.12);border:1px solid #ff9500;color:#ff9500;font-size:11px;font-weight:600;padding:3px 10px;border-radius:6px;text-decoration:none;margin-right:4px;margin-bottom:3px">💥 ${esc(p.name)} ⭐${p.stars}</a>`).join('');
}

// ── ENRICHMENT ENGINE ────────────────────────────────────────
async function enrichVulns(scope, cveIds){
  const uniq=[...new Set(cveIds)].filter(Boolean);
  if(!uniq.length) return;
  for(const cve of uniq){ const eb=document.getElementById('eb-'+scope+'-'+cve); if(eb) eb.innerHTML=`<span style="color:var(--muted);font-size:9px">…</span>`; }

  const [cisaRes, pocRes, epssRes, cvssRes] = await Promise.all([
    fetch('/api/cisa/check',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({cves:uniq})}).then(r=>r.json()).catch(()=>({inKev:[]})),
    fetch('/api/poc/check', {method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({cves:uniq})}).then(r=>r.json()).catch(()=>({pocs:{}})),
    fetch('/api/epss',      {method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({cves:uniq})}).then(r=>r.json()).catch(()=>({data:{}})),
    fetch('/api/nvd/cvss',  {method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({cves:uniq})}).then(r=>r.json()).catch(()=>({data:{}}))
  ]);

  const kevSet=new Set(cisaRes.inKev||[]);
  const pocs=pocRes.pocs||{};
  const epssMap=epssRes.data||{};
  const cvssData=cvssRes.data||{};

  for(const cve of uniq){
    const inKev=kevSet.has(cve);
    const ps=pocs[cve]||[];

    const eb=document.getElementById('eb-'+scope+'-'+cve);
    if(eb){
      let hb='';
      if(inKev) hb+=`<span title="CISA Known Exploited" style="background:#ff3b30;color:#fff;font-size:9px;font-weight:700;padding:2px 6px;border-radius:4px;margin-right:3px">🔥 KEV</span>`;
      if(ps.length){
        const pocUrl = safeUrl(ps[0].url);
        hb+=`<span title="${ps.length} PoC(s) on GitHub" style="background:#ff9500;color:#000;font-size:9px;font-weight:700;padding:2px 6px;border-radius:4px;margin-right:3px;cursor:pointer" onclick="event.stopPropagation();window.open('${esc(pocUrl)}','_blank')">💥 PoC×${ps.length}</span>`;
      }
      eb.innerHTML=hb;
    }

    const kevEl=document.getElementById('kev-'+scope+'-'+cve);
    if(kevEl) kevEl.innerHTML=kevBadge(inKev);

    const pocEl=document.getElementById('poc-'+scope+'-'+cve);
    if(pocEl) pocEl.innerHTML=pocBadge(ps);

    const cvssEl=document.getElementById('cvss-'+scope+'-'+cve);
    if(cvssEl) cvssEl.innerHTML=cvssHtml(cvssData[cve]);

    const cvssHdrEl=document.getElementById('cvss-hdr-'+scope+'-'+cve);
    if(cvssHdrEl&&cvssData[cve]){
      const v3=cvssData[cve].cvss3;
      if(v3){
        const s=v3.score;
        const cls=s>=9?'CRITICAL':s>=7?'HIGH':s>=4?'MEDIUM':'LOW';
        cvssHdrEl.innerHTML=`<span class="sev ${cls}" style="font-size:9px;padding:1px 6px">${s}</span>`;
      }
    }

    const epssEl=document.getElementById('epss-'+scope+'-'+cve);
    if(epssEl) epssEl.innerHTML=epssHtml(epssMap[cve]||null);
  }
}
