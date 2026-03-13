// ── EPSS ────────────────────────────────────────────────────
async function fetchEPSS(cves){
  if(!cves.length) return {};
  try{
    const r=await fetch('/api/epss',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({cves})});
    const d=await r.json(); return d.data||{};
  }catch{ return {}; }
}

// epssHtml lives in enrich.js (loaded after this file)

async function pollEpssStatus(){
  try{
    const r=await fetch('/api/epss/status');
    const d=await r.json();
    const dot=document.getElementById('epssDot');
    const lbl=document.getElementById('epssStatusLabel');
    const sub=document.getElementById('epssStatusSub');
    if(!dot) return;
    if(d.loaded){
      dot.className='sdot ok'; lbl.textContent='EPSS API'; sub.textContent='api.first.org · online';
    } else {
      dot.className='sdot err'; lbl.textContent='EPSS API'; sub.textContent='недоступен';
    }
  }catch{
    const dot=document.getElementById('epssDot');
    const sub=document.getElementById('epssStatusSub');
    if(dot) dot.className='sdot err';
    if(sub) sub.textContent='ошибка';
  }
}
