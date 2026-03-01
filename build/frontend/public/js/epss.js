// ── EPSS ────────────────────────────────────────────────────
async function fetchEPSS(cves){
  if(!cves.length) return {};
  try{
    const r=await fetch('/api/epss',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({cves})});
    const d=await r.json(); return d.data||{};
  }catch{ return {}; }
}

function epssHtml(score){
  if(!score) return '<span style="color:var(--muted);font-size:11px">not found</span>';
  const pct=(score.epss*100).toFixed(2);
  const cls=score.epss>=.1?'hi':score.epss>=.01?'mi':'';
  return `<div class="epss-row"><span class="epss-pct ${cls}">${pct}%</span>
    <div class="epss-bar"><div class="epss-fill ${cls}" style="width:${Math.min(score.epss*500,100)}%"></div></div>
    <span style="font-size:10px;color:var(--muted)">${(score.percentile*100).toFixed(0)}th pct</span></div>`;
}

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
