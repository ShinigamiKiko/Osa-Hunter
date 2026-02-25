// ── TOXIC-REPOS CHECK ────────────────────────────────────────
const TOXIC_TYPE_LABELS = {
  ddos:             { label:'DDoS tool',        color:'#ff3b30', icon:'☠️' },
  hostile_actions:  { label:'Hostile actions',  color:'#ff3b30', icon:'⚠️' },
  political_slogan: { label:'Political slogan', color:'#ff9500', icon:'📢' },
  malware:          { label:'Malware',          color:'#ff3b30', icon:'🦠' },
  ip_blocking:      { label:'IP blocking',      color:'#ff9500', icon:'🚫' },
};
function toxicTypeInfo(type){ return TOXIC_TYPE_LABELS[type]||{label:type||'Toxic',color:'#ff3b30',icon:'☣️'}; }

async function checkToxic(pkgName){
  const el=document.getElementById('toxicBadge');
  if(!el) return;
  try{
    const r=await fetch('/api/toxic/check',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({name:pkgName})});
    const d=await r.json();
    if(!d.found){
      el.innerHTML=`<span style="display:inline-flex;align-items:center;gap:5px;font-size:10px;background:rgba(52,199,89,.1);color:#34c759;border:1px solid rgba(52,199,89,.3);padding:2px 9px;border-radius:12px">✅ Toxic repos: not found</span>`;
    } else {
      const ti=toxicTypeInfo(d.problem_type);
      const fullDesc=d.description||'';
      const short=fullDesc.length>60;
      const preview=short?fullDesc.slice(0,60):fullDesc;
      const moreBtn=short
        ?`<button onclick="this.parentElement.querySelector('.toxic-full').style.display='inline';this.remove()" style="background:none;border:none;color:inherit;opacity:.75;cursor:pointer;font-size:10px;padding:0;text-decoration:underline;margin-left:2px">…</button><span class="toxic-full" style="display:none">${esc(fullDesc.slice(60))}</span>`:'';
      el.innerHTML=`<span style="display:inline-flex;align-items:center;flex-wrap:wrap;gap:4px;font-size:10px;background:rgba(255,59,48,.12);color:${ti.color};border:1px solid rgba(255,59,48,.35);padding:3px 10px;border-radius:12px">${ti.icon} <strong>Toxic: ${esc(ti.label)}</strong>${fullDesc?' — '+esc(preview)+moreBtn:''}</span>`;
    }
  }catch(e){
    el.innerHTML=`<span style="font-size:10px;color:var(--muted)">Toxic check: unavailable</span>`;
  }
}

// ── ACTIVITY CHECK (last GitHub commit) ─────────────────────
async function checkActivity(elId, pkgName, ecosystem){
  const el=document.getElementById(elId);
  if(!el) return;
  try{
    const r=await fetch('/api/activity',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({name:pkgName,ecosystem})});
    const d=await r.json();

    if(d.rateLimited){
      el.innerHTML=`<span class="act-badge" style="background:rgba(251,191,36,.08);border:1px solid rgba(251,191,36,.25);color:var(--m)">
        <span style="font-size:11px">⚠</span>
        GitHub rate limit · <span style="opacity:.65;font-size:11px">60 req/h exceeded — try again later</span>
        ${d.repoUrl?`<a href="${esc(safeUrl(d.repoUrl))}" target="_blank" rel="noopener noreferrer" style="color:var(--m);opacity:.7;text-decoration:none;margin-left:3px;font-size:11px">↗ repo</a>`:''}
      </span>`;
      return;
    }

    if(!d.found||!d.lastCommit){
      el.innerHTML=`<span class="act-badge unknown"><span class="act-dot"></span>Update info: not found</span>`;
      return;
    }

    const date=new Date(d.lastCommit), now=new Date();
    const days=Math.floor((now-date)/86400000);
    const months=Math.floor(days/30), years=Math.floor(days/365);
    let age='';
    if(days<1) age='today';
    else if(days<7) age=`${days}d ago`;
    else if(days<60) age=`${Math.floor(days/7)}w ago`;
    else if(months<24) age=`${months}mo ago`;
    else age=`${years}y ago`;

    const isStale=years>=2;
    const dateStr=date.toLocaleDateString('en-US',{year:'numeric',month:'short',day:'numeric'});
    const repoLink=d.repoUrl?`<a href="${esc(safeUrl(d.repoUrl))}" rel="noopener noreferrer" target="_blank" style="color:inherit;opacity:.6;text-decoration:none;font-size:11px;margin-left:3px">↗</a>`:'';

    if(isStale){
      el.innerHTML=`<span class="act-badge" style="background:rgba(255,140,50,.08);border:1px solid rgba(255,140,50,.25);color:var(--h)">
        <span style="width:6px;height:6px;border-radius:50%;background:var(--h);flex-shrink:0;display:inline-block"></span>
        Possibly stale <span style="opacity:.6;font-size:11px;margin-left:2px">· last commit ${age} · ${dateStr}</span>${repoLink}
      </span>`;
    } else {
      el.innerHTML=`<span class="act-badge active">
        <span class="act-dot"></span>
        Active <span class="act-date">· last commit ${age} · ${dateStr}</span>${repoLink}
      </span>`;
    }
  }catch(e){
    const el2=document.getElementById(elId);
    if(el2) el2.innerHTML=`<span class="act-badge unknown"><span class="act-dot"></span>Activity: unavailable</span>`;
  }
}
