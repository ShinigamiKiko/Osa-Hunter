// toxic.js — checkActivity (activity badge для lib и dep detail страниц)
// Toxic данные теперь приходят из /api/libscan и /api/depscan напрямую.
// Этот файл отвечает только за activity badge.

async function checkActivity(badgeId, pkgName, ecosystem){
  const el=document.getElementById(badgeId);
  if(!el) return;
  try{
    const r=await fetch('/api/activity',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({name:pkgName,ecosystem})});
    const d=await r.json();
    if(!d.found||!d.lastCommit){ el.innerHTML='<span style="font-size:10px;color:var(--muted)">Activity: unknown</span>'; return; }
    const date=new Date(d.lastCommit);
    const days=Math.floor((Date.now()-date)/86400000);
    const years=Math.floor(days/365);
    const age=days<1?'today':days<7?`${days}d ago`:days<60?`${Math.floor(days/7)}w ago`:years>=1?`${years}y ago`:`${Math.floor(days/30)}mo ago`;
    const stale=years>=2;
    const color=stale?'#ff9500':'#34c759';
    const label=stale?'⚠ Possibly stale':'● Active';
    const link=d.repoUrl?` <a href="${d.repoUrl}" target="_blank" style="color:${color};opacity:.7;font-size:10px;text-decoration:none">↗ repo</a>`:'';
    el.innerHTML=`<span style="font-size:10px;color:${color}">${label} · last commit ${age}</span>${link}`;
  }catch{
    el.innerHTML='<span style="font-size:10px;color:var(--muted)">Activity: error</span>';
  }
}
