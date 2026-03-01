function updateDepBadge(){
  const b=document.getElementById('depBadge');
  if(depScans.length){ b.style.display=''; b.textContent=depScans.length; }
  else b.style.display='none';
}

// ── LIST PAGE ─────────────────────────────────────────────────
