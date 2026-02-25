// ── UTILS ────────────────────────────────────────────────────

/** Escape HTML special chars — used everywhere data goes into innerHTML */
function esc(s){ return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;'); }

/** Safe localStorage read — returns fallback on corrupt/missing data */
function safeLoad(key, fallback=[]){
  try{ return JSON.parse(localStorage.getItem(key)||'null') ?? fallback; }
  catch{ return fallback; }
}

/** Safe localStorage write — silently ignores QuotaExceededError */
function safeSave(key, value){
  try{ localStorage.setItem(key, JSON.stringify(value)); }
  catch(e){ console.warn(`[storage] failed to save "${key}":`, e.message); }
}

/**
 * Validate that a URL is safe to use in href/window.open.
 * Only allows https:// and http:// — blocks javascript:, data:, etc.
 */
function safeUrl(u){
  try{
    const parsed = new URL(String(u||''));
    return (parsed.protocol==='https:' || parsed.protocol==='http:') ? parsed.href : '#';
  }catch{ return '#'; }
}

function fmtDate(d){ return new Date(d).toLocaleDateString('en-US',{month:'short',day:'numeric',hour:'2-digit',minute:'2-digit'}); }
function showErr(id,msg){ const e=document.getElementById(id); e.textContent='⚠ '+msg; e.style.display='block'; }
function setBtn(id,loading,label){
  const b=document.getElementById(id); if(!b)return;
  b.disabled=loading;
  b.innerHTML=loading?`<div class="spin"></div> ${label||'Loading...'}`:(label||'Go');
}

const SEV_ORD = ['CRITICAL','HIGH','MEDIUM','LOW','UNKNOWN','NONE'];
