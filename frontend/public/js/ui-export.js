// ui-export.js — Download PDF via POST /api/export/pdf
(function(){
  // Store export params by key to avoid JSON-in-onclick quoting issues
  var _store = {};

  function safeName(s){ return (s||'artifact').toString().replace(/[^a-z0-9._-]+/gi,'_').replace(/_+/g,'_'); }

  async function postPdf(type, params){
    const r = await fetch('/api/export/pdf', {
      method:'POST',
      headers:{'Content-Type':'application/json'},
      body: JSON.stringify({ type, params })
    });
    if(!r.ok){
      const t = await r.text().catch(()=>'');
      throw new Error(`Export failed (${r.status}): ${t.slice(0,200)}`);
    }
    return await r.blob();
  }

  async function downloadBlob(blob, filename){
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url; a.download = filename;
    document.body.appendChild(a); a.click(); a.remove();
    setTimeout(()=>URL.revokeObjectURL(url), 8000);
  }

  // Returns HTML for an export button. params = object or special string placeholder.
  window.exportBtnHtml = function(type, params){
    const key = 'exp_' + type + '_' + Date.now() + '_' + Math.random().toString(36).slice(2);
    _store[key] = params;
    return `<button class="btn-secondary" onclick="exportPdf('${type}','${key}')" style="display:inline-flex;align-items:center;gap:8px">⬇ Download artifact</button>`;
  };

  // Called from onclick — key references stored params
  window.exportPdf = async function(type, key){
    try {
      let p = _store[key] || key;

      // Lazy resolution for scanners that pass placeholder strings
      if(type === 'dep' && (p === '__DEP_SCAN__' || typeof p === 'string')){
        const scan = window.currentDepScan || window._lastDepScan;
        if(!scan) throw new Error('No dep scan in memory to export.');
        p = { scanData: scan };
      }
      if(type === 'os' && (p === '__OS_SCAN__' || typeof p === 'string')){
        const scan = window.currentOsScan || window._lastOsScan;
        if(!scan) throw new Error('No OS scan in memory to export.');
        p = { scanData: scan };
      }
      if(type === 'sast' && (p === '__SAST_SCAN__' || typeof p === 'string')){
        const scan = window.currentSastScan || window._lastSastScan;
        if(!scan) throw new Error('No SAST scan in memory to export.');
        p = { scanData: scan };
      }

      const blob = await postPdf(type, p);
      const base =
        type==='lib'  ? `${safeName(p?.ecosystem||'lib')}_${safeName(p?.name||p?.pkg||'package')}_${safeName(p?.version||'')}` :
        type==='img'  ? `image_${safeName(p?.image||'')}_${safeName(p?.tag||'')}` :
        type==='dep'  ? `deps_${safeName(p?.scanData?.package||'')}` :
        type==='os'   ? `os_${safeName(p?.scanData?.package||p?.scanData?.image||'')}` :
        type==='sast' ? `sast_${safeName(p?.scanData?.repo||'')}` :
        `artifact_${Date.now()}`;
      await downloadBlob(blob, `${base}.pdf`);
    } catch(e) {
      console.error(e);
      alert(e.message || 'Export failed');
    }
  };
})();
