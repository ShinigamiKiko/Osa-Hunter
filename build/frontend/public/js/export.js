// export.js — Download PDF artifacts (lib/img/dep) via POST /api/export/pdf
// Used by lib-scan.js / img-scan.js / dep-scan.js
(function(){
  function btn(label, onclick){
    return `<button class="btn-secondary" onclick="${onclick}" style="display:inline-flex;align-items:center;gap:8px">⬇ ${label}</button>`;
  }

  // Build a safe filename
  function safeName(s){ return (s||'artifact').toString().replace(/[^a-z0-9._-]+/gi,'_').replace(/_+/g,'_'); }

  async function postPdf(type, params){
    const r = await fetch('/api/export/pdf', {
      method:'POST',
      headers:{'Content-Type':'application/json'},
      body: JSON.stringify({ type, params })
    });
    if(!r.ok){
      const t = await r.text().catch(()=> '');
      throw new Error(`Export failed (${r.status}): ${t.slice(0,200)}`);
    }
    return await r.blob();
  }

  async function downloadBlob(blob, filename){
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    a.remove();
    setTimeout(()=>URL.revokeObjectURL(url), 8000);
  }

  // Public: returns HTML string for a button. `params` can be an object OR a special string placeholder.
  window.exportBtnHtml = function(type, params){
    // dep-scan uses placeholder so it can pass currentDepScan lazily
    const onclick = `exportPdf('${type}', ${typeof params==='string' ? `'${params}'` : JSON.stringify(params)})`;
    return btn('Download artifact', onclick);
  };

  // Public: callable from onclick
  window.exportPdf = async function(type, params){
    try{
      let p = params;

      // dep-scan passes placeholder "__DEP_SCAN__"
      if(type === 'dep' && (params === '__DEP_SCAN__' || params === '__DEP_SCAN__'.toString())){
        // currentDepScan is a global from dep-scan.js; also keep backward compat with _lastDepScan
        const scan = window.currentDepScan || window._lastDepScan;
        if(!scan) throw new Error('No dep scan in memory to export.');
        p = { scanData: scan };
      }

      const blob = await postPdf(type, p);
      const base =
        type==='lib' ? `${safeName(p?.ecosystem||'lib')}_${safeName(p?.name||p?.pkg||'package')}_${safeName(p?.version||'')}` :
        type==='img' ? `image_${safeName(p?.image||'')}_${safeName(p?.tag||'')}` :
        type==='dep' ? `deps_${safeName((p?.scanData?.package)||'')}_${safeName((p?.scanData?.version)||'')}` :
        `artifact_${Date.now()}`;
      await downloadBlob(blob, `${base}.pdf`);
    }catch(e){
      console.error(e);
      alert(e.message || 'Export failed');
    }
  };
})();
