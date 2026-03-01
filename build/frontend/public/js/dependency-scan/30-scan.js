async function doDepScan(){
  const sys  = selDepSys;
  const pkg  = document.getElementById('dPkg').value.trim();
  const ver  = document.getElementById('dVer').value.trim();
  const desc = document.getElementById('dDesc').value.trim();
  document.getElementById('dmerr').style.display='none';
  if(!sys) return showErr('dmerr','Select a package system');
  if(!pkg) return showErr('dmerr','Enter a package name');
  setBtn('btnDepGo',true,'Scanning…');
  try{
    const ep = (sys==='COMPOSER') ? '/api/composerscan' : '/api/depscan';
    const payload = (sys==='COMPOSER')
      ? { name:pkg, version:ver||undefined }
      : { name:pkg, system:sys, version:ver||undefined };
    const r=await fetch(ep,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(payload)});
    const data=await r.json();
    if(!r.ok) throw new Error(data.error||`Error ${r.status}`);
    // Normalize composerscan response → same shape as depscan
    // composerscan returns deps:{direct:[],transitive:[]} — convert to flat array with relation/counts fields
    if(sys==='COMPOSER' && data.deps && !Array.isArray(data.deps)){
      const normDeps=(list,relation)=>(list||[]).map(d=>{
        // composerscan stores epss/cvss/pocs/kev as {CVE-xxx: value} objects, not arrays
        const epssMap = d.epss||{};  // { 'CVE-xxx': {epss, percentile} }
        const cvssMap = d.cvss||{};  // { 'CVE-xxx': {cvss3, cvss2} }
        const pocsMap = d.pocs||{};  // { 'CVE-xxx': [...] }
        const kevSet  = new Set(d.kev||[]);

        const vulns=(d.vulns||[]).map(v=>{
          const cveId=[...(v.aliases||[]),v.id].find(x=>x&&x.startsWith('CVE-'))||null;
          return {
            ...v,
            fix     : v.fixed||v.fix||null,
            severity: v.severity||'UNKNOWN',
            aliases : v.aliases||[],
            refs    : v.refs||[],
            epss    : cveId ? (epssMap[cveId]||null) : null,
            cvss    : cveId ? (cvssMap[cveId]||null) : null,
            pocs    : cveId ? (pocsMap[cveId]||[])   : [],
            inKev   : cveId ? kevSet.has(cveId)       : false,
          };
        });
        const cnt={CRITICAL:0,HIGH:0,MEDIUM:0,LOW:0,UNKNOWN:0};
        vulns.forEach(v=>{const s=(v.severity||'UNKNOWN').toUpperCase();if(s in cnt)cnt[s]++;});
        const topSev=['CRITICAL','HIGH','MEDIUM','LOW'].find(s=>cnt[s]>0)||'NONE';
        return{...d,relation,vulns,counts:cnt,topSeverity:topSev,system:data.system||'COMPOSER',toxic:d.toxic||{found:false}};
      });
      // root — отдельное поле, не входит в direct/transitive
      console.log('[dep-scan] raw deps from server:', {
        hasRoot: !!data.deps.root,
        directCount: (data.deps.direct||[]).length,
        transitiveCount: (data.deps.transitive||[]).length,
        transitiveNames: (data.deps.transitive||[]).map(d=>d.name).slice(0,5),
      });
      const rootNorm = data.deps.root ? normDeps([data.deps.root], 'ROOT') : [];
      data.deps=[
        ...rootNorm,
        ...normDeps(data.deps.direct,     'DIRECT'),
        ...normDeps(data.deps.transitive,  'INDIRECT'),
      ];
      console.log('[dep-scan] after normalize:', data.deps.map(d=>d.name+':'+d.relation));
      // Recount severity totals from normalized deps (composerscan doesn't include them in summary)
      const sevTotals={CRITICAL:0,HIGH:0,MEDIUM:0,LOW:0};
      data.deps.forEach(d=>(d.vulns||[]).forEach(v=>{const s=(v.severity||'').toUpperCase();if(s in sevTotals)sevTotals[s]++;}));
      const toxicCount=data.deps.filter(d=>d.toxic?.found).length;
      const sm=data.summary||{};
      data.summary={
        ...sm,
        totalDeps : sm.total   ??sm.totalDeps  ??data.deps.length,
        directDeps: sm.direct  ??sm.directDeps ??data.deps.filter(d=>d.relation==='DIRECT').length,
        CRITICAL  : sevTotals.CRITICAL,
        HIGH      : sevTotals.HIGH,
        MEDIUM    : sevTotals.MEDIUM,
        LOW       : sevTotals.LOW,
        toxic     : toxicCount,
        withVulns : data.deps.filter(d=>(d.vulns||[]).length>0).length,
      };
    }
    const scan={...data,desc,id:Date.now()};
    depScans.unshift(scan);
    if(depScans.length>20) depScans=depScans.slice(0,20);
    saveDep(); closeDepModal(); updateDepBadge();
    navTo('dep-detail',{scan});
  }catch(e){ showErr('dmerr',e.message||'Scan failed'); }
  setBtn('btnDepGo',false,'▶ Scan');
}

// ── BADGE ─────────────────────────────────────────────────────
