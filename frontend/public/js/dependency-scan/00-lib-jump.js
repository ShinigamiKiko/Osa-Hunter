// Open a library scan directly from dep-scan (click on transitive/direct package names)
async function openLibFromDep(ev, systemId, name, version){
  try{
    if(ev) ev.stopPropagation();
    const map = {
      'NPM':      { ecoId:'npm',      osv:'npm',        label:'npm',       logo:'📦' },
      'PYPI':     { ecoId:'pypi',     osv:'PyPI',       label:'PyPI',      logo:'🐍' },
      'GO':       { ecoId:'go',       osv:'Go',         label:'Go',        logo:'🐹' },
      'CARGO':    { ecoId:'crates',   osv:'crates.io',  label:'Rust',      logo:'🦀' },
      'MAVEN':    { ecoId:'maven',    osv:'Maven',      label:'Maven',     logo:'☕' },
      'NUGET':    { ecoId:'nuget',    osv:'NuGet',      label:'NuGet',     logo:'💠' },
      'RUBYGEMS': { ecoId:'rubygems', osv:'RubyGems',   label:'RubyGems',  logo:'💎' },
      'COMPOSER': { ecoId:'composer', osv:'Packagist',  label:'Composer',  logo:'🐘' },
    };
    const eco = map[systemId] || map[(systemId||'').toUpperCase()];
    if(!eco) throw new Error('Unknown ecosystem for lib jump: '+systemId);
    const r = await fetch('/api/libscan', {
      method:'POST', headers:{'Content-Type':'application/json'},
      body: JSON.stringify({ name, ecosystem: eco.osv, version: (version||'').trim() })
    });
    const data = await r.json();
    if(!r.ok) throw new Error(data?.error || 'libscan failed');
    const vulns = (data.vulns||[]).map(v=>({...v,_sev:v.severity,_fix:v.fix,_aliases:v.aliases||[],_refs:v.refs||[]}));
    window.libScans = window.libScans || [];
    window.libScans.unshift({
      id:Date.now(), pkg:data.package, ver:data.version||'',
      eco:eco.ecoId, ecoLabel:eco.label, ecoLogo:eco.logo, desc:'',
      vulns, toxic:data.toxic, topSev:data.topSeverity||'NONE', scannedAt:data.scannedAt,
    });
    if(typeof window.saveLib === 'function') window.saveLib();
    navTo('lib-detail', { scan: window.libScans[0] });
  }catch(e){
    console.error(e);
    alert(e.message || 'Failed to open library');
  }
}

