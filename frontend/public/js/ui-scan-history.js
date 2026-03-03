// ui-scan-history.js — loads scan history from PostgreSQL
// Hooks into navTo() so history is merged right before a list page renders.

(function () {
  'use strict';

  const TTL_MS = 24 * 60 * 60 * 1000;

  const ECOS = [
    {id:'npm',       label:'npm',   logo:'📦'},
    {id:'pypi',      label:'PyPI',  logo:'🐍'},
    {id:'go',        label:'Go',    logo:'🐹'},
    {id:'crates',    label:'Rust',  logo:'🦀'},
    {id:'maven',     label:'Maven', logo:'☕'},
    {id:'rubygems',  label:'Ruby',  logo:'💎'},
    {id:'nuget',     label:'NuGet', logo:'🔷'},
    {id:'packagist', label:'PHP',   logo:'🐘'},
  ];
  const OS_DISTROS = [
    {id:'ubuntu', label:'Ubuntu', logo:'🟠'},
    {id:'debian', label:'Debian', logo:'🌀'},
    {id:'rhel',   label:'RHEL',   logo:'🎩'},
    {id:'alpine', label:'Alpine', logo:'🏔️'},
    {id:'suse',   label:'SUSE',   logo:'🦎'},
  ];

  function ecoMeta(id)    { return ECOS.find(x=>x.id===(id||'').toLowerCase())       || {id:id||'',label:id||'',logo:'📦'}; }
  function distroMeta(id) { return OS_DISTROS.find(x=>x.id===(id||'').toLowerCase()) || {id:id||'',label:id||'',logo:'🐧'}; }

  const converters = {
    lib(e) {
      const eco = ecoMeta(e.ecosystem);
      return {
        id:eco.id, pkg:e.package, ver:e.version||'',
        eco:eco.id, ecoLabel:eco.label, ecoLogo:eco.logo,
        desc:'',
        vulns:(e.vulns||[]).map(v=>({...v,_sev:v.severity,_fix:v.fix,_aliases:v.aliases||[],_refs:v.refs||[]})),
        toxic:e.toxic||{found:false}, topSev:e.topSeverity||'NONE',
        scannedAt:e.scannedAt||e._cachedAt,
        _cacheKey:e._cacheKey,
      };
    },
    dep(e)      { return {...e, id:e._cacheKey, desc:e.desc||'', scannedAt:e.scannedAt||e._cachedAt}; },
    composer(e) { return {...e, id:e._cacheKey, desc:e.desc||'', scannedAt:e.scannedAt||e._cachedAt}; },
    os(e) {
      const d = distroMeta(e.distro);
      return {
        id:e._cacheKey, pkg:e.package, pkgVer:e.version||'',
        distro:d.id, distroLabel:d.label, distroLogo:d.logo, distroVer:e.distroVersion||'',
        desc:'', vulns:e.vulns||[], counts:e.counts||{},
        topSev:e.topSeverity||'NONE', scannedAt:e.scannedAt||e._cachedAt,
      };
    },
    img(e) {
      const parts = e._cacheKey.replace(/^img:/,'').split(':');
      const tag=parts.pop(), image=parts.join(':');
      return {...e, id:e._cacheKey, image, tag, desc:'', scannedAt:e.scannedAt||e._cachedAt};
    },
    sast(e) {
      return {id:e._cacheKey, url:e.url||'', desc:e.desc||'', repo:e.repo||'',
              findings:e.findings||[], counts:e.counts||{}, topSev:e.topSev||'NONE',
              toxic:e.toxic||{found:false}, scannedAt:e.scannedAt||e._cachedAt};
    },
  };

  const META = {
    lib     :{lsKey:'es_lib',global:'libScans',max:50},
    dep     :{lsKey:'es_dep',global:'depScans',max:20},
    composer:{lsKey:'es_dep',global:'depScans',max:20},
    os      :{lsKey:'es_os', global:'osScans', max:30},
    img     :{lsKey:'es_img',global:'imgScans',max:20},
    sast    :{lsKey:'es_gh', global:'ghScans', max:20},
  };

  const PAGE_TYPES = {
    'lib-list':['lib'],
    'dep-list':['dep','composer'],
    'os-list' :['os'],
    'img-list':['img'],
    'gh-list' :['sast'],
  };

  const fetched = new Set();

  async function fetchAndMerge(type) {
    if (fetched.has(type)) return;
    fetched.add(type);

    let entries;
    try {
      const r = await fetch('/api/scans/history?type='+type, {credentials:'same-origin'});
      if (!r.ok) return;
      entries = (await r.json()).entries || [];
    } catch(e) { console.warn('[scan-history] fetch failed:', e.message); return; }

    if (!entries.length) return;

    const meta = META[type];
    const arr  = window[meta.global];
    if (!Array.isArray(arr)) return;

    const existing = new Set(arr.map(s => String(s._cacheKey || s.id || '')));
    let added = 0;

    for (const e of entries) {
      const key = e._cacheKey;
      if (existing.has(key)) continue;
      if (e._cachedAt && Date.now() - new Date(e._cachedAt) > TTL_MS) continue;
      arr.push(converters[type](e));
      existing.add(key);
      added++;
    }

    if (!added) return;

    arr.sort((a,b) => new Date(b.scannedAt||0) - new Date(a.scannedAt||0));
    if (arr.length > meta.max) arr.splice(meta.max);
    try { localStorage.setItem(meta.lsKey, JSON.stringify(arr)); } catch(_) {}
    console.log('[scan-history] +'+added+' '+type+' entries from server');
  }

  // Patch navTo — await fetch BEFORE calling original render
  function patchNavTo() {
    const orig = window.navTo;
    if (typeof orig !== 'function') { setTimeout(patchNavTo, 50); return; }

    window.navTo = async function(page, opts) {
      const types = PAGE_TYPES[page];
      if (types) await Promise.allSettled(types.map(fetchAndMerge));
      return orig(page, opts);
    };
    console.log('[scan-history] navTo patched ✓');
  }

  patchNavTo();

})();
