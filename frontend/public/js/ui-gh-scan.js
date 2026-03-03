// ui-gh-scan.js — GitHub Scan (Semgrep)

let ghScans = safeLoad('es_gh', []);
const saveGh = () => safeSave('es_gh', ghScans);

function updateGhBadge(){
  const b = document.getElementById('ghBadge');
  if(!b) return;
  if(ghScans.length){ b.style.display=''; b.textContent=ghScans.length; }
  else b.style.display='none';
}

async function doGhScan(){
  const url  = document.getElementById('ghUrl').value.trim();
  const desc = document.getElementById('ghDesc').value.trim();
  document.getElementById('ghErr').style.display='none';

  if(!url) return showErr('ghErr','Enter a GitHub repository URL');
  if(!/^https:\/\/github\.com\/[^/]+\/[^/]+/.test(url))
    return showErr('ghErr','Only public GitHub repositories are supported (https://github.com/owner/repo)');

  setBtn('btnGhScan', true, '⏳ Scanning…');
  try {
    const r = await fetch('/api/ghscan', {
      method:'POST',
      headers:{'Content-Type':'application/json'},
      body: JSON.stringify({ url, desc }),
    });
    const data = await r.json();
    if(!r.ok) throw new Error(data.error || `Error ${r.status}`);

    const _repo = data.repo || url.replace('https://github.com/','');
    const _ck = `sast:${_repo}`;
    const ckIdx = ghScans.findIndex(s => s._cacheKey === _ck);
    if (ckIdx !== -1) ghScans.splice(ckIdx, 1);
    ghScans.unshift({
      id: Date.now(), _cacheKey: _ck,
      url, desc,
      repo:      _repo,
      findings:  data.findings  || [],
      counts:    data.counts    || {},
      topSev:    data.topSev    || 'NONE',
      toxic:     data.toxic     || { found: false },
      scannedAt: data.scannedAt || new Date().toISOString(),
    });
    if(ghScans.length > 20) ghScans = ghScans.slice(0,20);
    saveGh(); updateGhBadge(); navTo('gh-list');
  } catch(e) { showErr('ghErr', e.message || 'Scan failed'); }
  setBtn('btnGhScan', false, 'Scan Repository');
}

// ── LIST ──────────────────────────────────────────────────────
async function renderGhList(){
  if (!window._histLoaded_sast) {
    window._histLoaded_sast = true;
    try {
      const r = await fetch('/api/scans/history?type=sast', {credentials:'same-origin'});
      if (r.ok) {
        const {entries=[]} = await r.json();
        const existing = new Set(ghScans.map(s=>s._cacheKey||String(s.id)));
        for (const e of entries) {
          if (existing.has(e._cacheKey)) continue;
          ghScans.push({
            id:e._cacheKey, _cacheKey:e._cacheKey,
            url:e.url||'', desc:e.desc||'', repo:e.repo||'',
            findings:e.findings||[], counts:e.counts||{},
            topSev:e.topSev||'NONE', toxic:e.toxic||{found:false},
            scannedAt:e.scannedAt||e._cachedAt,
          });
          existing.add(e._cacheKey);
        }
        ghScans.sort((a,b)=>new Date(b.scannedAt||0)-new Date(a.scannedAt||0));
        saveGh(); updateGhBadge();
      }
    } catch(e) { console.warn('[history] sast:', e.message); }
  }
  updateGhBadge();
  const el = document.getElementById('ghListContent');
  if(!ghScans.length){
    el.innerHTML='<div class="empty">'+_emptyRadar()+
      '<h2>No GitHub scans yet</h2>'+
      '<p>Paste a public GitHub repository URL to scan for security vulnerabilities with Semgrep</p>'+
      '<button class="btn-primary" style="background:#a78bfa;color:#07090f" onclick="navTo(\'gh-form\')">+ New scan</button>'+
      '</div>';
    _initEmptyRadar(); return;
  }
  var rows = ghScans.map(function(s,i){
    var counts = s.counts||{};
    var pills = ['CRITICAL','HIGH','MEDIUM','LOW'].filter(function(sv){return counts[sv];})
      .map(function(sv){return '<span class="sev '+sv+'" style="font-size:9px;padding:2px 6px">'+counts[sv]+' '+sv+'</span>';}).join(' ');
    var total = (s.findings||[]).length;
    return '<tr class="row" onclick="navTo(\'gh-detail\',{scan:ghScans['+i+']})">' +
      '<td><div style="display:flex;align-items:center;gap:9px"><div style="flex-shrink:0;font-size:18px;line-height:1">🔬</div><div>' +
      '<div class="row-name">'+esc(s.repo)+'</div>' +
      '<div style="font-size:10px;color:var(--muted);margin-top:2px">'+esc(s.url)+'</div>' +
      '<div style="margin-top:4px">'+_toxicBadgeHtml(s.toxic)+'</div>' +
      '</div></div></td>' +
      '<td><div class="row-desc">'+esc(s.desc||'—')+'</div></td>' +
      '<td><span class="sev '+s.topSev+'">'+s.topSev+'</span></td>' +
      '<td>'+(total===0?'<span style="color:var(--l);font-size:11px">✓ clean</span>':(pills||'<span style="color:var(--muted)">'+total+'</span>'))+'</td>' +
      '<td style="color:var(--muted);font-size:10px;white-space:nowrap">'+fmtDate(s.scannedAt)+'</td>' +
      '<td><button onclick="event.stopPropagation();ghScans.splice('+i+',1);saveGh();updateGhBadge();renderGhList()" style="background:none;border:none;color:var(--muted);cursor:pointer;font-size:13px;padding:3px 5px;border-radius:4px" onmouseover="this.style.color=\'var(--c)\'" onmouseout="this.style.color=\'var(--muted)\'">✕</button></td>' +
      '</tr>';
  }).join('');
  el.innerHTML =
    '<div style="display:flex;justify-content:flex-end;margin-bottom:14px">' +
    '<button class="btn-secondary" onclick="navTo(\'gh-form\')">+ New scan</button>' +
    '<button class="btn-secondary" onclick="if(confirm(\'Clear all GitHub scans?\')){ghScans=[];saveGh();updateGhBadge();renderGhList()}">Clear all</button></div>' +
    '<div class="tbl-wrap"><table class="tbl"><thead><tr>' +
    '<th>Repository</th><th>Description</th><th>Top Severity</th><th>Findings</th><th>Scanned</th><th style="width:28px"></th>' +
    '</tr></thead><tbody>'+rows+'</tbody></table></div>';
}

// ── CWE id parser ─────────────────────────────────────────────
function parseCweId(cweArr) {
  var raw = (cweArr || [])[0] || '';
  var m = raw.match(/CWE-(\d+)/i);
  return m ? parseInt(m[1], 10) : null;
}

// ── CWE number → label ────────────────────────────────────────
function cweToLabel(cweArr) {
  var id = parseCweId(cweArr);
  if (!id) return null;
  var map = {
    89:   { label: 'SQL Injection',            icon: '💉' },
    79:   { label: 'XSS',                      icon: '🔥' },
    78:   { label: 'Command Injection',         icon: '⚡' },
    94:   { label: 'Code Injection',            icon: '💀' },
    95:   { label: 'Eval Injection',            icon: '💀' },
    22:   { label: 'Path Traversal',            icon: '📂' },
    73:   { label: 'Path Traversal',            icon: '📂' },
    798:  { label: 'Hardcoded Secret',          icon: '🔑' },
    259:  { label: 'Hardcoded Secret',          icon: '🔑' },
    321:  { label: 'Hardcoded Secret',          icon: '🔑' },
    918:  { label: 'SSRF',                      icon: '🌐' },
    611:  { label: 'XXE',                       icon: '📄' },
    502:  { label: 'Insecure Deserialization',  icon: '📦' },
    601:  { label: 'Open Redirect',             icon: '↪️' },
    352:  { label: 'CSRF',                      icon: '🎭' },
    942:  { label: 'CORS Misconfiguration',     icon: '🌍' },
    347:  { label: 'JWT Issue',                 icon: '🎫' },
    327:  { label: 'Weak Cryptography',         icon: '🔓' },
    328:  { label: 'Weak Cryptography',         icon: '🔓' },
    117:  { label: 'Log Injection',             icon: '📝' },
    1321: { label: 'Prototype Pollution',       icon: '☠️' },
    338:  { label: 'Weak Randomness',           icon: '🎲' },
    1004: { label: 'Insecure Cookie',           icon: '🍪' },
    400:  { label: 'DoS / ReDoS',               icon: '💣' },
    200:  { label: 'Information Exposure',      icon: '👁' },
    209:  { label: 'Information Exposure',      icon: '👁' },
    116:  { label: 'Improper Encoding',         icon: '🔤' },
    434:  { label: 'Unrestricted Upload',       icon: '📤' },
    285:  { label: 'Improper Authorization',    icon: '🚫' },
    284:  { label: 'Improper Authorization',    icon: '🚫' },
    306:  { label: 'Missing Authentication',    icon: '🔐' },
    307:  { label: 'Brute Force',               icon: '🔨' },
    287:  { label: 'Improper Authentication',   icon: '🔐' },
    190:  { label: 'Integer Overflow',          icon: '🔢' },
    476:  { label: 'Null Dereference',          icon: '💥' },
    416:  { label: 'Use After Free',            icon: '💥' },
    125:  { label: 'Out-of-bounds Read',        icon: '📍' },
    787:  { label: 'Out-of-bounds Write',       icon: '📍' }
  };
  return map[id] || { label: 'CWE-'+id, icon: '⚠️' };
}

// ── Fallback: ruleId keyword match ────────────────────────────
function ruleIdToLabel(ruleId) {
  var r = (ruleId || '').toLowerCase();
  if (/sql.?inject|sqli/.test(r))                                       return { label: 'SQL Injection',           icon: '💉' };
  if (/xss|cross.site.script|html.inject/.test(r))                      return { label: 'XSS',                     icon: '🔥' };
  if (/command.inject|cmd.inject|shell.inject/.test(r))                 return { label: 'Command Injection',       icon: '⚡' };
  if (/eval|exec.inject|rce/.test(r))                                   return { label: 'Code Injection',          icon: '💀' };
  if (/path.travers|directory.travers|lfi|rfi/.test(r))                 return { label: 'Path Traversal',          icon: '📂' };
  if (/secret|hardcode|api.key|token|password|credential|private.key/.test(r)) return { label: 'Hardcoded Secret', icon: '🔑' };
  if (/ssrf|server.side.request/.test(r))                               return { label: 'SSRF',                    icon: '🌐' };
  if (/xxe|xml.inject|xml.external/.test(r))                            return { label: 'XXE',                     icon: '📄' };
  if (/deserializ|unsafe.deserial/.test(r))                             return { label: 'Insecure Deserialization', icon: '📦' };
  if (/open.redirect/.test(r))                                          return { label: 'Open Redirect',           icon: '↪️' };
  if (/csrf|cross.site.request/.test(r))                                return { label: 'CSRF',                    icon: '🎭' };
  if (/\bcors\b/.test(r))                                               return { label: 'CORS Misconfiguration',   icon: '🌍' };
  if (/jwt|token.verif/.test(r))                                        return { label: 'JWT Issue',               icon: '🎫' };
  if (/crypto|weak.hash|md5|sha1/.test(r))                              return { label: 'Weak Cryptography',       icon: '🔓' };
  if (/prototype.pollu/.test(r))                                        return { label: 'Prototype Pollution',     icon: '☠️' };
  if (/\bcookie\b/.test(r))                                             return { label: 'Insecure Cookie',         icon: '🍪' };
  if (/\bdos\b|redos/.test(r))                                          return { label: 'DoS / ReDoS',             icon: '💣' };
  if (/debug|stack.trace|info.leak/.test(r))                            return { label: 'Information Exposure',    icon: '👁' };
  return { label: 'Security Issue', icon: '⚠️' };
}

// Main: CWE first, ruleId fallback
function ghVulnType(finding) {
  if (typeof finding === 'string') return ruleIdToLabel(finding);
  var fromCwe = cweToLabel(finding.cwe);
  return fromCwe || ruleIdToLabel(finding.ruleId);
}

// ── DETAIL ────────────────────────────────────────────────────
function renderGhDetail(scan){
  var el = document.getElementById('ghDetailContent');
  var findings = scan.findings || [];
  var counts   = scan.counts   || {};
  var chips = ['CRITICAL','HIGH','MEDIUM','LOW'].filter(function(sv){return counts[sv];})
    .map(function(sv){return '<span class="sev '+sv+'">'+counts[sv]+' '+sv+'</span>';}).join('');

  var SEV_W = {CRITICAL:4,HIGH:3,MEDIUM:2,LOW:1,UNKNOWN:0};

  // Group by primary CWE id (or label fallback)
  var byGroup = new Map();
  findings.forEach(function(f){
    var vtype = ghVulnType(f);
    var cweId = parseCweId(f.cwe);
    var key = cweId ? 'cwe-'+cweId : vtype.label;
    if(!byGroup.has(key)) byGroup.set(key, { vtype: vtype, items: [] });
    byGroup.get(key).items.push(f);
  });

  // Sort groups by top severity
  var sortedGroups = Array.from(byGroup.values()).sort(function(a,b){
    var topA = Math.max.apply(null, a.items.map(function(f){return SEV_W[(f.severity||'UNKNOWN').toUpperCase()]||0;}));
    var topB = Math.max.apply(null, b.items.map(function(f){return SEV_W[(f.severity||'UNKNOWN').toUpperCase()]||0;}));
    return topB - topA;
  });

  var gvi = 0;
  var groupHtml = sortedGroups.map(function(group){
    var vtype = group.vtype;
    var items = group.items;
    items.sort(function(a,b){
      return (SEV_W[(b.severity||'UNKNOWN').toUpperCase()]||0)-(SEV_W[(a.severity||'UNKNOWN').toUpperCase()]||0);
    });
    var topSev = ['CRITICAL','HIGH','MEDIUM','LOW'].find(function(s){
      return items.some(function(f){return (f.severity||'').toUpperCase()===s;});
    })||'UNKNOWN';
    var sevCounts = {};
    items.forEach(function(f){var s=(f.severity||'UNKNOWN').toUpperCase();sevCounts[s]=(sevCounts[s]||0)+1;});
    var pills = ['CRITICAL','HIGH','MEDIUM','LOW'].filter(function(sv){return sevCounts[sv];})
      .map(function(sv){return '<span class="sev '+sv+'" style="font-size:9px;padding:1px 6px">'+sevCounts[sv]+'</span>';}).join('');

    var fileRows = items.map(function(f){
      var vi = gvi++;
      var sev = (f.severity||'UNKNOWN').toUpperCase();
      var fname = f.path ? (f.path.length > 70 ? '…'+f.path.slice(-67) : f.path) : 'unknown';
      var lineStr = f.line ? ':'+f.line : '';
      return '<div id="ghfi-'+vi+'" style="border-bottom:1px solid var(--br)">' +
        '<div onclick="toggleGhVI('+vi+')" style="display:flex;align-items:center;gap:10px;padding:9px 16px;cursor:pointer;transition:background .12s" onmouseover="this.style.background=\'var(--s3)\'" onmouseout="this.style.background=\'\'">' +
        '<span class="vbar '+sev+'" style="height:16px;width:3px;border-radius:2px;flex-shrink:0"></span>' +
        '<span style="font-family:var(--font-mono);font-size:11px;color:var(--accent);flex:1;min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">'+esc(fname)+'<span style="color:var(--muted)">'+esc(lineStr)+'</span></span>' +
        '<span class="sev '+sev+'" style="font-size:9px;padding:1px 6px;flex-shrink:0">'+sev+'</span>' +
        (f.isBlocking?'<span style="font-size:9px;padding:1px 6px;border-radius:4px;background:rgba(239,68,68,.15);color:#ef4444;border:1px solid rgba(239,68,68,.3);flex-shrink:0;font-weight:600">BLOCKING</span>':'') +
        '<span id="ghfichev-'+vi+'" style="color:var(--muted);font-size:10px;transition:transform .18s;flex-shrink:0;margin-left:4px">▶</span>' +
        '</div>' +
        '<div id="ghfib-'+vi+'" style="display:none">'+ghFindingBodyHtml(f)+'</div>' +
        '</div>';
    }).join('');

    return '<div class="pkg-group" style="margin-bottom:20px">' +
      '<div class="pkg-group-hdr" onclick="toggleGhGroup(this)" style="display:flex;align-items:center;gap:10px;padding:11px 16px;background:var(--s2);border:1px solid var(--br);border-radius:11px 11px 0 0;cursor:pointer;transition:background .13s;user-select:none" onmouseover="this.style.background=\'var(--s3)\'" onmouseout="this.style.background=\'var(--s2)\'">' +
      '<div class="vbar '+topSev+'" style="height:28px"></div>' +
      '<span style="font-size:16px;line-height:1">'+vtype.icon+'</span>' +
      '<span style="font-size:13px;font-weight:700;color:#fff;flex:1">'+esc(vtype.label)+'</span>' +
      '<div style="display:flex;align-items:center;gap:6px">'+pills+
      '<span style="font-size:11px;color:var(--muted);margin-left:4px">'+items.length+' finding'+(items.length>1?'s':'')+'</span>' +
      '<span class="pkg-chev" style="color:var(--muted);font-size:10px;transition:transform .18s;margin-left:4px">▼</span>' +
      '</div></div>' +
      '<div class="pkg-group-body" style="display:none;background:var(--s1);border:1px solid var(--br);border-top:none;border-radius:0 0 11px 11px;overflow:hidden">'+fileRows+'</div>' +
      '</div>';
  }).join('');

  window._lastSastScan = scan;
  var fileCount = new Set(findings.map(function(f){return f.path;}).filter(Boolean)).size;
  el.innerHTML =
    '<div class="detail-header">' +
    '<div class="detail-icon" style="background:rgba(167,139,250,.1);border:1px solid rgba(167,139,250,.25);display:flex;align-items:center;justify-content:center;width:56px;height:56px;border-radius:14px;flex-shrink:0">' +
    '<img src="/assets/osa.png" style="width:34px;height:34px;object-fit:contain;filter:drop-shadow(0 0 8px rgba(167,139,250,.4))"/></div>' +
    '<div class="detail-info">' +
    '<div class="detail-name">'+esc(scan.repo)+'</div>' +
    '<div class="detail-sub"><a href="'+esc(scan.url)+'" target="_blank" style="color:var(--muted);text-decoration:none">'+esc(scan.url)+' ↗</a>'+(scan.desc?' · '+esc(scan.desc):'')+' · '+findings.length+' finding'+(findings.length!==1?'s':'')+' in '+fileCount+' file'+(fileCount!==1?'s':'')+' · '+sortedGroups.length+' vuln type'+(sortedGroups.length!==1?'s':'')+' · scanned '+fmtDate(scan.scannedAt)+'</div>' +
    '<div style="margin-top:6px">'+_toxicBadgeHtml(scan.toxic)+'</div>' +
    '</div>' +
    '<div class="detail-chips">'+(chips||'<span class="sev NONE">✅ CLEAN</span>')+'</div>' +
    '<div style="margin-left:auto;flex-shrink:0">'+exportBtnHtml('sast','__SAST_SCAN__')+'</div>' +
    '</div>' +
    (findings.length===0?'<div style="text-align:center;padding:60px;color:var(--l);font-size:14px">✅ No findings — this repository looks clean!</div>':groupHtml);

  // Open first group by default
  var fb=el.querySelector('.pkg-group-body'),fc=el.querySelector('.pkg-chev');
  if(fb){fb.style.display='block';if(fc)fc.style.transform='rotate(180deg)';}
}

// ── Finding expanded body ─────────────────────────────────────
function ghFindingBodyHtml(f){
  var ruleId = f.ruleId || '';
  var msg    = f.message || 'No description';
  var cwe    = (f.cwe||[]).join(', ');
  var owasp  = (f.owasp||[]).join(', ');
  var refs   = f.references || [];
  var tech   = (f.technology||[]).join(', ');

  // Plain code block: just line number + code, no highlight
  var codeHtml = '';
  if(f.codeSnippet){
    var startLine = f.snippetStart || f.line || 1;
    var lines = f.codeSnippet.split('\n');
    var gutterW = String(startLine + lines.length - 1).length;
    var rows = lines.map(function(l, i){
      var ln = String(startLine + i).padStart(gutterW, ' ');
      return '<span style="color:var(--muted2);user-select:none;margin-right:14px">'+esc(ln)+'</span>'+esc(l);
    }).join('\n');
    codeHtml = '<span class="vk">Code</span><span class="vv"><pre style="margin:0;padding:8px 10px;background:#0d1117;border:1px solid var(--br);border-radius:7px;font-size:11px;color:#e6edf3;overflow-x:auto;line-height:1.7;font-family:var(--font-mono)">'+rows+'</pre></span>';
  }

  return '<div class="vgrid" style="padding:12px 16px 14px">' +
    '<span class="vk">Description</span><span class="vv" style="white-space:pre-wrap;line-height:1.6">'+esc(msg)+'</span>' +
    codeHtml +
    (f.fix?'<span class="vk">Suggested Fix</span><span class="vv"><pre style="margin:0;padding:8px 10px;background:rgba(52,199,89,.05);border:1px solid rgba(52,199,89,.2);border-radius:7px;font-size:11px;color:#34c759;overflow-x:auto;font-family:var(--font-mono)">'+esc(f.fix)+'</pre></span>':'') +
    '<span class="vk">Rule</span><span class="vv" style="font-family:var(--font-mono);font-size:11px;color:var(--muted);word-break:break-all">'+esc(ruleId)+'</span>' +
    (f.language?'<span class="vk">Language</span><span class="vv" style="font-size:11px;color:var(--muted)">'+esc(f.language)+'</span>':'') +
    (f.category?'<span class="vk">Category</span><span class="vv">'+esc(f.category)+'</span>':'') +
    (f.likelihood||f.impact||f.confidence?
      '<span class="vk">Risk Factors</span><span class="vv" style="display:flex;gap:8px;flex-wrap:wrap">' +
      (f.likelihood?'<span style="font-size:10px;padding:1px 7px;border-radius:10px;background:rgba(255,255,255,.06);color:var(--muted)">Likelihood: '+esc(f.likelihood)+'</span>':'') +
      (f.impact?'<span style="font-size:10px;padding:1px 7px;border-radius:10px;background:rgba(255,255,255,.06);color:var(--muted)">Impact: '+esc(f.impact)+'</span>':'') +
      (f.confidence?'<span style="font-size:10px;padding:1px 7px;border-radius:10px;background:rgba(255,255,255,.06);color:var(--muted)">Confidence: '+esc(f.confidence)+'</span>':'') +
      '</span>':'') +
    (cwe?'<span class="vk">CWE</span><span class="vv" style="color:var(--muted2);font-size:11px">'+esc(cwe)+'</span>':'') +
    (owasp?'<span class="vk">OWASP</span><span class="vv" style="color:var(--muted2);font-size:11px">'+esc(owasp)+'</span>':'') +
    (tech?'<span class="vk">Technology</span><span class="vv" style="color:var(--muted2);font-size:11px">'+esc(tech)+'</span>':'') +
    (refs.length?'<span class="vk">References</span><span class="vv">'+refs.slice(0,3).map(function(r){
      return '<a href="'+esc(safeUrl(r))+'" target="_blank" rel="noopener" style="display:block;color:var(--accent);font-size:11px;margin-bottom:2px">'+esc(r.length>70?r.slice(0,70)+'…':r)+'</a>';
    }).join('')+'</span>':'') +
    '</div>';
}

function toggleGhGroup(hdr){
  var body=hdr.nextElementSibling,chev=hdr.querySelector('.pkg-chev');
  if(!body)return;
  var open=body.style.display!=='none';
  body.style.display=open?'none':'block';
  if(chev)chev.style.transform=open?'':'rotate(180deg)';
}

function toggleGhVI(vi){
  var body=document.getElementById('ghfib-'+vi);
  var chev=document.getElementById('ghfichev-'+vi);
  if(!body)return;
  var open=body.style.display!=='none';
  body.style.display=open?'none':'block';
  if(chev)chev.style.transform=open?'':'rotate(90deg)';
}

document.addEventListener('keydown',function(e){
  if(document.getElementById('page-gh-form')&&document.getElementById('page-gh-form').classList.contains('active'))
    if(e.key==='Enter') doGhScan();
});
