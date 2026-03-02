'use strict';
const { wrapHtml, buildHeader, buildChips, buildAlerts, buildFooter, sevBadge } = require('./style');

// Parse CWE id from array like ["CWE-79: Improper..."]
function parseCweId(cweArr) {
  const raw = (cweArr||[])[0] || '';
  const m = raw.match(/CWE-(\d+)/i);
  return m ? parseInt(m[1], 10) : null;
}

function cweToLabel(cweArr) {
  const id = parseCweId(cweArr);
  if (!id) return null;
  const map = {
    89:{ label:'SQL Injection', icon:'💉' }, 79:{ label:'XSS', icon:'🔥' },
    78:{ label:'Command Injection', icon:'⚡' }, 94:{ label:'Code Injection', icon:'💀' },
    95:{ label:'Eval Injection', icon:'💀' }, 22:{ label:'Path Traversal', icon:'📂' },
    798:{ label:'Hardcoded Secret', icon:'🔑' }, 259:{ label:'Hardcoded Secret', icon:'🔑' },
    321:{ label:'Hardcoded Secret', icon:'🔑' }, 918:{ label:'SSRF', icon:'🌐' },
    611:{ label:'XXE', icon:'📄' }, 502:{ label:'Insecure Deserialization', icon:'📦' },
    601:{ label:'Open Redirect', icon:'↪️' }, 352:{ label:'CSRF', icon:'🎭' },
    942:{ label:'CORS Misconfiguration', icon:'🌍' }, 347:{ label:'JWT Issue', icon:'🎫' },
    327:{ label:'Weak Cryptography', icon:'🔓' }, 328:{ label:'Weak Cryptography', icon:'🔓' },
    117:{ label:'Log Injection', icon:'📝' }, 1321:{ label:'Prototype Pollution', icon:'☠️' },
    338:{ label:'Weak Randomness', icon:'🎲' }, 1004:{ label:'Insecure Cookie', icon:'🍪' },
    400:{ label:'DoS / ReDoS', icon:'💣' }, 200:{ label:'Information Exposure', icon:'👁' },
    209:{ label:'Information Exposure', icon:'👁' },
  };
  return map[id] || { label:`CWE-${id}`, icon:'⚠️' };
}

function ruleIdToLabel(ruleId) {
  const r = (ruleId||'').toLowerCase();
  if (/sql.?inject|sqli/.test(r))   return { label:'SQL Injection', icon:'💉' };
  if (/xss|html.inject/.test(r))    return { label:'XSS', icon:'🔥' };
  if (/command.inject|cmd.inject/.test(r)) return { label:'Command Injection', icon:'⚡' };
  if (/eval|exec.inject|rce/.test(r)) return { label:'Code Injection', icon:'💀' };
  if (/path.travers|lfi|rfi/.test(r)) return { label:'Path Traversal', icon:'📂' };
  if (/secret|hardcode|api.key|token|password|credential/.test(r)) return { label:'Hardcoded Secret', icon:'🔑' };
  if (/ssrf/.test(r))               return { label:'SSRF', icon:'🌐' };
  if (/csrf/.test(r))               return { label:'CSRF', icon:'🎭' };
  if (/jwt/.test(r))                return { label:'JWT Issue', icon:'🎫' };
  if (/prototype.pollu/.test(r))    return { label:'Prototype Pollution', icon:'☠️' };
  return { label:'Security Issue', icon:'⚠️' };
}

function vulnType(f) {
  const fromCwe = cweToLabel(f.cwe);
  return fromCwe || ruleIdToLabel(f.ruleId);
}

function buildSastReportHtml(scan, { osaPngB64 = '' } = {}) {
  const repo     = scan.repo || 'Repository';
  const url      = scan.url || '';
  const findings = scan.findings || [];
  const counts   = scan.counts || {};
  const topSev   = ['CRITICAL','HIGH','MEDIUM','LOW'].find(s => (counts[s]||0) > 0) || 'NONE';
  const date     = new Date(scan.scannedAt || Date.now()).toLocaleString('en-US', { year:'numeric', month:'short', day:'2-digit', hour:'2-digit', minute:'2-digit' });

  const fileCount = new Set(findings.map(f => f.path).filter(Boolean)).size;
  const SEV_W = { CRITICAL:4, HIGH:3, MEDIUM:2, LOW:1, UNKNOWN:0 };

  // Group by CWE id
  const byGroup = new Map();
  findings.forEach(f => {
    const vtype = vulnType(f);
    const cweId = parseCweId(f.cwe);
    const key   = cweId ? `cwe-${cweId}` : vtype.label;
    if (!byGroup.has(key)) byGroup.set(key, { vtype, cweId, items: [] });
    byGroup.get(key).items.push(f);
  });

  const sortedGroups = [...byGroup.values()].sort((a, b) => {
    const topA = Math.max(...a.items.map(f => SEV_W[(f.severity||'UNKNOWN').toUpperCase()]||0));
    const topB = Math.max(...b.items.map(f => SEV_W[(f.severity||'UNKNOWN').toUpperCase()]||0));
    return topB - topA;
  });

  const header = buildHeader({
    logo: osaPngB64,
    title: 'GitHub SAST Scan',
    sub: repo,
    sev: topSev,
    meta: `Scanned: ${date} · ${findings.length} finding${findings.length!==1?'s':''} in ${fileCount} file${fileCount!==1?'s':''} · ${sortedGroups.length} vuln type${sortedGroups.length!==1?'s':''}`,
  });

  const chips  = buildChips(counts, 0, 0);
  const alerts = buildAlerts(0, 0, scan.toxic);

  const groupSections = sortedGroups.map(({ vtype, cweId, items }) => {
    const topSevG = ['CRITICAL','HIGH','MEDIUM','LOW'].find(s => items.some(f => (f.severity||'').toUpperCase()===s)) || 'UNKNOWN';
    const cweLabel = cweId ? ` · CWE-${cweId}` : '';
    const rows = items.map(f => {
      const sev       = (f.severity||'UNKNOWN').toUpperCase();
      const shortName = f.ruleShortName || (f.ruleId||'').split('.').pop().replace(/[-_]/g,' ').replace(/\b\w/g,c=>c.toUpperCase());
      const fileLoc   = f.path ? `${f.path}${f.line ? ':'+f.line : ''}` : '';
      const codeStr   = f.codeSnippet ? (f.codeSnippet.split('\n')[0]||'').slice(0,100) : '';
      const cweStr    = (f.cwe||[]).join(', ');
      return `<div class="finding-row">
        <div class="finding-vbar ${sev}"></div>
        <div class="finding-body">
          <div class="finding-rule">${shortName}</div>
          <div class="finding-file">${fileLoc}</div>
          ${f.message ? `<div class="finding-desc">${String(f.message).slice(0,200)}</div>` : ''}
          ${codeStr ? `<div class="finding-code">${f.line ? f.line+'  ' : ''}${codeStr}</div>` : ''}
          ${cweStr ? `<div class="finding-cwe">${cweStr}</div>` : ''}
        </div>
        <div style="flex-shrink:0;margin-top:2px">${sevBadge(sev)}</div>
      </div>`;
    }).join('');

    return `<div class="section">
      <div class="sec-hdr">
        <span class="sec-title">${vtype.icon} ${vtype.label}${cweLabel}</span>
        <span class="sec-count">${items.length} finding${items.length!==1?'s':''}</span>
      </div>
      ${rows}
    </div>`;
  }).join('');

  const emptyHtml = findings.length === 0
    ? '<div style="text-align:center;padding:60px;color:#34d399;font-size:14px">✅ No findings — this repository looks clean!</div>'
    : groupSections;

  return wrapHtml(header + chips + alerts + emptyHtml + buildFooter(date));
}

module.exports = { buildSastReportHtml };
