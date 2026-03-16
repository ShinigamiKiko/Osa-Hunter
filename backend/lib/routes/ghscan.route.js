// routes/ghscan.route.js — POST /api/ghscan
'use strict';
const { withCache, ScanError } = require('../auth/scanCache');

const express      = require('express');
const router       = express.Router();
const { execFile } = require('child_process');
const fs           = require('fs');
const path         = require('path');
const os           = require('os');
const { scanLimiter, rateLimit, checkToxic, SEV_ORD } = require('../shared');

const GH_RE = /^https:\/\/github\.com\/([a-zA-Z0-9._-]+)\/([a-zA-Z0-9._-]+?)(\.git)?$/;

function validGhUrl(url) {
  return typeof url === 'string' && GH_RE.test(url.trim()) && url.length < 200;
}
function parseRepoName(url) {
  const m = url.match(GH_RE);
  return m ? `${m[1]}/${m[2]}` : url;
}
function exec(cmd, args, opts) {
  return new Promise((resolve, reject) => {
    execFile(cmd, args, opts, (err, stdout, stderr) => {
      if (err) return reject(Object.assign(err, { stdout, stderr }));
      resolve({ stdout, stderr });
    });
  });
}
function cleanup(dir) {
  try { fs.rmSync(dir, { recursive: true, force: true }); } catch {}
}
function cleanupFile(filePath) {
  try { fs.unlinkSync(filePath); } catch {}
}

// ── Rule ID → short display name (language-agnostic) ──────────
function ruleShortName(ruleId) {
  const parts = (ruleId || '').split('.');
  // Take last meaningful segment, skip generic ones like 'security', 'audit'
  const skip = new Set(['security','audit','correctness','performance','best-practice','lang','rules']);
  const last = [...parts].reverse().find(p => p && !skip.has(p)) || parts[parts.length - 1] || ruleId;
  return last.replace(/[-_]/g, ' ').replace(/\b\w/g, c => c.toUpperCase());
}

// ── Detect language from file extension ───────────────────────
function langFromPath(filePath) {
  const ext = (filePath || '').split('.').pop().toLowerCase();
  const map = {
    js:'JavaScript', ts:'TypeScript', jsx:'JavaScript', tsx:'TypeScript',
    py:'Python', rb:'Ruby', php:'PHP', java:'Java', go:'Go',
    cs:'C#', cpp:'C++', c:'C', rs:'Rust', kt:'Kotlin',
    swift:'Swift', scala:'Scala', sh:'Shell', bash:'Shell',
    yaml:'YAML', yml:'YAML', json:'JSON', xml:'XML', html:'HTML',
    tf:'Terraform', dockerfile:'Dockerfile',
  };
  return map[ext] || ext.toUpperCase() || 'Unknown';
}

// SEV_ORD imported from shared — no local redefinition needed
function normSev(s) {
  const up = (s||'').toUpperCase();
  if (up === 'ERROR')   return 'HIGH';
  if (up === 'WARNING') return 'MEDIUM';
  if (up === 'INFO')    return 'LOW';
  return SEV_ORD.includes(up) ? up : 'UNKNOWN';
}

router.post('/ghscan', rateLimit(scanLimiter), async (req, res) => {
  const ip = req.ip || req.socket?.remoteAddress || 'unknown';
  const { url, desc } = req.body || {};

  if (!url) return res.status(400).json({ error: 'url is required' });
  if (!validGhUrl(url)) return res.status(400).json({ error: 'Only public GitHub URLs supported' });

  const repo     = parseRepoName(url);
  const _cacheKey = `sast:${repo}`;

  return withCache(_cacheKey, 'sast', res, async () => {
  const cloneUrl = url.endsWith('.git') ? url : `${url}.git`;
  const tmpDir   = path.join(os.tmpdir(), `ghscan-${Date.now()}-${Math.random().toString(36).slice(2)}`);

  console.log(`[GHScan] ${repo} → ${tmpDir} (ip: ${ip})`);

  // ── 1. Check repo exists ──────────────────────────────────
  try {
    const check = await fetch(`https://api.github.com/repos/${repo}`, {
      signal: AbortSignal.timeout(8000),
      headers: { 'User-Agent': 'OSAHunter/1.0' },
    });
    if (check.status === 404) throw new ScanError(404, `Repository "${repo}" not found on GitHub`);
  } catch (e) {
    if (e instanceof ScanError) throw e;
    throw new ScanError(502, 'GitHub unreachable: ' + e.message);
  }

  // ── 2. Clone ──────────────────────────────────────────────
  try {
    await exec('git', [
      '-c', 'credential.helper=',
      '-c', 'core.askPass=',
      'clone', '--depth=1', '--single-branch',
      '--filter=blob:limit=2m',
      cloneUrl, tmpDir,
    ], {
      timeout: 120_000,
      env: { ...process.env, GIT_TERMINAL_PROMPT: '0', GIT_ASKPASS: 'echo' },
    });
  } catch (e) {
    cleanup(tmpDir);
    throw new ScanError(502, `Clone failed: ${e.message}`);
  }

  // ── 3. Size check ─────────────────────────────────────────
  try {
    const { stdout } = await exec('du', ['-sm', tmpDir], { timeout: 10_000 });
    const mb = parseInt(stdout.split('\t')[0], 10);
    console.log(`[GHScan] ${repo} — size: ${mb}MB`);
    if (mb > 700) {
      cleanup(tmpDir);
      throw new ScanError(413, `Repository too large (${mb}MB). Limit is 700MB.`);
    }
  } catch {}

  // ── 4. Semgrep — output to JSON file ─────────────────────
  const jsonOut = path.join(os.tmpdir(), `semgrep-${Date.now()}-${Math.random().toString(36).slice(2)}.json`);
  console.log(`[GHScan] ${repo} — starting semgrep p/security-audit → ${jsonOut}`);

  let semgrepErr = '';
  try {
    const { stderr } = await exec('semgrep', [
      '--config', 'p/security-audit',
      '--metrics=off',
      '--json',
      '--output', jsonOut,
      '--no-error',
      '--no-git-ignore',
      '--jobs', '1',
      '--timeout', '60',
      '--max-memory', '1000',
      tmpDir,
    ], {
      timeout: 300_000,
      maxBuffer: 1 * 1024 * 1024, // stdout unused; stderr only for logs
      env: {
        ...process.env,
        SEMGREP_SEND_METRICS: 'off',
        NO_COLOR: '1',
      },
    });
    semgrepErr = stderr || '';
    console.log(`[GHScan] ${repo} — semgrep done`);
    if (semgrepErr) console.log(`[GHScan] semgrep stderr: ${semgrepErr.slice(0, 300)}`);
  } catch (e) {
    semgrepErr = e.stderr || '';
    console.log(`[GHScan] semgrep exit: code=${e.code} signal=${e.signal} killed=${e.killed}`);
    console.log(`[GHScan] semgrep stderr: ${semgrepErr.slice(0, 500)}`);
    // If output file wasn't created at all — hard fail
    if (!fs.existsSync(jsonOut)) {
      cleanup(tmpDir);
      cleanupFile(jsonOut);
      throw new ScanError(500, 'Semgrep failed: ' + (semgrepErr.slice(0,200) || e.message));
    }
  } // end semgrep try/catch — tmpDir still alive here

  // ── 5. Read JSON file → parse ────────────────────────────
  let parsed;
  try {
    const raw = fs.readFileSync(jsonOut, 'utf8');
    parsed = JSON.parse(raw);
    console.log(`[GHScan] ${repo} — JSON file read, ${raw.length} bytes`);
  } catch (e) {
    console.error('[GHScan] JSON file read/parse failed:', e.message);
    cleanup(tmpDir);
    cleanupFile(jsonOut);
    throw new ScanError(500, 'Failed to read Semgrep JSON output: ' + e.message);
  } finally {
    cleanupFile(jsonOut);
    console.log(`[GHScan] ${repo} — JSON file deleted`);
  }

  // Now safe to delete the repo
  cleanup(tmpDir);
  console.log(`[GHScan] ${repo} — temp repo cleaned`);

  // ── 6. Build findings from JSON ──────────────────────────
  const rawFindings = parsed.results || [];
  const findings = rawFindings.map(f => {
    const rawPath = f.path || '';
    const relPath = rawPath.startsWith(tmpDir)
      ? rawPath.slice(tmpDir.length + 1)
      : rawPath;

    const ruleId  = f.check_id || '';
    const meta    = f.extra?.metadata || {};
    const normArr = v => Array.isArray(v) ? v : (v ? [v] : []);

    const startLine = f.start?.line || 1;
    const endLine   = f.end?.line   || startLine;

    // extra.lines is the actual source code at the finding location — use it directly
    const codeSnippet = (f.extra?.lines || '').trimEnd();

    return {
      ruleId,
      ruleShortName: ruleShortName(ruleId),
      path:          relPath,
      language:      meta.language || meta.languages?.[0] || langFromPath(relPath),
      line:          startLine,
      col:           f.start?.col || null,
      lineEnd:       endLine,
      colEnd:        f.end?.col   || null,
      snippetStart:  startLine,   // extra.lines starts at the finding line
      severity:      normSev(f.extra?.severity || f.severity),
      message:       f.extra?.message || '',
      codeSnippet,
      fix:           f.extra?.fix || null,
      category:      meta.category    || '',
      likelihood:    meta.likelihood  || '',
      impact:        meta.impact      || '',
      confidence:    meta.confidence  || '',
      cwe:           normArr(meta.cwe),
      owasp:         normArr(meta.owasp),
      references:    normArr(meta.references),
      technology:    normArr(meta.technology),
    };
  });

  findings.sort((a,b) => SEV_ORD.indexOf(a.severity) - SEV_ORD.indexOf(b.severity));

  const counts = { CRITICAL:0, HIGH:0, MEDIUM:0, LOW:0, UNKNOWN:0 };
  findings.forEach(f => { if (f.severity in counts) counts[f.severity]++; });
  const topSev = ['CRITICAL','HIGH','MEDIUM','LOW'].find(s => counts[s]) || 'NONE';

  console.log(`[GHScan] ${repo} — ${findings.length} findings (${topSev})`);

  const toxic = await checkToxic(repo).catch(() => ({ found: false }));
  console.log(`[GHScan] ${repo} — toxic: ${toxic.found}`);

  return { repo, url, desc: desc||'', findings, counts, topSev, toxic, errors: (parsed.errors||[]).length, scannedAt: new Date().toISOString() };
  }); // withCache
});

module.exports = router;
