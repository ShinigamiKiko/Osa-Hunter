// server.js — entry point
'use strict';
const express = require('express');
const cors    = require('cors');
const path    = require('path');

const app = express();

// ── Security headers ──────────────────────────────────────────
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  res.setHeader('Referrer-Policy', 'no-referrer');
  next();
});

// ── CORS ──────────────────────────────────────────────────────
app.use(cors({ origin: process.env.CORS_ORIGIN || '*' }));

// ── Body parsers ──────────────────────────────────────────────
app.use('/api/export/pdf', express.json({ limit: '10mb' }));
app.use(express.json({ limit: '64kb' }));

// ── Static frontend ───────────────────────────────────────────
app.use(express.static(path.join(__dirname, '../frontend/public')));

// ── Routes (with debug logging) ──────────────────────────────
const routes = [
  ['health',     './lib/routes/health.route'],
  ['trivy',      './lib/routes/trivy.route'],
  ['libscan',    './lib/routes/library-scan.route'],
  ['depscan',    './lib/routes/dependency-scan.route'],
  ['composer',   './lib/routes/composer-scan.route'],
  ['activity',   './lib/routes/activity.route'],
  ['export',     './lib/routes/export.route'],
  ['grype',      './lib/routes/grype.route'],
  ['ghscan',     './lib/routes/ghscan.route'],
];

for (const [name, modPath] of routes) {
  try {
    console.log(`[boot] Loading route: ${name} (${modPath})`);
    app.use('/api', require(modPath));
    console.log(`[boot] ✅ ${name} loaded`);
  } catch (e) {
    console.error(`[boot] ❌ ${name} FAILED: ${e.message}`);
    console.error(e.stack);
    process.exit(1);
  }
}

// ── Global error handler ──────────────────────────────────────
app.use((err, req, res, _next) => {
  console.error('[Unhandled]', err);
  res.status(500).json({ error: 'Internal server error' });
});

const PORT = process.env.PORT || 3001;
app.listen(PORT, () => console.log(`OSA Hunter → http://localhost:${PORT}`));