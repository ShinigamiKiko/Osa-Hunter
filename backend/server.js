// server.js — entry point
'use strict';
const express   = require('express');
const cors      = require('cors');
const path      = require('path');
const session   = require('express-session');
const pgSession = require('connect-pg-simple')(session);

const { getPool, runMigrations, seedAdmin } = require('./lib/auth/db');
const { requireAuth }            = require('./lib/auth/middleware');
const authRoutes                 = require('./lib/auth/routes');

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
app.use(cors({ origin: process.env.CORS_ORIGIN || '*', credentials: true }));

// ── Body parsers ──────────────────────────────────────────────
app.use('/api/export/pdf', express.json({ limit: '10mb' }));
app.use(express.json({ limit: '64kb' }));

// ── Static frontend (no auth needed for assets + login.html) ─
app.use(express.static(path.join(__dirname, '../frontend/public')));

// ── Global error handler ──────────────────────────────────────
app.use((err, req, res, _next) => {
  console.error('[Unhandled]', err);
  res.status(500).json({ error: 'Internal server error' });
});

// ── Start: migrations first, then session + routes ───────────
const PORT = process.env.PORT || 3001;

runMigrations()
  .then(async () => {
    await seedAdmin();
    // ✅ Session store init AFTER migrations — table 'session' now exists
    app.use(session({
      store: new pgSession({
        pool: getPool(),
        tableName: 'session',
        createTableIfMissing: false,
      }),
      secret: process.env.SESSION_SECRET || 'osa-hunter-secret-change-in-prod',
      resave: false,
      saveUninitialized: false,
      cookie: {
        secure: process.env.NODE_ENV === 'production' && process.env.HTTPS === 'true',
        httpOnly: true,
        maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
      },
    }));

    // ── Auth routes (open, before guard) ──────────────────────
    app.use('/api', authRoutes);

    // ── Auth guard on all /api/* ───────────────────────────────
    app.use('/api', requireAuth);

    // ── Redirect root → login if not authed ───────────────────
    app.get('/', (req, res, next) => {
      if (!req.session?.user) return res.redirect('/login.html');
      next();
    });

    // ── API routes ─────────────────────────────────────────────
    const routes = [
      ['health',   './lib/routes/health.route'],
      ['trivy',    './lib/routes/trivy.route'],
      ['libscan',  './lib/routes/library-scan.route'],
      ['depscan',  './lib/routes/dependency-scan.route'],
      ['composer', './lib/routes/composer-scan.route'],
      ['activity', './lib/routes/activity.route'],
      ['export',   './lib/routes/export.route'],
      ['grype',    './lib/routes/grype.route'],
      ['ghscan',   './lib/routes/ghscan.route'],
    ];

    for (const [name, modPath] of routes) {
      try {
        console.log(`[boot] Loading route: ${name}`);
        app.use('/api', require(modPath));
        console.log(`[boot] ✅ ${name} loaded`);
      } catch (e) {
        console.error(`[boot] ❌ ${name} FAILED: ${e.message}`);
        console.error(e.stack);
        process.exit(1);
      }
    }

    app.listen(PORT, () => console.log(`OSA Hunter → http://localhost:${PORT}`));
  })
  .catch(err => {
    console.error('[boot] Migration failed:', err.message);
    process.exit(1);
  });
