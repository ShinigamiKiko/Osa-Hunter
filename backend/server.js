// server.js — entry point
'use strict';
const express   = require('express');
const cors      = require('cors');
const path      = require('path');
const session   = require('express-session');
const pgSession = require('connect-pg-simple')(session);

const { getPool, runMigrations, seedAdmin } = require('./lib/auth/db');
const { purgeExpired }        = require('./lib/auth/scanCache');
const { requireAuth }         = require('./lib/auth/middleware');
const authRoutes              = require('./lib/auth/routes');
const apiKeyRoutes            = require('./lib/auth/api-key-routes');
const scanHistoryRoutes       = require('./lib/routes/scan-history.route');

// ── Guard: SESSION_SECRET must be explicitly set in production ─
if (!process.env.SESSION_SECRET) {
  if (process.env.NODE_ENV === 'production') {
    console.error('[boot] FATAL: SESSION_SECRET env var is not set. Refusing to start in production.');
    process.exit(1);
  } else {
    console.warn('[boot] WARNING: SESSION_SECRET is not set. Using insecure default — never do this in production.');
  }
}

const app = express();

// ── Trust reverse proxy so req.ip reflects the real client IP ─
// Required for rate-limiting and audit logs to work correctly
// when running behind nginx / Caddy / AWS ALB / etc.
app.set('trust proxy', 1);

// ── Security headers ──────────────────────────────────────────
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  res.setHeader('Referrer-Policy', 'no-referrer');
  res.setHeader(
    'Content-Security-Policy',
    "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com; img-src 'self' data:; connect-src 'self'"
  );
  next();
});

// ── CORS ──────────────────────────────────────────────────────
// credentials:true requires explicit origin — never use '*' with credentials
const corsOrigin = process.env.CORS_ORIGIN;
app.use(cors(
  corsOrigin
    ? { origin: corsOrigin, credentials: true }
    : { origin: false }   // same-origin only when no env override
));

// ── Body parsers ──────────────────────────────────────────────
app.use('/api/export/pdf', express.json({ limit: '10mb' }));
app.use(express.json({ limit: '64kb' }));

// ── Static frontend ───────────────────────────────────────────
app.use(express.static(path.join(__dirname, '../frontend/public')));

// ── Start ─────────────────────────────────────────────────────
const PORT = process.env.PORT || 3001;

runMigrations()
  .then(async () => {
    await seedAdmin();

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
        sameSite: 'lax',
        maxAge: 7 * 24 * 60 * 60 * 1000,
      },
    }));

    // ── Open auth routes (login / logout / me) ─────────────────
    app.use('/api', authRoutes);

    // ── Auth guard — everything below requires login ───────────
    app.use('/api', requireAuth);

    // ── Protected routes ───────────────────────────────────────
    app.use('/api', apiKeyRoutes);
    app.use('/api', scanHistoryRoutes);   // ← moved AFTER requireAuth

    // ── Redirect root → login if not authed ───────────────────
    app.get('/', (req, res, next) => {
      if (!req.session?.user) return res.redirect('/login.html');
      next();
    });

    const routes = [
      ['health',    './lib/routes/health.route'],
      ['trivy',     './lib/routes/trivy.route'],
      ['libscan',   './lib/routes/library-scan.route'],
      ['depscan',   './lib/routes/dependency-scan.route'],
      ['composer',  './lib/routes/composer-scan.route'],
      ['activity',  './lib/routes/activity.route'],
      ['export',    './lib/routes/export.route'],
      ['grype',     './lib/routes/grype.route'],
      ['ghscan',    './lib/routes/ghscan.route'],
      ['cache',     './lib/routes/cache.route'],
    ];

    for (const [name, modPath] of routes) {
      try {
        app.use('/api', require(modPath));
        console.log(`[boot] ✅ ${name} loaded`);
      } catch (e) {
        console.error(`[boot] ❌ ${name} FAILED: ${e.message}`);
        process.exit(1);
      }
    }

    // ── Global error handler — must be registered AFTER all routes ─
    app.use((err, req, res, _next) => {
      console.error('[Unhandled]', err.message);
      if (!res.headersSent) res.status(500).json({ error: 'Internal server error' });
    });

    // Purge expired cache entries every 6 hours
    setInterval(purgeExpired, 6 * 60 * 60 * 1000);
    purgeExpired();

    app.listen(PORT, () => console.log(`OSA Hunter → http://localhost:${PORT}`));
  })
  .catch(err => {
    console.error('[boot] Migration failed:', err.message);
    process.exit(1);
  });
