'use strict';
const express   = require('express');
const cors      = require('cors');
const path      = require('path');
const crypto    = require('crypto');
const session   = require('express-session');
const pgSession = require('connect-pg-simple')(session);

const { getPool, runMigrations, seedAdmin } = require('./lib/auth/db');
const { purgeExpired }        = require('./lib/auth/scanCache');
const { requireAuth }         = require('./lib/auth/middleware');
const authRoutes              = require('./lib/auth/routes');
const apiKeyRoutes            = require('./lib/auth/api-key-routes');
const scanHistoryRoutes       = require('./lib/routes/scan-history.route');

const sessionSecret = process.env.SESSION_SECRET || (() => {
  const generated = crypto.randomBytes(32).toString('hex');
  console.warn('[boot] SESSION_SECRET not set — generated a random one.');
  console.warn('[boot] All sessions will be lost on restart. Set SESSION_SECRET in .env to avoid this.');
  return generated;
})();

const app = express();

app.set('trust proxy', 1);

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

const corsOrigin = process.env.CORS_ORIGIN;
app.use(cors(
  corsOrigin
    ? { origin: corsOrigin, credentials: true }
    : { origin: false }
));

app.use('/api/export/pdf', express.json({ limit: '10mb' }));
app.use(express.json({ limit: '64kb' }));

app.use(express.static(path.join(__dirname, '../frontend/public')));

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
      secret: sessionSecret,
      resave: false,
      saveUninitialized: false,
      cookie: {
        secure: process.env.NODE_ENV === 'production' && process.env.HTTPS === 'true',
        httpOnly: true,
        sameSite: 'lax',
        maxAge: 7 * 24 * 60 * 60 * 1000,
      },
    }));

    app.use('/api', authRoutes);

    app.use('/api', requireAuth);

    app.use('/api', apiKeyRoutes);
    app.use('/api', scanHistoryRoutes);

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

    app.use((err, req, res, _next) => {
      console.error('[Unhandled]', err.message);
      if (!res.headersSent) res.status(500).json({ error: 'Internal server error' });
    });

    setInterval(purgeExpired, 6 * 60 * 60 * 1000);
    purgeExpired();

    app.listen(PORT, () => console.log(`OSA Hunter → http://localhost:${PORT}`));
  })
  .catch(err => {
    console.error('[boot] Migration failed:', err.message);
    process.exit(1);
  });
