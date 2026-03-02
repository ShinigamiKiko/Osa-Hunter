'use strict';

// Protect all /api/* routes except auth endpoints
function requireAuth(req, res, next) {
  const open = [
    '/api/auth/login',
    '/api/auth/status',
    '/api/health',
  ];
  if (open.some(p => req.path.startsWith(p))) return next();
  if (req.session?.user) return next();

  // API call → JSON error; browser → redirect to login
  const wants = req.headers.accept || '';
  if (wants.includes('text/html')) {
    return res.redirect('/login.html');
  }
  return res.status(401).json({ error: 'Unauthorized' });
}

// Admin-only middleware
function requireAdmin(req, res, next) {
  if (req.session?.user?.role === 'admin') return next();
  return res.status(403).json({ error: 'Forbidden — admin only' });
}

module.exports = { requireAuth, requireAdmin };
