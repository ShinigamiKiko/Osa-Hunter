'use strict';

const { RateLimiter } = require('./primitives');

const trivyLimiter = new RateLimiter(
  parseInt(process.env.TRIVY_RATE_LIMIT || '5'),
  parseInt(process.env.TRIVY_RATE_WINDOW || '60000')
);
const apiLimiter = new RateLimiter(
  parseInt(process.env.API_RATE_LIMIT || '120'),
  parseInt(process.env.API_RATE_WINDOW || '60000')
);
const scanLimiter = new RateLimiter(
  parseInt(process.env.SCAN_RATE_LIMIT || '20'),
  parseInt(process.env.SCAN_RATE_WINDOW || '60000')
);

function rateLimit(limiter) {
  return (req, res, next) => {
    // req.ip respects app.set('trust proxy', 1) set in server.js,
    // so it returns the real client IP even behind a reverse proxy.
    // Do NOT read X-Forwarded-For manually — it is trivially spoofable.
    const ip = req.ip || req.socket?.remoteAddress || 'unknown';
    if (!limiter.check(ip)) return res.status(429).json({ error: 'Rate limit exceeded. Please wait before retrying.' });
    next();
  };
}

module.exports = { trivyLimiter, apiLimiter, scanLimiter, rateLimit };
