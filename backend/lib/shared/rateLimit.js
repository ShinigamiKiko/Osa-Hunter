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
    const ip = req.headers['x-forwarded-for']?.split(',')[0].trim() || req.socket.remoteAddress || 'unknown';
    if (!limiter.check(ip)) return res.status(429).json({ error: 'Rate limit exceeded. Please wait before retrying.' });
    next();
  };
}

module.exports = { trivyLimiter, apiLimiter, scanLimiter, rateLimit };
