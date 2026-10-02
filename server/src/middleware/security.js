'use strict';

const helmet = require('helmet');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const config = require('../config');
const { AppError } = require('../lib/errors');

/**
 * Secure HTTP headers. The CSP only allows scripts, styles and connections
 * from our own origin: no inline scripts, no eval, no third-party code, so an
 * injected <script> tag has nothing it is allowed to run.
 */
const securityHeaders = helmet({
  contentSecurityPolicy: {
    useDefaults: false,
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'"],
      styleSrc: ["'self'"],
      imgSrc: ["'self'", 'data:'],
      fontSrc: ["'self'"],
      connectSrc: ["'self'"],
      objectSrc: ["'none'"],
      baseUri: ["'none'"],
      formAction: ["'self'"],
      frameAncestors: ["'none'"],
      ...(config.isProduction ? { upgradeInsecureRequests: [] } : {}),
    },
  },
  strictTransportSecurity: { maxAge: 31536000, includeSubDomains: true },
  referrerPolicy: { policy: 'no-referrer' },
  xFrameOptions: { action: 'deny' },
  crossOriginOpenerPolicy: { policy: 'same-origin' },
  crossOriginResourcePolicy: { policy: 'same-origin' },
});

/** Only listed origins may make credentialed cross-origin requests. */
const corsPolicy = cors({
  origin(origin, callback) {
    // Same-origin requests and non-browser clients send no Origin header.
    if (!origin || config.corsOrigins.includes(origin)) return callback(null, true);
    return callback(new AppError(403, 'origin_not_allowed', 'Origin not allowed'));
  },
  credentials: true,
  methods: ['GET', 'POST', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-CSRF-Token'],
  maxAge: 600,
});

/** API responses may contain tokens or private data: never cache them. */
function noStore(req, res, next) {
  res.set('Cache-Control', 'no-store');
  next();
}

function limiter({ windowMs, limit, message }) {
  return rateLimit({
    windowMs,
    limit,
    standardHeaders: 'draft-8',
    legacyHeaders: false,
    handler: (req, res, next) => next(new AppError(429, 'rate_limited', message)),
  });
}

// Factories rather than singletons so each app instance gets its own counters.
function createApiLimiter() {
  return limiter({
    windowMs: 15 * 60 * 1000,
    limit: config.rateLimitApiMax,
    message: 'Too many requests, please slow down',
  });
}

function createAuthLimiter() {
  return limiter({
    windowMs: 15 * 60 * 1000,
    limit: config.rateLimitAuthMax,
    message: 'Too many authentication attempts, please try again later',
  });
}

module.exports = { securityHeaders, corsPolicy, noStore, createApiLimiter, createAuthLimiter };
