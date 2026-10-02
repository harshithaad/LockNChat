'use strict';

const config = require('../config');
const { AppError } = require('../lib/errors');
const { CSRF_COOKIE } = require('../lib/cookies');
const { safeEqual } = require('../lib/tokens');

/**
 * Reject state-changing requests sent from a foreign origin. Browsers always
 * attach Origin to cross-site POSTs, so a forged request from another site is
 * stopped here. Requests with no Origin come from non-browser clients, which
 * cannot carry a victim's cookies and are not a CSRF vector.
 */
function requireTrustedOrigin(req, res, next) {
  const origin = req.get('origin');
  if (origin && !config.corsOrigins.includes(origin)) {
    return next(new AppError(403, 'origin_not_allowed', 'Origin not allowed'));
  }
  next();
}

/**
 * Double-submit check for endpoints authenticated by cookie (refresh, logout).
 * The X-CSRF-Token header must match the CSRF cookie. Another site can make
 * the browser send our cookies, but cannot read them to build this header.
 */
function requireCsrfToken(req, res, next) {
  const cookieToken = req.cookies?.[CSRF_COOKIE];
  const headerToken = req.get('x-csrf-token');
  if (!cookieToken || !headerToken || !safeEqual(cookieToken, headerToken)) {
    return next(new AppError(403, 'csrf_failed', 'CSRF token missing or invalid'));
  }
  next();
}

module.exports = { requireTrustedOrigin, requireCsrfToken };
