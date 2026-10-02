'use strict';

const jwt = require('jsonwebtoken');
const { verifyAccessToken } = require('../lib/tokens');
const { AppError } = require('../lib/errors');

/** Require a valid access token in `Authorization: Bearer <token>`. */
function requireAuth(req, res, next) {
  const header = req.get('authorization') || '';
  const [scheme, token] = header.split(' ');
  if (scheme !== 'Bearer' || !token) {
    res.set('WWW-Authenticate', 'Bearer');
    return next(new AppError(401, 'unauthenticated', 'Authentication required'));
  }

  try {
    req.user = verifyAccessToken(token);
    return next();
  } catch (err) {
    res.set('WWW-Authenticate', 'Bearer error="invalid_token"');
    if (err instanceof jwt.TokenExpiredError) {
      return next(new AppError(401, 'token_expired', 'Access token expired'));
    }
    return next(new AppError(401, 'invalid_token', 'Invalid access token'));
  }
}

module.exports = { requireAuth };
