'use strict';

const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const config = require('../config');

const ISSUER = 'locknchat';
const AUDIENCE = 'locknchat-api';

/** Short-lived access token, sent by the client in the Authorization header. */
function signAccessToken(user) {
  return jwt.sign({ username: user.username, type: 'access' }, config.jwtSecret, {
    algorithm: 'HS256',
    expiresIn: config.accessTokenTtlSeconds,
    issuer: ISSUER,
    audience: AUDIENCE,
    subject: user.id,
    jwtid: crypto.randomUUID(),
  });
}

/**
 * Verify an access token. The algorithm is pinned to HS256 so tokens using
 * `alg: none` or a different algorithm are rejected outright.
 * Throws jsonwebtoken errors (TokenExpiredError, JsonWebTokenError).
 */
function verifyAccessToken(token) {
  const payload = jwt.verify(token, config.jwtSecret, {
    algorithms: ['HS256'],
    issuer: ISSUER,
    audience: AUDIENCE,
  });
  if (payload.type !== 'access' || typeof payload.sub !== 'string') {
    throw new jwt.JsonWebTokenError('invalid token type');
  }
  return { id: payload.sub, username: payload.username, exp: payload.exp };
}

/** Opaque, high-entropy refresh token. Only its SHA-256 hash is stored. */
function generateRefreshToken() {
  const token = crypto.randomBytes(32).toString('base64url');
  return { token, hash: hashToken(token) };
}

function hashToken(token) {
  return crypto.createHash('sha256').update(token).digest('hex');
}

function generateCsrfToken() {
  return crypto.randomBytes(32).toString('base64url');
}

/** Constant-time string comparison, so response timing reveals nothing. */
function safeEqual(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string') return false;
  const bufA = Buffer.from(a);
  const bufB = Buffer.from(b);
  return bufA.length === bufB.length && crypto.timingSafeEqual(bufA, bufB);
}

module.exports = {
  signAccessToken,
  verifyAccessToken,
  generateRefreshToken,
  hashToken,
  generateCsrfToken,
  safeEqual,
};
