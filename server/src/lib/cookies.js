'use strict';

const config = require('../config');

const REFRESH_COOKIE = 'lnc_rt';
const CSRF_COOKIE = 'lnc_csrf';
const REFRESH_COOKIE_PATH = '/api/auth';

function setSessionCookies(res, { refreshToken, csrfToken, expiresAt }) {
  const maxAge = Math.max(0, expiresAt.getTime() - Date.now());

  // httpOnly: page JavaScript (and therefore XSS) can never read the token.
  // SameSite=Strict: the browser will not attach it to cross-site requests.
  // Path: only sent to the auth endpoints, not to every API call.
  res.cookie(REFRESH_COOKIE, refreshToken, {
    httpOnly: true,
    secure: config.cookieSecure,
    sameSite: 'strict',
    path: REFRESH_COOKIE_PATH,
    maxAge,
  });

  // Double-submit CSRF token: readable by our own page so it can be echoed
  // back in a header, which a cross-site attacker cannot do.
  res.cookie(CSRF_COOKIE, csrfToken, {
    httpOnly: false,
    secure: config.cookieSecure,
    sameSite: 'strict',
    path: '/',
    maxAge,
  });
}

function clearSessionCookies(res) {
  const base = { secure: config.cookieSecure, sameSite: 'strict' };
  res.clearCookie(REFRESH_COOKIE, { ...base, httpOnly: true, path: REFRESH_COOKIE_PATH });
  res.clearCookie(CSRF_COOKIE, { ...base, path: '/' });
}

module.exports = { REFRESH_COOKIE, CSRF_COOKIE, setSessionCookies, clearSessionCookies };
