'use strict';

const express = require('express');
const { z } = require('zod');
const auth = require('../services/auth');
const { validate } = require('../middleware/validate');
const { requireTrustedOrigin, requireCsrfToken } = require('../middleware/csrf');
const { createAuthLimiter } = require('../middleware/security');
const { REFRESH_COOKIE, setSessionCookies, clearSessionCookies } = require('../lib/cookies');
const s = require('../lib/schemas');

const registerSchema = z.object({
  username: s.username,
  authKey: s.authKey,
  publicKey: s.publicKey,
  encryptedPrivateKey: s.base64(32, 512),
  privateKeyIv: s.base64(16, 16),
});

const loginSchema = z.object({
  username: s.username,
  authKey: s.authKey,
});

function createAuthRouter() {
  const router = express.Router();
  const authLimiter = createAuthLimiter();

  // Also blocks login CSRF (a foreign site logging the victim into an
  // attacker-controlled account).
  router.use(requireTrustedOrigin);

  router.post('/register', authLimiter, validate({ body: registerSchema }), async (req, res) => {
    const { user, accessToken, session } = await auth.register(req.valid.body);
    setSessionCookies(res, session);
    res.status(201).json({ user, accessToken });
  });

  router.post('/login', authLimiter, validate({ body: loginSchema }), async (req, res) => {
    const { user, keys, accessToken, session } = await auth.login(req.valid.body);
    setSessionCookies(res, session);
    res.json({ user, keys, accessToken });
  });

  router.post('/refresh', requireCsrfToken, async (req, res) => {
    try {
      const { user, accessToken, session } = await auth.refresh(req.cookies[REFRESH_COOKIE]);
      setSessionCookies(res, session);
      res.json({ user, accessToken });
    } catch (err) {
      clearSessionCookies(res);
      throw err;
    }
  });

  router.post('/logout', requireCsrfToken, async (req, res) => {
    await auth.logout(req.cookies[REFRESH_COOKIE]);
    clearSessionCookies(res);
    res.status(204).end();
  });

  return router;
}

module.exports = { createAuthRouter };
