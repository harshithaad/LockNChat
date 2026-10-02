'use strict';

const crypto = require('crypto');
const request = require('supertest');
const db = require('../src/db/pool');

const ORIGIN = 'http://localhost:3000';

async function resetDb() {
  await db.query(
    'TRUNCATE messages, conversations, refresh_tokens, users RESTART IDENTITY CASCADE'
  );
}

async function closeDb() {
  await db.pool.end();
}

/** Registration payload with a real P-256 public key, as a browser would send. */
function makeCredentials(username) {
  const { publicKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  return {
    username,
    authKey: crypto.randomBytes(32).toString('base64'),
    publicKey: publicKey.export({ type: 'spki', format: 'der' }).toString('base64'),
    encryptedPrivateKey: crypto.randomBytes(154).toString('base64'),
    privateKeyIv: crypto.randomBytes(12).toString('base64'),
  };
}

/** Parse Set-Cookie headers into { name: { value, attributes } }. */
function parseCookies(res) {
  const cookies = {};
  for (const line of res.headers['set-cookie'] || []) {
    const [pair, ...attrs] = line.split(';').map((p) => p.trim());
    const idx = pair.indexOf('=');
    cookies[pair.slice(0, idx)] = {
      value: decodeURIComponent(pair.slice(idx + 1)),
      attributes: attrs.map((a) => a.toLowerCase()),
    };
  }
  return cookies;
}

/** Cookie header + CSRF header that a browser session would send. */
function sessionHeaders(session) {
  return {
    Cookie: `lnc_rt=${session.refreshToken}; lnc_csrf=${session.csrfToken}`,
    'X-CSRF-Token': session.csrfToken,
    Origin: ORIGIN,
  };
}

function sessionFrom(res) {
  const cookies = parseCookies(res);
  return { refreshToken: cookies.lnc_rt?.value, csrfToken: cookies.lnc_csrf?.value };
}

async function registerUser(app, username = 'alice') {
  const credentials = makeCredentials(username);
  const res = await request(app).post('/api/auth/register').set('Origin', ORIGIN).send(credentials);
  if (res.status !== 201) throw new Error(`register failed: ${res.status} ${JSON.stringify(res.body)}`);
  return {
    credentials,
    user: res.body.user,
    accessToken: res.body.accessToken,
    session: sessionFrom(res),
  };
}

module.exports = {
  ORIGIN,
  resetDb,
  closeDb,
  makeCredentials,
  parseCookies,
  sessionHeaders,
  sessionFrom,
  registerUser,
};
