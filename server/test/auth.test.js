'use strict';

const jwt = require('jsonwebtoken');
const request = require('supertest');
const db = require('../src/db/pool');
const { createApp } = require('../src/app');
const {
  ORIGIN,
  resetDb,
  closeDb,
  makeCredentials,
  parseCookies,
  sessionHeaders,
  sessionFrom,
  registerUser,
} = require('./helpers');

const app = createApp();
const SECRET = process.env.JWT_SECRET;

beforeEach(resetDb);
afterAll(closeDb);

const post = (path) => request(app).post(path).set('Origin', ORIGIN);

describe('registration', () => {
  test('creates a user, issues tokens and sets hardened cookies', async () => {
    const res = await post('/api/auth/register').send(makeCredentials('Alice'));

    expect(res.status).toBe(201);
    expect(res.body.user).toMatchObject({ username: 'alice' });
    expect(typeof res.body.accessToken).toBe('string');

    const cookies = parseCookies(res);
    expect(cookies.lnc_rt.attributes).toEqual(
      expect.arrayContaining(['httponly', 'secure', 'samesite=strict', 'path=/api/auth'])
    );
    expect(cookies.lnc_csrf.attributes).toEqual(expect.arrayContaining(['secure', 'samesite=strict', 'path=/']));
    expect(cookies.lnc_csrf.attributes).not.toContain('httponly');
  });

  test('stores a bcrypt hash, never the credential itself', async () => {
    const credentials = makeCredentials('bob');
    await post('/api/auth/register').send(credentials);

    const { rows } = await db.query('SELECT password_hash FROM users WHERE username = $1', ['bob']);
    expect(rows[0].password_hash).toMatch(/^\$2b\$\d{2}\$/);
    expect(rows[0].password_hash).not.toContain(credentials.authKey);
  });

  test('stores only a hash of the refresh token', async () => {
    const res = await post('/api/auth/register').send(makeCredentials('carol'));
    const { refreshToken } = sessionFrom(res);

    const { rows } = await db.query('SELECT token_hash FROM refresh_tokens');
    expect(rows).toHaveLength(1);
    expect(rows[0].token_hash).not.toBe(refreshToken);
    expect(rows[0].token_hash).toMatch(/^[0-9a-f]{64}$/);
  });

  test('rejects a duplicate username regardless of case', async () => {
    await post('/api/auth/register').send(makeCredentials('dave'));
    const res = await post('/api/auth/register').send(makeCredentials('DAVE'));
    expect(res.status).toBe(409);
    expect(res.body.error.code).toBe('username_taken');
  });

  test.each([
    ['username too short', { username: 'ab' }],
    ['username with symbols', { username: '<script>' }],
    ['malformed auth key', { authKey: 'password123' }],
    ['public key that is not a P-256 key', { publicKey: Buffer.alloc(120, 1).toString('base64') }],
    ['non-base64 private key blob', { encryptedPrivateKey: '!!!not base64!!!'.repeat(4) }],
    ['wrong IV length', { privateKeyIv: 'AAAA' }],
  ])('rejects %s', async (_label, override) => {
    const res = await post('/api/auth/register').send({ ...makeCredentials('erin'), ...override });
    expect(res.status).toBe(400);
    expect(res.body.error.code).toBe('validation_error');
  });

  test('ignores unexpected fields such as attempts to set server-managed columns', async () => {
    const res = await post('/api/auth/register').send({ ...makeCredentials('frank'), failed_login_count: -100, id: 'x' });
    expect(res.status).toBe(201);
    const { rows } = await db.query('SELECT failed_login_count FROM users WHERE username = $1', ['frank']);
    expect(rows[0].failed_login_count).toBe(0);
  });
});

describe('login', () => {
  test('returns tokens and the wrapped key bundle for valid credentials', async () => {
    const { credentials } = await registerUser(app, 'alice');
    const res = await post('/api/auth/login').send({ username: 'ALICE', authKey: credentials.authKey });

    expect(res.status).toBe(200);
    expect(res.body.keys).toEqual({
      encryptedPrivateKey: credentials.encryptedPrivateKey,
      privateKeyIv: credentials.privateKeyIv,
    });
    expect(sessionFrom(res).refreshToken).toBeTruthy();
  });

  test('gives the same response for a wrong password and an unknown user', async () => {
    await registerUser(app, 'alice');
    const wrong = await post('/api/auth/login').send({ username: 'alice', authKey: makeCredentials('x').authKey });
    const unknown = await post('/api/auth/login').send({ username: 'nobody', authKey: makeCredentials('x').authKey });

    expect(wrong.status).toBe(401);
    expect(unknown.status).toBe(401);
    expect(wrong.body).toEqual(unknown.body);
  });

  test('locks the account server-side after 5 failed attempts', async () => {
    const { credentials } = await registerUser(app, 'alice');
    const bad = { username: 'alice', authKey: makeCredentials('x').authKey };

    for (let i = 0; i < 4; i++) {
      expect((await post('/api/auth/login').send(bad)).status).toBe(401);
    }
    const fifth = await post('/api/auth/login').send(bad);
    expect(fifth.status).toBe(429);
    expect(fifth.body.error.code).toBe('account_locked');

    // Even the correct password is refused while locked.
    const correct = await post('/api/auth/login').send({ username: 'alice', authKey: credentials.authKey });
    expect(correct.status).toBe(429);

    // Once the lock expires, the correct password works again.
    await db.query("UPDATE users SET locked_until = now() - interval '1 second'");
    const later = await post('/api/auth/login').send({ username: 'alice', authKey: credentials.authKey });
    expect(later.status).toBe(200);
  });

  test.each([
    "admin' OR '1'='1",
    "alice'; DROP TABLE users; --",
    'alice" OR ""="',
  ])('rejects SQL injection payload in username: %s', async (payload) => {
    await registerUser(app, 'alice');
    const res = await post('/api/auth/login').send({ username: payload, authKey: makeCredentials('x').authKey });
    expect([400, 401]).toContain(res.status);

    const { rows } = await db.query('SELECT count(*)::int AS n FROM users');
    expect(rows[0].n).toBe(1);
  });

  test('rejects requests from a foreign origin (login CSRF)', async () => {
    const { credentials } = await registerUser(app, 'alice');
    const res = await request(app)
      .post('/api/auth/login')
      .set('Origin', 'https://evil.example')
      .send({ username: 'alice', authKey: credentials.authKey });
    expect(res.status).toBe(403);
  });
});

describe('access tokens', () => {
  test('grant access to protected routes', async () => {
    const { accessToken } = await registerUser(app, 'alice');
    const res = await request(app).get('/api/users/me').set('Authorization', `Bearer ${accessToken}`);
    expect(res.status).toBe(200);
    expect(res.body.user.username).toBe('alice');
  });

  test('expire after 15 minutes', async () => {
    const { accessToken } = await registerUser(app, 'alice');
    const { iat, exp } = jwt.decode(accessToken);
    expect(exp - iat).toBe(900);
  });

  test('are required', async () => {
    const res = await request(app).get('/api/users/me');
    expect(res.status).toBe(401);
    expect(res.headers['www-authenticate']).toBe('Bearer');
  });

  test('are rejected once expired', async () => {
    const { user } = await registerUser(app, 'alice');
    const expired = jwt.sign({ username: 'alice', type: 'access' }, SECRET, {
      algorithm: 'HS256',
      subject: user.id,
      issuer: 'locknchat',
      audience: 'locknchat-api',
      expiresIn: -10,
    });
    const res = await request(app).get('/api/users/me').set('Authorization', `Bearer ${expired}`);
    expect(res.status).toBe(401);
    expect(res.body.error.code).toBe('token_expired');
  });

  test('with alg "none" are rejected', async () => {
    const { user } = await registerUser(app, 'alice');
    const header = Buffer.from(JSON.stringify({ alg: 'none', typ: 'JWT' })).toString('base64url');
    const payload = Buffer.from(
      JSON.stringify({ sub: user.id, type: 'access', iss: 'locknchat', aud: 'locknchat-api', exp: 9999999999 })
    ).toString('base64url');
    const res = await request(app).get('/api/users/me').set('Authorization', `Bearer ${header}.${payload}.`);
    expect(res.status).toBe(401);
    expect(res.body.error.code).toBe('invalid_token');
  });

  test('signed with a different secret are rejected', async () => {
    const { user } = await registerUser(app, 'alice');
    const forged = jwt.sign({ type: 'access' }, 'attacker-secret-attacker-secret-attacker', {
      subject: user.id,
      issuer: 'locknchat',
      audience: 'locknchat-api',
    });
    const res = await request(app).get('/api/users/me').set('Authorization', `Bearer ${forged}`);
    expect(res.status).toBe(401);
  });

  test('with a tampered payload are rejected', async () => {
    const { accessToken } = await registerUser(app, 'alice');
    const [h, , sig] = accessToken.split('.');
    const evil = Buffer.from(JSON.stringify({ sub: 'someone-else', type: 'access' })).toString('base64url');
    const res = await request(app).get('/api/users/me').set('Authorization', `Bearer ${h}.${evil}.${sig}`);
    expect(res.status).toBe(401);
  });
});

describe('refresh token rotation', () => {
  test('issues a new access token and rotates the refresh token', async () => {
    const { session } = await registerUser(app, 'alice');
    const res = await request(app).post('/api/auth/refresh').set(sessionHeaders(session));

    expect(res.status).toBe(200);
    expect(typeof res.body.accessToken).toBe('string');
    const next = sessionFrom(res);
    expect(next.refreshToken).toBeTruthy();
    expect(next.refreshToken).not.toBe(session.refreshToken);
  });

  test('detects reuse of an old token and revokes the whole session (replay defense)', async () => {
    const { session } = await registerUser(app, 'alice');

    // Legitimate client refreshes: old token is now spent.
    const first = await request(app).post('/api/auth/refresh').set(sessionHeaders(session));
    const legitimate = sessionFrom(first);

    // Attacker replays the stolen, already-used token.
    const replay = await request(app).post('/api/auth/refresh').set(sessionHeaders(session));
    expect(replay.status).toBe(401);
    expect(replay.body.error.code).toBe('token_reused');

    // The legitimate client's newer token has been revoked too.
    const after = await request(app).post('/api/auth/refresh').set(sessionHeaders(legitimate));
    expect(after.status).toBe(401);

    const { rows } = await db.query('SELECT count(*)::int AS n FROM refresh_tokens WHERE revoked_at IS NULL');
    expect(rows[0].n).toBe(0);
  });

  test('does not let concurrent refreshes with one token both succeed', async () => {
    const { session } = await registerUser(app, 'alice');
    const results = await Promise.all([
      request(app).post('/api/auth/refresh').set(sessionHeaders(session)),
      request(app).post('/api/auth/refresh').set(sessionHeaders(session)),
    ]);
    expect(results.filter((r) => r.status === 200).length).toBeLessThanOrEqual(1);
  });

  test('rejects an expired session', async () => {
    const { session } = await registerUser(app, 'alice');
    await db.query("UPDATE refresh_tokens SET expires_at = now() - interval '1 second'");
    const res = await request(app).post('/api/auth/refresh').set(sessionHeaders(session));
    expect(res.status).toBe(401);
    expect(res.body.error.code).toBe('session_expired');
  });

  test('keeps the original session expiry when rotating', async () => {
    const { session } = await registerUser(app, 'alice');
    await request(app).post('/api/auth/refresh').set(sessionHeaders(session));
    const { rows } = await db.query('SELECT DISTINCT expires_at FROM refresh_tokens');
    expect(rows).toHaveLength(1);
  });

  test('rejects an unknown token', async () => {
    const res = await request(app)
      .post('/api/auth/refresh')
      .set(sessionHeaders({ refreshToken: 'made-up', csrfToken: 'abc' }));
    expect(res.status).toBe(401);
  });
});

describe('CSRF protection', () => {
  test('refresh without the CSRF header is rejected', async () => {
    const { session } = await registerUser(app, 'alice');
    const { 'X-CSRF-Token': _omit, ...headers } = sessionHeaders(session);
    const res = await request(app).post('/api/auth/refresh').set(headers);
    expect(res.status).toBe(403);
    expect(res.body.error.code).toBe('csrf_failed');
  });

  test('refresh with a mismatched CSRF header is rejected', async () => {
    const { session } = await registerUser(app, 'alice');
    const res = await request(app)
      .post('/api/auth/refresh')
      .set({ ...sessionHeaders(session), 'X-CSRF-Token': 'guessed-value' });
    expect(res.status).toBe(403);
  });

  test('refresh from a foreign origin is rejected even with a valid token', async () => {
    const { session } = await registerUser(app, 'alice');
    const res = await request(app)
      .post('/api/auth/refresh')
      .set({ ...sessionHeaders(session), Origin: 'https://evil.example' });
    expect(res.status).toBe(403);
  });
});

describe('logout', () => {
  test('revokes the session and clears cookies', async () => {
    const { session } = await registerUser(app, 'alice');
    const res = await request(app).post('/api/auth/logout').set(sessionHeaders(session));
    expect(res.status).toBe(204);
    expect(parseCookies(res).lnc_rt.value).toBe('');

    const again = await request(app).post('/api/auth/refresh').set(sessionHeaders(session));
    expect(again.status).toBe(401);
  });

  test('requires a CSRF token', async () => {
    const { session } = await registerUser(app, 'alice');
    const res = await request(app)
      .post('/api/auth/logout')
      .set({ Cookie: `lnc_rt=${session.refreshToken}`, Origin: ORIGIN });
    expect(res.status).toBe(403);
  });
});
