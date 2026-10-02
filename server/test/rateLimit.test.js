'use strict';

// Low limit for this file only; config is read when the app is first required.
process.env.RATE_LIMIT_AUTH_MAX = '3';

const request = require('supertest');
const { createApp } = require('../src/app');
const { ORIGIN, resetDb, closeDb, makeCredentials } = require('./helpers');

beforeAll(resetDb);
afterAll(closeDb);

test('limits login attempts per IP', async () => {
  const app = createApp();
  const attempt = () =>
    request(app)
      .post('/api/auth/login')
      .set('Origin', ORIGIN)
      .send({ username: 'nobody', authKey: makeCredentials('x').authKey });

  for (let i = 0; i < 3; i++) expect((await attempt()).status).toBe(401);

  const blocked = await attempt();
  expect(blocked.status).toBe(429);
  expect(blocked.body.error.code).toBe('rate_limited');
  expect(blocked.headers['ratelimit-policy']).toBeDefined();
});
