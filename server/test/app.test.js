'use strict';

const request = require('supertest');
const { createApp } = require('../src/app');
const { closeDb } = require('./helpers');

const app = createApp();

afterAll(closeDb);

describe('health', () => {
  test('reports ok when the database is reachable', async () => {
    const res = await request(app).get('/api/health');
    expect(res.status).toBe(200);
    expect(res.body).toEqual({ status: 'ok' });
  });
});

describe('security headers (Helmet)', () => {
  let res;
  beforeAll(async () => {
    res = await request(app).get('/api/health');
  });

  test('sets a strict Content-Security-Policy', () => {
    const csp = res.headers['content-security-policy'];
    expect(csp).toContain("default-src 'self'");
    expect(csp).toContain("script-src 'self'");
    expect(csp).toContain("object-src 'none'");
    expect(csp).toContain("frame-ancestors 'none'");
    expect(csp).not.toContain('unsafe-inline');
    expect(csp).not.toContain('unsafe-eval');
  });

  test('sets HSTS, nosniff, frame and referrer protections', () => {
    expect(res.headers['strict-transport-security']).toMatch(/max-age=31536000/);
    expect(res.headers['x-content-type-options']).toBe('nosniff');
    expect(res.headers['x-frame-options']).toBe('DENY');
    expect(res.headers['referrer-policy']).toBe('no-referrer');
  });

  test('does not reveal the server framework', () => {
    expect(res.headers['x-powered-by']).toBeUndefined();
  });

  test('marks API responses as non-cacheable', () => {
    expect(res.headers['cache-control']).toBe('no-store');
  });
});

describe('CORS', () => {
  test('allows listed origins with credentials', async () => {
    const res = await request(app).get('/api/health').set('Origin', 'http://localhost:3000');
    expect(res.headers['access-control-allow-origin']).toBe('http://localhost:3000');
    expect(res.headers['access-control-allow-credentials']).toBe('true');
  });

  test('rejects unlisted origins', async () => {
    const res = await request(app).get('/api/health').set('Origin', 'https://evil.example');
    expect(res.status).toBe(403);
    expect(res.body.error.code).toBe('origin_not_allowed');
    expect(res.headers['access-control-allow-origin']).toBeUndefined();
  });
});

describe('error handling', () => {
  test('unknown API routes return a JSON 404', async () => {
    const res = await request(app).get('/api/does-not-exist');
    expect(res.status).toBe(404);
    expect(res.body.error.code).toBe('not_found');
  });

  test('malformed JSON is rejected without leaking parser details', async () => {
    const res = await request(app)
      .post('/api/health')
      .set('Content-Type', 'application/json')
      .send('{"broken":');
    expect(res.status).toBe(400);
    expect(res.body).toEqual({ error: { code: 'invalid_json', message: 'Request body is not valid JSON' } });
  });

  test('oversized bodies are rejected', async () => {
    const res = await request(app)
      .post('/api/health')
      .set('Content-Type', 'application/json')
      .send(JSON.stringify({ blob: 'x'.repeat(20 * 1024) }));
    expect(res.status).toBe(413);
    expect(res.body.error.code).toBe('payload_too_large');
  });
});
