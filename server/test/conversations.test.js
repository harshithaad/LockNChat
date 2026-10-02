'use strict';

const crypto = require('crypto');
const request = require('supertest');
const db = require('../src/db/pool');
const { createApp } = require('../src/app');
const { resetDb, closeDb, registerUser } = require('./helpers');

const app = createApp();

let alice;
let bob;
let eve;

beforeEach(async () => {
  await resetDb();
  alice = await registerUser(app, 'alice');
  bob = await registerUser(app, 'bob');
  eve = await registerUser(app, 'eve');
});
afterAll(closeDb);

const as = (who) => ({ Authorization: `Bearer ${who.accessToken}` });

async function insertMessage(conversationId, sender, n) {
  await db.query('INSERT INTO messages (conversation_id, sender_id, ciphertext, iv) VALUES ($1, $2, $3, $4)', [
    conversationId,
    sender.user.id,
    Buffer.from(`ciphertext-${n}-padding-padding`).toString('base64'),
    crypto.randomBytes(12).toString('base64'),
  ]);
}

describe('user search', () => {
  test('finds users by username prefix, excluding yourself', async () => {
    const res = await request(app).get('/api/users/search?q=b').set(as(alice));
    expect(res.status).toBe(200);
    expect(res.body.users.map((u) => u.username)).toEqual(['bob']);
    expect(res.body.users[0].publicKey).toBe(bob.user.publicKey);
  });

  test('treats LIKE wildcards literally', async () => {
    const res = await request(app).get('/api/users/search').query({ q: '%' }).set(as(alice));
    expect(res.status).toBe(200);
    expect(res.body.users).toEqual([]);
  });

  test.each(["' OR '1'='1", "a' UNION SELECT password_hash--", "'; DROP TABLE users; --"])(
    'is not injectable: %s',
    async (payload) => {
      const res = await request(app).get('/api/users/search').query({ q: payload }).set(as(alice));
      expect(res.status).toBe(200);
      expect(res.body.users).toEqual([]);
      const { rows } = await db.query('SELECT count(*)::int AS n FROM users');
      expect(rows[0].n).toBe(3);
    }
  );

  test('never exposes password hashes or key blobs', async () => {
    const res = await request(app).get('/api/users/search?q=b').set(as(alice));
    expect(Object.keys(res.body.users[0]).sort()).toEqual(['id', 'publicKey', 'username']);
  });

  test('requires authentication', async () => {
    expect((await request(app).get('/api/users/search?q=b')).status).toBe(401);
  });
});

describe('public key directory', () => {
  test('returns a user public key by id', async () => {
    const res = await request(app).get(`/api/users/${bob.user.id}`).set(as(alice));
    expect(res.status).toBe(200);
    expect(res.body.user).toEqual(bob.user);
  });

  test('rejects malformed ids', async () => {
    const res = await request(app).get('/api/users/1 OR 1=1').set(as(alice));
    expect(res.status).toBe(400);
  });
});

describe('conversations', () => {
  test('creates one conversation per pair, regardless of who starts it', async () => {
    const first = await request(app).post('/api/conversations').set(as(alice)).send({ userId: bob.user.id });
    const second = await request(app).post('/api/conversations').set(as(bob)).send({ userId: alice.user.id });

    expect(first.status).toBe(200);
    expect(first.body.conversation.peer.username).toBe('bob');
    expect(second.body.conversation.peer.username).toBe('alice');
    expect(second.body.conversation.id).toBe(first.body.conversation.id);
  });

  test('cannot be started with yourself', async () => {
    const res = await request(app).post('/api/conversations').set(as(alice)).send({ userId: alice.user.id });
    expect(res.status).toBe(400);
  });

  test('cannot be started with an unknown user', async () => {
    const res = await request(app).post('/api/conversations').set(as(alice)).send({ userId: crypto.randomUUID() });
    expect(res.status).toBe(404);
  });

  test('lists only your own conversations', async () => {
    await request(app).post('/api/conversations').set(as(alice)).send({ userId: bob.user.id });
    const mine = await request(app).get('/api/conversations').set(as(alice));
    const others = await request(app).get('/api/conversations').set(as(eve));
    expect(mine.body.conversations).toHaveLength(1);
    expect(others.body.conversations).toHaveLength(0);
  });
});

describe('message history', () => {
  let conversationId;
  beforeEach(async () => {
    const res = await request(app).post('/api/conversations').set(as(alice)).send({ userId: bob.user.id });
    conversationId = res.body.conversation.id;
  });

  test('returns messages to participants in chronological order', async () => {
    for (let i = 1; i <= 3; i++) await insertMessage(conversationId, i % 2 ? alice : bob, i);
    const res = await request(app).get(`/api/conversations/${conversationId}/messages`).set(as(bob));
    expect(res.status).toBe(200);
    expect(res.body.messages.map((m) => m.id)).toEqual(['1', '2', '3']);
  });

  test('paginates with a cursor', async () => {
    for (let i = 1; i <= 5; i++) await insertMessage(conversationId, alice, i);
    const res = await request(app)
      .get(`/api/conversations/${conversationId}/messages?before=4&limit=2`)
      .set(as(alice));
    expect(res.body.messages.map((m) => m.id)).toEqual(['2', '3']);
  });

  test('is hidden from non-participants (IDOR)', async () => {
    await insertMessage(conversationId, alice, 1);
    const res = await request(app).get(`/api/conversations/${conversationId}/messages`).set(as(eve));
    expect(res.status).toBe(404);
    expect(res.body.messages).toBeUndefined();
  });

  test('rejects an injected cursor', async () => {
    const res = await request(app)
      .get(`/api/conversations/${conversationId}/messages`)
      .query({ before: '1; DELETE FROM messages' })
      .set(as(alice));
    expect(res.status).toBe(400);
  });
});
