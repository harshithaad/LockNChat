'use strict';

const crypto = require('crypto');
const http = require('http');
const jwt = require('jsonwebtoken');
const request = require('supertest');
const { io: connectClient } = require('socket.io-client');
const db = require('../src/db/pool');
const { createApp } = require('../src/app');
const { attachSocket } = require('../src/socket');
const { ORIGIN, resetDb, closeDb, registerUser } = require('./helpers');

const app = createApp();
let server;
let ioServer;
let url;
const clients = [];

let alice;
let bob;
let eve;
let conversationId;

beforeAll(async () => {
  server = http.createServer(app);
  ioServer = attachSocket(server);
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  url = `http://127.0.0.1:${server.address().port}`;
});

beforeEach(async () => {
  await resetDb();
  alice = await registerUser(app, 'alice');
  bob = await registerUser(app, 'bob');
  eve = await registerUser(app, 'eve');
  const res = await request(app)
    .post('/api/conversations')
    .set('Authorization', `Bearer ${alice.accessToken}`)
    .send({ userId: bob.user.id });
  conversationId = res.body.conversation.id;
});

afterEach(() => {
  while (clients.length) clients.pop().disconnect();
});

afterAll(async () => {
  await new Promise((resolve) => ioServer.close(resolve));
  await closeDb();
});

function connect(token, { origin = ORIGIN } = {}) {
  const socket = connectClient(url, {
    auth: token === undefined ? {} : { token },
    transports: ['websocket'],
    extraHeaders: { Origin: origin },
    reconnection: false,
    forceNew: true,
  });
  clients.push(socket);
  return socket;
}

function connected(socket) {
  return new Promise((resolve, reject) => {
    socket.once('connect', () => resolve(socket));
    socket.once('connect_error', reject);
  });
}

function once(socket, event, timeoutMs = 2000) {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error(`timed out waiting for ${event}`)), timeoutMs);
    socket.once(event, (data) => {
      clearTimeout(timer);
      resolve(data);
    });
  });
}

const encryptedPayload = () => ({
  conversationId,
  ciphertext: crypto.randomBytes(48).toString('base64'),
  iv: crypto.randomBytes(12).toString('base64'),
});

describe('handshake authentication', () => {
  test('refuses connections without a token', async () => {
    await expect(connected(connect(undefined))).rejects.toThrow('unauthenticated');
  });

  test('refuses connections with an invalid token', async () => {
    await expect(connected(connect('not-a-jwt'))).rejects.toThrow('invalid_token');
  });

  test('refuses connections with an expired token', async () => {
    const expired = jwt.sign({ username: 'alice', type: 'access' }, process.env.JWT_SECRET, {
      subject: alice.user.id,
      issuer: 'locknchat',
      audience: 'locknchat-api',
      expiresIn: -1,
    });
    await expect(connected(connect(expired))).rejects.toThrow('invalid_token');
  });

  test('refuses handshakes from a foreign origin', async () => {
    await expect(connected(connect(alice.accessToken, { origin: 'https://evil.example' }))).rejects.toThrow();
  });

  test('disconnects the socket when the access token expires', async () => {
    const shortLived = jwt.sign({ username: 'alice', type: 'access' }, process.env.JWT_SECRET, {
      subject: alice.user.id,
      issuer: 'locknchat',
      audience: 'locknchat-api',
      expiresIn: 1,
    });
    const socket = await connected(connect(shortLived));
    const expired = once(socket, 'session:expired', 3000);
    const disconnected = once(socket, 'disconnect', 3000);
    await expired;
    expect(await disconnected).toBe('io server disconnect');
  });
});

describe('messaging', () => {
  test('relays ciphertext to both participants and stores it', async () => {
    const aliceSocket = await connected(connect(alice.accessToken));
    const bobSocket = await connected(connect(bob.accessToken));

    const payload = encryptedPayload();
    const bobReceives = once(bobSocket, 'message:new');
    const aliceReceives = once(aliceSocket, 'message:new');
    const ack = await aliceSocket.emitWithAck('message:send', payload);

    expect(ack.ok).toBe(true);
    const received = await bobReceives;
    expect(received).toMatchObject({ ...payload, senderId: alice.user.id });
    expect((await aliceReceives).id).toBe(received.id);

    const { rows } = await db.query('SELECT ciphertext, iv FROM messages');
    expect(rows).toEqual([{ ciphertext: payload.ciphertext, iv: payload.iv }]);
  });

  test('does not deliver messages to non-participants', async () => {
    const aliceSocket = await connected(connect(alice.accessToken));
    const eveSocket = await connected(connect(eve.accessToken));
    let eveGotMessage = false;
    eveSocket.on('message:new', () => {
      eveGotMessage = true;
    });

    await aliceSocket.emitWithAck('message:send', encryptedPayload());
    await new Promise((r) => setTimeout(r, 200));
    expect(eveGotMessage).toBe(false);
  });

  test('rejects sending into a conversation you are not part of', async () => {
    const eveSocket = await connected(connect(eve.accessToken));
    const ack = await eveSocket.emitWithAck('message:send', encryptedPayload());
    expect(ack).toEqual({ ok: false, error: { code: 'not_found', message: 'Conversation not found' } });
    const { rows } = await db.query('SELECT count(*)::int AS n FROM messages');
    expect(rows[0].n).toBe(0);
  });

  test.each([
    ['missing fields', {}],
    ['non-base64 ciphertext', { ciphertext: '<img src=x onerror=alert(1)>' }],
    ['oversized ciphertext', { ciphertext: 'A'.repeat(12_004) }],
    ['bad conversation id', { conversationId: "1' OR '1'='1" }],
    ['bad iv', { iv: 'short' }],
  ])('rejects invalid payloads: %s', async (_label, override) => {
    const socket = await connected(connect(alice.accessToken));
    const payload = Object.keys(override).length ? { ...encryptedPayload(), ...override } : override;
    const ack = await socket.emitWithAck('message:send', payload);
    expect(ack.ok).toBe(false);
    expect(ack.error.code).toBe('validation_error');
  });

  test('rate limits message floods', async () => {
    const socket = await connected(connect(alice.accessToken));
    const acks = await Promise.all(
      Array.from({ length: 20 }, () => socket.emitWithAck('message:send', encryptedPayload()))
    );
    const limited = acks.filter((a) => !a.ok && a.error.code === 'rate_limited');
    expect(limited.length).toBeGreaterThan(0);
    expect(acks.filter((a) => a.ok).length).toBeLessThanOrEqual(11);
  });
});
