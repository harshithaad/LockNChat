// Full flow against the real server and test database:
// register → login → unwrap key → encrypted message over Socket.io → decrypt.
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { createRequire } from 'node:module';
import * as e2ee from '../public/js/crypto.js';

const serverRequire = createRequire(new URL('../../server/package.json', import.meta.url));
serverRequire('./test/env.js');
const { createApp } = serverRequire('./src/app.js');
const { attachSocket } = serverRequire('./src/socket/index.js');
const { migrate } = serverRequire('./src/db/migrate.js');
const db = serverRequire('./src/db/pool.js');
const { io: connectClient } = serverRequire('socket.io-client');

const ORIGIN = 'http://localhost:3000';
const FAST = { iterations: 1000 };
let server;
let ioServer;
let baseUrl;
const sockets = [];

before(async () => {
  await migrate({ log: () => {} });
  await db.query('TRUNCATE messages, conversations, refresh_tokens, users RESTART IDENTITY CASCADE');
  server = http.createServer(createApp());
  ioServer = attachSocket(server);
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  baseUrl = `http://127.0.0.1:${server.address().port}`;
});

after(async () => {
  sockets.forEach((s) => s.disconnect());
  await new Promise((resolve) => ioServer.close(resolve));
  await db.pool.end();
});

async function api(path, { method = 'GET', body, token } = {}) {
  const res = await fetch(baseUrl + path, {
    method,
    headers: {
      Origin: ORIGIN,
      ...(body ? { 'Content-Type': 'application/json' } : {}),
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
    },
    body: body ? JSON.stringify(body) : undefined,
  });
  return { status: res.status, body: res.status === 204 ? null : await res.json() };
}

async function signUp(username, password) {
  const { payload } = await e2ee.createRegistration(username, password, FAST);
  const res = await api('/api/auth/register', { method: 'POST', body: payload });
  assert.equal(res.status, 201);
  return res.body;
}

/** What the client does on login: derive keys, authenticate, unwrap private key. */
async function signIn(username, password) {
  const { authKey, wrapKey } = await e2ee.deriveCredentialKeys(username, password, FAST);
  const res = await api('/api/auth/login', { method: 'POST', body: { username, authKey } });
  if (res.status !== 200) return { status: res.status };
  const privateKey = await e2ee.unwrapPrivateKey(res.body.keys, wrapKey);
  return { status: 200, ...res.body, privateKey };
}

function connect(token) {
  const socket = connectClient(baseUrl, {
    auth: { token },
    transports: ['websocket'],
    extraHeaders: { Origin: ORIGIN },
    reconnection: false,
    forceNew: true,
  });
  sockets.push(socket);
  return new Promise((resolve, reject) => {
    socket.once('connect', () => resolve(socket));
    socket.once('connect_error', reject);
  });
}

test('two users exchange an end-to-end encrypted message the server cannot read', async () => {
  await signUp('alice', 'Alice-Password-1!');
  await signUp('bob', 'Bob-Password-2!');

  const alice = await signIn('alice', 'Alice-Password-1!');
  const bob = await signIn('bob', 'Bob-Password-2!');
  assert.equal(alice.status, 200);
  assert.equal(bob.status, 200);

  // Alice finds Bob and opens a conversation; both sides derive the key.
  const search = await api('/api/users/search?q=bo', { token: alice.accessToken });
  const bobEntry = search.body.users[0];
  const conv = await api('/api/conversations', {
    method: 'POST',
    token: alice.accessToken,
    body: { userId: bobEntry.id },
  });
  const conversationId = conv.body.conversation.id;

  const aliceKey = await e2ee.deriveConversationKey(alice.privateKey, bobEntry.publicKey, conversationId);
  const bobsView = await api('/api/conversations', { token: bob.accessToken });
  const bobKey = await e2ee.deriveConversationKey(
    bob.privateKey,
    bobsView.body.conversations[0].peer.publicKey,
    conversationId
  );

  // Safety numbers match on both devices.
  assert.equal(
    await e2ee.safetyNumber(alice.user.publicKey, bobEntry.publicKey),
    await e2ee.safetyNumber(bob.user.publicKey, bobsView.body.conversations[0].peer.publicKey)
  );

  const aliceSocket = await connect(alice.accessToken);
  const bobSocket = await connect(bob.accessToken);

  const plaintext = 'The vault code is 4-8-15-16 🔐';
  const sealed = await e2ee.encryptMessage(aliceKey, plaintext, { conversationId, senderId: alice.user.id });
  const delivered = new Promise((resolve) => bobSocket.once('message:new', resolve));
  const ack = await aliceSocket.emitWithAck('message:send', { conversationId, ...sealed });
  assert.equal(ack.ok, true);

  const received = await delivered;
  const decrypted = await e2ee.decryptMessage(bobKey, received, {
    conversationId,
    senderId: received.senderId,
  });
  assert.equal(decrypted, plaintext);

  // What the server holds: nothing readable.
  const { rows } = await db.query(
    'SELECT u.password_hash, u.encrypted_private_key, m.ciphertext FROM users u, messages m WHERE u.username = $1',
    ['alice']
  );
  const stored = JSON.stringify(rows);
  assert.ok(!stored.includes('vault code'));
  assert.ok(!stored.includes('Alice-Password-1!'));

  // History endpoint returns the same decryptable ciphertext.
  const history = await api(`/api/conversations/${conversationId}/messages`, { token: bob.accessToken });
  assert.equal(
    await e2ee.decryptMessage(bobKey, history.body.messages[0], { conversationId, senderId: alice.user.id }),
    plaintext
  );
});

test('a wrong password cannot log in', async () => {
  const res = await signIn('alice', 'not-the-password');
  assert.equal(res.status, 401);
});
