'use strict';

const { Server } = require('socket.io');
const config = require('../config');
const { verifyAccessToken } = require('../lib/tokens');
const { AppError } = require('../lib/errors');
const { createBucket } = require('../lib/rateBucket');
const { sendMessageSchema } = require('../lib/messageSchema');
const conversations = require('../services/conversations');

const MESSAGE_BURST = 10;
const MESSAGES_PER_SECOND = 2;

const userRoom = (userId) => `user:${userId}`;

function toAckError(err) {
  if (err instanceof AppError) return { code: err.code, message: err.message };
  if (!config.isTest) console.error(err);
  return { code: 'internal_error', message: 'Something went wrong' };
}

/**
 * Real-time relay. Every connection must present a valid access token in the
 * handshake and is disconnected the moment that token expires; the client
 * reconnects with a fresh token after refreshing. The server only ever relays
 * ciphertext.
 */
function attachSocket(httpServer) {
  const io = new Server(httpServer, {
    serveClient: true,
    maxHttpBufferSize: 32 * 1024,
    cors: { origin: config.corsOrigins, credentials: true },
    // Refuse handshakes from foreign origins (cross-site WebSocket hijacking).
    allowRequest(req, callback) {
      const origin = req.headers.origin;
      callback(null, !origin || config.corsOrigins.includes(origin));
    },
  });

  // One rate-limit bucket per user, shared across that user's tabs.
  const buckets = new Map();

  io.use((socket, next) => {
    const token = socket.handshake.auth?.token;
    if (typeof token !== 'string' || !token) return next(new Error('unauthenticated'));
    try {
      socket.data.user = verifyAccessToken(token);
      return next();
    } catch {
      return next(new Error('invalid_token'));
    }
  });

  io.on('connection', (socket) => {
    const { user } = socket.data;
    socket.join(userRoom(user.id));

    const bucketEntry = buckets.get(user.id) ?? {
      bucket: createBucket({ capacity: MESSAGE_BURST, refillPerSecond: MESSAGES_PER_SECOND }),
      sockets: 0,
    };
    bucketEntry.sockets += 1;
    buckets.set(user.id, bucketEntry);

    // Hard stop when the access token expires.
    const msUntilExpiry = user.exp * 1000 - Date.now();
    const expiryTimer = setTimeout(() => {
      socket.emit('session:expired');
      socket.disconnect(true);
    }, Math.max(0, msUntilExpiry));

    socket.on('message:send', async (payload, ack) => {
      const reply = typeof ack === 'function' ? ack : () => {};

      if (!bucketEntry.bucket.take()) {
        return reply({ ok: false, error: { code: 'rate_limited', message: 'You are sending messages too fast' } });
      }

      const parsed = sendMessageSchema.safeParse(payload);
      if (!parsed.success) {
        return reply({ ok: false, error: { code: 'validation_error', message: 'Invalid message' } });
      }

      try {
        const { conversationId, ciphertext, iv } = parsed.data;
        const { message, participants } = await conversations.createMessage(conversationId, user.id, {
          ciphertext,
          iv,
        });
        io.to(participants.map(userRoom)).emit('message:new', message);
        reply({ ok: true, message });
      } catch (err) {
        reply({ ok: false, error: toAckError(err) });
      }
    });

    socket.on('disconnect', () => {
      clearTimeout(expiryTimer);
      bucketEntry.sockets -= 1;
      if (bucketEntry.sockets <= 0) buckets.delete(user.id);
    });
  });

  return io;
}

module.exports = { attachSocket };
