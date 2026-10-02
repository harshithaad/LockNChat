'use strict';

const db = require('../db/pool');
const { AppError } = require('../lib/errors');

const MESSAGE_PAGE_MAX = 100;

function toConversation(row) {
  return {
    id: row.id,
    createdAt: row.created_at,
    lastMessageAt: row.last_message_at ?? null,
    peer: { id: row.peer_id, username: row.peer_username, publicKey: row.peer_public_key },
  };
}

function toMessage(row) {
  return {
    id: String(row.id),
    conversationId: row.conversation_id,
    senderId: row.sender_id,
    ciphertext: row.ciphertext,
    iv: row.iv,
    createdAt: row.created_at,
  };
}

const CONVERSATION_SELECT = `
  SELECT c.id, c.created_at,
         u.id AS peer_id, u.username AS peer_username, u.public_key AS peer_public_key,
         (SELECT max(m.created_at) FROM messages m WHERE m.conversation_id = c.id) AS last_message_at
  FROM conversations c
  JOIN users u ON u.id = CASE WHEN c.user_a = $1 THEN c.user_b ELSE c.user_a END`;

async function listConversations(userId) {
  const { rows } = await db.query(
    `${CONVERSATION_SELECT}
     WHERE c.user_a = $1 OR c.user_b = $1
     ORDER BY COALESCE(
       (SELECT max(m.created_at) FROM messages m WHERE m.conversation_id = c.id), c.created_at
     ) DESC`,
    [userId]
  );
  return rows.map(toConversation);
}

/** Return the 1-to-1 conversation between two users, creating it if needed. */
async function getOrCreateConversation(userId, peerId) {
  if (userId === peerId) throw new AppError(400, 'invalid_peer', 'You cannot start a conversation with yourself');

  const peer = await db.query('SELECT 1 FROM users WHERE id = $1', [peerId]);
  if (peer.rowCount === 0) throw new AppError(404, 'not_found', 'User not found');

  // Participants are stored in canonical order, so (A,B) and (B,A) map to the
  // same row and the unique constraint prevents duplicates under concurrency.
  const { rows } = await db.query(
    `INSERT INTO conversations (user_a, user_b)
     VALUES (LEAST($1::uuid, $2::uuid), GREATEST($1::uuid, $2::uuid))
     ON CONFLICT (user_a, user_b) DO UPDATE SET user_a = EXCLUDED.user_a
     RETURNING id`,
    [userId, peerId]
  );

  const result = await db.query(`${CONVERSATION_SELECT} WHERE c.id = $2`, [userId, rows[0].id]);
  return toConversation(result.rows[0]);
}

/**
 * Return the conversation's participants if `userId` is one of them.
 * Non-members get a 404 rather than a 403 so conversation ids cannot be
 * probed for existence (prevents IDOR and enumeration).
 */
async function assertParticipant(conversationId, userId) {
  const { rows } = await db.query(
    'SELECT user_a, user_b FROM conversations WHERE id = $1 AND (user_a = $2 OR user_b = $2)',
    [conversationId, userId]
  );
  if (!rows[0]) throw new AppError(404, 'not_found', 'Conversation not found');
  return [rows[0].user_a, rows[0].user_b];
}

async function listMessages(conversationId, userId, { before, limit }) {
  await assertParticipant(conversationId, userId);
  const { rows } = await db.query(
    `SELECT id, conversation_id, sender_id, ciphertext, iv, created_at
     FROM messages
     WHERE conversation_id = $1 AND ($2::bigint IS NULL OR id < $2::bigint)
     ORDER BY id DESC
     LIMIT $3`,
    [conversationId, before ?? null, Math.min(limit, MESSAGE_PAGE_MAX)]
  );
  return rows.reverse().map(toMessage);
}

/** Persist an encrypted message. The server never sees or inspects plaintext. */
async function createMessage(conversationId, senderId, { ciphertext, iv }) {
  const participants = await assertParticipant(conversationId, senderId);
  const { rows } = await db.query(
    `INSERT INTO messages (conversation_id, sender_id, ciphertext, iv)
     VALUES ($1, $2, $3, $4)
     RETURNING id, conversation_id, sender_id, ciphertext, iv, created_at`,
    [conversationId, senderId, ciphertext, iv]
  );
  return { message: toMessage(rows[0]), participants };
}

module.exports = {
  listConversations,
  getOrCreateConversation,
  assertParticipant,
  listMessages,
  createMessage,
  MESSAGE_PAGE_MAX,
};
