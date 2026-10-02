'use strict';

const { z } = require('zod');
const s = require('./schemas');

// Client caps plaintext at 2,000 characters; UTF-8 + GCM tag + base64 fits well
// under this. Anything larger is rejected before touching the database.
const MAX_CIPHERTEXT_LENGTH = 12_000;

const sendMessageSchema = z.object({
  conversationId: s.uuid,
  ciphertext: s.base64(24, MAX_CIPHERTEXT_LENGTH),
  iv: s.base64(16, 16),
});

module.exports = { sendMessageSchema, MAX_CIPHERTEXT_LENGTH };
