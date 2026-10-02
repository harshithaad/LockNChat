'use strict';

const express = require('express');
const { z } = require('zod');
const conversations = require('../services/conversations');
const { requireAuth } = require('../middleware/auth');
const { validate } = require('../middleware/validate');
const s = require('../lib/schemas');

const router = express.Router();

router.use(requireAuth);

router.get('/', async (req, res) => {
  res.json({ conversations: await conversations.listConversations(req.user.id) });
});

router.post('/', validate({ body: z.object({ userId: s.uuid }) }), async (req, res) => {
  const conversation = await conversations.getOrCreateConversation(req.user.id, req.valid.body.userId);
  res.json({ conversation });
});

const messagesQuery = z.object({
  before: z.string().regex(/^\d{1,18}$/, 'Invalid cursor').optional(),
  limit: z.coerce.number().int().min(1).max(conversations.MESSAGE_PAGE_MAX).default(50),
});

router.get(
  '/:id/messages',
  validate({ params: z.object({ id: s.uuid }), query: messagesQuery }),
  async (req, res) => {
    const messages = await conversations.listMessages(req.valid.params.id, req.user.id, req.valid.query);
    res.json({ messages });
  }
);

module.exports = router;
