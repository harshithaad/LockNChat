'use strict';

const express = require('express');
const db = require('../db/pool');
const { requireAuth } = require('../middleware/auth');
const { AppError } = require('../lib/errors');

const router = express.Router();

router.use(requireAuth);

router.get('/me', async (req, res) => {
  const { rows } = await db.query('SELECT id, username, public_key FROM users WHERE id = $1', [req.user.id]);
  if (!rows[0]) throw new AppError(404, 'not_found', 'User not found');
  res.json({ user: { id: rows[0].id, username: rows[0].username, publicKey: rows[0].public_key } });
});

module.exports = router;
