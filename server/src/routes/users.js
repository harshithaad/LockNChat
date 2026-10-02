'use strict';

const express = require('express');
const { z } = require('zod');
const db = require('../db/pool');
const { requireAuth } = require('../middleware/auth');
const { validate } = require('../middleware/validate');
const { AppError } = require('../lib/errors');
const s = require('../lib/schemas');

const router = express.Router();

router.use(requireAuth);

const toUser = (row) => ({ id: row.id, username: row.username, publicKey: row.public_key });

/** Escape LIKE wildcards so user input like "%" or "_" matches literally. */
const escapeLike = (value) => value.replace(/[\\%_]/g, (c) => `\\${c}`);

router.get('/me', async (req, res) => {
  const { rows } = await db.query('SELECT id, username, public_key FROM users WHERE id = $1', [req.user.id]);
  if (!rows[0]) throw new AppError(404, 'not_found', 'User not found');
  res.json({ user: toUser(rows[0]) });
});

const searchSchema = z.object({ q: z.string().trim().toLowerCase().min(1).max(32) });

router.get('/search', validate({ query: searchSchema }), async (req, res) => {
  const { rows } = await db.query(
    `SELECT id, username, public_key FROM users
     WHERE username LIKE $1 ESCAPE '\\' AND id <> $2
     ORDER BY username
     LIMIT 10`,
    [`${escapeLike(req.valid.query.q)}%`, req.user.id]
  );
  res.json({ users: rows.map(toUser) });
});

// Public key directory: clients fetch a peer's public key to derive the
// shared conversation key. Public keys are not secret.
router.get('/:id', validate({ params: z.object({ id: s.uuid }) }), async (req, res) => {
  const { rows } = await db.query('SELECT id, username, public_key FROM users WHERE id = $1', [
    req.valid.params.id,
  ]);
  if (!rows[0]) throw new AppError(404, 'not_found', 'User not found');
  res.json({ user: toUser(rows[0]) });
});

module.exports = router;
