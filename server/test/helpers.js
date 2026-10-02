'use strict';

const db = require('../src/db/pool');

async function resetDb() {
  await db.query(
    'TRUNCATE messages, conversations, refresh_tokens, users RESTART IDENTITY CASCADE'
  );
}

async function closeDb() {
  await db.pool.end();
}

module.exports = { resetDb, closeDb };
