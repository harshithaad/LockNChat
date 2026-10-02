'use strict';

const crypto = require('crypto');
const bcrypt = require('bcrypt');
const config = require('../config');
const db = require('../db/pool');
const { AppError } = require('../lib/errors');
const {
  signAccessToken,
  generateRefreshToken,
  generateCsrfToken,
  hashToken,
} = require('../lib/tokens');

const MAX_FAILED_LOGINS = 5;
const LOCKOUT_MINUTES = 15;

// Compared against when the username does not exist, so a login for an
// unknown user takes as long as one for a real user (no timing oracle).
const DUMMY_HASH = bcrypt.hashSync(crypto.randomBytes(32).toString('base64'), config.bcryptRounds);

const invalidCredentials = () =>
  new AppError(401, 'invalid_credentials', 'Invalid username or password');

const accountLocked = () =>
  new AppError(
    429,
    'account_locked',
    `Too many failed login attempts. Try again in ${LOCKOUT_MINUTES} minutes.`
  );

function toPublicUser(row) {
  return { id: row.id, username: row.username, publicKey: row.public_key };
}

/** Store a new refresh token and return the raw values to hand to the client. */
async function insertRefreshToken(client, userId, familyId, expiresAt) {
  const { token, hash } = generateRefreshToken();
  const { rows } = await client.query(
    `INSERT INTO refresh_tokens (user_id, family_id, token_hash, expires_at)
     VALUES ($1, $2, $3, $4)
     RETURNING id, expires_at`,
    [userId, familyId, hash, expiresAt]
  );
  return { id: rows[0].id, refreshToken: token, expiresAt: rows[0].expires_at };
}

/** Start a new session (a new refresh-token family) for a user. */
async function startSession(user) {
  const expiresAt = new Date(Date.now() + config.refreshTokenTtlDays * 24 * 60 * 60 * 1000);
  const issued = await insertRefreshToken(db, user.id, crypto.randomUUID(), expiresAt);
  return {
    accessToken: signAccessToken(user),
    session: { refreshToken: issued.refreshToken, csrfToken: generateCsrfToken(), expiresAt: issued.expiresAt },
  };
}

async function register({ username, authKey, publicKey, encryptedPrivateKey, privateKeyIv }) {
  const passwordHash = await bcrypt.hash(authKey, config.bcryptRounds);

  let row;
  try {
    const { rows } = await db.query(
      `INSERT INTO users (username, password_hash, public_key, encrypted_private_key, private_key_iv)
       VALUES ($1, $2, $3, $4, $5)
       RETURNING id, username, public_key`,
      [username, passwordHash, publicKey, encryptedPrivateKey, privateKeyIv]
    );
    row = rows[0];
  } catch (err) {
    if (err.code === '23505') throw new AppError(409, 'username_taken', 'Username is already taken');
    throw err;
  }

  return { user: toPublicUser(row), ...(await startSession(row)) };
}

async function login({ username, authKey }) {
  const { rows } = await db.query(
    `SELECT id, username, password_hash, public_key, encrypted_private_key, private_key_iv,
            (locked_until IS NOT NULL AND locked_until > now()) AS is_locked
     FROM users WHERE username = $1`,
    [username]
  );
  const user = rows[0];

  if (!user) {
    await bcrypt.compare(authKey, DUMMY_HASH);
    throw invalidCredentials();
  }

  // Lockout is enforced server-side, so refreshing the page or switching
  // clients does not reset the counter.
  if (user.is_locked) throw accountLocked();

  const ok = await bcrypt.compare(authKey, user.password_hash);
  if (!ok) {
    const { rows: updated } = await db.query(
      `UPDATE users SET
         failed_login_count = CASE WHEN failed_login_count + 1 >= $2 THEN 0 ELSE failed_login_count + 1 END,
         locked_until = CASE WHEN failed_login_count + 1 >= $2
                             THEN now() + make_interval(mins => $3) ELSE locked_until END
       WHERE id = $1
       RETURNING (locked_until IS NOT NULL AND locked_until > now()) AS is_locked`,
      [user.id, MAX_FAILED_LOGINS, LOCKOUT_MINUTES]
    );
    if (updated[0]?.is_locked) throw accountLocked();
    throw invalidCredentials();
  }

  await db.query('UPDATE users SET failed_login_count = 0, locked_until = NULL WHERE id = $1', [user.id]);

  return {
    user: toPublicUser(user),
    keys: { encryptedPrivateKey: user.encrypted_private_key, privateKeyIv: user.private_key_iv },
    ...(await startSession(user)),
  };
}

/**
 * Exchange a refresh token for a new access token and a NEW refresh token
 * (rotation). Each refresh token works exactly once. If an already-used token
 * is presented again, someone is replaying a stolen copy, so every token in
 * that session family is revoked and both the attacker and the victim must
 * log in again.
 */
async function refresh(rawToken) {
  if (!rawToken) throw new AppError(401, 'invalid_refresh', 'No active session');
  const tokenHash = hashToken(rawToken);

  const outcome = await db.withTransaction(async (client) => {
    // FOR UPDATE locks the row, so two concurrent refreshes with the same
    // token cannot both succeed.
    const { rows } = await client.query(
      `SELECT id, user_id, family_id, expires_at, revoked_at, (expires_at <= now()) AS expired
       FROM refresh_tokens WHERE token_hash = $1
       FOR UPDATE`,
      [tokenHash]
    );
    const current = rows[0];
    if (!current) return { error: 'invalid' };

    if (current.revoked_at) {
      await client.query(
        'UPDATE refresh_tokens SET revoked_at = now() WHERE family_id = $1 AND revoked_at IS NULL',
        [current.family_id]
      );
      return { error: 'reused', userId: current.user_id };
    }

    if (current.expired) return { error: 'expired' };

    // The new token keeps the family's original expiry: a session has a hard
    // lifetime and cannot be extended forever by refreshing.
    const next = await insertRefreshToken(client, current.user_id, current.family_id, current.expires_at);
    await client.query('UPDATE refresh_tokens SET revoked_at = now(), replaced_by = $2 WHERE id = $1', [
      current.id,
      next.id,
    ]);

    const { rows: users } = await client.query('SELECT id, username, public_key FROM users WHERE id = $1', [
      current.user_id,
    ]);
    return { user: users[0], next };
  });

  if (outcome.error === 'reused') {
    if (!config.isTest) {
      console.warn(`[security] refresh token reuse detected for user ${outcome.userId}; session revoked`);
    }
    throw new AppError(401, 'token_reused', 'Session invalidated. Please log in again.');
  }
  if (outcome.error === 'expired') throw new AppError(401, 'session_expired', 'Session expired. Please log in again.');
  if (outcome.error) throw new AppError(401, 'invalid_refresh', 'No active session');

  return {
    user: toPublicUser(outcome.user),
    accessToken: signAccessToken(outcome.user),
    session: {
      refreshToken: outcome.next.refreshToken,
      csrfToken: generateCsrfToken(),
      expiresAt: outcome.next.expiresAt,
    },
  };
}

/** Revoke the whole session family the presented token belongs to. */
async function logout(rawToken) {
  if (!rawToken) return;
  await db.query(
    `UPDATE refresh_tokens SET revoked_at = now()
     WHERE family_id = (SELECT family_id FROM refresh_tokens WHERE token_hash = $1)
       AND revoked_at IS NULL`,
    [hashToken(rawToken)]
  );
}

module.exports = { register, login, refresh, logout, MAX_FAILED_LOGINS, LOCKOUT_MINUTES };
