'use strict';

const crypto = require('crypto');
const { z } = require('zod');

const BASE64 = /^[A-Za-z0-9+/]+={0,2}$/;

const base64 = (min, max) =>
  z.string().min(min).max(max).regex(BASE64, 'Must be base64-encoded');

const username = z
  .string()
  .trim()
  .toLowerCase()
  .regex(/^[a-z0-9_]{3,32}$/, 'Username must be 3-32 characters: letters, numbers or underscores');

// 32-byte key derived from the password on the client (base64, 44 chars).
// The server never receives the password itself; see SECURITY.md.
const authKey = z.string().regex(/^[A-Za-z0-9+/]{43}=$/, 'Invalid auth key');

/** True if `b64` is a DER/SPKI-encoded elliptic-curve P-256 public key. */
function isP256PublicKey(b64) {
  try {
    const key = crypto.createPublicKey({ key: Buffer.from(b64, 'base64'), format: 'der', type: 'spki' });
    return key.asymmetricKeyType === 'ec' && key.asymmetricKeyDetails?.namedCurve === 'prime256v1';
  } catch {
    return false;
  }
}

const publicKey = base64(100, 200).refine(isP256PublicKey, 'Must be a P-256 public key (SPKI)');

const uuid = z.uuid('Invalid id');

module.exports = { base64, username, authKey, publicKey, uuid, isP256PublicKey };
