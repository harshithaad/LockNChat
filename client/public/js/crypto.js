/**
 * LockNChat end-to-end encryption, built only on the browser's Web Crypto API.
 *
 *   password ──PBKDF2(600k)──► master ──HKDF("auth")──► authKey  → sent to server, bcrypt-hashed there
 *                                    └──HKDF("wrap")──► wrapKey  → never leaves the device
 *
 *   identity key pair: ECDH P-256, generated on the device.
 *     public key  → published to the server's key directory
 *     private key → encrypted with wrapKey (AES-GCM) before upload
 *
 *   conversation key = HKDF(ECDH(myPrivate, peerPublic), salt = conversationId)
 *   message          = AES-256-GCM(conversation key, random 96-bit IV,
 *                                  AAD = conversationId | senderId)
 *
 * The server sees the authKey (useless for decryption), public keys, the
 * wrapped private key and ciphertext. It never sees the password, the
 * wrapKey, a usable private key or any plaintext.
 */

const subtle = globalThis.crypto.subtle;
const encoder = new TextEncoder();
const decoder = new TextDecoder();

export const KDF_ITERATIONS = 600_000;
export const MAX_MESSAGE_LENGTH = 2000;

const CURVE = { name: 'ECDH', namedCurve: 'P-256' };
const LABEL = {
  kdfSalt: 'locknchat/v2/kdf-salt/',
  auth: 'locknchat/v2/auth',
  wrap: 'locknchat/v2/wrap',
  identityKey: 'locknchat/v2/identity-key',
  messageKey: 'locknchat/v2/message-key',
  message: 'locknchat/v2/message',
  safety: 'locknchat/v2/safety-number',
};

// ---------------------------------------------------------------- encoding

export function toBase64(data) {
  const bytes = data instanceof Uint8Array ? data : new Uint8Array(data);
  let binary = '';
  for (let i = 0; i < bytes.length; i += 0x8000) {
    binary += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
  }
  return btoa(binary);
}

export function fromBase64(b64) {
  const binary = atob(b64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

const randomBytes = (n) => globalThis.crypto.getRandomValues(new Uint8Array(n));

export const normalizeUsername = (username) => username.trim().toLowerCase();

// ------------------------------------------------------- password → keys

/**
 * Derive the server credential (authKey) and the local key-wrapping key from
 * the password. HKDF with different labels makes the two keys independent:
 * knowing the authKey reveals nothing about the wrapKey.
 *
 * The PBKDF2 salt is derived from the username, so the client can compute it
 * without asking the server first (which would allow username probing). The
 * server additionally bcrypt-hashes the authKey with its own random salt.
 */
export async function deriveCredentialKeys(username, password, { iterations = KDF_ITERATIONS } = {}) {
  const salt = new Uint8Array(
    await subtle.digest('SHA-256', encoder.encode(LABEL.kdfSalt + normalizeUsername(username)))
  );
  const passwordKey = await subtle.importKey(
    'raw',
    encoder.encode(password.normalize('NFKC')),
    'PBKDF2',
    false,
    ['deriveBits']
  );
  const master = await subtle.deriveBits({ name: 'PBKDF2', hash: 'SHA-256', salt, iterations }, passwordKey, 256);
  const masterKey = await subtle.importKey('raw', master, 'HKDF', false, ['deriveBits', 'deriveKey']);

  const authBits = await subtle.deriveBits(
    { name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(0), info: encoder.encode(LABEL.auth) },
    masterKey,
    256
  );
  const wrapKey = await subtle.deriveKey(
    { name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(0), info: encoder.encode(LABEL.wrap) },
    masterKey,
    { name: 'AES-GCM', length: 256 },
    false, // non-extractable: page scripts can use it but never read its bytes
    ['encrypt', 'decrypt']
  );

  return { authKey: toBase64(authBits), wrapKey };
}

// ---------------------------------------------------------- identity keys

export function generateIdentityKeyPair() {
  // Extractable only so the private key can be wrapped once; the copy kept in
  // memory afterwards is re-imported as non-extractable.
  return subtle.generateKey(CURVE, true, ['deriveBits']);
}

export async function exportPublicKey(publicKey) {
  return toBase64(await subtle.exportKey('spki', publicKey));
}

export function importPublicKey(b64) {
  return subtle.importKey('spki', fromBase64(b64), CURVE, true, []);
}

export async function wrapPrivateKey(privateKey, wrapKey) {
  const pkcs8 = await subtle.exportKey('pkcs8', privateKey);
  const iv = randomBytes(12);
  const ciphertext = await subtle.encrypt(
    { name: 'AES-GCM', iv, additionalData: encoder.encode(LABEL.identityKey) },
    wrapKey,
    pkcs8
  );
  return { encryptedPrivateKey: toBase64(ciphertext), privateKeyIv: toBase64(iv) };
}

/** Decrypt the private key. Fails (throws) if the password was wrong. */
export async function unwrapPrivateKey({ encryptedPrivateKey, privateKeyIv }, wrapKey) {
  const pkcs8 = await subtle.decrypt(
    { name: 'AES-GCM', iv: fromBase64(privateKeyIv), additionalData: encoder.encode(LABEL.identityKey) },
    wrapKey,
    fromBase64(encryptedPrivateKey)
  );
  return subtle.importKey('pkcs8', pkcs8, CURVE, false, ['deriveBits']);
}

/**
 * Everything needed to register: the server payload plus the non-extractable
 * private key to keep on this device.
 */
export async function createRegistration(username, password, options) {
  const { authKey, wrapKey } = await deriveCredentialKeys(username, password, options);
  const { publicKey, privateKey: extractable } = await generateIdentityKeyPair();
  const wrapped = await wrapPrivateKey(extractable, wrapKey);
  // Round-trip proves the wrapped blob is decryptable and gives us a
  // non-extractable handle to the private key.
  const privateKey = await unwrapPrivateKey(wrapped, wrapKey);

  return {
    payload: {
      username: normalizeUsername(username),
      authKey,
      publicKey: await exportPublicKey(publicKey),
      ...wrapped,
    },
    privateKey,
  };
}

// ------------------------------------------------------ message encryption

/** Both participants derive the same AES key without ever sending it. */
export async function deriveConversationKey(privateKey, peerPublicKeyB64, conversationId) {
  const peerPublicKey = await importPublicKey(peerPublicKeyB64);
  const shared = await subtle.deriveBits({ name: 'ECDH', public: peerPublicKey }, privateKey, 256);
  const sharedKey = await subtle.importKey('raw', shared, 'HKDF', false, ['deriveKey']);
  return subtle.deriveKey(
    {
      name: 'HKDF',
      hash: 'SHA-256',
      salt: encoder.encode(conversationId),
      info: encoder.encode(LABEL.messageKey),
    },
    sharedKey,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
}

// Binding the conversation and sender into the GCM tag means the server
// cannot move a message to another conversation or relabel who sent it.
const messageAad = ({ conversationId, senderId }) =>
  encoder.encode(`${LABEL.message}|${conversationId}|${senderId}`);

export async function encryptMessage(key, plaintext, context) {
  if (typeof plaintext !== 'string' || plaintext.length === 0) {
    throw new RangeError('Message must be a non-empty string');
  }
  if (plaintext.length > MAX_MESSAGE_LENGTH) {
    throw new RangeError(`Message must be at most ${MAX_MESSAGE_LENGTH} characters`);
  }
  // A fresh random IV per message: reusing an IV with the same GCM key would
  // break confidentiality and integrity.
  const iv = randomBytes(12);
  const ciphertext = await subtle.encrypt(
    { name: 'AES-GCM', iv, additionalData: messageAad(context) },
    key,
    encoder.encode(plaintext)
  );
  return { ciphertext: toBase64(ciphertext), iv: toBase64(iv) };
}

/** Throws if the ciphertext, IV, conversation or sender were tampered with. */
export async function decryptMessage(key, { ciphertext, iv }, context) {
  const plaintext = await subtle.decrypt(
    { name: 'AES-GCM', iv: fromBase64(iv), additionalData: messageAad(context) },
    key,
    fromBase64(ciphertext)
  );
  return decoder.decode(plaintext);
}

// ------------------------------------------------------------ verification

/**
 * A 30-digit number both users can compare out-of-band (in person, on a call).
 * If it matches, nobody (including the server) has swapped in their own
 * public key to sit in the middle of the conversation.
 */
export async function safetyNumber(publicKeyA, publicKeyB) {
  const [first, second] = [publicKeyA, publicKeyB].sort();
  const digest = new Uint8Array(
    await subtle.digest('SHA-256', encoder.encode(`${LABEL.safety}|${first}|${second}`))
  );
  const groups = [];
  for (let i = 0; i < 6; i++) {
    let value = 0;
    for (let j = 0; j < 5; j++) value = value * 256 + digest[i * 5 + j];
    groups.push(String(value % 100000).padStart(5, '0'));
  }
  return groups.join(' ');
}
