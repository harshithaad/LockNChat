import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import * as e2ee from '../public/js/crypto.js';

// The server's own validators, to prove client output matches the API contract.
const require = createRequire(import.meta.url);
const serverSchemas = require('../../server/src/lib/schemas.js');

// Low iteration count keeps the suite fast; one test exercises the real value.
const FAST = { iterations: 1000 };

async function makeUser(name, password = 'Correct-Horse-9') {
  const { payload, privateKey } = await e2ee.createRegistration(name, password, FAST);
  return { id: crypto.randomUUID(), payload, privateKey };
}

async function conversationKeys(conversationId = crypto.randomUUID()) {
  const alice = await makeUser('alice');
  const bob = await makeUser('bob');
  const aliceKey = await e2ee.deriveConversationKey(alice.privateKey, bob.payload.publicKey, conversationId);
  const bobKey = await e2ee.deriveConversationKey(bob.privateKey, alice.payload.publicKey, conversationId);
  return { alice, bob, aliceKey, bobKey, conversationId };
}

function flipByte(b64, index = 0) {
  const bytes = e2ee.fromBase64(b64);
  bytes[index] ^= 0x01;
  return e2ee.toBase64(bytes);
}

describe('base64', () => {
  test('round-trips arbitrary bytes, including large inputs', () => {
    const data = crypto.getRandomValues(new Uint8Array(60_000));
    assert.deepEqual(e2ee.fromBase64(e2ee.toBase64(data)), data);
  });
});

describe('password key derivation', () => {
  test('is deterministic for the same username and password', async () => {
    const a = await e2ee.deriveCredentialKeys('alice', 'pw-1', FAST);
    const b = await e2ee.deriveCredentialKeys('  ALICE ', 'pw-1', FAST);
    assert.equal(a.authKey, b.authKey);
  });

  test('differs for different passwords and different usernames', async () => {
    const base = await e2ee.deriveCredentialKeys('alice', 'pw-1', FAST);
    const otherPw = await e2ee.deriveCredentialKeys('alice', 'pw-2', FAST);
    const otherUser = await e2ee.deriveCredentialKeys('bob', 'pw-1', FAST);
    assert.notEqual(base.authKey, otherPw.authKey);
    assert.notEqual(base.authKey, otherUser.authKey);
  });

  test('produces an authKey the server accepts and never equals the password', async () => {
    const { authKey } = await e2ee.deriveCredentialKeys('alice', 'pw-1', FAST);
    assert.equal(serverSchemas.authKey.safeParse(authKey).success, true);
    assert.notEqual(authKey, 'pw-1');
  });

  test('keeps the wrapping key non-extractable', async () => {
    const { wrapKey } = await e2ee.deriveCredentialKeys('alice', 'pw-1', FAST);
    assert.equal(wrapKey.extractable, false);
    await assert.rejects(crypto.subtle.exportKey('raw', wrapKey));
  });

  test('uses 600,000 PBKDF2 iterations by default', async () => {
    assert.equal(e2ee.KDF_ITERATIONS, 600_000);
    const slow = await e2ee.deriveCredentialKeys('alice', 'pw-1');
    const fast = await e2ee.deriveCredentialKeys('alice', 'pw-1', FAST);
    assert.notEqual(slow.authKey, fast.authKey);
  });
});

describe('identity keys', () => {
  test('registration payload passes the server validators', async () => {
    const { payload } = await makeUser('Alice_01');
    assert.equal(payload.username, 'alice_01');
    assert.equal(serverSchemas.publicKey.safeParse(payload.publicKey).success, true);
    assert.equal(serverSchemas.base64(32, 512).safeParse(payload.encryptedPrivateKey).success, true);
    assert.equal(serverSchemas.base64(16, 16).safeParse(payload.privateKeyIv).success, true);
  });

  test('the payload sent to the server contains no usable private key', async () => {
    const { payload } = await makeUser('alice');
    assert.deepEqual(Object.keys(payload).sort(), [
      'authKey',
      'encryptedPrivateKey',
      'privateKeyIv',
      'publicKey',
      'username',
    ]);
    await assert.rejects(
      crypto.subtle.importKey('pkcs8', e2ee.fromBase64(payload.encryptedPrivateKey), { name: 'ECDH', namedCurve: 'P-256' }, false, ['deriveBits'])
    );
  });

  test('the wrapped private key unlocks with the right password only', async () => {
    const { payload } = await e2ee.createRegistration('alice', 'right-password', FAST);
    const right = await e2ee.deriveCredentialKeys('alice', 'right-password', FAST);
    const wrong = await e2ee.deriveCredentialKeys('alice', 'wrong-password', FAST);

    const key = await e2ee.unwrapPrivateKey(payload, right.wrapKey);
    assert.equal(key.type, 'private');
    await assert.rejects(e2ee.unwrapPrivateKey(payload, wrong.wrapKey));
  });

  test('the in-memory private key is non-extractable', async () => {
    const { privateKey } = await makeUser('alice');
    assert.equal(privateKey.extractable, false);
    await assert.rejects(crypto.subtle.exportKey('pkcs8', privateKey));
  });
});

describe('message encryption', () => {
  test('both participants derive the same key: alice encrypts, bob decrypts', async () => {
    const { alice, aliceKey, bobKey, conversationId } = await conversationKeys();
    const context = { conversationId, senderId: alice.id };
    const sealed = await e2ee.encryptMessage(aliceKey, 'meet at 6 🔒', context);
    assert.equal(await e2ee.decryptMessage(bobKey, sealed, context), 'meet at 6 🔒');
  });

  test('ciphertext does not contain the plaintext', async () => {
    const { alice, aliceKey, conversationId } = await conversationKeys();
    const sealed = await e2ee.encryptMessage(aliceKey, 'secret plan', { conversationId, senderId: alice.id });
    assert.ok(!Buffer.from(sealed.ciphertext, 'base64').toString('utf8').includes('secret plan'));
  });

  test('uses a fresh IV for every message', async () => {
    const { alice, aliceKey, conversationId } = await conversationKeys();
    const context = { conversationId, senderId: alice.id };
    const a = await e2ee.encryptMessage(aliceKey, 'same', context);
    const b = await e2ee.encryptMessage(aliceKey, 'same', context);
    assert.notEqual(a.iv, b.iv);
    assert.notEqual(a.ciphertext, b.ciphertext);
  });

  test('a third party with their own keys cannot decrypt', async () => {
    const { alice, bob, aliceKey, conversationId } = await conversationKeys();
    const eve = await makeUser('eve');
    const context = { conversationId, senderId: alice.id };
    const sealed = await e2ee.encryptMessage(aliceKey, 'hi bob', context);

    const eveKey = await e2ee.deriveConversationKey(eve.privateKey, bob.payload.publicKey, conversationId);
    await assert.rejects(e2ee.decryptMessage(eveKey, sealed, context));
  });

  test('keys are separate per conversation', async () => {
    const { alice, bob, aliceKey, conversationId } = await conversationKeys();
    const context = { conversationId, senderId: alice.id };
    const sealed = await e2ee.encryptMessage(aliceKey, 'hi', context);
    const otherKey = await e2ee.deriveConversationKey(bob.privateKey, alice.payload.publicKey, crypto.randomUUID());
    await assert.rejects(e2ee.decryptMessage(otherKey, sealed, context));
  });

  describe('tamper detection (AES-GCM authentication)', () => {
    test('rejects a modified ciphertext', async () => {
      const { alice, aliceKey, bobKey, conversationId } = await conversationKeys();
      const context = { conversationId, senderId: alice.id };
      const sealed = await e2ee.encryptMessage(aliceKey, 'pay 10', context);
      await assert.rejects(e2ee.decryptMessage(bobKey, { ...sealed, ciphertext: flipByte(sealed.ciphertext) }, context));
    });

    test('rejects a modified IV', async () => {
      const { alice, aliceKey, bobKey, conversationId } = await conversationKeys();
      const context = { conversationId, senderId: alice.id };
      const sealed = await e2ee.encryptMessage(aliceKey, 'pay 10', context);
      await assert.rejects(e2ee.decryptMessage(bobKey, { ...sealed, iv: flipByte(sealed.iv) }, context));
    });

    test('rejects a message relabelled as sent by someone else', async () => {
      const { alice, bob, aliceKey, bobKey, conversationId } = await conversationKeys();
      const sealed = await e2ee.encryptMessage(aliceKey, 'from alice', { conversationId, senderId: alice.id });
      await assert.rejects(e2ee.decryptMessage(bobKey, sealed, { conversationId, senderId: bob.id }));
    });

    test('rejects a message moved to a different conversation', async () => {
      const { alice, aliceKey, bobKey, conversationId } = await conversationKeys();
      const sealed = await e2ee.encryptMessage(aliceKey, 'hi', { conversationId, senderId: alice.id });
      await assert.rejects(
        e2ee.decryptMessage(bobKey, sealed, { conversationId: crypto.randomUUID(), senderId: alice.id })
      );
    });
  });

  test('enforces message length limits', async () => {
    const { alice, aliceKey, conversationId } = await conversationKeys();
    const context = { conversationId, senderId: alice.id };
    await assert.rejects(e2ee.encryptMessage(aliceKey, '', context), RangeError);
    await assert.rejects(e2ee.encryptMessage(aliceKey, 'x'.repeat(2001), context), RangeError);
    await e2ee.encryptMessage(aliceKey, 'x'.repeat(2000), context);
  });

  test('a maximum-length message fits within the server ciphertext limit', async () => {
    const { alice, aliceKey, conversationId } = await conversationKeys();
    // Worst case per character: a BMP character such as '中' is 1 UTF-16 unit but 3 UTF-8 bytes.
    const sealed = await e2ee.encryptMessage(aliceKey, '中'.repeat(2000), { conversationId, senderId: alice.id });
    assert.ok(sealed.ciphertext.length <= 12_000, `ciphertext length ${sealed.ciphertext.length}`);
  });
});

describe('safety numbers', () => {
  test('are identical on both sides and formatted as 6 groups of 5 digits', async () => {
    const alice = await makeUser('alice');
    const bob = await makeUser('bob');
    const fromAlice = await e2ee.safetyNumber(alice.payload.publicKey, bob.payload.publicKey);
    const fromBob = await e2ee.safetyNumber(bob.payload.publicKey, alice.payload.publicKey);
    assert.equal(fromAlice, fromBob);
    assert.match(fromAlice, /^\d{5}( \d{5}){5}$/);
  });

  test('change when a key is swapped (man-in-the-middle)', async () => {
    const alice = await makeUser('alice');
    const bob = await makeUser('bob');
    const mallory = await makeUser('mallory');
    const genuine = await e2ee.safetyNumber(alice.payload.publicKey, bob.payload.publicKey);
    const attacked = await e2ee.safetyNumber(alice.payload.publicKey, mallory.payload.publicKey);
    assert.notEqual(genuine, attacked);
  });
});
