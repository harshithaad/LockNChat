// Device key storage in IndexedDB.
//
// The private key is stored as a non-extractable CryptoKey object: the browser
// keeps the raw key material internally and page JavaScript can use it but
// never read or export its bytes. This lets a reload restore the session
// without asking for the password again.
//
// The same database remembers each peer's public key (trust on first use) so
// the UI can warn if a contact's key ever changes.

const DB_NAME = 'locknchat';
const DB_VERSION = 1;

function openDb() {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(DB_NAME, DB_VERSION);
    req.onupgradeneeded = () => {
      const db = req.result;
      if (!db.objectStoreNames.contains('identity')) db.createObjectStore('identity');
      if (!db.objectStoreNames.contains('peers')) db.createObjectStore('peers');
    };
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}

async function run(storeName, mode, fn) {
  const db = await openDb();
  try {
    return await new Promise((resolve, reject) => {
      const tx = db.transaction(storeName, mode);
      const req = fn(tx.objectStore(storeName));
      tx.oncomplete = () => resolve(req?.result);
      tx.onerror = () => reject(tx.error);
      tx.onabort = () => reject(tx.error);
    });
  } finally {
    db.close();
  }
}

export function saveIdentity(userId, privateKey) {
  return run('identity', 'readwrite', (store) => store.put(privateKey, userId));
}

export async function loadIdentity(userId) {
  return (await run('identity', 'readonly', (store) => store.get(userId))) ?? null;
}

/**
 * Remove the private key on logout. Remembered peer public keys are kept:
 * they are not secret, and keeping them is what makes key-change warnings work.
 */
export function clearIdentity() {
  return run('identity', 'readwrite', (store) => store.clear());
}

/**
 * Record a peer's public key the first time it is seen. Returns
 * { changed: true, previous } if a different key was stored before.
 */
export async function checkPeerKey(myId, peerId, publicKey) {
  const id = `${myId}:${peerId}`;
  const previous = await run('peers', 'readonly', (store) => store.get(id));
  if (!previous) {
    await run('peers', 'readwrite', (store) => store.put(publicKey, id));
    return { changed: false };
  }
  return previous === publicKey ? { changed: false } : { changed: true, previous };
}

/** Accept a changed key after the user has re-verified the safety number. */
export function trustPeerKey(myId, peerId, publicKey) {
  return run('peers', 'readwrite', (store) => store.put(publicKey, `${myId}:${peerId}`));
}
