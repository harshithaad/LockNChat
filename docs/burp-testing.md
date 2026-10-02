# Manual security testing with Burp Suite

A hands-on test plan for LockNChat using **Burp Suite Community Edition**, which is free. Each test lists:

- **Goal:** what is being tested.
- **Steps:** what to do.
- **Expected:** the secure result.
- **Why it matters:** what the result proves.

Record what you observe in the [manual testing log in SECURITY.md](../SECURITY.md#manual-testing-log).

> Only test systems you own. Everything here targets your local copy of LockNChat.

---

## 0. Setup

1. Start the app (see the README): `npm run db` then `npm start`. It runs on http://localhost:3000.
2. Install [Burp Suite Community](https://portswigger.net/burp/communitydownload) and create a temporary project.
3. Open **Proxy → Intercept → Open browser**. Burp's built-in Chromium is pre-configured to use the proxy and trust Burp's certificate. Turn **Intercept off** for now; traffic still appears in **Proxy → HTTP history** and **Proxy → WebSockets history**.
4. In Burp's browser, go to http://localhost:3000 and register two users, e.g. `alice` and `bob`. Use a second Burp browser window (or a private window) for the second user. Start a chat and send a few messages.
5. Useful tools:
   - **Repeater** (right-click a request → *Send to Repeater*): edit and resend a request by hand.
   - **Intruder**: send many variations of a request automatically. It's throttled in Community, which is fine here.
   - **Decoder**: base64 and URL encoding.
   - Optional: the **JWT Editor** extension from the BApp Store (Extensions → BApp Store) makes token editing easier.

> If you browse to `127.0.0.1` instead of `localhost`, add `http://127.0.0.1:3000` to `CORS_ORIGINS` in `server/.env`. Otherwise the Origin checks will (correctly) reject you.

---

## Part A: Diagnose the v1 prototype (optional, but recommended)

The original React + Firebase version is preserved at the `v1-firebase` tag. Testing it shows *why* v2 was needed. It only works if the original Firebase project still exists.

```bash
git worktree add ../LockNChat-v1 v1-firebase
cd ../LockNChat-v1
npm install
# Windows:  set NODE_OPTIONS=--openssl-legacy-provider && set PORT=3001 && npm start
# macOS/Linux: NODE_OPTIONS=--openssl-legacy-provider PORT=3001 npm start
```

### A1. Key leakage through the database API

- **Steps:**
  1. Register and log in to v1 through Burp's browser.
  2. In **HTTP history**, filter by search term `privkey`. Firestore traffic goes to `firestore.googleapis.com`.
- **Look for:** responses containing user documents with a `privkey` field.
- **Why it matters:** a "private" key stored on the server and delivered to clients means the server, or anyone who can query that collection, can decrypt messages. The encryption wasn't end-to-end.
- **v2 fix:** private keys are generated in the browser and uploaded only after AES-GCM wrapping with a key derived from the password. Repeat this search in v2 (test B2): you'll only find `encryptedPrivateKey`.

### A2. Client-trusted session

- **Steps:** open DevTools → Application → Local Storage and inspect the `user` entry.
- **Look for:** a plain `{ email, uid }` object with no signature or expiry, which the app trusts to decide who is logged in.
- **Why it matters:** there's no server-verified session token, expiry or revocation.
- **v2 fix:**
  - signed 15-minute JWTs, held in memory only
  - an httpOnly refresh cookie
  - rotation with reuse detection

### A3. Broken key exchange

- **Steps:** this one is a code review rather than a Burp test. Read the `power()` function in `src/screens/login-screen/LoginScreen.jsx`.
- **Look for:** it computes `a·b mod p` (repeated addition) instead of `a^b mod p`.
- **Why it matters:** the "public key" is `g·x mod p`, so anyone can recover the private value with one modular inverse. The Diffie-Hellman exchange gave no security.
- **v2 fix:** ECDH P-256 through the Web Crypto API.

When done: `git worktree remove ../LockNChat-v1`.

---

## Part B: Verify v2

### B1. Security headers

- **Steps:** in HTTP history, select `GET /` and `GET /api/health` and inspect the response headers.
- **Expected:**
  - `Content-Security-Policy` with `default-src 'self'; script-src 'self'` and no `unsafe-inline` or `unsafe-eval`
  - `frame-ancestors 'none'`
  - `Strict-Transport-Security`
  - `X-Content-Type-Options: nosniff`
  - `X-Frame-Options: DENY`
  - `Referrer-Policy: no-referrer`
  - no `X-Powered-By`
  - `Cache-Control: no-store` on `/api/*`
- **Why it matters:** these headers come from Helmet.js. The CSP is the main backstop against XSS.

### B2. Token storage and leakage

- **Steps:**
  1. Find `POST /api/auth/login` in HTTP history and inspect the `Set-Cookie` headers.
  2. In DevTools, check Local Storage, Session Storage and `document.cookie` in the console.
  3. In HTTP history, search for `privkey` and `password`.
- **Expected:**
  - `lnc_rt` is `HttpOnly; Secure; SameSite=Strict; Path=/api/auth`.
  - No JWT (`eyJ…`) is in web storage, and `lnc_rt` isn't visible to JavaScript.
  - No password and no plaintext private key appear anywhere, only `authKey` (a derived key) and `encryptedPrivateKey`.
- **Why it matters:** XSS can't steal the refresh token, and the server never handles the password.

### B3. JWT tampering

Send `GET /api/users/me`, with its `Authorization: Bearer …` header, to Repeater.

| Try | Expected |
|-----|----------|
| Send unchanged | `200` |
| Remove the header | `401 unauthenticated` |
| Change one character of the signature | `401 invalid_token` |
| Edit the payload (Decoder → base64url) to another user's `sub` and keep the signature | `401 invalid_token` |
| Set header to `{"alg":"none","typ":"JWT"}`, keep payload, empty signature (`xxx.yyy.`) | `401 invalid_token` |
| Wait 15 minutes and resend the original | `401 token_expired` |

- **Why it matters:**
  - the signature is verified
  - the algorithm is pinned to HS256, which defeats `alg: none`
  - tokens expire after 15 minutes

### B4. Session replay: refresh token reuse

1. Find a `POST /api/auth/refresh` request in HTTP history. The app sends one on page load. Send it to Repeater.
2. Send it once. You get `200` and a new `lnc_rt` cookie, so the old token is now used.
3. Send the **same** request again, replaying the old token.
   - **Expected:** `401 token_reused`.
4. Go back to the browser and reload the page.
   - **Expected:** you're logged out, because the whole session was revoked when the replay was detected.

- **Why it matters:** if a refresh token is stolen, the first time the attacker and the real user both use it, the server notices and kills the session for both. The server log shows `[security] refresh token reuse detected`.

### B5. Revocation after logout

1. Send a fresh `POST /api/auth/refresh` to Repeater.
2. Click **Log out** in the app.
3. Resend the request from Repeater.

- **Expected:** `401`.
- **Why it matters:** logout revokes tokens on the server. It doesn't just delete cookies in the browser.

### B6. CSRF

In Repeater, using the refresh or logout request:

| Try | Expected |
|-----|----------|
| Remove the `X-CSRF-Token` header | `403 csrf_failed` |
| Change `X-CSRF-Token` to a different value | `403 csrf_failed` |
| Change `Origin` to `https://evil.example` | `403 origin_not_allowed` |

Then try a real cross-site attack:

1. Save this as `csrf.html` in an empty folder and serve it from a different origin, e.g. `npx http-server -p 8000`:

   ```html
   <form action="http://localhost:3000/api/auth/logout" method="POST">
     <button>Win a prize</button>
   </form>
   ```

2. While logged in to LockNChat, open http://localhost:8000/csrf.html in the same browser and click the button.

- **Expected:** the response is `403 origin_not_allowed`, and you're still logged in to LockNChat.
- **Why it matters:** this is defense in depth.
  - Browsers treat `localhost:8000` and `localhost:3000` as the *same site*, because ports don't count. So `SameSite=Strict` does **not** stop the cookie in this test. That's exactly why the other two layers exist:
    - The Origin check rejects the request.
    - Even with a valid Origin, the attacker can't read the CSRF cookie to put it in the `X-CSRF-Token` header.
  - Against a truly cross-site attacker (a different domain), `SameSite=Strict` also stops the browser from sending the cookie at all.

### B7. CORS

- **Steps:** in Repeater, add `Origin: https://evil.example` to `GET /api/health`.
- **Expected:** `403` with no `Access-Control-Allow-Origin` header.

### B8. SQL injection

Send `GET /api/users/search?q=a` (with its Bearer header) to Repeater, then to Intruder. Mark the `q` value as the payload position, and URL-encode the payloads.

```
'
' OR '1'='1
' OR 1=1--
a' UNION SELECT password_hash--
'; DROP TABLE users;--
'; SELECT pg_sleep(5)--
%
_
\
```

- **Expected:**
  - every request returns `200` with an empty `users` list, or `400 validation_error` for payloads over 32 characters
  - no SQL errors in responses or server logs
  - no 5-second delay for `pg_sleep`
  - `%` and `_` match literally rather than returning every user
- Also try injection payloads in the `username` field of `POST /api/auth/login`, and in the `before` parameter of `/api/conversations/:id/messages`. **Expected:** `400 validation_error`.
- **Why it matters:** every query uses parameters (`$1`), so input is never interpreted as SQL. The LIKE wildcards are escaped too.

### B9. XSS

1. In the app, send messages containing payloads such as:
   - `<script>alert(1)</script>`
   - `<img src=x onerror=alert(1)>`
   - `"><svg onload=alert(1)>`
2. Try registering a username containing `<script>`.
3. Request `/api/users/search?q=<script>alert(1)</script>` directly in the browser.

- **Expected:**
  1. The messages appear as literal text and no alert fires.
  2. The username is rejected (`400`).
  3. The response is JSON (`Content-Type: application/json`, `nosniff`) and doesn't execute.
- **Why it matters:**
  - The client only uses `textContent`.
  - The CSP would block inline script even if markup were injected.
  - Usernames are restricted to `[a-z0-9_]`.

### B10. IDOR: accessing other users' conversations

1. Log in as a third user, `eve`, in another window.
2. Copy the alice–bob conversation id from one of alice's requests, e.g. `/api/conversations/<id>/messages`.
3. In Repeater, replace alice's Bearer token with eve's and resend.

- **Expected:** `404 not_found`. It's not `403`, so eve can't even confirm the conversation exists.

### B11. WebSocket tampering

1. Open **Proxy → WebSockets history** and find a `message:send` frame sent by the client. It looks like `42["message:send",{...}]`.
2. Send it to Repeater (WebSockets), or turn on interception and edit a frame before it's forwarded.

| Try | Expected |
|-----|----------|
| Change `conversationId` to one you're not in (as eve) | ack: `{"ok":false,"error":{"code":"not_found"}}`, nothing delivered |
| Replace `ciphertext` with `<script>` | ack: `validation_error` |
| Flip one character inside `ciphertext` (keep valid base64) | Message is delivered, but the recipient sees **"This message could not be decrypted"** |
| Send more than 10 frames within a couple of seconds | Later acks return `rate_limited` (bursts of 10 allowed, refilling 2 per second, so clicking slowly won't trigger it) |

- **Why it matters:**
  - The server enforces membership, payload shape and rate limits on WebSocket traffic.
  - AES-GCM's authentication tag makes any change to the ciphertext detectable.
  - The relay can't forge or alter messages.

### B12. WebSocket authentication

1. In WebSockets history, look at the handshake: the token is sent in the Socket.io `40{"token":"…"}` frame.
2. Replay a connection with a missing or edited token.
3. Leave a chat open for more than 15 minutes.

- **Expected:**
  - The connection is refused with `unauthenticated` or `invalid_token`.
  - After 15 minutes, the server sends `session:expired`, disconnects, and the client reconnects with a fresh token.

### B13. Brute force and lockout

1. Send `POST /api/auth/login` to Intruder with a wrong `authKey` and a fixed username.
2. Run 25 requests.

- **Expected:**
  - After 5 failures, the account returns `429 account_locked`, even for the correct password, for 15 minutes.
  - After 20 attempts from one IP within 15 minutes, the server returns `429 rate_limited`.
- Also compare the response for a wrong password and for a nonexistent user. **Expected:** both are identical (`401 invalid_credentials`), so usernames can't be enumerated through login.

### B14. What the server actually stores

```bash
docker compose exec db psql -U locknchat -d locknchat \
  -c "SELECT username, left(password_hash, 20) AS hash, left(encrypted_private_key, 20) AS key FROM users;" \
  -c "SELECT sender_id, left(ciphertext, 40) AS ciphertext FROM messages ORDER BY id DESC LIMIT 5;" \
  -c "SELECT left(token_hash, 16) AS token_hash, revoked_at FROM refresh_tokens ORDER BY created_at DESC LIMIT 5;"
```

- **Expected:**
  - bcrypt hashes (`$2b$12$…`)
  - opaque base64 blobs
  - SHA-256 token hashes
  - no readable message text or keys anywhere
- In the app, open **"What the server sees"** in the encryption panel to compare a message with its ciphertext.

---

## Recording results

For each test, add a row to the log in [SECURITY.md](../SECURITY.md#manual-testing-log):

- the date
- the section number
- pass or fail
- for any failure: what you observed and how you fixed it

A good finding entry has four parts:

1. **What:** the request and the response.
2. **Impact:** what an attacker could do.
3. **Root cause:** why it happened.
4. **Fix:** the commit or change that resolved it.
