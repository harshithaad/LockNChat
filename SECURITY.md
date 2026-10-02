# Security

This document describes what LockNChat protects, how, and where its protections stop.

## Security goals

1. **Confidentiality of messages from the server.** Someone with full access to the server or database cannot read message content.
2. **Integrity of messages.** Any modification of a message in transit or at rest is detected by the recipient.
3. **Account and session security.** Stolen or replayed tokens have limited value, and passwords are never stored or seen by the server.
4. **Resistance to common web attacks.** XSS, CSRF, SQL injection, IDOR, brute force and clickjacking.

## Threat model

| Adversary | Can | Defenses |
|-----------|-----|----------|
| Network attacker | Observe or modify traffic | TLS in production (HSTS), E2EE, AES-GCM authentication |
| Database thief / curious server operator | Read every table | Only ciphertext, public keys, bcrypt hashes, SHA-256 token hashes and password-wrapped private keys are stored |
| Attacker with a stolen refresh token | Replay it | Single-use rotation with family-wide revocation on reuse; hard 7-day session lifetime |
| Attacker with a stolen access token | Call the API | 15-minute lifetime; WebSocket disconnected at expiry |
| Malicious website (CSRF / cross-site WebSocket) | Make the victim's browser send requests | `SameSite=Strict` cookies, Origin allowlist, double-submit CSRF token, Bearer tokens for the API, Origin check on WebSocket handshake |
| XSS attacker | Inject script into the page | Strict CSP (`script-src 'self'`, no inline), all user content rendered with `textContent`, refresh token `httpOnly`, private key non-extractable |
| Credential-stuffing / brute-force bot | Guess passwords | Per-IP rate limiting, per-account lockout (5 failures → 15 minutes), PBKDF2 + bcrypt cost |
| Another registered user | Probe other users' data | Participant checks on every conversation read/write; non-members get 404 (no existence oracle) |

**Out of scope:** a compromised user device, a malicious browser extension, and a server that serves malicious JavaScript (see limitations).

## Cryptographic design

| Purpose | Algorithm | Notes |
|---------|-----------|-------|
| Password stretching | PBKDF2-HMAC-SHA256, 600,000 iterations | Done in the browser. Salt = SHA-256(app label + username). |
| Key separation | HKDF-SHA256 | `master → authKey` (sent to server) and `master → wrapKey` (never leaves device) |
| Server credential storage | bcrypt, cost 12 | Hashes the authKey. Production config refuses a cost below 12. |
| Identity keys | ECDH on P-256 | Generated in the browser. Private key re-imported as non-extractable. |
| Private key at rest on server | AES-256-GCM with wrapKey | Fixed associated data so the blob can't be confused with other ciphertexts |
| Conversation key | HKDF-SHA256 over the ECDH shared secret, salt = conversation id | Independent key per conversation |
| Messages | AES-256-GCM, random 96-bit IV per message | AAD = conversation id + sender id. Prevents moving or relabelling messages. |
| Key verification | SHA-256 over both public keys → 30-digit safety number | Compared out-of-band. Trust-on-first-use warning if a peer key changes. |
| Access tokens | JWT HS256, 15 minutes | Algorithm pinned. Issuer, audience and `type` claims checked. |
| Refresh tokens | 256-bit random, stored as SHA-256 | Raw token only exists in the httpOnly cookie |

All cryptography uses the platform's Web Crypto API or Node's `crypto` module. There is no hand-written cryptography.

## Authentication and sessions

- **Registration:**
  - The browser generates the identity key pair and derives `authKey` and `wrapKey` from the password.
  - It uploads `authKey`, the public key and the wrapped private key.
  - The server validates that the public key is a genuine P-256 SPKI key and stores `bcrypt(authKey)`.
- **Login:**
  - The server compares with bcrypt. For unknown usernames it compares against a dummy hash, so both cases take the same time and return the same error.
  - Failed attempts are counted in the database, so the lockout survives page reloads and new clients.
- **Tokens:**
  - The access token is kept in JavaScript memory only.
  - The refresh token is in an `httpOnly; Secure; SameSite=Strict; Path=/api/auth` cookie.
  - The CSRF token is in a separate readable cookie and must be echoed in `X-CSRF-Token`.
- **Rotation and replay detection:**
  - `/api/auth/refresh` locks the token row (`SELECT … FOR UPDATE`), marks the token as used and issues a new one in the same family.
  - Presenting a used token revokes every token in the family and returns `token_reused`.
  - New tokens inherit the family's original expiry, so a session cannot be extended indefinitely.
- **WebSockets:**
  - The handshake must carry a valid access token.
  - The server schedules a disconnect for the moment the token expires. The client refreshes and reconnects.
- **Logout:** revokes the session family and clears the cookies. The client deletes the private key from IndexedDB.

## OWASP Top 10 mapping

| Risk | Control in LockNChat |
|------|----------------------|
| A01 Broken Access Control | Every conversation read and write checks participation in SQL. Non-members get 404. Only public user fields are ever selected. |
| A02 Cryptographic Failures | E2EE with AES-GCM / ECDH / HKDF. bcrypt for credentials. Hashed refresh tokens. HSTS. |
| A03 Injection (SQL, XSS) | All queries are parameterized (`$1, $2…`). zod schemas validate and strip every body, query, params and socket payload. LIKE wildcards are escaped. Client renders text with `textContent`. CSP blocks inline and third-party scripts. |
| A04 Insecure Design | Server designed as untrusted for content. Threat model above. Hard session lifetime. |
| A05 Security Misconfiguration | Helmet headers: CSP, HSTS, `X-Content-Type-Options`, `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`, COOP/CORP. `x-powered-by` removed. Errors never expose stack traces. Config validated at startup (weak `JWT_SECRET` refused). DB bound to localhost. |
| A07 Identification & Authentication Failures | Lockout, rate limiting, uniform login errors, short-lived tokens, rotation with reuse detection, revocation on logout |
| A08 Software & Data Integrity Failures | Static assets served from our own origin only. Dependency audit in CI. |
| A09 Logging & Monitoring | Refresh-token reuse is logged as a security event |
| CSRF | SameSite=Strict, Origin allowlist on auth routes, double-submit token on cookie-authenticated endpoints. The API otherwise requires a Bearer header that browsers never attach automatically. |
| Clickjacking | `frame-ancestors 'none'` and `X-Frame-Options: DENY` |

## Known limitations

These are deliberate trade-offs or open work. They are listed so that nobody over-trusts the system.

1. **No forward secrecy.**
   - Conversation keys come from long-term identity keys, with no Double Ratchet like Signal.
   - If a user's private key and the stored ciphertext are both compromised, all of that user's past messages can be decrypted.
2. **The server delivers the client code.**
   - As with any web-based E2EE app, a malicious or compromised server could serve modified JavaScript that steals keys.
   - The CSP limits third parties, not the origin itself.
3. **First contact trusts the key directory.**
   - Users are protected against a swapped key only if they compare safety numbers, or if the key changes after first contact (trust-on-first-use warning).
4. **The password protects the private key.**
   - If the database leaks, an attacker can attempt an offline guessing attack against a user's wrapped private key.
   - PBKDF2 with 600k iterations slows this down.
   - The username-derived salt allows precomputation targeted at a specific username, though not across users.
   - Strong passwords are enforced on the client.
5. **Metadata is visible to the server:** who talks to whom, when, and approximate message sizes.
6. **No password change or account recovery.** A forgotten password means the private key, and therefore the message history, is lost by design.
7. **No replay protection at the message layer.** The server could re-deliver an old ciphertext. It would decrypt correctly, though it would keep its original id and timestamp.
8. **Lockout can be abused** to temporarily lock a known username (denial of service). Per-IP rate limiting reduces, but does not remove, this risk.
9. **Rate limiting is in-memory**, per server instance. Running several instances would need a shared store (e.g. Redis).
10. **Concurrent refreshes:**
    - Refreshes are serialized within a tab and across tabs using the Web Locks API.
    - In a browser without Web Locks, two tabs refreshing at the same moment can trigger reuse detection and end the session. That is safe, but inconvenient.
11. **XSS could use the key while the page is open.** A successful script injection could ask the browser to decrypt with the non-extractable key while the page is open, though it could not copy the key out. The CSP is the main defense here.

## Testing

- **Automated:** `npm test` runs the server suite (Jest + Supertest + Socket.io client) and the client suite (Node test runner). Between them they cover:
  - token expiry and JWT tampering (`alg: none`, forged signature, modified payload)
  - refresh-token reuse and concurrent refresh
  - CSRF and CORS rejection
  - lockout and rate limits
  - SQL injection payloads and IDOR
  - WebSocket authentication, origin checks, expiry disconnect and flood limits
  - AES-GCM tamper detection
  - a full encrypted round trip asserting the database contains no plaintext
- **Manual:** [docs/burp-testing.md](docs/burp-testing.md) is a step-by-step Burp Suite test plan.

### Manual testing log

Record each manual test run here: what was tested, what was found, and how it was resolved.

| Date | Test (guide section) | Result | Finding / fix |
|------|----------------------|--------|---------------|
|      |                      |        |               |

## Reporting a vulnerability

Please open a GitHub issue without exploit details, or contact the maintainer directly. We'll then arrange a private channel.
