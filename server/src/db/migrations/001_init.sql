-- LockNChat v2 schema.
-- The server stores only public keys, a password-wrapped private key blob it
-- cannot open, and message ciphertext. It never holds plaintext or usable keys.

CREATE TABLE users (
  id                    UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  username              TEXT NOT NULL,
  -- bcrypt hash of the client-derived auth key (see SECURITY.md)
  password_hash         TEXT NOT NULL,
  -- ECDH P-256 public key, SPKI, base64
  public_key            TEXT NOT NULL,
  -- ECDH private key encrypted on the client with a password-derived key
  encrypted_private_key TEXT NOT NULL,
  private_key_iv        TEXT NOT NULL,
  failed_login_count    INTEGER NOT NULL DEFAULT 0,
  locked_until          TIMESTAMPTZ,
  created_at            TIMESTAMPTZ NOT NULL DEFAULT now(),
  CONSTRAINT username_format CHECK (username ~ '^[a-z0-9_]{3,32}$')
);

CREATE UNIQUE INDEX users_username_key ON users (username);

CREATE TABLE refresh_tokens (
  id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id     UUID NOT NULL REFERENCES users (id) ON DELETE CASCADE,
  -- All tokens issued from one login share a family; reuse revokes the family.
  family_id   UUID NOT NULL,
  -- SHA-256 of the token; the raw token is never stored.
  token_hash  TEXT NOT NULL UNIQUE,
  expires_at  TIMESTAMPTZ NOT NULL,
  revoked_at  TIMESTAMPTZ,
  replaced_by UUID REFERENCES refresh_tokens (id) ON DELETE SET NULL,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX refresh_tokens_family_idx ON refresh_tokens (family_id);
CREATE INDEX refresh_tokens_user_idx ON refresh_tokens (user_id);

CREATE TABLE conversations (
  id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  -- Participants stored in a canonical order so each pair has one conversation.
  user_a     UUID NOT NULL REFERENCES users (id) ON DELETE CASCADE,
  user_b     UUID NOT NULL REFERENCES users (id) ON DELETE CASCADE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  CONSTRAINT participants_ordered CHECK (user_a < user_b),
  CONSTRAINT participants_unique UNIQUE (user_a, user_b)
);

CREATE INDEX conversations_user_b_idx ON conversations (user_b);

CREATE TABLE messages (
  id              BIGSERIAL PRIMARY KEY,
  conversation_id UUID NOT NULL REFERENCES conversations (id) ON DELETE CASCADE,
  sender_id       UUID NOT NULL REFERENCES users (id) ON DELETE CASCADE,
  -- AES-256-GCM ciphertext and IV, base64. Opaque to the server.
  ciphertext      TEXT NOT NULL,
  iv              TEXT NOT NULL,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX messages_conversation_idx ON messages (conversation_id, id DESC);
