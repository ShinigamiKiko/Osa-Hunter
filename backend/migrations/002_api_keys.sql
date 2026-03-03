-- ── 002_api_keys.sql ──────────────────────────────────────────
CREATE TABLE IF NOT EXISTS api_keys (
  id          SERIAL PRIMARY KEY,
  user_id     INTEGER      NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  name        VARCHAR(128) NOT NULL,                -- human label, e.g. "CI pipeline"
  key_hash    VARCHAR(255) NOT NULL UNIQUE,         -- sha256 hash of actual key
  key_prefix  VARCHAR(12)  NOT NULL,                -- first 8 chars for display: "osa_abc1…"
  last_used   TIMESTAMPTZ,
  created_at  TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_api_keys_user ON api_keys (user_id);
