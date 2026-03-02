-- ── 001_init.sql ──────────────────────────────────────────────
-- Users table
CREATE TABLE IF NOT EXISTS users (
  id          SERIAL PRIMARY KEY,
  username    VARCHAR(64)  NOT NULL UNIQUE,
  password    VARCHAR(255) NOT NULL,          -- bcrypt hash
  role        VARCHAR(16)  NOT NULL DEFAULT 'user', -- 'admin' | 'user'
  created_at  TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
  updated_at  TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

-- Sessions table (connect-pg-simple)
CREATE TABLE IF NOT EXISTS session (
  sid     VARCHAR      NOT NULL COLLATE "default" PRIMARY KEY,
  sess    JSON         NOT NULL,
  expire  TIMESTAMPTZ  NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_session_expire ON session (expire);

-- Scan history tables (not wired to frontend yet — ready for future migration)
CREATE TABLE IF NOT EXISTS scans (
  id          SERIAL PRIMARY KEY,
  user_id     INTEGER      NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  type        VARCHAR(16)  NOT NULL, -- 'lib' | 'dep' | 'img' | 'os' | 'sast'
  package     VARCHAR(255),
  ecosystem   VARCHAR(64),
  payload     JSONB        NOT NULL, -- full scan result
  scanned_at  TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_scans_user ON scans (user_id, type, scanned_at DESC);
