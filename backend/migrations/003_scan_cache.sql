-- ── 003_scan_cache.sql ───────────────────────────────────────
CREATE TABLE IF NOT EXISTS scan_cache (
  id          SERIAL PRIMARY KEY,
  cache_key   VARCHAR(512) NOT NULL UNIQUE,   -- deterministic key: "lib:npm:lodash:4.17.20"
  type        VARCHAR(16)  NOT NULL,          -- lib | dep | composer | os | img | sast
  payload     JSONB        NOT NULL,          -- full scan result
  scanned_at  TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_scan_cache_key       ON scan_cache (cache_key);
CREATE INDEX IF NOT EXISTS idx_scan_cache_scanned   ON scan_cache (scanned_at);
CREATE INDEX IF NOT EXISTS idx_scan_cache_type      ON scan_cache (type, scanned_at DESC);
