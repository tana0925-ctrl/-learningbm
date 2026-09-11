-- DEF_STAGE_V1 (bin 1) : classroom defense stage table
-- created via D1 MCP on 2026-09-12. never run DDL on a request path.
CREATE TABLE IF NOT EXISTS defense_stage (
  class_id   TEXT PRIMARY KEY,
  stage      INTEGER NOT NULL DEFAULT 1,
  updated_at TEXT
);
