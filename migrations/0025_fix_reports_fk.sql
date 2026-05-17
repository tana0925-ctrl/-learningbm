-- Fix reports table FK: accounts(id) -> users(id)
-- The original 0011_reports.sql referenced a non-existent "accounts" table,
-- causing every INSERT into reports to fail with HTTP 500 (SQLITE_ERROR:
-- no such table: main.accounts) because PRAGMA foreign_keys is ON.
-- This migration rebuilds the table with the correct FK to users(id).

PRAGMA foreign_keys=OFF;

CREATE TABLE IF NOT EXISTS reports_fixed (
  id TEXT PRIMARY KEY,
  account_id TEXT NOT NULL,
  display_name TEXT NOT NULL DEFAULT '',
  category TEXT NOT NULL DEFAULT 'bug',
  body TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'open',
  admin_note TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at TEXT NOT NULL DEFAULT (datetime('now')),
  FOREIGN KEY (account_id) REFERENCES users(id)
);

INSERT INTO reports_fixed SELECT * FROM reports;
DROP TABLE reports;
ALTER TABLE reports_fixed RENAME TO reports;

CREATE INDEX IF NOT EXISTS idx_reports_account ON reports(account_id);
CREATE INDEX IF NOT EXISTS idx_reports_status ON reports(status);
CREATE INDEX IF NOT EXISTS idx_reports_created ON reports(created_at);

PRAGMA foreign_keys=ON;
