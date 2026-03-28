-- Reports table for bug reports and feature requests
CREATE TABLE IF NOT EXISTS reports (
  id TEXT PRIMARY KEY,
  account_id TEXT NOT NULL,
  display_name TEXT NOT NULL DEFAULT '',
  category TEXT NOT NULL DEFAULT 'bug',
  body TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'open',
  admin_note TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at TEXT NOT NULL DEFAULT (datetime('now')),
  FOREIGN KEY (account_id) REFERENCES accounts(id)
);

CREATE INDEX IF NOT EXISTS idx_reports_account ON reports(account_id);
CREATE INDEX IF NOT EXISTS idx_reports_status ON reports(status);
CREATE INDEX IF NOT EXISTS idx_reports_created ON reports(created_at);
