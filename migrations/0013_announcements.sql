-- 0013_announcements.sql
-- 教師・管理者からクラスへのおしらせ機能

CREATE TABLE IF NOT EXISTS announcements (
  id TEXT PRIMARY KEY,
  class_id TEXT,
  teacher_id TEXT NOT NULL,
  title TEXT NOT NULL,
  body TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  FOREIGN KEY (class_id) REFERENCES classes(id),
  FOREIGN KEY (teacher_id) REFERENCES teacher_accounts(id)
);

CREATE TABLE IF NOT EXISTS announcement_reads (
  user_id TEXT NOT NULL,
  announcement_id TEXT NOT NULL,
  read_at TEXT NOT NULL DEFAULT (datetime('now')),
  PRIMARY KEY (user_id, announcement_id),
  FOREIGN KEY (announcement_id) REFERENCES announcements(id)
);
