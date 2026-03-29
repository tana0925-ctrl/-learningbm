-- 0014_contact_notes.sql
-- 連絡帳機能：教師からクラスへの日常連絡

CREATE TABLE IF NOT EXISTS contact_notes (
  id TEXT PRIMARY KEY,
  class_id TEXT NOT NULL,
  teacher_id TEXT NOT NULL,
  day_key TEXT NOT NULL,
  body TEXT NOT NULL,
  reward_deadline TEXT,
  reward_coins INTEGER NOT NULL DEFAULT 5,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  FOREIGN KEY (class_id) REFERENCES classes(id)
);

CREATE TABLE IF NOT EXISTS contact_note_reads (
  user_id TEXT NOT NULL,
  note_id TEXT NOT NULL,
  read_at TEXT NOT NULL DEFAULT (datetime('now')),
  reward_claimed INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (user_id, note_id),
  FOREIGN KEY (note_id) REFERENCES contact_notes(id)
);
