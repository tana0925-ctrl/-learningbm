-- Messages: teacher <-> student direct messaging
CREATE TABLE IF NOT EXISTS messages (
  id TEXT PRIMARY KEY,
  class_id TEXT NOT NULL,
  sender_id TEXT NOT NULL,
  sender_role TEXT NOT NULL CHECK(sender_role IN ('teacher','student')),
  recipient_id TEXT NOT NULL,
  body TEXT NOT NULL,
  read_at TEXT,
  created_at TEXT DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_messages_recipient ON messages(recipient_id, read_at);
CREATE INDEX IF NOT EXISTS idx_messages_sender ON messages(sender_id);
CREATE INDEX IF NOT EXISTS idx_messages_class ON messages(class_id);
