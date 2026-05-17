-- Store homework photos as BLOB in D1 (alternative to R2)
-- Photo bytes saved here; teacher dashboard reads via /api/photo/:userId/:dayKey
CREATE TABLE IF NOT EXISTS homework_photos (
  user_id TEXT NOT NULL,
  day_key TEXT NOT NULL,
  mime_type TEXT NOT NULL DEFAULT 'image/jpeg',
  bytes BLOB NOT NULL,
  byte_size INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  PRIMARY KEY (user_id, day_key),
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_homework_photos_user ON homework_photos(user_id);
