-- VIEWAS_V1 👀 子どもの画面に入る（見るだけ）の記録
-- だれが（teacher_id）・いつ（started_at / ended_at）・だれの画面を（student_id）見たか。
-- blocked_count は、見ているあいだにサーバが止めた書きこみの数（保存されなかった数）。
-- 子どものデータ（progress など）には一切触れない、記録専用のテーブル。
CREATE TABLE IF NOT EXISTS view_as_log (
  id            TEXT PRIMARY KEY,
  teacher_id    TEXT NOT NULL,
  teacher_role  TEXT NOT NULL DEFAULT '',
  student_id    TEXT NOT NULL,
  class_id      TEXT NOT NULL DEFAULT '',
  started_at    TEXT NOT NULL DEFAULT (datetime('now')),
  ended_at      TEXT,
  last_seen_at  TEXT,
  blocked_count INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_view_as_log_teacher ON view_as_log (teacher_id, started_at);
CREATE INDEX IF NOT EXISTS idx_view_as_log_student ON view_as_log (student_id, started_at);
