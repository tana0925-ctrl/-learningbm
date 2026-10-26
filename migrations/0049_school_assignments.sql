-- 0049_school_assignments.sql
-- TEISHUTSU_V1 📮 学校の提出物チェック（ドリル・ノート・プリントなど）
--
-- school_assignments … 先生が作る提出物。1クラスに何件でも。
--   due_date  … しめきり日（'YYYY-MM-DD'）。空でもよい。
--   subject   … 教科（任意）。
--   done_at   … 先生が「完了」にした時刻（画面で畳む・子どもの「📮 まだの提出物」から消える）。NULL なら進行中。
--   deleted   … まちがえて作ったときの「けす」（1 なら どこにも出さない）。
-- school_assignment_checks … 出した印（✓）。1人1件1行。✓を取り消したら行を消す。
--   checked_day … ✓をつけた日（日本時間の 'YYYY-MM-DD'）。しめきりとくらべる「出し方のようす」に使う。
--
-- ※ リクエスト経路では実行しない。必ず migrations として流すこと（2026-09-03 の障害）。
-- ※ コインは付けない。子どもの画面には自分の分だけ。カルテには未提出の数を出さない。

CREATE TABLE IF NOT EXISTS school_assignments (
  id         TEXT PRIMARY KEY,
  class_id   TEXT NOT NULL,
  title      TEXT NOT NULL,
  subject    TEXT NOT NULL DEFAULT '',
  due_date   TEXT NOT NULL DEFAULT '',
  created_by TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  done_at    TEXT,
  deleted    INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_school_assign_class ON school_assignments (class_id, deleted, done_at);

CREATE TABLE IF NOT EXISTS school_assignment_checks (
  assignment_id TEXT NOT NULL,
  user_id       TEXT NOT NULL,
  checked_at    TEXT NOT NULL DEFAULT (datetime('now')),
  checked_day   TEXT NOT NULL DEFAULT '',
  checked_by    TEXT,
  PRIMARY KEY (assignment_id, user_id)
);
CREATE INDEX IF NOT EXISTS idx_school_check_user ON school_assignment_checks (user_id, checked_day);
