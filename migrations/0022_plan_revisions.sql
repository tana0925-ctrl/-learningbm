-- 週間計画の修正履歴テーブル（自己調整の記録）
CREATE TABLE IF NOT EXISTS plan_revisions (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  plan_id INTEGER NOT NULL,
  user_id TEXT NOT NULL,
  week_key TEXT NOT NULL,
  revision_number INTEGER NOT NULL DEFAULT 1,
  before_json TEXT NOT NULL,
  after_json TEXT NOT NULL,
  reason TEXT NOT NULL DEFAULT '',
  created_at INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_plan_revisions_plan_id ON plan_revisions(plan_id);
CREATE INDEX IF NOT EXISTS idx_plan_revisions_user_week ON plan_revisions(user_id, week_key);

-- student_weekly_plans に修正回数カラムを追加
ALTER TABLE student_weekly_plans ADD COLUMN revision_count INTEGER NOT NULL DEFAULT 0;

-- 構造化ふりかえりテーブル
CREATE TABLE IF NOT EXISTS structured_reflections (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id TEXT NOT NULL,
  week_key TEXT NOT NULL,
  concentration INTEGER NOT NULL DEFAULT 2,       -- 集中度 1〜3（★）
  good_point TEXT NOT NULL DEFAULT '',             -- うまくいったこと
  improve_point TEXT NOT NULL DEFAULT '',          -- もっとがんばりたいこと
  next_action TEXT NOT NULL DEFAULT '',            -- 明日の作戦（選択式）
  free_text TEXT NOT NULL DEFAULT '',              -- 自由記述
  created_at INTEGER NOT NULL,
  UNIQUE(user_id, week_key)
);

CREATE INDEX IF NOT EXISTS idx_structured_reflections_user ON structured_reflections(user_id, week_key);
