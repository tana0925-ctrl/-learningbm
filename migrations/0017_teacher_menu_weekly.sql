-- 先生メニュー（クラス全体の課題指示）+ 週間計画・振り返りフィールド

-- 先生メニュー: クラス単位で漢字スキル・計算スキルのページ指示
CREATE TABLE IF NOT EXISTS class_weekly_menu (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  class_id TEXT NOT NULL,
  week_key TEXT NOT NULL,          -- 'YYYY-Wnn' 形式 (例: 2026-W15)
  kanji_page TEXT DEFAULT '',      -- 漢字スキル「○ページまで」
  keisan_page TEXT DEFAULT '',     -- 計算スキル「○ページまで」
  other_tasks TEXT DEFAULT '',     -- その他の課題（自由記述）
  updated_at INTEGER NOT NULL DEFAULT 0,
  UNIQUE(class_id, week_key)
);

CREATE INDEX IF NOT EXISTS idx_cwm_class_week ON class_weekly_menu(class_id, week_key);

-- homework_submissions に週間計画・振り返りフィールドを追加
ALTER TABLE homework_submissions ADD COLUMN weekly_plan TEXT DEFAULT '';
ALTER TABLE homework_submissions ADD COLUMN weekly_reflection TEXT DEFAULT '';
ALTER TABLE homework_submissions ADD COLUMN self_study_plan TEXT DEFAULT '';
