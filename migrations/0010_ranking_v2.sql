-- 0010_ranking_v2.sql
-- ランキングv2: 6種類ランキング + 週間/累計 + 学年ポイント補正

-- ranking_statsに新カラム追加
ALTER TABLE ranking_stats ADD COLUMN grade INTEGER NOT NULL DEFAULT 0;
ALTER TABLE ranking_stats ADD COLUMN battle_power INTEGER NOT NULL DEFAULT 0;
ALTER TABLE ranking_stats ADD COLUMN pokedex_count INTEGER NOT NULL DEFAULT 0;
ALTER TABLE ranking_stats ADD COLUMN wild_win_streak INTEGER NOT NULL DEFAULT 0;
ALTER TABLE ranking_stats ADD COLUMN ranking_points REAL NOT NULL DEFAULT 0;

-- 週間ランキング用: 週の開始日と、その時点のベースライン値
-- 週間スコア = 現在の累計値 - ベースライン値
ALTER TABLE ranking_stats ADD COLUMN week_start TEXT NOT NULL DEFAULT '';
ALTER TABLE ranking_stats ADD COLUMN week_base_correct_count INTEGER NOT NULL DEFAULT 0;
ALTER TABLE ranking_stats ADD COLUMN week_base_total_level INTEGER NOT NULL DEFAULT 0;
ALTER TABLE ranking_stats ADD COLUMN week_base_battle_power INTEGER NOT NULL DEFAULT 0;
ALTER TABLE ranking_stats ADD COLUMN week_base_pokedex_count INTEGER NOT NULL DEFAULT 0;
ALTER TABLE ranking_stats ADD COLUMN week_base_wild_win_streak INTEGER NOT NULL DEFAULT 0;
ALTER TABLE ranking_stats ADD COLUMN week_base_ranking_points REAL NOT NULL DEFAULT 0;

-- インデックス
CREATE INDEX IF NOT EXISTS idx_ranking_stats_grade ON ranking_stats(grade);
CREATE INDEX IF NOT EXISTS idx_ranking_stats_week ON ranking_stats(week_start);
