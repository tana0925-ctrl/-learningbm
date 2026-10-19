-- 0041_karte_recos.sql
-- MICHI_V2 えらべる3つの道
--
-- karte_recos         … 紙にのせた「おすすめ」（どの教科・どの単元から・🅰🅱）。1人1行。
--                       source='teacher' は先生が差しかえたもの（7日間は自動で上書きしない）。
-- karte_reco_feedback … 子どもの「このおすすめ、どう思う？」（fit/easy/hard/other）。1人1週1行。
--                       次の週のおすすめに使う（かんたん→1つ先へ／むずかしい→1つ前へ）。コインは付けない。
--
-- ※ リクエスト経路では実行しない。必ず migrations として流すこと（2026-09-03 の障害）。

CREATE TABLE IF NOT EXISTS karte_recos (
  user_id    TEXT PRIMARY KEY,
  week_key   TEXT,
  reco_json  TEXT NOT NULL,
  source     TEXT NOT NULL DEFAULT 'auto',
  updated_by TEXT,
  updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS karte_reco_feedback (
  user_id    TEXT NOT NULL,
  reco_week  TEXT NOT NULL,
  choice     TEXT NOT NULL,
  subj       TEXT,
  unit       TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  PRIMARY KEY (user_id, reco_week)
);
