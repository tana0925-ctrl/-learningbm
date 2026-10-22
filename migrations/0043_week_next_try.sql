-- 0043_week_next_try.sql
-- MAEJIBUN_V1 週の振り返りに足した「来週やってみたいこと」（どちらも任意）
--
-- week_next_try … 1人1週1行（user_id + week_key が主キー）。week_key は振り返りを書いた週（'2026-W43' の形）。
--                  unit / unit_name … 子どもが選んだ単元（CURRICULUM の id と名前）。空でもよい。
--                  text            … 一言（40字まで）。空でもよい。
--                  次の週のカルテの「🅲 じぶんで決める」に最初から入れ、単元なら 🅰🅱 のおすすめにも優先して使う。
--                  今日のひと往復（外部AIへのコピー）にも入れる。コインは付けない。
--
-- ※ リクエスト経路では実行しない。必ず migrations として流すこと（2026-09-03 の障害）。

CREATE TABLE IF NOT EXISTS week_next_try (
  user_id    TEXT NOT NULL,
  week_key   TEXT NOT NULL,
  unit       TEXT NOT NULL DEFAULT '',
  unit_name  TEXT NOT NULL DEFAULT '',
  text       TEXT NOT NULL DEFAULT '',
  updated_at TEXT NOT NULL DEFAULT (datetime('now')),
  PRIMARY KEY (user_id, week_key)
);
