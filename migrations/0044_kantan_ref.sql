-- 0044_kantan_ref.sql  KANTAN_REF_V1（2026-10-26）かんたんふりかえり／自分から学びにくい子の自動検出
--
-- app_open_days … アプリを開いた日（1人1日1行。主キーで重複しない）。直近2週の「開いた日」を数えるのに使う。
-- week_ref_taps … かんたんふりかえりで えらんだもの（1人1週1行・上書き）。
--                 self_mark … 今週の自分の学び（本人の見立て）'good'=◎よくできた／'ok'=○まあまあ／'more'=△もう少し。
--                             成績・評価には使わない。「前の自分とくらべる」に並べるためだけ。
--                 reason_key / next_key / next_how / mood … えらんだ候補の目印（文そのものは structured_reflections に入る）。
--                 文は structured_reflections に既存の型で入る：good_point＝「◎ よくできた ／ なんで：…」、
--                 next_action＝「次：…」、free_text＝組み立てた文。
-- コインは付けない（コインは既存の week_ref_rewards 台帳のまま）。
-- ※ リクエスト経路では実行しない。本番には先に流してある。
CREATE TABLE IF NOT EXISTS app_open_days (
  user_id    TEXT NOT NULL,
  day_key    TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  PRIMARY KEY (user_id, day_key)
);
CREATE TABLE IF NOT EXISTS week_ref_taps (
  user_id     TEXT NOT NULL,
  week_key    TEXT NOT NULL,
  self_mark   TEXT NOT NULL DEFAULT '',
  reason_key  TEXT NOT NULL DEFAULT '',
  next_key    TEXT NOT NULL DEFAULT '',
  next_how    TEXT NOT NULL DEFAULT '',
  mood        TEXT NOT NULL DEFAULT '',
  added_chars INTEGER NOT NULL DEFAULT 0,
  updated_at  TEXT NOT NULL DEFAULT (datetime('now')),
  PRIMARY KEY (user_id, week_key)
);
