-- DEF_MVP_V1 防衛戦の部門べつ ベスト3（せめ／ねばり／まもり）の台帳。
-- 1行 ＝ その子の その部門の きろく。place が 1..3 のときだけ コインの資格がある。
-- 同じ行から 2回 配らないように、applied_at を「予約ずみ」の印として使う。
-- 金額も資格も サーバ側の定数だけで決める（クライアントの申告は使わない）。
CREATE TABLE IF NOT EXISTS defense_mvp_rewards (
  event_key  TEXT    NOT NULL,
  class_id   TEXT    NOT NULL,
  user_id    TEXT    NOT NULL,
  category   TEXT    NOT NULL,
  place      INTEGER NOT NULL DEFAULT 0,
  coins      INTEGER NOT NULL DEFAULT 0,
  value      REAL    NOT NULL DEFAULT 0,
  ok         INTEGER NOT NULL DEFAULT 0,
  applied_at TEXT,
  created_at TEXT    NOT NULL DEFAULT (datetime('now')),
  PRIMARY KEY (event_key, class_id, user_id, category)
);
CREATE INDEX IF NOT EXISTS idx_def_mvp_pending ON defense_mvp_rewards (user_id, applied_at);
