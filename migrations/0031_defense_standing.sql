-- 0031_defense_standing.sql
-- 防衛戦「一度登録したらずっと」用のテーブル
-- 注意: このDDLはリクエストパスでは実行しない。D1へ直接適用する。

CREATE TABLE IF NOT EXISTS defense_standing (
  user_id        TEXT PRIMARY KEY,
  monster_id     INTEGER,
  strategy       TEXT,
  snapshot_json  TEXT,
  snapshot_level INTEGER,
  updated_at     TEXT
);

-- 決戦後の一括エントリー化をクラスで1回だけにするためのロック
CREATE TABLE IF NOT EXISTS defense_carry_lock (
  event_key TEXT NOT NULL,
  class_id  TEXT NOT NULL,
  done_at   TEXT,
  PRIMARY KEY (event_key, class_id)
);
