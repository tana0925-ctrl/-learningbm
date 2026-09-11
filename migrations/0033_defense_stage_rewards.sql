-- DEFSTAGE_BONUS_V1（第3便）: ステージ初クリアのボーナス台帳
-- 2026-09-12 に D1 MCP から直接流した記録。リクエストパスでは絶対に DDL を流さない
-- （2026-09-03 の本番障害を参照）。
--
-- 1行 =（クラス, ステージ, 児童）1人ぶんの「まだ配っていないボーナス」。
-- applied_at が NULL のあいだだけ未適用。配るときは
--   UPDATE ... SET applied_at=datetime('now') WHERE ... AND applied_at IS NULL
-- で枠を先に予約し、changes===1 になった1回の中だけ progress を json_set で更新する。
-- PRIMARY KEY(class_id, stage, user_id) が二重付与を構造的に止める。
--
-- coins      : 勝利コイン20とは別のステージボーナス（30 + 10 * stage）
-- monster_id : 限定キャラ（ステージ 3/5/7/10 のときだけ。ほかは NULL）

CREATE TABLE IF NOT EXISTS defense_stage_rewards (
  class_id   TEXT    NOT NULL,
  stage      INTEGER NOT NULL,
  user_id    TEXT    NOT NULL,
  coins      INTEGER NOT NULL DEFAULT 0,
  monster_id INTEGER,
  applied_at TEXT,
  PRIMARY KEY (class_id, stage, user_id)
);

CREATE INDEX IF NOT EXISTS idx_defense_stage_rewards_pending
  ON defense_stage_rewards (user_id, applied_at);
