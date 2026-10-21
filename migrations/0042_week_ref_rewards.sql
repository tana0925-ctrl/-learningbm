-- 0042_week_ref_rewards.sql
-- WEEKREF_V1 週の振り返りを書いたら小さなボーナス（1週につき1回・20コイン）
--
-- week_ref_rewards … ボーナスの台帳。week_key（'2026-W43' の形）＋ user_id が主キー。
--                    素の INSERT が通ったときだけ progress にコインを足す（予約→付与→失敗したら解放）。
--                    hanshin_answer_rewards / homework_rewards と同じ作法。
--
-- ※ リクエスト経路では実行しない。必ず migrations として流すこと（2026-09-03 の障害）。

CREATE TABLE IF NOT EXISTS week_ref_rewards (
  week_key   TEXT NOT NULL,
  user_id    TEXT NOT NULL,
  coins      INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  PRIMARY KEY (week_key, user_id)
);
