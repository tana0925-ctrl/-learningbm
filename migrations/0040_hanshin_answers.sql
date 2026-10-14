-- 0040_hanshin_answers.sql
-- HANSHIN_Q_V1（MICHI_V1 学びの道しるべ）
--
-- 阪神マンのカルテの「考えてほしいこと」に、子どもがアプリで答える。
--
-- hanshin_answers        … 子どもの答え（書きなおすと上書き）。先生の画面と、次のひと往復の材料に使う。
-- hanshin_answer_rewards … ボーナスの台帳。question_id（公開したカルテ ai_review_drafts.id）＋ user_id が主キー。
--                          素の INSERT が通ったときだけ progress にコインを足す（予約→付与→失敗したら解放）。
--                          homework_rewards / defense_stage_rewards と同じ作法。
--
-- ※ リクエスト経路では実行しない。必ず migrations として流すこと（2026-09-03 の障害）。

CREATE TABLE IF NOT EXISTS hanshin_answers (
  question_id TEXT NOT NULL,
  user_id     TEXT NOT NULL,
  week_key    TEXT,
  question    TEXT,
  answer      TEXT NOT NULL,
  created_at  TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at  TEXT NOT NULL DEFAULT (datetime('now')),
  PRIMARY KEY (question_id, user_id)
);
CREATE INDEX IF NOT EXISTS idx_hanshin_answers_user ON hanshin_answers (user_id, updated_at);

CREATE TABLE IF NOT EXISTS hanshin_answer_rewards (
  question_id TEXT NOT NULL,
  user_id     TEXT NOT NULL,
  coins       INTEGER NOT NULL DEFAULT 0,
  created_at  TEXT NOT NULL DEFAULT (datetime('now')),
  PRIMARY KEY (question_id, user_id)
);
