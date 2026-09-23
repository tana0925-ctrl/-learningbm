-- 0037_karte_material_uses.sql
-- KARTE_MATERIAL_V1
--
-- カルテの材料として「一度渡したもの」の台帳。
--
-- ねらい：カルテは4月からのデータぜんぶを引き出しとして使ってよい。
--         ただし一度ほめた材料は二度目を渡さない。
--         「引き出しは広く・言ったことは外す」の “外す” がわ。
--
-- reserved_at … コピー用のまとまりに入れた時刻。まだ「使った」ではない。
-- used_at     … 先生が公開した時刻。ここが入って初めて「使った」＝次から渡さない。
--               （makeup_grants / defense_mvp_rewards と同じ「予約→確定」の流儀）
--
-- source は 'record'（学習の記録＝取り込んだプリント）と 'note'（授業の観察メモ）。
-- テストの点数はカルテ本文に使わない方針なので、ここでは台帳に載せない。
--
-- ※ リクエスト経路では実行しない。必ず migrations として流すこと（2026-09-03 の障害）。

CREATE TABLE IF NOT EXISTS karte_material_uses (
  user_id     TEXT NOT NULL,
  source      TEXT NOT NULL,
  source_id   TEXT NOT NULL,
  class_id    TEXT,
  reserved_at TEXT NOT NULL DEFAULT (datetime('now')),
  used_at     TEXT,
  PRIMARY KEY (user_id, source, source_id)
);

CREATE INDEX IF NOT EXISTS idx_kmu_pending ON karte_material_uses (user_id, used_at);

-- ── カルテ本文が「どの週のことを書いたか」を、作ったときに一緒に残す列 ──
--
-- これまでは印刷した日から週を逆算していたので、金曜に作って月曜に印刷すると
-- 見出し（9月14日〜18日）と本文（9月7日〜11日）が一週ズレていた。
-- 週を保存して見出しもそれを使えば、いつ作っていつ印刷しても必ず一致する。
--
-- week_guessed … 1 なら「作成日からの推定」。先生の画面に（推定）と出す。
ALTER TABLE student_ai_comments ADD COLUMN week_start TEXT;
ALTER TABLE student_ai_comments ADD COLUMN week_end TEXT;
ALTER TABLE student_ai_comments ADD COLUMN week_guessed INTEGER NOT NULL DEFAULT 0;
