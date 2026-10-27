-- 0050_portfolio.sql
-- PORTFOLIO_V1 成果物ポートフォリオ（先生だけが見る写真の記録）
--   ・ここ（本体のDB）には「どの子の・いつの・何の写真か」という目録だけを置く。写真そのものは置かない。
--   ・写真そのものは R2（バインディング PF）か、写真専用の別の D1（バインディング PFDB・migrations_pf/）に置く。
--   ・家庭学習の写真（homework_photos / homework_photos2）には一切さわらない（読むだけ）。
--   ・子どもの画面からは読まない。読むのは /api/teacher/portfolio/* だけ（先生・管理者）。
-- ※ リクエスト経路では DDL を実行しない。必ず migrations として流すこと。

CREATE TABLE IF NOT EXISTS portfolio_items (
  id          TEXT PRIMARY KEY,
  user_id     TEXT NOT NULL,
  class_id    TEXT,
  src         TEXT NOT NULL,              -- 'hw' 家庭学習から自動 / 'teacher' 先生が追加
  hw_day_key  TEXT,                       -- src='hw' のとき：どの日の提出の写真か
  hw_idx      INTEGER,                    -- src='hw' のとき：何まい目か（0〜）
  taken_on    TEXT NOT NULL,              -- YYYY-MM-DD
  fy          INTEGER NOT NULL,           -- 年度（4月はじまり）
  subj        TEXT,
  memo        TEXT,
  store       TEXT NOT NULL,              -- 'r2' | 'd1'
  obj_key     TEXT NOT NULL,
  thumb_key   TEXT,
  mime        TEXT NOT NULL DEFAULT 'image/jpeg',
  byte_size   INTEGER NOT NULL DEFAULT 0,
  thumb_size  INTEGER NOT NULL DEFAULT 0,
  created_by  TEXT,
  created_at  TEXT NOT NULL DEFAULT (datetime('now')),
  deleted_at  TEXT                        -- 消したら写真は消し、この印だけ残す（家庭学習の写真を二度とりこまないため）
);
CREATE INDEX IF NOT EXISTS idx_pf_user  ON portfolio_items(user_id, taken_on);
CREATE INDEX IF NOT EXISTS idx_pf_class ON portfolio_items(class_id, fy);
CREATE INDEX IF NOT EXISTS idx_pf_hw    ON portfolio_items(user_id, hw_day_key, hw_idx);

CREATE TABLE IF NOT EXISTS portfolio_settings (
  class_id      TEXT PRIMARY KEY,
  keep_mode     TEXT NOT NULL DEFAULT 'fy_end',  -- 'fy_end' 年度末まで（消す前に先生へ確認）/ 'keep' 消さない
  auto_hw       INTEGER NOT NULL DEFAULT 1,      -- 家庭学習の写真を自動で入れる
  remind_snooze TEXT,                            -- この日（YYYY-MM-DD）までは年度末の確認を出さない
  updated_by    TEXT,
  updated_at    TEXT
);

-- PORTFOLIO_AI_V1 成果物の分析（外部AI）の返事は、今日のひと往復と同じ下書き表 ai_review_drafts に
--   kind='WORK'（子どもへのひとこと・カルテの📓）/ 'WORKMEMO'（先生用の分析メモ）で入る。
--   子どものカルテが「その子の最新の WORK」を引くための索引。
--   ※ ai_review_drafts は本番ではすでにある（下の CREATE は何もしない）。まっさらな環境でも索引を作れるように置いている。
CREATE TABLE IF NOT EXISTS ai_review_drafts (
  id TEXT PRIMARY KEY, teacher_id TEXT NOT NULL, class_id TEXT NOT NULL, week_key TEXT, kind TEXT NOT NULL,
  target_id TEXT, target_name TEXT, ref_key TEXT, body TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'draft',
  created_at TEXT, published_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_aird_target ON ai_review_drafts(target_id, kind, status, published_at);
