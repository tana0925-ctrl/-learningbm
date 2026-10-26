-- 0045_minna_furi.sql
-- MINNA_FURI_V1 みんなのふりかえり（子ども同士で読み合う）＋先生の「📋振り返り一覧」
--
-- minna_consents … 子どもの「のせてもいいよ」。1つの振り返り（毎日＝day_key／週＝week_key）につき1行。
--                  mode = 'anon'（名前なし）/ 'named'（名前あり）/ ''（とりけし）。行は消さずに mode を空にする。
--                  id は AI に渡す「振り返りID」（名前は渡さない）。
-- minna_picks    … 今日のひと往復で AI がえらんだ掲載候補（⭐）と理由。1つの回（kind+ref_key）につき最大5件（コード側の定数）。
-- minna_posts    … 先生が直して「採用」した文面。元の振り返りは書きかえない。status='on'/'off'（取り消し）。
--                  名前を出すかどうかは、見るときに minna_consents.mode で決める（子どもが後から変えてもすぐ効く）。
-- minna_rewards  … 採用されたときの 300コイン の台帳。1つの振り返り（user_id+kind+ref_key）につき1回だけ。
--                  素の INSERT が通ったときだけ progress にコインを足す（予約→付与→失敗したら解放）。
--
-- ※ リクエスト経路では実行しない。必ず migrations として流すこと（2026-09-03 の障害）。

CREATE TABLE IF NOT EXISTS minna_consents (
  id         TEXT PRIMARY KEY,
  user_id    TEXT NOT NULL,
  class_id   TEXT NOT NULL,
  kind       TEXT NOT NULL,              -- 'day' | 'week'
  ref_key    TEXT NOT NULL,              -- 'YYYY-MM-DD' | 'YYYY-Www'
  mode       TEXT NOT NULL DEFAULT '',   -- 'anon' | 'named' | ''
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at TEXT NOT NULL DEFAULT (datetime('now')),
  UNIQUE (user_id, kind, ref_key)
);
CREATE INDEX IF NOT EXISTS idx_minna_consents_class ON minna_consents (class_id, kind, ref_key);

CREATE TABLE IF NOT EXISTS minna_picks (
  consent_id TEXT PRIMARY KEY,
  class_id   TEXT NOT NULL,
  kind       TEXT NOT NULL,
  ref_key    TEXT NOT NULL,
  reason     TEXT NOT NULL DEFAULT '',
  teacher_id TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_minna_picks_class ON minna_picks (class_id, kind, ref_key);

CREATE TABLE IF NOT EXISTS minna_posts (
  consent_id TEXT PRIMARY KEY,
  class_id   TEXT NOT NULL,
  user_id    TEXT NOT NULL,
  kind       TEXT NOT NULL,
  ref_key    TEXT NOT NULL,
  body       TEXT NOT NULL,
  status     TEXT NOT NULL DEFAULT 'on',  -- 'on' | 'off'
  teacher_id TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_minna_posts_class ON minna_posts (class_id, status, ref_key);

CREATE TABLE IF NOT EXISTS minna_rewards (
  user_id    TEXT NOT NULL,
  kind       TEXT NOT NULL,
  ref_key    TEXT NOT NULL,
  coins      INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  PRIMARY KEY (user_id, kind, ref_key)
);
