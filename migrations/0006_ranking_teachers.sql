-- 0006_ranking_teachers.sql
-- 教師アカウント・クラス・ランキング機能の追加

-- 教師アカウント（usersテーブルのCHECK制約を回避するため別テーブル）
CREATE TABLE IF NOT EXISTS teacher_accounts (
  id TEXT PRIMARY KEY,
  login_id TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  password_salt TEXT NOT NULL,
  name TEXT NOT NULL,
  school TEXT NOT NULL DEFAULT '',
  is_active INTEGER NOT NULL DEFAULT 0,  -- 0=申請中, 1=承認済み
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

-- 教師が作成するクラス
CREATE TABLE IF NOT EXISTS classes (
  id TEXT PRIMARY KEY,
  class_code TEXT NOT NULL UNIQUE,  -- 生徒が参加するための6文字コード
  name TEXT NOT NULL,
  teacher_id TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_classes_teacher ON classes(teacher_id);
CREATE INDEX IF NOT EXISTS idx_classes_code ON classes(class_code);

-- クラスメンバー（生徒とクラスの紐付け）
CREATE TABLE IF NOT EXISTS class_members (
  user_id TEXT NOT NULL,
  class_id TEXT NOT NULL,
  joined_at TEXT NOT NULL DEFAULT (datetime('now')),
  PRIMARY KEY (user_id, class_id)
);

CREATE INDEX IF NOT EXISTS idx_class_members_class ON class_members(class_id);
CREATE INDEX IF NOT EXISTS idx_class_members_user ON class_members(user_id);

-- ランキング統計（progress保存時にstateJsonから自動抽出）
CREATE TABLE IF NOT EXISTS ranking_stats (
  user_id TEXT PRIMARY KEY,
  display_name TEXT NOT NULL DEFAULT '',
  total_level INTEGER NOT NULL DEFAULT 0,    -- player.level + Σmonster.level
  monster_count INTEGER NOT NULL DEFAULT 0,  -- 図鑑登録数
  correct_count INTEGER NOT NULL DEFAULT 0,  -- 全モードの正解数合計
  updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

-- アプリ全体設定（管理者が管理）
CREATE TABLE IF NOT EXISTS admin_settings (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL,
  updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

INSERT OR IGNORE INTO admin_settings (key, value) VALUES ('ranking_scope', 'class');
INSERT OR IGNORE INTO admin_settings (key, value) VALUES ('ranking_enabled', '1');
