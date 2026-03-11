-- 0004_realtime_battle.sql
-- リアルタイム対戦用テーブル

-- 対戦ルーム
CREATE TABLE IF NOT EXISTS battle_rooms (
  id TEXT PRIMARY KEY,           -- ルームID (6桁英数字)
  host_user_id TEXT NOT NULL,    -- ホストのユーザーID
  host_name TEXT NOT NULL,       -- ホストの表示名
  host_party_json TEXT NOT NULL, -- ホストのパーティJSON
  guest_user_id TEXT,            -- ゲストのユーザーID
  guest_name TEXT,               -- ゲストの表示名
  guest_party_json TEXT,         -- ゲストのパーティJSON
  status TEXT NOT NULL DEFAULT 'waiting', -- waiting|ready|playing|finished
  area TEXT NOT NULL DEFAULT 'rounding',  -- 出題エリア
  current_question_json TEXT,    -- 現在の問題JSON
  question_index INTEGER NOT NULL DEFAULT 0,
  host_score INTEGER NOT NULL DEFAULT 0,
  guest_score INTEGER NOT NULL DEFAULT 0,
  host_hp INTEGER NOT NULL DEFAULT 100,
  guest_hp INTEGER NOT NULL DEFAULT 100,
  winner TEXT,                   -- 'host'|'guest'|'draw'
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at TEXT NOT NULL DEFAULT (datetime('now')),
  FOREIGN KEY (host_user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- 対戦ルームの各ターンの回答
CREATE TABLE IF NOT EXISTS battle_answers (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  room_id TEXT NOT NULL,
  user_id TEXT NOT NULL,
  question_index INTEGER NOT NULL,
  answer TEXT,                   -- 回答内容
  is_correct INTEGER NOT NULL DEFAULT 0,
  answered_at TEXT NOT NULL DEFAULT (datetime('now')),
  UNIQUE(room_id, user_id, question_index),
  FOREIGN KEY (room_id) REFERENCES battle_rooms(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_battle_rooms_status ON battle_rooms(status);
CREATE INDEX IF NOT EXISTS idx_battle_rooms_host ON battle_rooms(host_user_id);
CREATE INDEX IF NOT EXISTS idx_battle_answers_room ON battle_answers(room_id, question_index);
