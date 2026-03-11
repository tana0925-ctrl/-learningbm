-- 0005_realtime_battle_v2.sql
-- リアルタイム対戦ルーム（パーティ交換・HP同期）

CREATE TABLE IF NOT EXISTS rt_rooms (
  id TEXT PRIMARY KEY,                  -- 6桁ルームコード
  host_user_id TEXT NOT NULL,
  host_name TEXT NOT NULL,
  host_party_json TEXT NOT NULL,        -- [{i:monsterId, l:level}, ...]
  host_area TEXT NOT NULL DEFAULT 'rounding', -- 野生バトル出題エリア
  host_hp INTEGER NOT NULL DEFAULT 100, -- 残りHP（%）
  host_ready INTEGER NOT NULL DEFAULT 0,
  guest_user_id TEXT,
  guest_name TEXT,
  guest_party_json TEXT,
  guest_hp INTEGER NOT NULL DEFAULT 100,
  guest_ready INTEGER NOT NULL DEFAULT 0,
  battle_type TEXT NOT NULL DEFAULT 'normal', -- 'normal'=野生形式 / 'gym'=ジム形式
  status TEXT NOT NULL DEFAULT 'waiting',    -- waiting/ready/playing/finished
  winner TEXT,                               -- 'host'/'guest'/'draw'
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

-- バトルイベントログ（正解ダメージをリアルタイムに相手へ反映）
CREATE TABLE IF NOT EXISTS rt_events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  room_id TEXT NOT NULL,
  user_id TEXT NOT NULL,           -- 誰が
  event_type TEXT NOT NULL,        -- 'damage' / 'faint' / 'win' / 'lose'
  value INTEGER NOT NULL DEFAULT 0,-- ダメージ量
  monster_id INTEGER,              -- 攻撃したキャラID
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  FOREIGN KEY (room_id) REFERENCES rt_rooms(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_rt_rooms_status ON rt_rooms(status);
CREATE INDEX IF NOT EXISTS idx_rt_events_room ON rt_events(room_id, id);
