-- Class collaborative missions: count total correct answers across the class
-- Reward (coins + shards) granted to every class member on achievement.
CREATE TABLE IF NOT EXISTS class_missions (
  id TEXT PRIMARY KEY,
  class_id TEXT NOT NULL,
  title TEXT NOT NULL DEFAULT 'クラスミッション',
  goal_correct INTEGER NOT NULL,
  reward_coins INTEGER NOT NULL DEFAULT 0,
  reward_shards INTEGER NOT NULL DEFAULT 0,
  start_at TEXT NOT NULL DEFAULT (datetime('now')),
  end_at TEXT,
  auto_generated INTEGER NOT NULL DEFAULT 0,
  created_by TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_class_missions_class ON class_missions(class_id, end_at);

-- One row per (mission, student) once they claim the reward.
CREATE TABLE IF NOT EXISTS class_mission_claims (
  mission_id TEXT NOT NULL,
  user_id TEXT NOT NULL,
  reward_coins INTEGER NOT NULL DEFAULT 0,
  reward_shards INTEGER NOT NULL DEFAULT 0,
  claimed_at TEXT NOT NULL DEFAULT (datetime('now')),
  PRIMARY KEY (mission_id, user_id)
);
