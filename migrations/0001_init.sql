-- 0001_init.sql
-- Users (students + admin)
CREATE TABLE IF NOT EXISTS users (
  id TEXT PRIMARY KEY,
  role TEXT NOT NULL CHECK (role IN ('student','admin')),
  login_id TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  password_salt TEXT NOT NULL,
  name TEXT NOT NULL,
  grade INTEGER NOT NULL,
  class_name TEXT NOT NULL,
  is_active INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_users_role ON users(role);
CREATE INDEX IF NOT EXISTS idx_users_active ON users(is_active);

-- Game progress: store all state as JSON for flexibility
CREATE TABLE IF NOT EXISTS progress (
  user_id TEXT PRIMARY KEY,
  state_json TEXT NOT NULL,
  updated_at TEXT NOT NULL DEFAULT (datetime('now')),
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- Learning results log
CREATE TABLE IF NOT EXISTS learning_results (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id TEXT NOT NULL,
  unit TEXT NOT NULL,
  question_id TEXT,
  is_correct INTEGER NOT NULL CHECK (is_correct IN (0,1)),
  time_ms INTEGER,
  answered_at TEXT NOT NULL DEFAULT (datetime('now')),
  meta_json TEXT,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_results_user_id ON learning_results(user_id);
CREATE INDEX IF NOT EXISTS idx_results_answered_at ON learning_results(answered_at);
