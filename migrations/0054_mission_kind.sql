-- MISSION_KIND_V1（2026-11-18）クラスミッションの しゅるい（正解数のしぼりこみ・野生でつかまえる・野生バトル勝ち数・連勝）
ALTER TABLE class_missions ADD COLUMN kind TEXT NOT NULL DEFAULT 'correct';
ALTER TABLE class_missions ADD COLUMN filt TEXT;
CREATE TABLE IF NOT EXISTS mission_events (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id TEXT NOT NULL, kind TEXT NOT NULL, mid INTEGER, mname TEXT, mtype TEXT, val INTEGER NOT NULL DEFAULT 1, at TEXT NOT NULL DEFAULT (datetime('now')));
CREATE INDEX IF NOT EXISTS idx_mission_events_at ON mission_events(kind, at);
