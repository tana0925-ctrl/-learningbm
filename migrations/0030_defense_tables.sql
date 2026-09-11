-- 0030_defense_tables.sql
-- Recorded from ensureDefenseTables() in src/index.tsx.
--
-- These three tables already exist in production D1 and the DDL below is
-- byte-for-byte the DDL that used to run on every defense API request.
-- The per-request DDL was removed because the defense event opens at 12:30
-- with a whole class (about 22 pupils) hitting these routes at once, and
-- awaiting DDL on each request serialises the concurrent queries (see the
-- 2026-09-03 incident: /api/teacher/classes, /api/teacher/all-students and
-- /api/defense/status all returning 500).
--
-- This file is for the record. Applying it is a no-op against the existing
-- database because every statement is CREATE TABLE IF NOT EXISTS.

CREATE TABLE IF NOT EXISTS defense_entries (event_key TEXT NOT NULL, user_id TEXT NOT NULL, class_id TEXT, monster_json TEXT, strategy TEXT, created_at TEXT, PRIMARY KEY(event_key, user_id));

CREATE TABLE IF NOT EXISTS defense_results (event_key TEXT NOT NULL, class_id TEXT NOT NULL, result TEXT, log_json TEXT, base_hp_end INTEGER, resolved_at TEXT, PRIMARY KEY(event_key, class_id));

CREATE TABLE IF NOT EXISTS defense_rewards (event_key TEXT NOT NULL, class_id TEXT NOT NULL, user_id TEXT NOT NULL, coins INTEGER DEFAULT 0, seen INTEGER DEFAULT 0, created_at TEXT, PRIMARY KEY(event_key, class_id, user_id));

