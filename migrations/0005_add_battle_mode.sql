-- 0005_add_battle_mode.sql
-- battle_roomsテーブルにbattle_modeカラムを追加
ALTER TABLE battle_rooms ADD COLUMN battle_mode TEXT NOT NULL DEFAULT 'normal';
