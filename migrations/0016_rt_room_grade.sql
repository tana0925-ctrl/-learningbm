-- 0016_rt_room_grade.sql
-- 友達対戦ルームに学年カラムを追加（0=すべて, 1-6=小学校）

ALTER TABLE rt_rooms ADD COLUMN host_grade INTEGER NOT NULL DEFAULT 0;
