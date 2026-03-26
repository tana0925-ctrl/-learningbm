-- 0008_class_ranking_enabled.sql
-- クラスごとにランキング参加を教師が許可できる機能

ALTER TABLE classes ADD COLUMN ranking_enabled INTEGER NOT NULL DEFAULT 0;
