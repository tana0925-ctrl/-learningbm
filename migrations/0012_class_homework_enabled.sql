-- 0012_class_homework_enabled.sql
-- クラスごとに家庭学習機能の表示/非表示を教師が設定できる機能

ALTER TABLE classes ADD COLUMN homework_enabled INTEGER NOT NULL DEFAULT 1;
