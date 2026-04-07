-- 先生メニューに「今週のテスト」カラムを追加
ALTER TABLE class_weekly_menu ADD COLUMN tests TEXT DEFAULT '';
