-- 家庭学習の週間メニューに「有効な曜日」カラムを追加
-- 教師が祝日等に合わせて宿題を出す曜日を柔軟に設定できるようにする
ALTER TABLE class_weekly_menu ADD COLUMN active_days TEXT DEFAULT '["mon","tue","wed","thu","fri"]';
