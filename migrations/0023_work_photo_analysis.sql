-- 成果物写真のAI分析テキストを保存するカラム追加
ALTER TABLE homework_submissions ADD COLUMN work_photo_analysis TEXT DEFAULT '';
