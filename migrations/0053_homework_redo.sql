-- HW_REDO_V1 差し戻された 家庭学習の やり直し
ALTER TABLE homework_submissions ADD COLUMN redo_at INTEGER;
ALTER TABLE homework_submissions ADD COLUMN redo_json TEXT;
