-- HW_REJECT_V1 差し戻し（ずる など）。返却あつかいだが ごほうびなし・先生PJの 練習も ひらかない
ALTER TABLE homework_submissions ADD COLUMN rejected_at INTEGER;
