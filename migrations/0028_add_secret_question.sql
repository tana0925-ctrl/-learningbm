-- 0028_add_secret_question.sql
-- パスワード自己復旧用「ひみつのしつもん」カラム（非破壊追加）
-- 既存の password_hash / password_salt には一切影響しない
ALTER TABLE users ADD COLUMN secret_question TEXT;
ALTER TABLE users ADD COLUMN secret_answer_hash TEXT;
ALTER TABLE users ADD COLUMN secret_answer_salt TEXT;
