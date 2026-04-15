-- サポーター（おうちの方）からのコメントを保存
ALTER TABLE homework_submissions ADD COLUMN parent_comment TEXT DEFAULT '';
