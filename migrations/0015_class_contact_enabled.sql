-- クラスごとの連絡帳表示/非表示設定
ALTER TABLE classes ADD COLUMN contact_enabled INTEGER NOT NULL DEFAULT 1;
