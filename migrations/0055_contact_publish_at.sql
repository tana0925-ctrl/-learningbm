-- 0055_contact_publish_at.sql 連絡帳の 送信予約（UTC 'YYYY-MM-DD HH:MM:SS'。NULL＝すぐ）
ALTER TABLE contact_notes ADD COLUMN publish_at TEXT;
