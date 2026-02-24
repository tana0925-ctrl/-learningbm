-- 0002_add_user_security.sql
-- add disabled reason and password reset tracking

ALTER TABLE users ADD COLUMN disabled_reason TEXT;
ALTER TABLE users ADD COLUMN password_updated_at TEXT;
ALTER TABLE users ADD COLUMN must_change_password INTEGER NOT NULL DEFAULT 0;
