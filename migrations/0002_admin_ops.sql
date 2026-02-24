-- 0002_admin_ops.sql
-- Add updated_at and password reset support
ALTER TABLE users ADD COLUMN updated_at TEXT;

-- track last update timestamp if needed
CREATE TRIGGER IF NOT EXISTS users_set_updated_at
AFTER UPDATE ON users
BEGIN
  UPDATE users SET updated_at = datetime('now') WHERE id = NEW.id;
END;
