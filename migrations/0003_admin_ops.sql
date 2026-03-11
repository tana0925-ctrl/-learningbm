-- 0003_admin_ops.sql
-- track last update timestamp if needed
CREATE TRIGGER IF NOT EXISTS users_set_updated_at
AFTER UPDATE ON users
BEGIN
  UPDATE users SET updated_at = datetime('now') WHERE id = NEW.id;
END;
