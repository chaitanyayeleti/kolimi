-- Most recent successful login, shown in the admin user list.
ALTER TABLE users ADD COLUMN last_login_at INTEGER;
