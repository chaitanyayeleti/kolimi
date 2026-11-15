-- First-login MFA enrollment for admin-created and invited accounts.
ALTER TABLE users ADD COLUMN must_setup_mfa INTEGER NOT NULL DEFAULT 0;
