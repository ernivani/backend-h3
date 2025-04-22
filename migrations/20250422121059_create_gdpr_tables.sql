-- Add migration script here

-- Create login_history table for tracking user logins (GDPR compliance)
CREATE TABLE IF NOT EXISTS login_history (
    id INTEGER PRIMARY KEY,
    user_id INTEGER NOT NULL,
    login_timestamp DATETIME NOT NULL,
    ip_address TEXT NOT NULL,
    user_agent TEXT NOT NULL,
    success BOOLEAN NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
);

-- Create user_consents table for tracking user consent (GDPR compliance)
CREATE TABLE IF NOT EXISTS user_consents (
    id INTEGER PRIMARY KEY,
    user_id INTEGER NOT NULL,
    purpose TEXT NOT NULL,
    granted BOOLEAN NOT NULL,
    timestamp DATETIME NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
);

-- Add indexes for better performance
CREATE INDEX idx_login_history_user_id ON login_history (user_id);
CREATE INDEX idx_login_history_success ON login_history (success);
CREATE INDEX idx_user_consents_user_id ON user_consents (user_id);
CREATE INDEX idx_user_consents_purpose ON user_consents (purpose);
