-- Create consent_history table to track all consent changes
CREATE TABLE IF NOT EXISTS consent_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    consent_id INTEGER NOT NULL,
    purpose TEXT NOT NULL,
    granted BOOLEAN NOT NULL,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL,
    ip_address TEXT,
    user_agent TEXT,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (consent_id) REFERENCES user_consents(id) ON DELETE CASCADE
);

-- Create table for inactive user archiving
CREATE TABLE IF NOT EXISTS archived_users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    original_user_id INTEGER NOT NULL UNIQUE,
    anonymized_data TEXT NOT NULL, -- JSON blob of anonymized data
    archive_reason TEXT NOT NULL, -- 'INACTIVE', 'USER_REQUEST', etc.
    archive_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL,
    retention_end_date TIMESTAMP NOT NULL -- When the data should be permanently deleted
);

-- Create an index for faster consent history lookups
CREATE INDEX IF NOT EXISTS idx_consent_history_user_id ON consent_history(user_id);
CREATE INDEX IF NOT EXISTS idx_consent_history_consent_id ON consent_history(consent_id);

-- Create index for archive queries
CREATE INDEX IF NOT EXISTS idx_archived_users_retention_end_date ON archived_users(retention_end_date); 