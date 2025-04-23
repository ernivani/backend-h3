use sqlx::SqlitePool;
use anyhow::{Result, anyhow};
use chrono::{DateTime, Utc, Duration};
use log::info;
use serde::{Deserialize, Serialize};
use serde_json::json;
use sqlx::Row;

use crate::models::User;

pub struct GdprService {
    pool: SqlitePool,
}

// Data export structure for user data
#[derive(Debug, Serialize, Deserialize)]
pub struct UserDataExport {
    pub user: User,
    pub login_history: Vec<LoginRecord>,
    pub data_processing_consents: Vec<UserConsent>,
    pub consent_history: Vec<ConsentHistoryRecord>,
}

#[derive(Debug, Serialize, Deserialize, sqlx::FromRow)]
pub struct LoginRecord {
    pub id: i64,
    pub user_id: i64,
    pub login_timestamp: DateTime<Utc>,
    pub ip_address: String,
    pub user_agent: String,
    pub success: bool,
}

#[derive(Debug, Serialize, Deserialize, sqlx::FromRow)]
pub struct UserConsent {
    pub id: i64,
    pub user_id: i64,
    pub purpose: String,
    pub granted: bool,
    pub timestamp: DateTime<Utc>,
}

#[derive(Debug, Serialize, Deserialize, sqlx::FromRow)]
pub struct ConsentHistoryRecord {
    pub id: i64,
    pub user_id: i64,
    pub consent_id: i64,
    pub purpose: String,
    pub granted: bool,
    pub timestamp: DateTime<Utc>,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, sqlx::FromRow)]
pub struct ArchivedUser {
    pub id: i64,
    pub original_user_id: i64,
    pub anonymized_data: String, // JSON string
    pub archive_reason: String,
    pub archive_date: DateTime<Utc>,
    pub retention_end_date: DateTime<Utc>,
}

// Data retention configuration
#[derive(Debug, Serialize, Deserialize)]
pub struct DataRetentionConfig {
    pub inactive_user_months: i64,        // Archive users inactive for this many months
    pub archive_retention_years: i64,     // Keep archived data for this many years
    pub consent_history_years: i64,       // Keep consent history for this many years
    pub login_history_months: i64,        // Keep login history for this many months
}

impl Default for DataRetentionConfig {
    fn default() -> Self {
        Self {
            inactive_user_months: 36,     // 3 years
            archive_retention_years: 5,   // 5 years
            consent_history_years: 3,     // 3 years
            login_history_months: 12,     // 12 months
        }
    }
}

impl GdprService {
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }

    // Export all user data (right of access)
    pub async fn export_user_data(&self, user_id: i64) -> Result<UserDataExport> {
        info!("Exporting data for user ID: {}", user_id);

        // Get user data
        let user = sqlx::query_as!(
            User,
            r#"
            SELECT id as "id!", name, email, password, created_at as "created_at: DateTime<Utc>", updated_at as "updated_at: DateTime<Utc>"
            FROM users 
            WHERE id = ?
            "#,
            user_id
        )
        .fetch_optional(&self.pool)
        .await?
        .ok_or_else(|| anyhow!("User not found"))?;

        // Get login history if it exists
        let login_history = match sqlx::query_as!(
            LoginRecord,
            r#"
            SELECT id as "id!", user_id, login_timestamp as "login_timestamp: DateTime<Utc>", 
                   ip_address, user_agent, success
            FROM login_history 
            WHERE user_id = ?
            ORDER BY login_timestamp DESC
            "#,
            user_id
        )
        .fetch_all(&self.pool)
        .await {
            Ok(records) => records,
            Err(_) => Vec::new(), // Return empty vector if table doesn't exist
        };

        // Get consent history if it exists
        let data_processing_consents = match sqlx::query_as!(
            UserConsent,
            r#"
            SELECT id as "id!", user_id, purpose, granted, timestamp as "timestamp: DateTime<Utc>"
            FROM user_consents 
            WHERE user_id = ?
            ORDER BY timestamp DESC
            "#,
            user_id
        )
        .fetch_all(&self.pool)
        .await {
            Ok(consents) => consents,
            Err(_) => Vec::new(), // Return empty vector if table doesn't exist
        };

        // Get consent history records
        let consent_history = match sqlx::query_as!(
            ConsentHistoryRecord,
            r#"
            SELECT id as "id!", user_id, consent_id, purpose, granted, 
                   timestamp as "timestamp: DateTime<Utc>", ip_address, user_agent
            FROM consent_history 
            WHERE user_id = ?
            ORDER BY timestamp DESC
            "#,
            user_id
        )
        .fetch_all(&self.pool)
        .await {
            Ok(history) => history,
            Err(_) => Vec::new(), // Return empty vector if table doesn't exist
        };

        Ok(UserDataExport {
            user,
            login_history,
            data_processing_consents,
            consent_history,
        })
    }

    // Update user data (right to rectification)
    pub async fn update_user_data(
        &self,
        user_id: i64,
        name: Option<String>,
        email: Option<String>,
    ) -> Result<User> {
        info!("Updating data for user ID: {}", user_id);

        let mut updates = Vec::new();
        let mut params = Vec::new();
        
        if let Some(name) = name {
            updates.push("name = ?");
            params.push(name);
        }
        
        if let Some(email) = email {
            updates.push("email = ?");
            params.push(email);
        }
        
        if updates.is_empty() {
            return Err(anyhow!("No updates provided"));
        }
        
        let query = format!(
            r#"
            UPDATE users 
            SET {}, updated_at = datetime('now')
            WHERE id = ?
            RETURNING id as "id!", name, email, password, created_at as "created_at: DateTime<Utc>", updated_at as "updated_at: DateTime<Utc>"
            "#,
            updates.join(", ")
        );
        
        let mut query = sqlx::query_as::<_, User>(&query);
        
        for param in params {
            query = query.bind(param);
        }
        query = query.bind(user_id);
        
        let updated_user = query.fetch_one(&self.pool).await?;
        Ok(updated_user)
    }

    // Delete user data (right to erasure / right to be forgotten)
    pub async fn delete_user_data(&self, user_id: i64) -> Result<()> {
        info!("Deleting data for user ID: {}", user_id);

        // Start a transaction to ensure atomicity
        let mut tx = self.pool.begin().await?;

        // Delete login history if exists
        match sqlx::query!(
            "DELETE FROM login_history WHERE user_id = ?",
            user_id
        )
        .execute(&mut *tx)
        .await {
            Ok(_) => {},
            Err(_) => {}, // Ignore error if table doesn't exist
        };

        // Delete consents if exists
        match sqlx::query!(
            "DELETE FROM user_consents WHERE user_id = ?",
            user_id
        )
        .execute(&mut *tx)
        .await {
            Ok(_) => {},
            Err(_) => {}, // Ignore error if table doesn't exist
        };

        // Delete consent history if exists
        match sqlx::query!(
            "DELETE FROM consent_history WHERE user_id = ?",
            user_id
        )
        .execute(&mut *tx)
        .await {
            Ok(_) => {},
            Err(_) => {}, // Ignore error if table doesn't exist
        };

        // Delete the user
        sqlx::query!(
            "DELETE FROM users WHERE id = ?",
            user_id
        )
        .execute(&mut *tx)
        .await?;

        // Commit the transaction
        tx.commit().await?;

        Ok(())
    }

    // Get user consent
    pub async fn get_consent(&self, user_id: i64) -> Result<Vec<UserConsent>> {
        info!("Getting consent for user ID: {}", user_id);

        let consents = sqlx::query_as!(
            UserConsent,
            r#"
            SELECT id as "id!", user_id, purpose, granted, timestamp as "timestamp: DateTime<Utc>"
            FROM user_consents 
            WHERE user_id = ?
            ORDER BY timestamp DESC
            "#,
            user_id
        )
        .fetch_all(&self.pool)
        .await?;

        Ok(consents)
    }
    
    // Get user consent history
    pub async fn get_consent_history(&self, user_id: i64) -> Result<Vec<ConsentHistoryRecord>> {
        info!("Getting consent history for user ID: {}", user_id);

        let history = sqlx::query_as!(
            ConsentHistoryRecord,
            r#"
            SELECT id as "id!", user_id, consent_id, purpose, granted, 
                   timestamp as "timestamp: DateTime<Utc>", ip_address, user_agent
            FROM consent_history 
            WHERE user_id = ?
            ORDER BY timestamp DESC
            "#,
            user_id
        )
        .fetch_all(&self.pool)
        .await?;

        Ok(history)
    }

    // Record user consent
    pub async fn record_consent(
        &self, 
        user_id: i64, 
        purpose: &str, 
        granted: bool,
        ip_address: Option<&str>,
        user_agent: Option<&str>
    ) -> Result<()> {
        info!("Recording consent for user ID: {}, purpose: {}, granted: {}", user_id, purpose, granted);

        // Check if the user exists
        let user_exists = sqlx::query!(
            "SELECT id FROM users WHERE id = ?",
            user_id
        )
        .fetch_optional(&self.pool)
        .await?
        .is_some();

        if !user_exists {
            return Err(anyhow!("User not found"));
        }

        // Create the consents table if it doesn't exist
        sqlx::query!(
            r#"
            CREATE TABLE IF NOT EXISTS user_consents (
                id INTEGER PRIMARY KEY,
                user_id INTEGER NOT NULL,
                purpose TEXT NOT NULL,
                granted BOOLEAN NOT NULL,
                timestamp DATETIME NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users (id)
            )
            "#
        )
        .execute(&self.pool)
        .await?;

        // Create the consent history table if it doesn't exist
        sqlx::query!(
            r#"
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
            )
            "#
        )
        .execute(&self.pool)
        .await?;

        // Start a transaction
        let mut tx = self.pool.begin().await?;

        // Check if consent already exists
        let existing_consent = sqlx::query!(
            r#"
            SELECT id FROM user_consents 
            WHERE user_id = ? AND purpose = ?
            "#,
            user_id, purpose
        )
        .fetch_optional(&mut *tx)
        .await?;

        // Type-compatible version: both branches return le même type (Option<i64>)
        let consent_id = if let Some(consent) = existing_consent {
            // Update existing consent
            sqlx::query!(
                r#"
                UPDATE user_consents 
                SET granted = ?, timestamp = datetime('now')
                WHERE id = ?
                "#,
                granted, consent.id
            )
            .execute(&mut *tx)
            .await?;
            consent.id
        } else {
            // Insert new consent
            let result = sqlx::query!(
                r#"
                INSERT INTO user_consents (user_id, purpose, granted, timestamp)
                VALUES (?, ?, ?, datetime('now'))
                RETURNING id
                "#,
                user_id, purpose, granted
            )
            .fetch_one(&mut *tx)
            .await?;
            Some(result.id)
        };

        // Record in consent history
        sqlx::query!(
            r#"
            INSERT INTO consent_history 
            (user_id, consent_id, purpose, granted, ip_address, user_agent)
            VALUES (?, ?, ?, ?, ?, ?)
            "#,
            user_id, consent_id, purpose, granted, ip_address, user_agent
        )
        .execute(&mut *tx)
        .await?;

        // Commit the transaction
        tx.commit().await?;

        Ok(())
    }

    // Record login attempt
    pub async fn record_login_attempt(
        &self, 
        user_id: i64, 
        ip_address: &str, 
        user_agent: &str,
        success: bool
    ) -> Result<()> {
        info!("Recording login attempt for user ID: {}", user_id);

        // Create the login_history table if it doesn't exist
        sqlx::query!(
            r#"
            CREATE TABLE IF NOT EXISTS login_history (
                id INTEGER PRIMARY KEY,
                user_id INTEGER NOT NULL,
                login_timestamp DATETIME NOT NULL,
                ip_address TEXT NOT NULL,
                user_agent TEXT NOT NULL,
                success BOOLEAN NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users (id)
            )
            "#
        )
        .execute(&self.pool)
        .await?;

        // Record the login attempt
        sqlx::query!(
            r#"
            INSERT INTO login_history (user_id, login_timestamp, ip_address, user_agent, success)
            VALUES (?, datetime('now'), ?, ?, ?)
            "#,
            user_id, ip_address, user_agent, success
        )
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    // Helper function to safely extract ID from record
    fn extract_id(record: &sqlx::sqlite::SqliteRow) -> Result<i64> {
        record.try_get("id").map_err(|e| anyhow!("Failed to extract ID: {}", e))
    }

    // Archive inactive users
    pub async fn archive_inactive_users(&self, config: &DataRetentionConfig) -> Result<usize> {
        info!("Archiving inactive users");

        // Calculate the cutoff date
        let cutoff_date = Utc::now() - Duration::days(30 * config.inactive_user_months);
        let retention_end_date = Utc::now() + Duration::days(365 * config.archive_retention_years);

        // Find inactive users
        let inactive_users = sqlx::query!(
            r#"
            SELECT u.id, u.name, u.email, u.created_at, MAX(l.login_timestamp) as last_activity
            FROM users u
            LEFT JOIN login_history l ON u.id = l.user_id
            GROUP BY u.id
            HAVING (last_activity < ? OR last_activity IS NULL) AND u.updated_at < ?
            "#,
            cutoff_date, cutoff_date
        )
        .fetch_all(&self.pool)
        .await?;

        let mut archived_count = 0;

        // Process each inactive user
        for user in inactive_users {
            let mut tx = self.pool.begin().await?;

            // Email is stored as a string directly in SQLite, but it's returned as an Option
            // Handle the case where it might be NULL
            let email_domain = match &user.email {
                Some(email) => email.split('@').last().unwrap_or("unknown"),
                None => "unknown"
            };

            let anonymized_data = json!({
                "original_id": user.id,
                "account_created": user.created_at,
                "last_active": user.last_activity,
                "email_domain": email_domain,
            }).to_string();

            // Create a safe ID string for use in email
            // Use debug formatting for Option<i64>
            let user_id_str = format!("{:?}", user.id);
            let anonymized_email = format!("anonymized_{}@example.com", user_id_str);
            
            // Insert into archived_users
            sqlx::query!(
                r#"
                INSERT INTO archived_users 
                (original_user_id, anonymized_data, archive_reason, archive_date, retention_end_date)
                VALUES (?, ?, 'INACTIVE', datetime('now'), ?)
                "#,
                user.id, anonymized_data, retention_end_date
            )
            .execute(&mut *tx)
            .await?;

            // Delete or anonymize user data
            sqlx::query!(
                r#"
                UPDATE users
                SET name = 'Anonymized User', 
                    email = ?, 
                    password = 'anonymized'
                WHERE id = ?
                "#,
                anonymized_email, user.id
            )
            .execute(&mut *tx)
            .await?;

            tx.commit().await?;
            archived_count += 1;
        }

        info!("Archived {} inactive users", archived_count);
        Ok(archived_count)
    }

    // Clean up expired archived data
    pub async fn clean_expired_archived_data(&self) -> Result<usize> {
        info!("Cleaning up expired archived data");

        let now = Utc::now();
        
        // Find and delete expired archived data
        let result = sqlx::query!(
            r#"
            DELETE FROM archived_users
            WHERE retention_end_date < ?
            "#,
            now
        )
        .execute(&self.pool)
        .await?;

        let deleted_count = result.rows_affected() as usize;
        info!("Deleted {} expired archive records", deleted_count);
        
        Ok(deleted_count)
    }

    // Clean up old consent history
    pub async fn clean_old_consent_history(&self, config: &DataRetentionConfig) -> Result<usize> {
        info!("Cleaning up old consent history");

        let cutoff_date = Utc::now() - Duration::days(365 * config.consent_history_years);
        
        // Delete old consent history
        let result = sqlx::query!(
            r#"
            DELETE FROM consent_history
            WHERE timestamp < ?
            "#,
            cutoff_date
        )
        .execute(&self.pool)
        .await?;

        let deleted_count = result.rows_affected() as usize;
        info!("Deleted {} old consent history records", deleted_count);
        
        Ok(deleted_count)
    }

    // Clean up old login history
    pub async fn clean_old_login_history(&self, config: &DataRetentionConfig) -> Result<usize> {
        info!("Cleaning up old login history");

        let cutoff_date = Utc::now() - Duration::days(30 * config.login_history_months);
        
        // Delete old login history
        let result = sqlx::query!(
            r#"
            DELETE FROM login_history
            WHERE login_timestamp < ?
            "#,
            cutoff_date
        )
        .execute(&self.pool)
        .await?;

        let deleted_count = result.rows_affected() as usize;
        info!("Deleted {} old login history records", deleted_count);
        
        Ok(deleted_count)
    }

    // Run all data retention tasks
    pub async fn run_data_retention_tasks(&self, config: &DataRetentionConfig) -> Result<()> {
        // Archive inactive users
        let archived_count = self.archive_inactive_users(config).await?;
        
        // Clean up expired archived data
        let expired_archives_deleted = self.clean_expired_archived_data().await?;
        
        // Clean up old consent history
        let consent_records_deleted = self.clean_old_consent_history(config).await?;
        
        // Clean up old login history
        let login_records_deleted = self.clean_old_login_history(config).await?;
        
        info!(
            "Data retention tasks completed: {} users archived, {} expired archives deleted, {} consent records deleted, {} login records deleted",
            archived_count, expired_archives_deleted, consent_records_deleted, login_records_deleted
        );
        
        Ok(())
    }
} 