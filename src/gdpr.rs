use sqlx::SqlitePool;
use anyhow::{Result, anyhow};
use chrono::{DateTime, Utc};
use log::info;
use serde::{Deserialize, Serialize};

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

        Ok(UserDataExport {
            user,
            login_history,
            data_processing_consents,
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
    
    

    // Record user consent
    pub async fn record_consent(&self, user_id: i64, purpose: &str, granted: bool) -> Result<()> {
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

        // Record the consent
        sqlx::query!(
            r#"
            INSERT INTO user_consents (user_id, purpose, granted, timestamp)
            VALUES (?, ?, ?, datetime('now'))
            "#,
            user_id,
            purpose,
            granted
        )
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    // Create login history table and record function - for tracking data access
    pub async fn record_login_attempt(
        &self, 
        user_id: i64, 
        ip_address: &str, 
        user_agent: &str,
        success: bool
    ) -> Result<()> {
        // Create the login history table if it doesn't exist
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
            user_id,
            ip_address,
            user_agent,
            success
        )
        .execute(&self.pool)
        .await?;

        Ok(())
    }
} 