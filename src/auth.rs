use crate::models::{AuthResponse, LoginCredentials, RegisterCredentials, User};
use anyhow::{Result, anyhow};
use bcrypt::{hash, verify, DEFAULT_COST};
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;
use std::env;
use chrono::{DateTime, Duration, Utc};
use log::{error, info};

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    sub: i64, // user id
    exp: i64, // expiration timestamp
    updated_at: i64, // user's last update timestamp
}

pub struct AuthService {
    pool: SqlitePool,
}

impl AuthService {
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }

    pub async fn register(&self, creds: RegisterCredentials) -> Result<AuthResponse> {
        // Check if user already exists
        let existing_user = sqlx::query!(
            "SELECT id FROM users WHERE email = ?",
            creds.email
        )
        .fetch_optional(&self.pool)
        .await?;

        if existing_user.is_some() {
            error!("User with email {} already exists", creds.email);
            return Err(anyhow!("User already exists"));
        }

        let hashed_password = hash(creds.password.as_bytes(), DEFAULT_COST)?;
        
        info!("Creating new user with email: {}", creds.email);
        let user = sqlx::query_as!(
            User,
            r#"
            INSERT INTO users (name, email, password, created_at, updated_at)
            VALUES (?, ?, ?, datetime('now'), datetime('now'))
            RETURNING id as "id!", name, email, password, created_at as "created_at: DateTime<Utc>", updated_at as "updated_at: DateTime<Utc>"
            "#,
            creds.name,
            creds.email,
            hashed_password
        )
        .fetch_one(&self.pool)
        .await?;

        let token = self.create_token(&user)?;
        info!("User registered successfully: {}", user.email);
        Ok(AuthResponse { token, user })
    }

    pub async fn login(&self, creds: LoginCredentials) -> Result<AuthResponse> {
        info!("Attempting login for user: {}", creds.email);
        
        let user = sqlx::query_as!(
            User,
            r#"
            SELECT id as "id!", name, email, password, created_at as "created_at: DateTime<Utc>", updated_at as "updated_at: DateTime<Utc>"
            FROM users 
            WHERE email = ?
            "#,
            creds.email
        )
        .fetch_optional(&self.pool)
        .await?
        .ok_or_else(|| {
            error!("User not found: {}", creds.email);
            anyhow!("Invalid email or password")
        })?;

        if !verify(creds.password.as_bytes(), &user.password)? {
            error!("Invalid password for user: {}", creds.email);
            return Err(anyhow!("Invalid email or password"));
        }

        let token = self.create_token(&user)?;
        info!("User logged in successfully: {}", user.email);
        Ok(AuthResponse { token, user })
    }

    pub async fn validate_token(&self, token: &str) -> Result<User> {
        let secret = env::var("JWT_SECRET")
            .unwrap_or_else(|_| "your_secret_key_here".to_string());
        
        let claims = decode::<Claims>(
            token,
            &DecodingKey::from_secret(secret.as_bytes()),
            &Validation::default()
        )?.claims;

        let user = sqlx::query_as!(
            User,
            r#"
            SELECT id as "id!", name, email, password, created_at as "created_at: DateTime<Utc>", updated_at as "updated_at: DateTime<Utc>"
            FROM users 
            WHERE id = ?
            "#,
            claims.sub
        )
        .fetch_optional(&self.pool)
        .await?
        .ok_or_else(|| anyhow!("User not found"))?;

        // Check if user has been updated since token was issued
        if user.updated_at.timestamp() != claims.updated_at {
            return Err(anyhow!("Token invalid: user has been updated"));
        }

        Ok(user)
    }

    fn create_token(&self, user: &User) -> Result<String> {
        let expiration = Utc::now()
            .checked_add_signed(Duration::hours(24))
            .expect("valid timestamp")
            .timestamp();

        let claims = Claims {
            sub: user.id,
            exp: expiration,
            updated_at: user.updated_at.timestamp(),
        };

        let token = encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret(
                env::var("JWT_SECRET")
                    .unwrap_or_else(|_| "your_secret_key_here".to_string())
                    .as_bytes(),
            ),
        )?;

        Ok(token)
    }

    pub async fn update_user(&self, user_id: i64, name: Option<String>, email: Option<String>) -> Result<User> {
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
} 