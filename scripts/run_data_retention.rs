use backend_h3::gdpr::{GdprService, DataRetentionConfig};
use sqlx::SqlitePool;
use std::error::Error;
use log::info;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    env_logger::init();
    dotenv::dotenv().ok();
    
    // Connect to database
    let database_url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "sqlite:data.db".to_string());
    
    info!("Connecting to database at {}", database_url);
    let pool = SqlitePool::connect(&database_url).await?;
    
    // Initialize GDPR service
    let gdpr_service = GdprService::new(pool);
    
    // Load configuration (could also be loaded from a config file or database)
    let config = DataRetentionConfig::default();
    
    info!("Running data retention tasks with configuration:");
    info!("- Inactive user months: {}", config.inactive_user_months);
    info!("- Archive retention years: {}", config.archive_retention_years);
    info!("- Consent history years: {}", config.consent_history_years);
    info!("- Login history months: {}", config.login_history_months);
    
    // Run all data retention tasks
    gdpr_service.run_data_retention_tasks(&config).await?;
    
    info!("Data retention tasks completed successfully");
    Ok(())
} 