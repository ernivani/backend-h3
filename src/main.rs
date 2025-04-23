mod auth;
mod models;
mod routes;
mod gdpr;
mod breach_detection;

use actix_web::{web, App, HttpServer};
use actix_cors::Cors;
use sqlx::sqlite::SqlitePoolOptions;
use std::sync::Arc;
use auth::AuthService;
use gdpr::{GdprService, DataRetentionConfig};
use breach_detection::BreachDetectionService;
use sqlx::SqlitePool;
use std::time::Duration;
use log::{info, error};
use tokio::task;
use tokio::time::sleep;

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    env_logger::init();
    dotenv::dotenv().ok();

    // Debug initialization
    #[cfg(debug_assertions)]
    routes::init();

    // Setup database connection
    let pool = SqlitePool::connect("sqlite:data.db").await.expect("Failed to connect to database");
    
    // Run migrations to ensure all tables exist
    println!("Running database migrations...");
    sqlx::migrate!("./migrations")
        .run(&pool)
        .await
        .expect("Failed to run migrations");
    println!("Migrations completed successfully");
    
    // Create services with DB connection
    let auth_service = Arc::new(AuthService::new(pool.clone()));
    let gdpr_service = Arc::new(GdprService::new(pool.clone()));
    let breach_service = Arc::new(BreachDetectionService::new(pool.clone()));
    
    // Start background task for data retention
    let retention_service = gdpr_service.clone();
    task::spawn(async move {
        // Load configuration (could also be loaded from a config file or database)
        let config = DataRetentionConfig::default();
        
        // Run every 24 hours
        loop {
            sleep(Duration::from_secs(24 * 60 * 60)).await;
            info!("Running scheduled data retention tasks");
            
            match retention_service.run_data_retention_tasks(&config).await {
                Ok(_) => info!("Data retention tasks completed successfully"),
                Err(e) => error!("Error running data retention tasks: {}", e),
            }
        }
    });

    HttpServer::new(move || {
        let cors = Cors::default()
            .allowed_origin("http://localhost:5173")
            .allowed_methods(vec!["GET", "POST", "PUT", "DELETE"])
            .allowed_headers(vec!["Authorization", "Content-Type"])
            .supports_credentials()
            .max_age(3600);

        App::new()
            .wrap(cors)
            .app_data(web::Data::new(auth_service.clone()))
            .app_data(web::Data::new(gdpr_service.clone()))
            .app_data(web::Data::new(breach_service.clone()))
            .configure(routes::user_routes::config)
            .configure(routes::gdpr_routes::config)
            .configure(routes::breach_routes::config)
    })
    .bind("127.0.0.1:8000")?
    .run()
    .await
}
