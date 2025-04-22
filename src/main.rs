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
use gdpr::GdprService;
use breach_detection::BreachDetectionService;

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    env_logger::init();
    dotenv::dotenv().ok();

    // Debug initialization
    #[cfg(debug_assertions)]
    routes::init();

    let database_url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "sqlite:data.db".to_string());

    let pool = SqlitePoolOptions::new()
        .max_connections(5)
        .connect(&database_url)
        .await
        .expect("Failed to create pool");

    let auth_service = Arc::new(AuthService::new(pool.clone()));
    let gdpr_service = Arc::new(GdprService::new(pool.clone()));
    let breach_service = Arc::new(BreachDetectionService::new(pool.clone()));

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
