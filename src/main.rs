use actix_web::{web, App, HttpServer, HttpResponse, Responder};
use actix_cors::Cors;
use sqlx::sqlite::SqlitePoolOptions;
use std::env;
use log::{error, info};
use serde_json::json;

mod models;
mod auth;

use auth::AuthService;
use models::{LoginCredentials, RegisterCredentials};

async fn register(
    auth_service: web::Data<AuthService>,
    credentials: web::Json<RegisterCredentials>,
) -> impl Responder {
    info!("Received registration request for: {}", credentials.email);
    match auth_service.register(credentials.0).await {
        Ok(response) => {
            info!("Registration successful for: {}", response.user.email);
            HttpResponse::Ok().json(response)
        },
        Err(e) => {
            error!("Registration failed: {}", e);
            HttpResponse::BadRequest().json(json!({
                "error": e.to_string()
            }))
        }
    }
}

async fn login(
    auth_service: web::Data<AuthService>,
    credentials: web::Json<LoginCredentials>,
) -> impl Responder {
    info!("Received login request for: {}", credentials.email);
    match auth_service.login(credentials.0).await {
        Ok(response) => {
            info!("Login successful for: {}", response.user.email);
            HttpResponse::Ok().json(response)
        },
        Err(e) => {
            error!("Login failed: {}", e);
            HttpResponse::Unauthorized().json(json!({
                "error": e.to_string()
            }))
        }
    }
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    dotenv::dotenv().ok();
    env_logger::init();

    let database_url = env::var("DATABASE_URL").expect("DATABASE_URL must be set");
    info!("Connecting to database: {}", database_url);
    
    let pool = SqlitePoolOptions::new()
        .max_connections(5)
        .connect(&database_url)
        .await
        .expect("Failed to create pool");

    info!("Running database migrations");
    sqlx::migrate!()
        .run(&pool)
        .await
        .expect("Failed to run migrations");

    let auth_service = web::Data::new(AuthService::new(pool));
    info!("Starting server at http://127.0.0.1:8080");

    HttpServer::new(move || {
        let cors = Cors::default()
            .allow_any_origin()
            .allow_any_method()
            .allow_any_header()
            .max_age(3600);

        App::new()
            .wrap(cors)
            .app_data(auth_service.clone())
            .service(
                web::scope("/api")
                    .route("/register", web::post().to(register))
                    .route("/login", web::post().to(login))
            )
    })
    .bind("127.0.0.1:8080")?
    .run()
    .await
}
