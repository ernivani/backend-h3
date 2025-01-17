use actix_web::{web, HttpResponse, Responder, HttpRequest};
use crate::auth::AuthService;
use crate::models::{LoginCredentials, RegisterCredentials, User};
use actix_web::error::ErrorUnauthorized;
use anyhow::Result;
use std::sync::Arc;

pub fn config(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/api")
            .service(
                web::scope("/auth")
                    .route("/register", web::post().to(register))
                    .route("/login", web::post().to(login))
            )
            .service(
                web::scope("/users")
                    .route("/me", web::get().to(get_current_user))
                    .route("/me", web::put().to(update_current_user))
            )
    );
}

async fn register(
    auth_service: web::Data<Arc<AuthService>>,
    credentials: web::Json<RegisterCredentials>,
) -> impl Responder {
    match auth_service.register(credentials.into_inner()).await {
        Ok(response) => HttpResponse::Ok().json(response),
        Err(e) => HttpResponse::BadRequest().body(e.to_string()),
    }
}

async fn login(
    auth_service: web::Data<Arc<AuthService>>,
    credentials: web::Json<LoginCredentials>,
) -> impl Responder {
    match auth_service.login(credentials.into_inner()).await {
        Ok(response) => HttpResponse::Ok().json(response),
        Err(e) => HttpResponse::Unauthorized().body(e.to_string()),
    }
}

async fn get_current_user(
    req: HttpRequest,
    auth_service: web::Data<Arc<AuthService>>,
) -> Result<HttpResponse, actix_web::Error> {
    let user = extract_user(&req, &auth_service).await?;
    Ok(HttpResponse::Ok().json(user))
}

async fn update_current_user(
    req: HttpRequest,
    auth_service: web::Data<Arc<AuthService>>,
    update_data: web::Json<UpdateUserData>,
) -> Result<HttpResponse, actix_web::Error> {
    let user = extract_user(&req, &auth_service).await?;
    
    match auth_service
        .update_user(user.id, update_data.name.clone(), update_data.email.clone())
        .await
    {
        Ok(updated_user) => Ok(HttpResponse::Ok().json(updated_user)),
        Err(e) => Ok(HttpResponse::BadRequest().body(e.to_string())),
    }
}

#[derive(serde::Deserialize)]
struct UpdateUserData {
    name: Option<String>,
    email: Option<String>,
}

async fn extract_user(
    req: &HttpRequest,
    auth_service: &Arc<AuthService>,
) -> Result<User, actix_web::Error> {
    let auth_header = req
        .headers()
        .get("Authorization")
        .and_then(|h| h.to_str().ok())
        .and_then(|h| h.strip_prefix("Bearer "))
        .ok_or_else(|| ErrorUnauthorized("No authorization token provided"))?;

    auth_service
        .validate_token(auth_header)
        .await
        .map_err(|e| ErrorUnauthorized(e.to_string()))
} 