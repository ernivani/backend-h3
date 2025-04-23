use actix_web::{web, HttpResponse, HttpRequest};
use crate::gdpr::{GdprService, DataRetentionConfig};
use crate::auth::AuthService;
use crate::models::User;
use actix_web::error::ErrorUnauthorized;
use serde::Deserialize;
use std::sync::Arc;
use log::info;

#[derive(Deserialize)]
pub struct ConsentInput {
    purpose: String,
    granted: bool,
}

#[derive(Deserialize)]
pub struct DataRetentionInput {
    inactive_user_months: Option<i64>,
    archive_retention_years: Option<i64>,
    consent_history_years: Option<i64>,
    login_history_months: Option<i64>,
}

pub fn config(cfg: &mut web::ServiceConfig) {
    // Add logging to help debug route registration
    info!("Configuring GDPR routes at /api/gdpr");
    
    cfg.service(
        web::scope("/gdpr")
            .route("/export", web::get().to(export_user_data))
            .route("/consent", web::post().to(record_consent))
            .route("/consent", web::get().to(get_consent))
            .route("/consent/history", web::get().to(get_consent_history))
            .route("/delete", web::delete().to(delete_user_data))
            .route("/retention", web::post().to(run_data_retention))
            .route("/retention/config", web::get().to(get_retention_config))
            .route("/health", web::get().to(health_check))
    );
}

async fn extract_user_and_client_info(
    req: &HttpRequest,
    auth_service: &Arc<AuthService>,
) -> Result<(User, String, String), actix_web::Error> {
    // Extract the authorization token
    let auth_header = req
        .headers()
        .get("Authorization")
        .and_then(|h| h.to_str().ok())
        .and_then(|h| h.strip_prefix("Bearer "))
        .ok_or_else(|| ErrorUnauthorized("No authorization token provided"))?;

    // Validate the token and get user
    let user = auth_service
        .validate_token(auth_header)
        .await
        .map_err(|e| ErrorUnauthorized(e.to_string()))?;

    // Extract IP address and user agent
    let ip = req.connection_info().realip_remote_addr()
        .unwrap_or("unknown")
        .to_string();
    
    let user_agent = req
        .headers()
        .get("User-Agent")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("unknown")
        .to_string();

    Ok((user, ip, user_agent))
}

// GDPR Right to Access - Allow users to export their data
async fn export_user_data(
    req: HttpRequest,
    auth_service: web::Data<Arc<AuthService>>,
    gdpr_service: web::Data<Arc<GdprService>>,
) -> Result<HttpResponse, actix_web::Error> {
    info!("Request to export user data received");
    
    let (user, ip, user_agent) = extract_user_and_client_info(&req, &auth_service).await?;
    
    // Record the data access attempt for transparency
    if let Err(e) = gdpr_service.record_login_attempt(user.id, &ip, &user_agent, true).await {
        info!("Failed to record login attempt: {}", e);
        // Continue even if recording fails
    }

    match gdpr_service.export_user_data(user.id).await {
        Ok(data) => Ok(HttpResponse::Ok().json(data)),
        Err(e) => Ok(HttpResponse::InternalServerError().body(e.to_string())),
    }
}

// GDPR Consent Management
async fn get_consent(
    req: HttpRequest,
    gdpr_service: web::Data<Arc<GdprService>>,
    auth_service: web::Data<Arc<AuthService>>,
) -> Result<HttpResponse, actix_web::Error> {
    info!("Request to get consent received");

    let (user, _, _) = extract_user_and_client_info(&req, &auth_service).await?;
    
    match gdpr_service.get_consent(user.id).await {
        Ok(consent) => Ok(HttpResponse::Ok().json(consent)),
        Err(e) => Ok(HttpResponse::InternalServerError().body(e.to_string())),
    }
}

// Get user consent history
async fn get_consent_history(
    req: HttpRequest,
    gdpr_service: web::Data<Arc<GdprService>>,
    auth_service: web::Data<Arc<AuthService>>,
) -> Result<HttpResponse, actix_web::Error> {
    info!("Request to get consent history received");

    let (user, _, _) = extract_user_and_client_info(&req, &auth_service).await?;
    
    match gdpr_service.get_consent_history(user.id).await {
        Ok(history) => Ok(HttpResponse::Ok().json(history)),
        Err(e) => Ok(HttpResponse::InternalServerError().body(e.to_string())),
    }
}

async fn record_consent(
    req: HttpRequest,
    gdpr_service: web::Data<Arc<GdprService>>,
    auth_service: web::Data<Arc<AuthService>>,
    consent_data: web::Json<ConsentInput>,
) -> Result<HttpResponse, actix_web::Error> {
    info!("Request to record consent received for purpose: {}", consent_data.purpose);
    
    let (user, ip, user_agent) = extract_user_and_client_info(&req, &auth_service).await?;
    
    match gdpr_service
        .record_consent(
            user.id, 
            &consent_data.purpose, 
            consent_data.granted,
            Some(&ip),
            Some(&user_agent)
        )
        .await
    {
        Ok(_) => Ok(HttpResponse::Ok().json(serde_json::json!({
            "status": "success",
            "message": "Consent recorded successfully"
        }))),
        Err(e) => Ok(HttpResponse::InternalServerError().body(e.to_string())),
    }
}

// GDPR Right to Erasure (Right to be Forgotten)
async fn delete_user_data(
    req: HttpRequest,
    gdpr_service: web::Data<Arc<GdprService>>,
    auth_service: web::Data<Arc<AuthService>>,
) -> Result<HttpResponse, actix_web::Error> {
    info!("Request to delete user data received");
    
    let (user, _, _) = extract_user_and_client_info(&req, &auth_service).await?;
    
    match gdpr_service.delete_user_data(user.id).await {
        Ok(_) => Ok(HttpResponse::Ok().json(serde_json::json!({
            "status": "success",
            "message": "User data successfully deleted"
        }))),
        Err(e) => Ok(HttpResponse::InternalServerError().body(e.to_string())),
    }
}

// Run data retention tasks (admin only)
async fn run_data_retention(
    req: HttpRequest,
    gdpr_service: web::Data<Arc<GdprService>>,
    auth_service: web::Data<Arc<AuthService>>,
    config_input: Option<web::Json<DataRetentionInput>>,
) -> Result<HttpResponse, actix_web::Error> {
    info!("Request to run data retention tasks received");
    
    let (user, _, _) = extract_user_and_client_info(&req, &auth_service).await?;
    
    // In a real app, we would check if the user is an admin
    // For simplicity, we'll just log who triggered this
    info!("User {} triggered data retention tasks", user.id);
    
    // Configure data retention
    let mut config = DataRetentionConfig::default();
    
    if let Some(input) = config_input {
        if let Some(months) = input.inactive_user_months {
            config.inactive_user_months = months;
        }
        if let Some(years) = input.archive_retention_years {
            config.archive_retention_years = years;
        }
        if let Some(years) = input.consent_history_years {
            config.consent_history_years = years;
        }
        if let Some(months) = input.login_history_months {
            config.login_history_months = months;
        }
    }
    
    match gdpr_service.run_data_retention_tasks(&config).await {
        Ok(_) => Ok(HttpResponse::Ok().json(serde_json::json!({
            "status": "success",
            "message": "Data retention tasks executed successfully"
        }))),
        Err(e) => Ok(HttpResponse::InternalServerError().body(e.to_string())),
    }
}

// Get current data retention configuration
async fn get_retention_config() -> HttpResponse {
    let config = DataRetentionConfig::default();
    
    HttpResponse::Ok().json(config)
}

// Simple health check endpoint to test connectivity
async fn health_check() -> HttpResponse {
    info!("GDPR Health check called");
    println!("GDPR Health check was called - endpoint is working");
    HttpResponse::Ok().json(serde_json::json!({
        "status": "ok",
        "message": "GDPR API is working correctly",
        "debug": "This endpoint is working fine"
    }))
} 