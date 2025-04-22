use actix_web::{web, HttpResponse, HttpRequest};
use crate::breach_detection::BreachDetectionService;
use crate::auth::AuthService;
use actix_web::error::ErrorUnauthorized;
use std::sync::Arc;
use log::info;

pub fn config(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/api/security")
            .route("/scan", web::post().to(run_breach_scan))
    );
}

// This route is for admin use only and requires authorization
async fn run_breach_scan(
    req: HttpRequest,
    auth_service: web::Data<Arc<AuthService>>,
    breach_service: web::Data<Arc<BreachDetectionService>>,
) -> Result<HttpResponse, actix_web::Error> {
    // Verify authorization
    let auth_header = req
        .headers()
        .get("Authorization")
        .and_then(|h| h.to_str().ok())
        .and_then(|h| h.strip_prefix("Bearer "))
        .ok_or_else(|| ErrorUnauthorized("No authorization token provided"))?;

    let _user = auth_service
        .validate_token(auth_header)
        .await
        .map_err(|e| ErrorUnauthorized(e.to_string()))?;

    // In a real app, you would check if the user has admin privileges
    // For now, we'll allow any authenticated user to trigger the scan

    info!("Starting breach detection scan");
    match breach_service.detect_breaches().await {
        Ok(reports) => {
            let response = serde_json::json!({
                "status": "success",
                "message": format!("Scan completed. Found {} potential incidents", reports.len()),
                "reports": reports
            });
            Ok(HttpResponse::Ok().json(response))
        },
        Err(e) => {
            let error_msg = e.to_string();
            Ok(HttpResponse::InternalServerError().json(serde_json::json!({
                "status": "error",
                "message": format!("Failed to run breach scan: {}", error_msg)
            })))
        }
    }
} 