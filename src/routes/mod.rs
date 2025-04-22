pub mod user_routes;
pub mod gdpr_routes;
pub mod breach_routes;

// Debug log to check that this module is being loaded
#[cfg(debug_assertions)]
pub fn init() {
    println!("Routes module initialized");
    println!("GDPR routes should be available at /api/gdpr");
} 