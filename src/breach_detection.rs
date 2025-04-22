use chrono::{DateTime, Utc, Duration};
use sqlx::SqlitePool;
use serde::{Deserialize, Serialize};
use std::fs::File;
use std::io::Write;
use log::info;

// Suspicious activity thresholds
const MAX_FAILED_LOGINS: i64 = 5;
const UNUSUAL_ACTIVITY_TIMEFRAME_HOURS: i64 = 24;
const UNUSUAL_DATA_EXPORT_THRESHOLD: i64 = 3;

#[derive(Debug, Serialize, Deserialize)]
pub struct BreachReport {
    pub timestamp: DateTime<Utc>,
    pub incident_type: String,
    pub description: String,
    pub affected_users: Vec<i64>,
    pub data_categories: Vec<String>,
    pub severity: String,
    pub recommended_actions: Vec<String>,
    pub needs_notification: bool,
}

pub struct BreachDetectionService {
    pool: SqlitePool,
}

impl BreachDetectionService {
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }

    // Main method to run breach detection
    pub async fn detect_breaches(&self) -> Result<Vec<BreachReport>, anyhow::Error> {
        info!("Starting breach detection scan");
        let mut reports = Vec::new();

        // Run different detection strategies
        let failed_login_reports = self.detect_failed_logins().await?;
        let unusual_export_reports = self.detect_unusual_data_exports().await?;
        let unusual_admin_reports = self.detect_unusual_admin_activity().await?;

        reports.extend(failed_login_reports);
        reports.extend(unusual_export_reports);
        reports.extend(unusual_admin_reports);

        // If any high severity breaches are found, save a detailed report
        for report in &reports {
            if report.severity == "high" {
                self.save_breach_report(report).await?;
            }
        }

        info!("Breach detection completed. Found {} potential incidents", reports.len());
        Ok(reports)
    }

    // Detect multiple failed login attempts for the same user
    async fn detect_failed_logins(&self) -> Result<Vec<BreachReport>, anyhow::Error> {
        info!("Checking for suspicious failed login patterns");
        let mut reports = Vec::new();

        // Get timestamp for lookback period
        let lookback_time = Utc::now() - Duration::hours(UNUSUAL_ACTIVITY_TIMEFRAME_HOURS);

        // Query for users with multiple failed login attempts
        let query_result = sqlx::query!(
            r#"
            SELECT user_id, COUNT(*) as failed_count 
            FROM login_history 
            WHERE success = 0 AND login_timestamp > ? 
            GROUP BY user_id 
            HAVING COUNT(*) >= ?
            "#,
            lookback_time,
            MAX_FAILED_LOGINS
        )
        .fetch_all(&self.pool)
        .await;

        match query_result {
            Ok(rows) => {
                for row in rows {
                    let user_id = row.user_id;
                    let failed_count = row.failed_count;

                    // Get the IP addresses used in these attempts
                    let ip_addresses = sqlx::query!(
                        r#"
                        SELECT DISTINCT ip_address
                        FROM login_history
                        WHERE user_id = ? AND success = 0 AND login_timestamp > ?
                        "#,
                        user_id,
                        lookback_time
                    )
                    .fetch_all(&self.pool)
                    .await?;

                    let ips: Vec<String> = ip_addresses
                        .iter()
                        .map(|row| row.ip_address.clone())
                        .collect();

                    // Create a breach report
                    let severity = if failed_count > MAX_FAILED_LOGINS * 2 {
                        "high"
                    } else {
                        "medium"
                    };

                    let report = BreachReport {
                        timestamp: Utc::now(),
                        incident_type: "failed_login_attempts".to_string(),
                        description: format!(
                            "Multiple failed login attempts ({}) detected for user ID {} from {} different IP addresses",
                            failed_count,
                            user_id,
                            ips.len()
                        ),
                        affected_users: vec![user_id],
                        data_categories: vec!["authentication_credentials".to_string()],
                        severity: severity.to_string(),
                        recommended_actions: vec![
                            "Lock the account temporarily".to_string(),
                            "Notify the user of suspicious activity".to_string(),
                            "Review IP addresses for potential malicious origin".to_string(),
                        ],
                        needs_notification: severity == "high",
                    };

                    reports.push(report);
                }
            }
            Err(e) => {
                if let sqlx::Error::Database(db_err) = &e {
                    // Table might not exist yet - that's fine
                    if db_err.message().contains("no such table") {
                        info!("Login history table does not exist yet");
                        return Ok(Vec::new());
                    }
                }
                // Other errors should be propagated
                return Err(e.into());
            }
        }

        Ok(reports)
    }

    // Detect unusual data export activity
    async fn detect_unusual_data_exports(&self) -> Result<Vec<BreachReport>, anyhow::Error> {
        info!("Checking for unusual data export activity");
        let mut reports = Vec::new();

        // For simplicity, we'll assume data exports are tracked in the login_history table
        // with a certain user_agent format or pattern that indicates data export activity
        let lookback_time = Utc::now() - Duration::hours(UNUSUAL_ACTIVITY_TIMEFRAME_HOURS);

        let query_result = sqlx::query!(
            r#"
            SELECT user_id, COUNT(*) as export_count 
            FROM login_history 
            WHERE user_agent LIKE '%export%' AND login_timestamp > ? 
            GROUP BY user_id 
            HAVING COUNT(*) >= ?
            "#,
            lookback_time,
            UNUSUAL_DATA_EXPORT_THRESHOLD
        )
        .fetch_all(&self.pool)
        .await;

        match query_result {
            Ok(rows) => {
                for row in rows {
                    let user_id = row.user_id;
                    let export_count = row.export_count;

                    // Create a breach report
                    let report = BreachReport {
                        timestamp: Utc::now(),
                        incident_type: "unusual_data_export".to_string(),
                        description: format!(
                            "Unusual number of data exports ({}) detected for user ID {}",
                            export_count, user_id
                        ),
                        affected_users: vec![user_id],
                        data_categories: vec!["personal_data".to_string(), "user_account_data".to_string()],
                        severity: "medium".to_string(),
                        recommended_actions: vec![
                            "Review account activity for suspicious patterns".to_string(),
                            "Contact user to verify the exports were intentional".to_string(),
                        ],
                        needs_notification: false,
                    };

                    reports.push(report);
                }
            }
            Err(e) => {
                if let sqlx::Error::Database(db_err) = &e {
                    // Table might not exist yet - that's fine
                    if db_err.message().contains("no such table") {
                        info!("Login history table does not exist yet");
                        return Ok(Vec::new());
                    }
                }
                // Other errors should be propagated
                return Err(e.into());
            }
        }

        Ok(reports)
    }

    // Detect unusual admin activity (example only - extend this based on your app structure)
    async fn detect_unusual_admin_activity(&self) -> Result<Vec<BreachReport>, anyhow::Error> {
        // In a real app, you would have logging of admin actions in a table
        // For this example, we'll just return an empty vector
        Ok(Vec::new())
    }

    // Save breach report to file (in a real system, you might send to a SIEM or security team)
    async fn save_breach_report(&self, report: &BreachReport) -> Result<(), anyhow::Error> {
        let filename = format!(
            "breach_report_{}.json",
            report.timestamp.format("%Y%m%d_%H%M%S")
        );

        info!("Saving breach report to {}", filename);
        
        let report_json = serde_json::to_string_pretty(report)?;
        let mut file = File::create(&filename)?;
        file.write_all(report_json.as_bytes())?;

        // For high severity incidents that require notification
        if report.severity == "high" && report.needs_notification {
            self.prepare_notification(report).await?;
        }

        Ok(())
    }

    // Prepare notifications for affected users and authorities (GDPR requirement)
    async fn prepare_notification(&self, report: &BreachReport) -> Result<(), anyhow::Error> {
        info!("Preparing breach notifications for incident: {}", report.incident_type);
        
        // In a real implementation, this would:
        // 1. Prepare email templates for users
        // 2. Prepare CNIL notification if needed
        // 3. Document the incident for regulatory compliance
        
        // For demonstration purposes, we'll just create a notification plan file
        let filename = format!(
            "breach_notification_plan_{}.txt",
            report.timestamp.format("%Y%m%d_%H%M%S")
        );
        
        let mut file = File::create(&filename)?;
        
        let notification_content = format!(
            "GDPR DATA BREACH NOTIFICATION PLAN\n\n\
             Incident timestamp: {}\n\
             Incident type: {}\n\
             Description: {}\n\
             Affected users: {:?}\n\
             Data categories involved: {:?}\n\
             Severity: {}\n\n\
             NOTIFICATION TO USERS:\n\
             - All affected users will be notified within 72 hours\n\
             - Notification will include nature of the breach and recommended actions\n\n\
             NOTIFICATION TO AUTHORITIES:\n\
             - CNIL will be notified within the mandated 72 hour timeframe\n\
             - Full incident report and remediation plan will be included\n\n\
             REMEDIATION ACTIONS:\n{}\n",
            report.timestamp,
            report.incident_type,
            report.description,
            report.affected_users,
            report.data_categories,
            report.severity,
            report.recommended_actions.join("\n- ")
        );
        
        file.write_all(notification_content.as_bytes())?;
        info!("Notification plan saved to {}", filename);
        
        Ok(())
    }
} 