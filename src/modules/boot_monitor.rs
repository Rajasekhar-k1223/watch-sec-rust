use serde_json::json;
use std::fs;

pub fn audit_boot() -> serde_json::Value {
    let mut uptime_seconds = 0.0;
    
    // Parse /proc/uptime
    if let Ok(content) = fs::read_to_string("/proc/uptime") {
        if let Some(uptime_str) = content.split_whitespace().next() {
            uptime_seconds = uptime_str.parse().unwrap_or(0.0);
        }
    }

    // Try systemd-analyze
    let mut systemd_report = "systemd-analyze not available".to_string();
    if let Ok(output) = crate::hidden_command!("systemd-analyze").output() {
        if output.status.success() {
            systemd_report = String::from_utf8_lossy(&output.stdout).trim().to_string();
        }
    }

    json!({
        "EventType": "SystemBootReport",
        "UptimeSeconds": uptime_seconds,
        "SystemdAnalyze": systemd_report
    })
}
