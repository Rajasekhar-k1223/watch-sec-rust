use serde_json::json;
use std::fs;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

pub fn perform_audit() -> serde_json::Value {
    let mut passed_checks = 0;
    let mut failed_checks = 0;
    let mut details = Vec::<serde_json::Value>::new();

    // 1. Check if /etc/shadow is locked down (CIS Baseline)
    #[cfg(unix)]
    if let Ok(metadata) = fs::metadata("/etc/shadow") {
        let mode = metadata.permissions().mode() & 0o777;
        if mode == 0o600 || mode == 0o000 {
            passed_checks += 1;
            details.push(json!({"Check": "File permissions on /etc/shadow", "Status": "Pass", "Details": format!("{:o}", mode)}));
        } else {
            failed_checks += 1;
            details.push(json!({"Check": "File permissions on /etc/shadow", "Status": "Fail", "Details": format!("Expected 600 or 000, got {:o}", mode)}));
        }
    }
    #[cfg(not(unix))]
    { details.push(json!({"Check": "File permissions on /etc/shadow", "Status": "N/A", "Details": "Not applicable on this OS"})); }


    // 2. Check if root login is disabled in SSH (CIS Baseline)
    if let Ok(content) = fs::read_to_string("/etc/ssh/sshd_config") {
        if content.contains("PermitRootLogin no") && !content.contains("#PermitRootLogin no") {
            passed_checks += 1;
            details.push(json!({"Check": "SSH PermitRootLogin", "Status": "Pass"}));
        } else {
            failed_checks += 1;
            details.push(json!({"Check": "SSH PermitRootLogin", "Status": "Fail", "Details": "PermitRootLogin no is missing or commented out"}));
        }
    } else {
        // Not a failure if SSH isn't installed, but we'll mark as NA
        details.push(json!({"Check": "SSH PermitRootLogin", "Status": "N/A", "Details": "sshd_config not found"}));
    }

    let score = if (passed_checks + failed_checks) > 0 {
        (passed_checks as f64 / (passed_checks + failed_checks) as f64) * 100.0
    } else {
        100.0
    };

    println!("[CIS Audit] Completed scan. Score: {:.1}%", score);

    json!({
        "EventType": "CISAuditReport",
        "Score": score,
        "Passed": passed_checks,
        "Failed": failed_checks,
        "Details": details
    })
}
