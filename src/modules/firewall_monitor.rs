use std::process::Command;
use serde_json::json;

pub fn check_firewall_status() -> serde_json::Value {
    let mut fw_enabled = false;
    let mut details = String::new();

    #[cfg(unix)]
    {
        // Try ufw
        if let Ok(output) = crate::hidden_command!("ufw").arg("status").output() {
            let stdout = String::from_utf8_lossy(&output.stdout).to_string();
            if stdout.contains("Status: active") {
                fw_enabled = true;
                details = "UFW is active".to_string();
            } else if stdout.contains("Status: inactive") {
                details = "UFW is inactive".to_string();
            }
        }
        
        // If UFW isn't active/found, try firewalld
        if !fw_enabled && details.is_empty() {
            if let Ok(output) = crate::hidden_command!("firewall-cmd").arg("--state").output() {
                let stdout = String::from_utf8_lossy(&output.stdout).to_string();
                if stdout.contains("running") {
                    fw_enabled = true;
                    details = "firewalld is running".to_string();
                } else if stdout.contains("not running") {
                    details = "firewalld is not running".to_string();
                }
            }
        }
        
        if details.is_empty() {
            details = "No known firewall detected (checked ufw, firewalld)".to_string();
        }
    }

    #[cfg(windows)]
    {
        if let Ok(output) = crate::hidden_command!("netsh").args(&["advfirewall", "show", "allprofiles", "state"]).output() {
            let stdout = String::from_utf8_lossy(&output.stdout).to_string();
            // This is a naive check. A better approach would parse Domain, Private, Public separately.
            if stdout.contains("ON") {
                fw_enabled = true;
                details = "Windows Firewall is ON".to_string();
            } else {
                details = "Windows Firewall is OFF".to_string();
            }
        } else {
            details = "Failed to query netsh".to_string();
        }
    }

    json!({
        "type": "FirewallStatus",
        "enabled": fw_enabled,
        "details": details,
    })
}
