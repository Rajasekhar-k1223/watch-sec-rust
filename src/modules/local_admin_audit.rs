use serde_json::json;
use std::fs;

pub fn audit_admins() -> serde_json::Value {
    let mut sudo_users = Vec::new();

    // Parse /etc/group to find users in 'sudo' or 'wheel' group
    if let Ok(content) = fs::read_to_string("/etc/group") {
        for line in content.lines() {
            if line.starts_with("sudo:") || line.starts_with("wheel:") {
                let parts: Vec<&str> = line.split(':').collect();
                if parts.len() >= 4 {
                    let users = parts[3];
                    for user in users.split(',') {
                        let u = user.trim();
                        if !u.is_empty() {
                            sudo_users.push(u.to_string());
                        }
                    }
                }
            }
        }
    }

    json!({
        "EventType": "LocalAdminAudit",
        "AdminCount": sudo_users.len(),
        "Admins": sudo_users
    })
}
