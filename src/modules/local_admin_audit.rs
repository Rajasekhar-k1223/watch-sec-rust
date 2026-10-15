use serde_json::json;
use std::fs;

pub fn audit_admins() -> serde_json::Value {
    let mut sudo_users = Vec::new();

    #[cfg(not(target_os = "windows"))]
    {
        // Parse /etc/group to find users in 'sudo', 'wheel', or 'admin' group
        if let Ok(content) = fs::read_to_string("/etc/group") {
            for line in content.lines() {
                if line.starts_with("sudo:") || line.starts_with("wheel:") || line.starts_with("admin:") {
                    let parts: Vec<&str> = line.split(':').collect();
                    if parts.len() >= 4 {
                        let users = parts[3];
                        for user in users.split(',') {
                            let u = user.trim();
                            if !u.is_empty() && !sudo_users.contains(&u.to_string()) {
                                sudo_users.push(u.to_string());
                            }
                        }
                    }
                }
            }
        }
    }

    #[cfg(target_os = "windows")]
    {
        // Use 'net localgroup administrators' to list Windows local admins
        if let Ok(output) = std::process::Command::new("net")
            .args(["localgroup", "administrators"])
            .output() 
        {
            let stdout = String::from_utf8_lossy(&output.stdout);
            let mut collecting = false;
            for line in stdout.lines() {
                let line = line.trim();
                if line.starts_with("---") {
                    collecting = true;
                    continue;
                }
                if line == "The command completed successfully." {
                    break;
                }
                if collecting && !line.is_empty() {
                    sudo_users.push(line.to_string());
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
