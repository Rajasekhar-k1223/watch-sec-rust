use std::process::Command;
use serde_json::json;

pub fn get_local_users() -> serde_json::Value {
    let mut users = Vec::new();

    #[cfg(unix)]
    {
        if let Ok(contents) = std::fs::read_to_string("/etc/passwd") {
            for line in contents.lines() {
                let parts: Vec<&str> = line.split(':').collect();
                if parts.len() >= 7 {
                    let username = parts[0];
                    let uid = parts[2];
                    let description = parts[4];
                    let shell = parts[6];

                    // Heuristic: skip common system users to reduce noise, unless they have a real shell
                    if uid.parse::<u32>().unwrap_or(1000) >= 1000 || uid == "0" || !shell.contains("nologin") && !shell.contains("false") {
                        users.push(json!({
                            "username": username,
                            "uid": uid,
                            "description": description,
                            "is_admin": uid == "0",
                            "shell": shell,
                        }));
                    }
                }
            }
        }
    }

    #[cfg(windows)]
    {
        let cmd = crate::hidden_command!("powershell")
            .arg("-NoProfile")
            .arg("-Command")
            .arg("Get-LocalUser | Select-Object Name, Enabled, Description | ConvertTo-Json -Compress")
            .output();

        if let Ok(out) = cmd {
            let stdout = String::from_utf8_lossy(&out.stdout).trim().to_string();
            if !stdout.is_empty() {
                if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(&stdout) {
                    if let Some(arr) = parsed.as_array() {
                        for item in arr {
                            users.push(item.clone());
                        }
                    } else {
                        users.push(parsed);
                    }
                }
            }
        }
    }

    json!({
        "type": "LocalUsersAudit",
        "users": users,
    })
}
