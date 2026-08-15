use serde_json::json;

pub fn get_active_sessions() -> serde_json::Value {
    let mut sessions = Vec::new();

    #[cfg(unix)]
    {
        if let Ok(output) = crate::hidden_command!("who").output() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            for line in stdout.lines() {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 5 {
                    let user = parts[0];
                    let terminal = parts[1];
                    let date = parts[2];
                    let time = parts[3];
                    let ip = parts[4].trim_matches('(').trim_matches(')');
                    
                    sessions.push(json!({
                        "user": user,
                        "terminal": terminal,
                        "login_time": format!("{} {}", date, time),
                        "ip_address": ip,
                    }));
                } else if parts.len() >= 2 {
                    sessions.push(json!({
                        "user": parts[0],
                        "terminal": parts[1],
                    }));
                }
            }
        }
    }

    #[cfg(windows)]
    {
        if let Ok(output) = crate::hidden_command!("query").arg("session").output() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            for line in stdout.lines().skip(1) {
                let is_current = line.starts_with('>');
                let line_clean = line.trim_start_matches('>');
                let parts: Vec<&str> = line_clean.split_whitespace().collect();
                
                if parts.len() >= 3 {
                    // Heuristic: if the second column is a number, there is no username
                    // If it's not a number, it's likely a username
                    let mut user = "Unknown";
                    let mut state = "Unknown";
                    
                    if parts[1].chars().all(|c| c.is_ascii_digit()) {
                        // "services 0 Disc"
                        state = parts[2];
                    } else {
                        // "console admin 1 Active"
                        user = parts[1];
                        if parts.len() > 3 {
                            state = parts[3];
                        }
                    }

                    sessions.push(json!({
                        "session_name": parts[0],
                        "user": user,
                        "state": state,
                        "is_current": is_current,
                    }));
                }
            }
        }
    }

    json!({
        "type": "SessionAudit",
        "active_sessions": sessions,
    })
}
