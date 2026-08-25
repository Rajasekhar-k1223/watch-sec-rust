use serde_json::json;

pub fn fetch_auth_logs() -> serde_json::Value {
    let mut logs = Vec::new();

    #[cfg(unix)]
    {
        // Try Debian/Ubuntu
        let mut output = crate::hidden_command!("tail").args(&["-n", "50", "/var/log/auth.log"]).output();
        
        // If it fails (e.g. file doesn't exist), try RHEL/CentOS
        if output.is_err() || !output.as_ref().unwrap().status.success() {
            output = crate::hidden_command!("tail").args(&["-n", "50", "/var/log/secure"]).output();
        }

        if let Ok(out) = output {
            let stdout = String::from_utf8_lossy(&out.stdout);
            for line in stdout.lines() {
                if line.contains("Failed password") || line.contains("session opened") || line.contains("su:") {
                    logs.push(line.to_string());
                }
            }
        }
    }

    #[cfg(windows)]
    {
        // Fetch recent successful (4624) and failed (4625) logons using Native wevtutil (Zero PowerShell)
        let cmd = crate::hidden_command!("wevtutil")
            .args(&[
                "qe", "Security",
                "/c:20",
                "/rd:true",
                "/f:text",
                "/q:*[System[(EventID=4624 or EventID=4625)]]"
            ])
            .output();

        if let Ok(out) = cmd {
            let stdout = String::from_utf8_lossy(&out.stdout).trim().to_string();
            if !stdout.is_empty() {
                // wevtutil returns raw text, split by Event[0]:, Event[1]: etc.
                for event_str in stdout.split("Event[").skip(1) {
                    // Limit the size of each event string to avoid massive payloads
                    let trimmed = event_str.chars().take(200).collect::<String>();
                    logs.push(format!("Event: {}", trimmed.replace("\r\n", " ").replace("\n", " ")));
                }
            } else {
                logs.push("No relevant logon events found or permission denied.".to_string());
            }
        } else {
            logs.push("Permission Denied or Failed to execute wevtutil".to_string());
        }
    }

    json!({
        "type": "EventLogAudit",
        "suspicious_events": logs,
    })
}
