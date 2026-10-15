use serde_json::json;

pub fn fetch_auth_logs() -> serde_json::Value {
    let mut logs = Vec::new();

    // ── Linux: auth.log / secure / journald ────────────────────────────────
    #[cfg(target_os = "linux")]
    {
        // Try Debian/Ubuntu path first
        let mut output = crate::hidden_command!("tail")
            .args(&["-n", "50", "/var/log/auth.log"])
            .output();

        // Fallback: RHEL/CentOS/Fedora
        if output.is_err() || !output.as_ref().unwrap().status.success() {
            output = crate::hidden_command!("tail")
                .args(&["-n", "50", "/var/log/secure"])
                .output();
        }

        // Fallback: journald (systemd systems without log files)
        if output.is_err() || !output.as_ref().unwrap().status.success() {
            output = crate::hidden_command!("journalctl")
                .args(&["-u", "sshd", "-u", "sudo", "-n", "50", "--no-pager", "-o", "short"])
                .output();
        }

        if let Ok(out) = output {
            let stdout = String::from_utf8_lossy(&out.stdout);
            for line in stdout.lines() {
                if line.contains("Failed password")
                    || line.contains("session opened")
                    || line.contains("su:")
                    || line.contains("sudo:")
                    || line.contains("authentication failure")
                {
                    logs.push(line.to_string());
                }
            }
        }
    }

    // ── macOS: Unified Logging System (log show) ────────────────────────────
    #[cfg(target_os = "macos")]
    {
        // Query the unified log for authentication events (last 1 hour)
        let auth_result = crate::hidden_command!("log")
            .args(&[
                "show",
                "--predicate",
                "eventMessage CONTAINS \"authentication\" OR eventMessage CONTAINS \"failed\" OR eventMessage CONTAINS \"sudo\"",
                "--last", "1h",
                "--style", "syslog",
            ])
            .output();

        if let Ok(out) = auth_result {
            let stdout = String::from_utf8_lossy(&out.stdout);
            for line in stdout.lines().take(50) {
                if line.contains("authentication")
                    || line.contains("failed")
                    || line.contains("sudo")
                    || line.contains("sshd")
                {
                    logs.push(line.chars().take(200).collect::<String>());
                }
            }
        }

        // Also check /var/log/system.log as a fallback on older macOS
        if logs.is_empty() {
            if let Ok(out) = crate::hidden_command!("tail")
                .args(&["-n", "50", "/var/log/system.log"])
                .output()
            {
                let stdout = String::from_utf8_lossy(&out.stdout);
                for line in stdout.lines() {
                    if line.contains("authentication")
                        || line.contains("failed")
                        || line.contains("sudo")
                    {
                        logs.push(line.to_string());
                    }
                }
            }
        }
    }

    // ── Windows: Security Event Log via wevtutil ────────────────────────────
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
                for event_str in stdout.split("Event[").skip(1) {
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
