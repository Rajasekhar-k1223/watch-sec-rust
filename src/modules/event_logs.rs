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
        // Fetch recent successful (4624) and failed (4625) logons
        let cmd = crate::hidden_command!("powershell")
            .arg("-NoProfile")
            .arg("-Command")
            .arg("Get-EventLog -LogName Security -Newest 20 | Where-Object { $_.InstanceId -eq 4624 -or $_.InstanceId -eq 4625 } | Select-Object TimeGenerated, EventID, Message | ConvertTo-Json -Compress")
            .output();

        if let Ok(out) = cmd {
            let stdout = String::from_utf8_lossy(&out.stdout).trim().to_string();
            if !stdout.is_empty() {
                if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(&stdout) {
                    if let Some(arr) = parsed.as_array() {
                        for item in arr {
                            logs.push(item.to_string());
                        }
                    } else {
                        logs.push(parsed.to_string());
                    }
                } else {
                    logs.push("Failed to parse JSON from PowerShell".to_string());
                }
            }
        } else {
            logs.push("Permission Denied or Failed to access Security Log".to_string());
        }
    }

    json!({
        "type": "EventLogAudit",
        "suspicious_events": logs,
    })
}
