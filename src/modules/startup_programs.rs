use std::process::Command;
use serde_json::json;

pub fn get_startup_programs() -> serde_json::Value {
    let mut programs = Vec::new();

    #[cfg(unix)]
    {
        if let Ok(output) = crate::hidden_command!("systemctl").args(&["list-unit-files", "--state=enabled"]).output() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            for line in stdout.lines().skip(1) { // Skip header
                if line.trim().is_empty() {
                    break; // Stop at empty line before summary
                }
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 2 {
                    programs.push(json!({
                        "name": parts[0],
                        "state": parts[1],
                        "source": "systemd",
                    }));
                }
            }
        }
    }

    #[cfg(windows)]
    {
        // Query Run keys
        let cmd = crate::hidden_command!("powershell")
            .arg("-NoProfile")
            .arg("-Command")
            .arg("Get-ItemProperty HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run | Select-Object -Property * -ExcludeProperty PSPath, PSParentPath, PSChildName, PSDrive, PSProvider | ConvertTo-Json -Compress")
            .output();

        if let Ok(out) = cmd {
            let stdout = String::from_utf8_lossy(&out.stdout).trim().to_string();
            if !stdout.is_empty() {
                if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(&stdout) {
                    if let Some(obj) = parsed.as_object() {
                        for (key, val) in obj {
                            programs.push(json!({
                                "name": key,
                                "command": val.as_str().unwrap_or(""),
                                "source": "HKLM Run",
                            }));
                        }
                    }
                }
            }
        }
    }

    json!({
        "type": "StartupProgramsAudit",
        "programs": programs,
    })
}
