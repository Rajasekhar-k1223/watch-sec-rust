use serde_json::json;

pub fn get_startup_programs() -> serde_json::Value {
    let mut programs = Vec::new();

    #[cfg(target_os = "linux")]
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

    #[cfg(target_os = "macos")]
    {
        if let Ok(output) = crate::hidden_command!("launchctl").args(&["list"]).output() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            for line in stdout.lines().skip(1) { // Skip header
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 3 {
                    programs.push(json!({
                        "name": parts[2], // The label is usually the 3rd column
                        "state": "enabled",
                        "source": "launchd",
                    }));
                }
            }
        }
    }

    #[cfg(windows)]
    {
        use winreg::enums::*;
        use winreg::RegKey;

        let paths = vec![
            (RegKey::predef(HKEY_LOCAL_MACHINE), "Software\\Microsoft\\Windows\\CurrentVersion\\Run"),
            (RegKey::predef(HKEY_LOCAL_MACHINE), "Software\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Run"),
            (RegKey::predef(HKEY_CURRENT_USER), "Software\\Microsoft\\Windows\\CurrentVersion\\Run"),
        ];

        for (hive, path) in paths {
            if let Ok(run_key) = hive.open_subkey_with_flags(path, KEY_READ) {
                for (name, val) in run_key.enum_values().filter_map(|x| x.ok()) {
                    programs.push(json!({
                        "name": name,
                        "command": val.to_string(),
                        "source": path,
                    }));
                }
            }
        }
    }

    json!({
        "type": "StartupProgramsAudit",
        "programs": programs,
    })
}
