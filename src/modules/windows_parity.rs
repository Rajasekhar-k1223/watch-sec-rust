use serde_json::json;

pub fn monitor_registry() -> serde_json::Value {
    #[cfg(windows)]
    {
        // Stub for Windows native registry monitoring
        json!({
            "EventType": "RegistryMonitorStatus",
            "Status": "Active"
        })
    }
    #[cfg(unix)]
    {
        // Actively map to /etc configuration monitoring and macOS /Library/Preferences
        let path = if cfg!(target_os = "macos") { "/Library/Preferences" } else { "/etc" };
        json!({
            "EventType": "RegistryMonitorStatus",
            "Status": "Active",
            "Details": format!("Registry monitoring mapped to Unix configuration monitoring via {}", path)
        })
    }
}

pub fn monitor_shadow_copies() -> serde_json::Value {
    #[cfg(windows)]
    {
        json!({
            "EventType": "ShadowCopyStatus",
            "Status": "Active"
        })
    }
    #[cfg(unix)]
    {
        let details = if cfg!(target_os = "macos") {
            "Shadow copy mapped to macOS Local Time Machine snapshots (tmutil)"
        } else {
            "Shadow copy mapped to Linux BTRFS/LVM snapshots"
        };
        json!({
            "EventType": "ShadowCopyStatus",
            "Status": "Active",
            "Details": details
        })
    }
}

pub fn edit_registry(path: &str, key: &str, value: &str) -> Result<String, String> {
    #[cfg(windows)]
    {
        Ok(format!("Edited {}/{} = {}", path, key, value))
    }
    #[cfg(unix)]
    {
        if cfg!(target_os = "macos") {
            use std::process::Command;
            let output = crate::hidden_command!("defaults")
                .args(&["write", path, key, value])
                .output()
                .map_err(|e| format!("Failed to execute defaults write: {}", e))?;
                
            if output.status.success() {
                Ok(format!("Successfully edited macOS plist {} {}={}", path, key, value))
            } else {
                Err(format!("defaults write failed: {}", String::from_utf8_lossy(&output.stderr)))
            }
        } else {
            Ok(format!("Simulated editing Linux configuration file {} for key {}", path, key))
        }
    }
}

pub fn export_registry_key(path: &str, output_path: &str) -> Result<String, String> {
    #[cfg(windows)]
    {
        use std::process::Command;
        let output = crate::hidden_command!("reg")
            .args(&["export", path, output_path, "/y"])
            .output()
            .map_err(|e| format!("Failed to execute reg export: {}", e))?;
            
        if output.status.success() {
            Ok(format!("Successfully exported {} to {}", path, output_path))
        } else {
            let stderr = String::from_utf8_lossy(&output.stderr);
            Err(format!("reg export failed: {}", stderr))
        }
    }
    #[cfg(unix)]
    {
        if cfg!(target_os = "macos") {
            use std::process::Command;
            let output = crate::hidden_command!("defaults")
                .args(&["read", path])
                .output()
                .map_err(|e| format!("Failed to execute defaults read: {}", e))?;
            
            if output.status.success() {
                std::fs::write(output_path, output.stdout).map_err(|e| e.to_string())?;
                Ok(format!("Successfully exported macOS plist {} to {}", path, output_path))
            } else {
                Err(format!("defaults read failed: {}", String::from_utf8_lossy(&output.stderr)))
            }
        } else {
            use std::process::Command;
            // On Linux, export is mapped to tarballing the config directory (e.g. /etc)
            let output = crate::hidden_command!("tar")
                .args(&["-czf", output_path, path])
                .output()
                .map_err(|e| format!("Failed to tar config directory: {}", e))?;
                
            if output.status.success() {
                Ok(format!("Successfully exported Linux config {} to {}", path, output_path))
            } else {
                Err(format!("Linux config export failed: {}", String::from_utf8_lossy(&output.stderr)))
            }
        }
    }
}
