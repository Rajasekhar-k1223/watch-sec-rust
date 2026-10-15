use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

pub fn execute_script(language: &str, content: &str) -> Result<String, String> {
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis();
        
    let ext = match language.to_lowercase().as_str() {
        "python" => "py",
        "bash" | "sh" => "sh",
        "powershell" | "ps1" => "ps1",
        "cmd" | "bat" => "bat",
        _ => "txt",
    };

    let temp_dir = std::env::temp_dir();
    let file_path: PathBuf = temp_dir.join(format!("monitorix_task_{}.{}", timestamp, ext));

    if let Err(e) = fs::write(&file_path, content) {
        return Err(format!("Failed to write script to disk: {}", e));
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(mut perms) = fs::metadata(&file_path).map(|m| m.permissions()) {
            perms.set_mode(0o700);
            let _ = fs::set_permissions(&file_path, perms);
        }
    }

    let mut cmd = match language.to_lowercase().as_str() {
        "python" => {
            let mut c = crate::hidden_command!("python3");
            c.arg(&file_path);
            c
        },
        "bash" | "sh" => {
            let mut c = crate::hidden_command!("sh");
            c.arg(&file_path);
            c
        },
        "powershell" | "ps1" => {
            // Check if powershell is allowed via local configuration
            let allowed = std::env::var("MONITORIX_ALLOW_POWERSHELL").unwrap_or_else(|_| "0".to_string());
            if allowed != "1" {
                let _ = fs::remove_file(&file_path);
                return Err("PowerShell execution is disabled by Agent configuration to comply with SOC2 strict environments.".to_string());
            }

            let mut c = crate::hidden_command!("powershell");
            c.arg("-ExecutionPolicy").arg("Bypass").arg("-File").arg(&file_path);
            c
        },
        "cmd" | "bat" => {
            let mut c = crate::hidden_command!("cmd");
            c.arg("/C").arg(&file_path);
            c
        },
        _ => {
            let _ = fs::remove_file(&file_path);
            return Err(format!("Unsupported script language: {}", language));
        }
    };

    let output = match cmd.output() {
        Ok(out) => out,
        Err(e) => {
            let _ = fs::remove_file(&file_path);
            return Err(format!("Failed to execute script: {}", e));
        }
    };

    // Always attempt to clean up the script
    let _ = fs::remove_file(&file_path);

    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();

    if output.status.success() {
        Ok(stdout)
    } else {
        Err(format!("Script failed with exit code {}.\nStdout: {}\nStderr: {}", 
            output.status.code().unwrap_or(-1), stdout, stderr))
    }
}
