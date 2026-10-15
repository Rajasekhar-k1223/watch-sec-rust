use std::fs;
use std::path::Path;

pub fn backup_policy(current_path: &str) -> Result<String, String> {
    if !Path::new(current_path).exists() {
        return Ok("No existing policy to backup".to_string());
    }
    
    let backup_path = format!("{}.bak", current_path);
    match fs::copy(current_path, &backup_path) {
        Ok(_) => Ok(format!("Policy backed up to {}", backup_path)),
        Err(e) => Err(format!("Failed to backup policy: {}", e))
    }
}

pub fn rollback_policy(current_path: &str) -> Result<String, String> {
    let backup_path = format!("{}.bak", current_path);
    
    if !Path::new(&backup_path).exists() {
        return Err("No backup policy found to rollback to.".to_string());
    }

    match fs::copy(&backup_path, current_path) {
        Ok(_) => Ok("Successfully rolled back policy to previous known-good state.".to_string()),
        Err(e) => Err(format!("Failed to restore policy: {}", e))
    }
}

pub fn create_vss_snapshot(drive_letter: &str) -> Result<String, String> {
    #[cfg(windows)]
    {
        // Requires Administrator privileges to run vssadmin
        match crate::hidden_command!("vssadmin")
            .args(&["Create", "Shadow", &format!("/For={}:\\", drive_letter)])
            .output()
        {
            Ok(out) => {
                let stdout = String::from_utf8_lossy(&out.stdout);
                if out.status.success() {
                    Ok(format!("Successfully created VSS snapshot for drive {}:\\", drive_letter))
                } else {
                    Err(format!("vssadmin failed: {}", stdout))
                }
            },
            Err(e) => Err(format!("Failed to execute vssadmin: {}", e)),
        }
    }
    
    #[cfg(target_os = "linux")]
    {
        // Example: lvcreate -s -n monitorix_snapshot /dev/mapper/ubuntu-root
        match crate::hidden_command!("lvcreate")
            .args(&["-s", "-n", "monitorix_snapshot", "/dev/mapper/ubuntu-root"])
            .output()
        {
            Ok(out) => {
                if out.status.success() {
                    Ok("Successfully created LVM snapshot for Linux".to_string())
                } else {
                    Err(format!("lvcreate failed: {}", String::from_utf8_lossy(&out.stderr)))
                }
            },
            Err(e) => Err(format!("Failed to execute lvcreate: {}", e)),
        }
    }
    
    #[cfg(target_os = "macos")]
    {
        match crate::hidden_command!("tmutil")
            .arg("localsnapshot")
            .output()
        {
            Ok(out) => {
                if out.status.success() {
                    Ok("Successfully created APFS local snapshot for macOS".to_string())
                } else {
                    Err(format!("tmutil failed: {}", String::from_utf8_lossy(&out.stderr)))
                }
            },
            Err(e) => Err(format!("Failed to execute tmutil: {}", e)),
        }
    }
}

pub fn restore_from_vss(drive_letter: &str) -> Result<String, String> {
    #[cfg(windows)]
    {
        match crate::hidden_command!("vssadmin")
            .args(&["Revert", "Shadow", &format!("/For={}:\\", drive_letter), "/Quiet"])
            .output()
        {
            Ok(out) => {
                if out.status.success() {
                    Ok(format!("Successfully restored drive {}:\\ from latest VSS snapshot", drive_letter))
                } else {
                    Err(format!("vssadmin revert failed: {}", String::from_utf8_lossy(&out.stdout)))
                }
            },
            Err(e) => Err(format!("Failed to execute vssadmin revert: {}", e)),
        }
    }
    
    #[cfg(target_os = "linux")]
    {
        match crate::hidden_command!("lvconvert")
            .args(&["--merge", "/dev/mapper/ubuntu-root/monitorix_snapshot"])
            .output()
        {
            Ok(out) => {
                if out.status.success() {
                    Ok("Successfully merged LVM snapshot for Linux. Reboot may be required.".to_string())
                } else {
                    Err(format!("lvconvert failed: {}", String::from_utf8_lossy(&out.stderr)))
                }
            },
            Err(e) => Err(format!("Failed to execute lvconvert: {}", e)),
        }
    }
    #[cfg(target_os = "macos")]
    {
        Err("Automatic rollback from APFS snapshot requires Recovery Mode on macOS.".to_string())
    }
}


/// Feature 56: Agent Version Management & Self-Healing Rollback
/// Reverts the running agent executable to the backup (.bak) or specified target version.
pub fn rollback_agent_binary(target_version: Option<&str>) -> Result<String, String> {
    let current_exe = std::env::current_exe().map_err(|e| format!("Failed to get current executable path: {}", e))?;
    let backup_exe = current_exe.with_extension("bak");

    // Check if target_version specified a versioned binary or fallback to backup_exe
    let candidate_path = if let Some(ver) = target_version {
        let parent = current_exe.parent().unwrap_or(std::path::Path::new("."));
        let ver_path = parent.join(format!("monitorix-agent-{}", ver));
        if ver_path.exists() {
            ver_path
        } else {
            backup_exe
        }
    } else {
        backup_exe
    };

    if !candidate_path.exists() {
        return Err(format!("No rollback backup binary found at {:?}", candidate_path));
    }

    crate::log_msg(&format!("[Rollback] Initiating rollback to binary: {:?}", candidate_path));

    #[cfg(windows)]
    {
        let mut script_path = std::env::temp_dir();
        script_path.push("monitorix_rollback.bat");

        let exe_name = current_exe
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("monitorix-agent-rust.exe");

        let script_content = format!(
            "@echo off\n\
             :retry\n\
             net stop MonitorixAgent 2>NUL\n\
             taskkill /F /IM \"{}\" 2>NUL\n\
             copy /y \"{}\" \"{}\"\n\
             if errorlevel 1 (\n\
                 timeout /t 1 /nobreak > NUL\n\
                 goto retry\n\
             )\n\
             sc query MonitorixAgent >NUL 2>&1\n\
             if %ERRORLEVEL% EQU 0 (\n\
                 net start MonitorixAgent\n\
                 if %ERRORLEVEL% NEQ 0 (\n\
                     start \"\" \"{}\"\n\
                 )\n\
             ) else (\n\
                 start \"\" \"{}\"\n\
             )\n\
             schtasks /delete /tn MonitorixRollback /f >NUL 2>&1\n\
             (goto) 2>nul & del \"%~f0\"\n",
            exe_name,
            candidate_path.display(),
            current_exe.display(),
            current_exe.display(),
            current_exe.display()
        );

        fs::write(&script_path, script_content).map_err(|e| format!("Failed to write rollback script: {}", e))?;

        let script_str = script_path.to_str().unwrap();
        let _ = crate::hidden_command!("cmd.exe").args(&["/c", script_str]).spawn();
        
        crate::log_msg("[Rollback] Rollback script spawned. Exiting current process for binary rollback...");
        std::process::exit(0);
    }

    #[cfg(not(windows))]
    {
        let mut script_path = std::env::temp_dir();
        script_path.push("monitorix_rollback.sh");

        let exe_name = current_exe.file_name().and_then(|n| n.to_str()).unwrap_or("monitorix-agent");

        let script_content = format!(
            "#!/bin/bash\n\
             sleep 1\n\
             systemctl stop monitorix-agent 2>/dev/null\n\
             pkill -9 monitorix-agent 2>/dev/null\n\
             pkill -9 {} 2>/dev/null\n\
             cp -f \"{}\" \"{}\"\n\
             chmod +x \"{}\"\n\
             systemctl start monitorix-agent 2>/dev/null || ( \"{}\" & )\n\
             ",
            exe_name,
            candidate_path.display(),
            current_exe.display(),
            current_exe.display(),
            current_exe.display()
        );

        fs::write(&script_path, script_content.as_bytes()).map_err(|e| format!("Failed to write rollback script: {}", e))?;
        
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(&script_path, fs::Permissions::from_mode(0o755));
        }

        crate::log_msg(&format!("[Rollback] Executing rollback script: {}", script_path.display()));
        let _ = crate::hidden_command!("bash").arg(&script_path).spawn();

        crate::log_msg("[Rollback] Rollback script spawned. Exiting current process for binary rollback...");
        std::process::exit(0);
    }
}

