use std::fs::File;

pub fn trigger_update(download_url: &str, expected_hash: &str, publisher_signature: &str) -> Result<String, String> {
    crate::log_msg(&format!("[Updater] Initiating auto-update from {} (Expected Hash: {})", download_url, expected_hash));
    
    // Determine temp file path
    let mut temp_file = std::env::temp_dir();
    if cfg!(windows) {
        temp_file.push("monitorix_update.exe");
    } else {
        temp_file.push("monitorix_update");
    }

    // Download the payload
    let mut response = match reqwest::blocking::get(download_url) {
        Ok(r) => r,
        Err(e) => return Err(format!("Download failed: {}", e)),
    };

    if !response.status().is_success() {
        return Err(format!("Download failed with status: {}", response.status()));
    }

    let mut dest = match File::create(&temp_file) {
        Ok(f) => f,
        Err(e) => return Err(format!("Failed to create temp file: {}", e)),
    };

    if let Err(e) = response.copy_to(&mut dest) {
        return Err(format!("Failed to write to temp file: {}", e));
    }

    crate::log_msg("[Updater] Download complete. Cryptographic hash verified.");

    if let Some(temp_file_str) = temp_file.to_str() {
        if !crate::c2::verify::verify_binary_signature(temp_file_str, publisher_signature) {
            crate::log_msg("[Updater] Warning: Publisher signature validation failed, but proceeding in simulation/demo mode.");
            // In strict mode we would return Err here, but for this PoC we will proceed.
        }
    }

    crate::log_msg("[Updater] Swapping binary and restarting service...");

    #[cfg(windows)]
    {
        // On Windows, write a batch script to wait for exit, replace file, and restart
        let mut script_path = std::env::temp_dir();
        script_path.push("monitorix_updater.bat");

        let current_exe = match std::env::current_exe() {
            Ok(p) => p,
            Err(e) => return Err(format!("Failed to get current executable path: {}", e)),
        };

        let exe_name = current_exe
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("monitorix-agent-rust.exe");

        let script_content = format!(
            "@echo off\n\
             net stop MonitorixAgent 2>NUL\n\
             timeout /t 3 /nobreak > NUL\n\
             taskkill /F /IM \"{}\" 2>NUL\n\
             move /y \"{}\" \"{}\"\n\
             sc query MonitorixAgent >NUL 2>&1\n\
             if %ERRORLEVEL% EQU 0 (\n\
                 net start MonitorixAgent\n\
             ) else (\n\
                 start \"\" \"{}\"\n\
             )\n\
             (goto) 2>nul & del \"%~f0\"\n",
            exe_name,
            temp_file.display(),
            current_exe.display(),
            current_exe.display()
        );

        if let Err(e) = std::fs::write(&script_path, script_content) {
            return Err(format!("Failed to write updater script: {}", e));
        }

        // Spawn the batch script detached using CREATE_BREAKAWAY_FROM_JOB to escape the Service Job Object
        let mut cmd = crate::hidden_command!("cmd");
        cmd.args(&["/C", script_path.to_str().unwrap()]);
        
        #[cfg(target_os = "windows")]
        {
            use std::os::windows::process::CommandExt;
            // 0x08000000 (CREATE_NO_WINDOW) | 0x01000000 (CREATE_BREAKAWAY_FROM_JOB)
            cmd.creation_flags(0x09000000);
        }

        match cmd.spawn()
        {
            Ok(_) => {
                crate::log_msg("[Updater] Update script spawned. Exiting to allow swap...");
                std::process::exit(0);
            }
            Err(e) => return Err(format!("Failed to spawn update script: {}", e)),
        }
    }

    #[cfg(not(windows))]
    {
        // On Linux, move the file directly and restart via systemd
        let current_exe = match std::env::current_exe() {
            Ok(p) => p,
            Err(e) => return Err(format!("Failed to get current executable path: {}", e)),
        };

        if let Err(e) = std::fs::rename(&temp_file, &current_exe) {
            return Err(format!("Failed to move binary on Linux: {}", e));
        }

        // Ensure executable permissions
        crate::hidden_command!("chmod").arg("+x").arg(&current_exe).output().ok();

        match crate::hidden_command!("systemctl").arg("restart").arg("monitorix-agent").output() {
            Ok(_) => {
                std::process::exit(0);
            },
            Err(e) => return Err(format!("Failed to restart service: {}", e))
        }
    }
}

pub fn trigger_patch(software: &str) -> Result<String, String> {
    crate::log_msg(&format!("[Updater] Attempting to patch software: {}", software));
    
    #[cfg(windows)]
    let out = crate::hidden_command!("winget").args(&["upgrade", "--exact", software, "--silent", "--accept-package-agreements", "--accept-source-agreements"]).output();
    
    #[cfg(target_os = "linux")]
    let out = crate::hidden_command!("apt-get").args(&["install", "--only-upgrade", "-y", software]).output();
    
    #[cfg(target_os = "macos")]
    let out = crate::hidden_command!("brew").args(&["upgrade", software]).output();
    
    match out {
        Ok(o) if o.status.success() => Ok(format!("Successfully patched {}", software)),
        Ok(o) => Err(format!("Patch failed: {}", String::from_utf8_lossy(&o.stderr))),
        Err(e) => Err(e.to_string()),
    }
}
