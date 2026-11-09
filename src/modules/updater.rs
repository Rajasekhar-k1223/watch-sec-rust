use std::fs::File;
use std::io::{Read, Write};
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

pub fn trigger_update(download_url: &str, expected_hash: &str, publisher_signature: &str, mut progress_cb: Box<dyn FnMut(u64)>) -> Result<String, String> {
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

    let total_size = response.content_length().unwrap_or(0);
    let mut downloaded: u64 = 0;
    let mut last_reported_percent: u64 = 0;
    let mut buffer = [0; 8192];
    
    // Report initial progress
    progress_cb(1);

    while let Ok(n) = response.read(&mut buffer) {
        if n == 0 { break; }
        if let Err(e) = dest.write_all(&buffer[..n]) {
            return Err(format!("Failed to write to temp file: {}", e));
        }
        downloaded += n as u64;
        
        if total_size > 0 {
            let percent = ((downloaded as f64 / total_size as f64) * 100.0) as u64;
            // Cap at 95% during download to leave 5% for signature verification and restart
            let percent = if percent > 95 { 95 } else { percent };
            if percent >= last_reported_percent + 5 {
                last_reported_percent = percent;
                progress_cb(percent);
            }
        }
    }
    progress_cb(95);
    
    // Explicitly drop the file handle to flush buffers and release the exclusive write lock on Windows.
    // Otherwise, std::fs::read in verify_binary_signature will fail with a Sharing Violation (Access Denied).
    drop(dest);

    // Cryptographic SHA-256 hash verification
    if !expected_hash.is_empty() {
        let file_bytes = match std::fs::read(&temp_file) {
            Ok(b) => b,
            Err(e) => return Err(format!("Failed to read downloaded binary for hash check: {}", e)),
        };
        let digest = ring::digest::digest(&ring::digest::SHA256, &file_bytes);
        let actual_hash = hex::encode(digest.as_ref());
        if !expected_hash.eq_ignore_ascii_case(&actual_hash) {
            let _ = std::fs::remove_file(&temp_file);
            return Err(format!(
                "Cryptographic hash verification failed! Expected: {}, Actual: {}",
                expected_hash, actual_hash
            ));
        }
        crate::log_msg(&format!("[Updater] Download complete. Cryptographic hash verified ({}).", actual_hash));
    } else {
        crate::log_msg("[Updater] Download complete. No expected hash provided.");
    }

    // Only run publisher signature check if the server actually provided one.
    if !publisher_signature.is_empty() {
        if let Some(temp_file_str) = temp_file.to_str() {
            if !crate::c2::verify::verify_binary_signature(temp_file_str, publisher_signature) {
                crate::log_msg("[Updater] CRITICAL: Publisher signature validation failed. Rejecting payload.");
                let _ = std::fs::remove_file(&temp_file);
                return Err("Publisher certificate signature invalid. Refusing to install rogue payload.".to_string());
            }
        }
    } else {
        crate::log_msg("[Updater] No publisher signature provided by server — relying on hash verification.");
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
             :retry\n\
             net stop MonitorixAgent 2>NUL\n\
             taskkill /F /IM \"{}\" 2>NUL\n\
             copy /y \"{}\" \"{}.bak\" 2>NUL\n\
             move /y \"{}\" \"{}\"\n\
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
             schtasks /delete /tn MonitorixUpdater /f >NUL 2>&1\n\
             (goto) 2>nul & del \"%~f0\"\n",
            exe_name,
            current_exe.display(),
            current_exe.display(),
            temp_file.display(),
            current_exe.display(),
            current_exe.display(),
            current_exe.display()
        );

        if let Err(e) = std::fs::write(&script_path, script_content) {
            return Err(format!("Failed to write updater script: {}", e));
        }

        // Spawn the batch script using SchTasks to completely detach from the Service Job Object
        let script_str = script_path.to_str().unwrap();
        
        let create_task = crate::hidden_command!("schtasks")
            .args(&["/create", "/tn", "MonitorixUpdater", "/tr", &format!("cmd.exe /c \"{}\"", script_str), "/sc", "once", "/st", "00:00", "/ru", "SYSTEM", "/f"])
            .output();
            
        let mut schtasks_success = false;
        if let Ok(output) = create_task {
            if output.status.success() {
                let run_task = crate::hidden_command!("schtasks")
                    .args(&["/run", "/tn", "MonitorixUpdater"])
                    .output();
                if let Ok(run_out) = run_task {
                    if run_out.status.success() {
                        schtasks_success = true;
                    }
                }
            }
        }

        if !schtasks_success {
            crate::log_msg("[Updater] SchTask failed (likely not running as Admin). Falling back to direct cmd spawn...");
            if let Err(e) = crate::hidden_command!("cmd.exe")
                .args(&["/c", script_str])
                .spawn()
            {
                return Err(format!("Failed to spawn fallback updater script: {}", e));
            }
        }

        crate::log_msg("[Updater] Update SchTask spawned. Exiting to allow swap...");
        std::process::exit(0);
    }

    #[cfg(not(windows))]
    {
        // On Linux, move the file directly and restart via systemd
        let current_exe = match std::env::current_exe() {
            Ok(p) => p,
            Err(e) => return Err(format!("Failed to get current executable path: {}", e)),
        };

        let mut script_path = std::env::temp_dir();
        script_path.push("monitorix_updater.sh");

        let exe_name = current_exe.file_name().and_then(|n| n.to_str()).unwrap_or("monitorix-agent");

        let script_content = format!(
            "#!/bin/bash\n\
             sleep 2\n\
             systemctl stop monitorix-agent 2>/dev/null\n\
             pkill -9 monitorix-agent 2>/dev/null\n\
             pkill -9 {} 2>/dev/null\n\
             cp -f \"{}\" \"{}.bak\" 2>/dev/null\n\
             mv -f \"{}\" \"{}\"\n\
             chmod +x \"{}\"\n\
             systemctl start monitorix-agent 2>/dev/null || ( \"{}\" & )\n\
             ",
            exe_name,
            current_exe.display(),
            current_exe.display(),
            temp_file.display(),
            current_exe.display(),
            current_exe.display(),
            current_exe.display()
        );

        let mut script_file = match File::create(&script_path) {
            Ok(f) => f,
            Err(e) => return Err(format!("Failed to create updater script: {}", e)),
        };

        if let Err(e) = script_file.write_all(script_content.as_bytes()) {
            return Err(format!("Failed to write updater script: {}", e));
        }

        let mut perms = script_file.metadata().unwrap().permissions();
        perms.set_mode(0o755);
        let _ = script_file.set_permissions(perms);
        
        crate::log_msg(&format!("[Updater] Executing updater script: {}", script_path.display()));

        if let Err(e) = crate::hidden_command!("bash")
            .arg(script_path)
            .spawn()
        {
            return Err(format!("Failed to spawn updater script: {}", e));
        }

        crate::log_msg("[Updater] Update script spawned. Exiting to allow swap...");
        std::process::exit(0);
    }
}

pub fn trigger_patch(software: &str) -> Result<String, String> {
    crate::log_msg(&format!("[Updater] Attempting to patch software: {}", software));
    
    #[cfg(windows)]
    {
        // Try winget first (works well for user sessions)
        let mut out = crate::hidden_command!("winget")
            .args(&["upgrade", "--exact", software, "--silent", "--accept-package-agreements", "--accept-source-agreements"])
            .output();
            
        // If winget fails (very common under SYSTEM account in Session 0), fallback to choco
        if let Ok(ref o) = out {
            if !o.status.success() {
                crate::log_msg(&format!("[Updater] Winget failed to patch {}. Falling back to Chocolatey...", software));
                out = crate::hidden_command!("choco")
                    .args(&["upgrade", software, "-y"])
                    .output();
            }
        } else {
            crate::log_msg(&format!("[Updater] Winget command not found. Falling back to Chocolatey for {}...", software));
            out = crate::hidden_command!("choco")
                .args(&["upgrade", software, "-y"])
                .output();
        }
        
        match out {
            Ok(o) if o.status.success() => return Ok(format!("Successfully patched {}", software)),
            Ok(o) => return Err(format!("Patch failed: {}", String::from_utf8_lossy(&o.stderr))),
            Err(e) => return Err(e.to_string()),
        }
    }
    
    #[cfg(target_os = "linux")]
    {
        let out = crate::hidden_command!("apt-get").args(&["install", "--only-upgrade", "-y", software]).output();
        match out {
            Ok(o) if o.status.success() => return Ok(format!("Successfully patched {}", software)),
            Ok(o) => return Err(format!("Patch failed: {}", String::from_utf8_lossy(&o.stderr))),
            Err(e) => return Err(e.to_string()),
        }
    }
    
    #[cfg(target_os = "macos")]
    {
        let out = crate::hidden_command!("brew").args(&["upgrade", software]).output();
        match out {
            Ok(o) if o.status.success() => return Ok(format!("Successfully patched {}", software)),
            Ok(o) => return Err(format!("Patch failed: {}", String::from_utf8_lossy(&o.stderr))),
            Err(e) => return Err(e.to_string()),
        }
    }
}
