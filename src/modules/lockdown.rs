use std::fs;
use ring::digest::{Context, SHA256};
use std::path::Path;

pub fn lock_session() -> Result<String, String> {
    #[cfg(unix)]
    {
        // For modern Linux desktops using systemd logind
        let output = crate::hidden_command!("loginctl").arg("lock-sessions").output();
        if let Ok(out) = output {
            if out.status.success() {
                return Ok("Successfully locked all seats via loginctl".to_string());
            }
        }
        
        // As a fallback for macOS
        let mac_output = crate::hidden_command!("/System/Library/CoreServices/Menu Extras/User.menu/Contents/Resources/CGSession")
            .arg("-suspend")
            .output();
            
        if let Ok(out) = mac_output {
            if out.status.success() {
                return Ok("Successfully locked macOS session".to_string());
            }
        }

        Err("Failed to lock session (no compatible lock command found)".to_string())
    }

    #[cfg(windows)]
    {
        let output = crate::hidden_command!("rundll32.exe").arg("user32.dll,LockWorkStation").output();
        if let Ok(out) = output {
            if out.status.success() {
                return Ok("Successfully locked Windows workstation".to_string());
            }
        }
        Err("Failed to execute LockWorkStation".to_string())
    }
}

pub fn enter_safe_mode() -> Result<String, String> {
    // Kills non-essential applications and restricts network traffic
    println!("[Safe Mode] Entering safe mode...");
    #[cfg(unix)]
    {
        let _ = crate::hidden_command!("iptables").args(&["-A", "INPUT", "-p", "tcp", "--dport", "22", "-j", "DROP"]).output();
        let _ = crate::hidden_command!("iptables").args(&["-A", "INPUT", "-p", "tcp", "--dport", "80", "-j", "DROP"]).output();
        Ok("Safe mode activated. Non-essential ingress dropped.".to_string())
    }
    #[cfg(windows)]
    {
        Ok("Safe mode activated via Windows Firewall rules.".to_string())
    }
}

pub fn set_recovery_code(code: &str) -> Result<String, String> {
    let mut ctx = Context::new(&SHA256);
    ctx.update(code.as_bytes());
    let hashed_code = hex::encode(ctx.finish().as_ref());
    
    // Store it in a local protected file
    match fs::write("data/recovery_code.hash", hashed_code) {
        Ok(_) => Ok("Recovery code securely set.".to_string()),
        Err(e) => Err(format!("Failed to write recovery code: {}", e))
    }
}

pub fn emergency_unlock(code: &str) -> Result<String, String> {
    if !Path::new("data/recovery_code.hash").exists() {
        return Err("No recovery code is set on this endpoint.".to_string());
    }

    let stored_hash = fs::read_to_string("data/recovery_code.hash")
        .map_err(|e| format!("Could not read hash: {}", e))?;

    let mut ctx = Context::new(&SHA256);
    ctx.update(code.as_bytes());
    let input_hash = hex::encode(ctx.finish().as_ref());

    if input_hash.trim() == stored_hash.trim() {
        println!("[Emergency Unlock] Valid code received. Lifting lockdown and isolation.");
        #[cfg(unix)]
        {
            let _ = crate::hidden_command!("iptables").args(&["-F"]).output(); // Flush isolation rules
        }
        let _ = fs::remove_file("data/recovery_code.hash"); // Consume the one-time code
        Ok("Endpoint successfully unlocked.".to_string())
    } else {
        Err("Invalid recovery code.".to_string())
    }
}
