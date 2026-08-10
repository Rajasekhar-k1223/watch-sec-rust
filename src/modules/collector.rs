use std::process::Command;
use std::fs;
use std::path::Path;

pub fn trigger_collection(output_dir: &str) -> Result<String, String> {
    let out_path = Path::new(output_dir);
    if !out_path.exists() {
        fs::create_dir_all(out_path).map_err(|e| format!("Failed to create output dir: {}", e))?;
    }

    #[cfg(unix)]
    {
        // Copy critical logs (ignoring errors if files don't exist)
        let _ = fs::copy("/var/log/auth.log", out_path.join("auth.log"));
        let _ = fs::copy("/var/log/secure", out_path.join("secure"));
        let _ = fs::copy("/var/log/syslog", out_path.join("syslog"));
        let _ = fs::copy("/etc/passwd", out_path.join("passwd"));
        
        // Process dump
        if let Ok(ps) = crate::hidden_command!("ps").arg("aux").output() {
            let _ = fs::write(out_path.join("ps_aux.txt"), ps.stdout);
        }
        
        // Network state
        if let Ok(ss) = crate::hidden_command!("ss").args(&["-tunap"]).output() {
            let _ = fs::write(out_path.join("ss_tunap.txt"), ss.stdout);
        }
        
        // Kernel messages
        if let Ok(dmesg) = crate::hidden_command!("dmesg").output() {
            let _ = fs::write(out_path.join("dmesg.txt"), dmesg.stdout);
        }

        Ok(format!("Unix forensic artifacts collected successfully to {}", output_dir))
    }

    #[cfg(windows)]
    {
        // Export Event Logs via wevtutil
        let sys_path = out_path.join("System.evtx").to_string_lossy().to_string();
        let _ = crate::hidden_command!("wevtutil").args(&["epl", "System", &sys_path]).output();
            
        let sec_path = out_path.join("Security.evtx").to_string_lossy().to_string();
        let _ = crate::hidden_command!("wevtutil").args(&["epl", "Security", &sec_path]).output();
            
        // Process dump
        if let Ok(tasklist) = crate::hidden_command!("tasklist").args(&["/v"]).output() {
            let _ = fs::write(out_path.join("tasklist.txt"), tasklist.stdout);
        }
        
        // Network state
        if let Ok(netstat) = crate::hidden_command!("netstat").args(&["-ano"]).output() {
            let _ = fs::write(out_path.join("netstat.txt"), netstat.stdout);
        }
        
        Ok(format!("Windows forensic artifacts collected successfully to {}", output_dir))
    }
}
