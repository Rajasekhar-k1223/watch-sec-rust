use std::fs;

pub fn trigger_memory_dump(pid: &str, output_dir: &str) -> Result<String, String> {
    println!("[MemoryDump] Triggering memory dump for PID {} into {}", pid, output_dir);
    
    // Ensure output directory exists
    let _ = fs::create_dir_all(output_dir);
    
    let dump_file = format!("{}/core.{}", output_dir, pid);
    
    #[cfg(target_os = "linux")]
    match crate::hidden_command!("gcore").arg("-o").arg(&format!("{}/core", output_dir)).arg(pid).output() {
        Ok(output) => {
            if output.status.success() {
                Ok(format!("Memory dump successfully generated at {}", dump_file))
            } else {
                let stderr = String::from_utf8_lossy(&output.stderr).to_string();
                Err(format!("gcore failed: {}", stderr))
            }
        },
        Err(e) => Err(format!("Failed to execute gcore (is it installed?): {}", e))
    }

    #[cfg(target_os = "macos")]
    match crate::hidden_command!("lldb").arg("-p").arg(pid).arg("-o").arg(format!("process save-core {}/core.{}", output_dir, pid)).arg("-o").arg("quit").output() {
        Ok(output) => {
            if output.status.success() {
                Ok(format!("User-space memory dump generated at {} via lldb", dump_file))
            } else {
                let stderr = String::from_utf8_lossy(&output.stderr).to_string();
                // Fallback to vmmap or sysdiagnose due to SIP
                if let Ok(vmmap_out) = crate::hidden_command!("vmmap").arg(pid).output() {
                    let map_file = format!("{}/vmmap.{}", output_dir, pid);
                    let _ = fs::write(&map_file, vmmap_out.stdout);
                    Ok(format!("lldb dump blocked by SIP. Gathered process memory map via vmmap at {}", map_file))
                } else {
                    Err(format!("lldb dump failed (SIP restricted) and vmmap fallback failed: {}", stderr))
                }
            }
        },
        Err(e) => Err(format!("Failed to execute lldb (is it installed?): {}", e))
    }
    
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = dump_file; // suppress unused warning on other platforms
        Err("Memory dump not supported on this OS".to_string())
    }
}
