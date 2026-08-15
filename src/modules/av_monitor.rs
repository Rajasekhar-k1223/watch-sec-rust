use sysinfo::System;
use serde_json::json;

pub fn check_av_status() -> serde_json::Value {
    let mut av_found = false;
    let mut details = String::from("Unknown");

    #[cfg(unix)]
    {
        let mut sys = System::new();
        sys.refresh_processes();
        let av_processes = ["clamd", "falcon-sensor", "trapsd", "bdss", "sophos"]; 
        
        for process in sys.processes().values() {
            let name = process.name().to_string().to_lowercase();
            for av in av_processes.iter() {
                if name.contains(av) {
                    av_found = true;
                    details = format!("Found AV Process: {}", name);
                    break;
                }
            }
            if av_found { break; }
        }
        
        if !av_found {
            details = "No known AV process found".to_string();
        }
    }

    #[cfg(windows)]
    {
        let cmd = crate::hidden_command!("powershell")
            .arg("-NoProfile")
            .arg("-Command")
            .arg("Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntivirusProduct | Select-Object -ExpandProperty displayName")
            .output();
            
        if let Ok(output) = cmd {
            let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
            if !stdout.is_empty() {
                av_found = true;
                details = format!("Found AV: {}", stdout);
            } else {
                details = "No AV registered in SecurityCenter2".to_string();
            }
        } else {
            details = "Failed to query SecurityCenter2".to_string();
        }
    }

    json!({
        "type": "AntivirusStatus",
        "enabled": av_found,
        "details": details,
    })
}
