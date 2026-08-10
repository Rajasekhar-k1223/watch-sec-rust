use std::process::Command;
use serde_json::json;

pub fn get_connected_usbs() -> Vec<serde_json::Value> {
    let mut usbs = Vec::new();

    #[cfg(unix)]
    {
        if let Ok(output) = crate::hidden_command!("lsblk").args(&["-J", "-o", "NAME,RM,TYPE,MOUNTPOINT,SIZE"]).output() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(&stdout) {
                if let Some(blockdevices) = parsed.get("blockdevices").and_then(|v| v.as_array()) {
                    for dev in blockdevices {
                        let rm_val = dev.get("rm");
                        let is_removable = match rm_val {
                            Some(serde_json::Value::String(s)) => s == "1" || s == "true",
                            Some(serde_json::Value::Bool(b)) => *b,
                            Some(serde_json::Value::Number(n)) => n.as_i64() == Some(1),
                            _ => false,
                        };

                        if is_removable {
                            usbs.push(json!({
                                "device_name": dev.get("name").and_then(|v| v.as_str()).unwrap_or("Unknown"),
                                "size": dev.get("size").and_then(|v| v.as_str()).unwrap_or("Unknown"),
                                "mountpoint": dev.get("mountpoint").and_then(|v| v.as_str()).unwrap_or("Unmounted"),
                            }));
                        }
                    }
                }
            }
        }
    }

    #[cfg(windows)]
    {
        let cmd = crate::hidden_command!("powershell")
            .arg("-NoProfile")
            .arg("-Command")
            // Query WMI for external USB drives
            .arg("Get-CimInstance Win32_DiskDrive | Where-Object MediaType -match 'External' | Select-Object Model, Size, DeviceID | ConvertTo-Json -Compress")
            .output();

        if let Ok(output) = cmd {
            let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
            if !stdout.is_empty() {
                if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(&stdout) {
                    if let Some(arr) = parsed.as_array() {
                        for item in arr {
                            usbs.push(item.clone());
                        }
                    } else {
                        usbs.push(parsed);
                    }
                }
            }
        }
    }

    usbs
}

pub fn start_usb_monitor(event_tx: tokio::sync::mpsc::UnboundedSender<serde_json::Value>) {
    std::thread::spawn(move || {
        crate::log_msg("[UsbMonitor] Starting USB active blocking thread.");
        let mut known_usbs: std::collections::HashSet<String> = std::collections::HashSet::new();
        
        loop {
            std::thread::sleep(std::time::Duration::from_secs(5));
            let usbs = get_connected_usbs();
            
            for usb in usbs {
                let id = usb.get("device_name").or_else(|| usb.get("DeviceID")).and_then(|v| v.as_str()).unwrap_or("Unknown").to_string();
                
                if !known_usbs.contains(&id) {
                    known_usbs.insert(id.clone());
                    
                    crate::log_msg(&format!("[UsbMonitor] New USB detected: {}. Attempting to block.", id));
                    
                    #[cfg(unix)]
                    {
                        if let Some(mount) = usb.get("mountpoint").and_then(|v| v.as_str()) {
                            if mount != "Unmounted" {
                                let _ = crate::hidden_command!("umount").arg("-f").arg(mount).output();
                            }
                        }
                    }
                    
                    #[cfg(windows)]
                    {
                        let _ = crate::hidden_command!("powershell")
                            .arg("-NoProfile")
                            .arg("-Command")
                            .arg(&format!("Disable-PnpDevice -InstanceId '{}' -Confirm:$false", id.replace("'", "''")))
                            .output();
                    }
                    
                    let alert = json!({
                        "EventType": "UsbBlocked",
                        "Severity": "High",
                        "DeviceID": id,
                        "ActionTaken": "Blocked/Unmounted",
                        "Timestamp": chrono::Utc::now().to_rfc3339()
                    });
                    
                    let _ = event_tx.send(alert);
                }
            }
        }
    });
}
