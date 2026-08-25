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
        use wmi::{COMLibrary, WMIConnection};
        use serde::Deserialize;

        #[derive(Deserialize, Debug)]
        #[serde(rename_all = "PascalCase")]
        struct Win32_DiskDrive {
            pub model: Option<String>,
            pub size: Option<u64>,
            pub device_id: Option<String>,
            pub media_type: Option<String>,
        }

        if let Ok(com_con) = COMLibrary::new() {
            if let Ok(wmi_con) = WMIConnection::with_namespace_path("ROOT\\CIMV2", com_con.into()) {
                if let Ok(results) = wmi_con.raw_query::<Win32_DiskDrive>("SELECT Model, Size, DeviceID, MediaType FROM Win32_DiskDrive") {
                    for drive in results {
                        if let Some(media) = drive.media_type {
                            if media.to_lowercase().contains("external") {
                                usbs.push(json!({
                                    "Model": drive.model.unwrap_or_default(),
                                    "Size": drive.size.unwrap_or_default(),
                                    "DeviceID": drive.device_id.unwrap_or_default(),
                                }));
                            }
                        }
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
            std::thread::sleep(std::time::Duration::from_secs(60));
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
                        // Using native pnputil instead of powershell
                        let _ = crate::hidden_command!("pnputil")
                            .args(&["/disable-device", &id])
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
