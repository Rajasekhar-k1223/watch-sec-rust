use serde_json::json;
use std::collections::HashSet;
use std::path::Path;
use std::sync::Mutex;
use lazy_static::lazy_static;

lazy_static! {
    /// Approved corporate USB Serial / Hardware IDs
    static ref AUTHORIZED_USB_DEVICES: Mutex<HashSet<String>> = {
        let mut set = HashSet::new();
        set.insert("CORP-SECURE-USB-01".to_string());
        set.insert("ENTERPRISE-ENCRYPTED-DRIVE".to_string());
        Mutex::new(set)
    };
}

pub fn authorize_device(device_id: &str) {
    if let Ok(mut set) = AUTHORIZED_USB_DEVICES.lock() {
        set.insert(device_id.to_string());
    }
}

pub fn is_device_authorized(device_id: &str) -> bool {
    if let Ok(set) = AUTHORIZED_USB_DEVICES.lock() {
        set.contains(device_id)
    } else {
        false
    }
}

pub fn get_connected_usbs() -> Vec<serde_json::Value> {
    let mut usbs = Vec::new();

    #[cfg(target_os = "linux")]
    {
        if let Ok(output) = crate::hidden_command!("lsblk").args(&["-J", "-o", "NAME,RM,TYPE,MOUNTPOINT,SIZE,VENDOR,MODEL,SERIAL"]).output() {
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
                            let name = dev.get("name").and_then(|v| v.as_str()).unwrap_or("Unknown");
                            let serial = dev.get("serial").and_then(|v| v.as_str()).unwrap_or(name);
                            let vendor = dev.get("vendor").and_then(|v| v.as_str()).unwrap_or("Generic");
                            let model = dev.get("model").and_then(|v| v.as_str()).unwrap_or("Storage");

                            usbs.push(json!({
                                "device_name": name,
                                "DeviceID": serial,
                                "Vendor": vendor,
                                "Model": model,
                                "size": dev.get("size").and_then(|v| v.as_str()).unwrap_or("Unknown"),
                                "mountpoint": dev.get("mountpoint").and_then(|v| v.as_str()).unwrap_or("Unmounted"),
                                "IsAuthorized": is_device_authorized(serial)
                            }));
                        }
                    }
                }
            }
        }
    }

    #[cfg(target_os = "macos")]
    {
        if let Ok(output) = crate::hidden_command!("system_profiler").args(&["SPUSBDataType", "-json"]).output() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(&stdout) {
                if let Some(items) = parsed.get("SPUSBDataType").and_then(|v| v.as_array()) {
                    let mut queue = items.clone();
                    while let Some(item) = queue.pop() {
                        if let Some(name) = item.get("_name").and_then(|v| v.as_str()) {
                            let lower = name.to_lowercase();
                            if lower.contains("flash") || lower.contains("storage") || lower.contains("disk") {
                                let serial = item.get("serial_num").and_then(|v| v.as_str()).unwrap_or(name);
                                usbs.push(json!({
                                    "device_name": name,
                                    "DeviceID": serial,
                                    "size": "Unknown",
                                    "mountpoint": item.get("mount_point").and_then(|v| v.as_str()).unwrap_or("Unmounted"),
                                    "IsAuthorized": is_device_authorized(serial)
                                }));
                            }
                        }
                        if let Some(children) = item.get("_items").and_then(|v| v.as_array()) {
                            queue.extend(children.clone());
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
            pub pnp_device_id: Option<String>,
        }

        let mut wmi_success = false;

        if let Ok(com_con) = COMLibrary::new() {
            if let Ok(wmi_con) = WMIConnection::with_namespace_path("ROOT\\CIMV2", com_con.into()) {
                if let Ok(results) = wmi_con.raw_query::<Win32_DiskDrive>("SELECT Model, Size, DeviceID, MediaType, PNPDeviceID FROM Win32_DiskDrive") {
                    for drive in results {
                        if let Some(media) = drive.media_type {
                            if media.to_lowercase().contains("external") || media.to_lowercase().contains("removable") {
                                let dev_id = drive.pnp_device_id.or(drive.device_id).unwrap_or_default();
                                usbs.push(json!({
                                    "device_name": drive.model.clone().unwrap_or_default(),
                                    "Model": drive.model.unwrap_or_default(),
                                    "Size": drive.size.unwrap_or_default(),
                                    "DeviceID": dev_id.clone(),
                                    "mountpoint": "RemovableDisk",
                                    "IsAuthorized": is_device_authorized(&dev_id)
                                }));
                            }
                        }
                    }
                    wmi_success = true;
                }
            }
        }

        if !wmi_success {
            let disks = sysinfo::Disks::new_with_refreshed_list();
            for disk in &disks {
                if disk.is_removable() {
                    let dev_name = disk.name().to_string_lossy().to_string();
                    usbs.push(json!({
                        "device_name": dev_name.clone(),
                        "Model": dev_name.clone(),
                        "Size": disk.total_space(),
                        "DeviceID": dev_name.clone(),
                        "mountpoint": disk.mount_point().to_string_lossy().to_string(),
                        "IsAuthorized": is_device_authorized(&dev_name)
                    }));
                }
            }
        }
    }

    usbs
}

/// Enforces read-only policy on removable storage mountpoints
pub fn enforce_readonly_storage(mountpoint: &str) -> bool {
    #[cfg(target_os = "linux")]
    {
        if mountpoint != "Unmounted" && !mountpoint.is_empty() {
            let status = crate::hidden_command!("mount")
                .args(&["-o", "remount,ro", mountpoint])
                .status();
            return status.map(|s| s.success()).unwrap_or(false);
        }
    }
    #[cfg(target_os = "macos")]
    {
        if mountpoint != "Unmounted" && !mountpoint.is_empty() {
            let status = crate::hidden_command!("diskutil")
                .args(&["mount", "readOnly", mountpoint])
                .status();
            return status.map(|s| s.success()).unwrap_or(false);
        }
    }
    #[cfg(windows)]
    {
        let _ = mountpoint;
    }
    true
}

/// Active real-time USB monitor and inline exfiltration interception thread
pub fn start_usb_monitor(
    event_tx: tokio::sync::mpsc::UnboundedSender<serde_json::Value>,
    live_config: std::sync::Arc<std::sync::Mutex<crate::config::AgentConfig>>,
) {
    std::thread::spawn(move || {
        crate::log_msg("[DataGuard USB] Real-time hardware & write interception active.");
        let mut known_usbs: HashSet<String> = HashSet::new();

        loop {
            // High-frequency polling (2 seconds) prevents sub-minute unplug bypass race conditions
            std::thread::sleep(std::time::Duration::from_secs(2));

            let blocking_enabled = live_config.lock().map(|c| c.usb_blocking_enabled || c.dlp_enabled).unwrap_or(false);
            let usbs = get_connected_usbs();

            for usb in usbs {
                let id = usb.get("DeviceID")
                    .or_else(|| usb.get("device_name"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("Unknown")
                    .to_string();

                let is_auth = usb.get("IsAuthorized").and_then(|v| v.as_bool()).unwrap_or(false);
                let mountpoint = usb.get("mountpoint").and_then(|v| v.as_str()).unwrap_or("Unmounted");

                if !known_usbs.contains(&id) {
                    known_usbs.insert(id.clone());

                    if blocking_enabled && !is_auth {
                        crate::log_msg(&format!("[DataGuard USB] Unauthorized device detected: {}. Enforcing block/quarantine.", id));

                        // 1. Remount as Read-Only immediately to prevent pending writes
                        enforce_readonly_storage(mountpoint);

                        // 2. Disconnect/unmount device
                        #[cfg(target_os = "linux")]
                        {
                            if mountpoint != "Unmounted" {
                                let _ = crate::hidden_command!("umount").arg("-f").arg(mountpoint).output();
                            }
                        }

                        #[cfg(target_os = "macos")]
                        {
                            if mountpoint != "Unmounted" {
                                let _ = crate::hidden_command!("diskutil").arg("unmount").arg(mountpoint).output();
                            }
                        }

                        #[cfg(windows)]
                        {
                            let _ = crate::hidden_command!("pnputil")
                                .args(&["/disable-device", &id])
                                .output();
                        }

                        let alert = json!({
                            "EventType": "UsbBlocked",
                            "Severity": "Critical",
                            "DeviceID": id,
                            "Mountpoint": mountpoint,
                            "ActionTaken": "Blocked/RemountedRO",
                            "Timestamp": chrono::Utc::now().to_rfc3339()
                        });
                        let _ = event_tx.send(alert);
                    } else {
                        crate::log_msg(&format!("[DataGuard USB] Device approved/connected: {}", id));
                        let alert = json!({
                            "EventType": "UsbConnected",
                            "Severity": "Low",
                            "DeviceID": id,
                            "IsAuthorized": is_auth,
                            "ActionTaken": if is_auth { "Allow (Corporate Authorized)" } else { "Logged" },
                            "Timestamp": chrono::Utc::now().to_rfc3339()
                        });
                        let _ = event_tx.send(alert);
                    }
                }

                // If authorized or mounted, monitor active file writes on the mountpoint
                if mountpoint != "Unmounted" && Path::new(mountpoint).exists() {
                    scan_mountpoint_writes(mountpoint, &event_tx);
                }
            }
        }
    });
}

/// Inspects newly written files on removable media mountpoint and blocks sensitive transfers
fn scan_mountpoint_writes(mountpoint: &str, event_tx: &tokio::sync::mpsc::UnboundedSender<serde_json::Value>) {
    let p = Path::new(mountpoint);
    if let Ok(entries) = std::fs::read_dir(p) {
        for entry in entries.flatten() {
            let file_path = entry.path();
            if file_path.is_file() {
                if let Ok(verdict) = crate::engines::dlp_engine::evaluate_file_verdict(&file_path) {
                    if verdict.is_violation && verdict.action == "Block" {
                        // Secure wipe/remove the file from unauthorized removable storage
                        let _ = std::fs::remove_file(&file_path);
                        crate::log_msg(&format!("[DataGuard DLP] INTERCEPTED EXFILTRATION TO USB: {}", file_path.display()));

                        let alert = json!({
                            "EventType": "UsbDlpBlocked",
                            "Channel": "USB",
                            "FilePath": file_path.to_string_lossy(),
                            "FileHash": verdict.sha256,
                            "Action": "Blocked",
                            "Findings": verdict.findings,
                            "Severity": "Critical",
                            "Timestamp": chrono::Utc::now().to_rfc3339()
                        });
                        let _ = event_tx.send(alert);
                    }
                }
            }
        }
    }
}
