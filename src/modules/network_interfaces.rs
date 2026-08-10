use serde_json::json;
use std::fs;

pub fn audit_interfaces() -> serde_json::Value {
    let mut interfaces = Vec::new();
    
    if let Ok(entries) = fs::read_dir("/sys/class/net") {
        for entry in entries.flatten() {
            if let Ok(name) = entry.file_name().into_string() {
                let mac_path = format!("/sys/class/net/{}/address", name);
                let operstate_path = format!("/sys/class/net/{}/operstate", name);
                
                let mac = fs::read_to_string(&mac_path).unwrap_or_else(|_| "UNKNOWN".to_string()).trim().to_string();
                let operstate = fs::read_to_string(&operstate_path).unwrap_or_else(|_| "UNKNOWN".to_string()).trim().to_string();
                
                interfaces.push(json!({
                    "Interface": name,
                    "MAC": mac,
                    "Status": operstate,
                }));
            }
        }
    }

    json!({
        "EventType": "NetworkInterfaceAudit",
        "InterfaceCount": interfaces.len(),
        "Interfaces": interfaces
    })
}
