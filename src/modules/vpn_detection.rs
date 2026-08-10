use serde_json::json;
use std::fs;

pub fn detect_vpn() -> serde_json::Value {
    let mut vpn_interfaces = Vec::new();
    
    if let Ok(entries) = fs::read_dir("/sys/class/net") {
        for entry in entries.flatten() {
            if let Ok(name) = entry.file_name().into_string() {
                // Common VPN interfaces: tun, tap, wg (wireguard), ppp
                if name.starts_with("tun") || name.starts_with("tap") || name.starts_with("wg") || name.starts_with("ppp") {
                    vpn_interfaces.push(name);
                }
            }
        }
    }

    json!({
        "EventType": "VPNDetectionAudit",
        "UnauthorizedTunnelsFound": vpn_interfaces.len(),
        "VPNInterfaces": vpn_interfaces
    })
}
