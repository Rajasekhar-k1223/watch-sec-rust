use serde_json::json;
use std::fs;

pub fn check_bandwidth() -> serde_json::Value {
    let mut usage = Vec::new();
    
    if let Ok(entries) = fs::read_dir("/sys/class/net") {
        for entry in entries.flatten() {
            if let Ok(name) = entry.file_name().into_string() {
                let rx_path = format!("/sys/class/net/{}/statistics/rx_bytes", name);
                let tx_path = format!("/sys/class/net/{}/statistics/tx_bytes", name);
                
                if let Ok(rx_str) = fs::read_to_string(&rx_path) {
                    if let Ok(tx_str) = fs::read_to_string(&tx_path) {
                        let rx_bytes: u64 = rx_str.trim().parse().unwrap_or(0);
                        let tx_bytes: u64 = tx_str.trim().parse().unwrap_or(0);
                        
                        usage.push(json!({
                            "Interface": name,
                            "RX_Bytes": rx_bytes,
                            "TX_Bytes": tx_bytes,
                        }));
                    }
                }
            }
        }
    }

    json!({
        "EventType": "BandwidthUtilizationReport",
        "UsageData": usage
    })
}
