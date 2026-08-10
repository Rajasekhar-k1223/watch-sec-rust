use serde_json::json;
use std::fs;

pub fn check_dns_config() -> serde_json::Value {
    let mut nameservers = Vec::new();
    let mut hosts_entries = Vec::new();
    let mut anomalies = Vec::new();

    // Parse /etc/resolv.conf
    if let Ok(content) = fs::read_to_string("/etc/resolv.conf") {
        for line in content.lines() {
            if line.starts_with("nameserver ") {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() > 1 {
                    nameservers.push(parts[1].to_string());
                }
            }
        }
    }

    // Parse /etc/hosts for hijacked domains
    if let Ok(content) = fs::read_to_string("/etc/hosts") {
        for line in content.lines() {
            let line = line.trim();
            if !line.starts_with('#') && !line.is_empty() {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() > 1 {
                    let ip = parts[0];
                    let domain = parts[1];
                    hosts_entries.push(format!("{} -> {}", domain, ip));
                    
                    // Simple anomaly check: localhost domains pointing to non-loopback
                    if (domain == "localhost" || domain == "google.com") && !ip.starts_with("127.") && ip != "::1" {
                        anomalies.push(format!("Anomalous DNS routing in hosts file: {} -> {}", domain, ip));
                    }
                }
            }
        }
    }

    json!({
        "EventType": "DNSMonitorReport",
        "Nameservers": nameservers,
        "HostsEntriesCount": hosts_entries.len(),
        "Anomalies": anomalies
    })
}
