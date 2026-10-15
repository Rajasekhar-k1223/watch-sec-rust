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

pub fn sinkhole_domains(domains: Vec<String>) -> Result<String, String> {
    crate::log_msg(&format!("[DNS] Sinkholing {} domains...", domains.len()));
    
    let hosts_path = if cfg!(windows) {
        r"C:\Windows\System32\drivers\etc\hosts"
    } else {
        "/etc/hosts"
    };

    let mut content = fs::read_to_string(hosts_path).unwrap_or_default();
    
    // Add our sinkhole header if not present
    if !content.contains("# --- MONITORIX SINKHOLE ---") {
        content.push_str("\n\n# --- MONITORIX SINKHOLE ---\n");
    }

    let mut added = 0;
    for domain in domains {
        let entry = format!("127.0.0.1 {}", domain);
        if !content.contains(&entry) {
            content.push_str(&format!("{}\n", entry));
            added += 1;
        }
    }

    if added > 0 {
        if let Err(e) = fs::write(hosts_path, content) {
            return Err(format!("Failed to write to hosts file: {}", e));
        }
        Ok(format!("Successfully sinkholed {} new domains", added))
    } else {
        Ok("All domains were already sinkholed".to_string())
    }
}
