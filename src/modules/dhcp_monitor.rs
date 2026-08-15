use serde_json::json;

pub fn audit_dhcp() -> serde_json::Value {
    let mut dhcp_events: Vec<String> = Vec::new();

    #[cfg(unix)]
    {
        // Simple heuristic: grep journalctl for DHCPACK or DHCPREQUEST
        if let Ok(output) = crate::hidden_command!("journalctl").args(&["-u", "NetworkManager", "--since", "1 hour ago"]).output() {
            let log_out = String::from_utf8_lossy(&output.stdout);
            for line in log_out.lines() {
                if line.contains("DHCPACK") || line.contains("DHCPREQUEST") {
                    dhcp_events.push(line.trim().to_string());
                }
            }
        }
    }

    let is_empty = dhcp_events.is_empty();
    json!({
        "EventType": "DHCPMonitorReport",
        "RecentEvents": dhcp_events,
        "Status": if is_empty { "No recent DHCP activity" } else { "DHCP Activity Detected" }
    })
}
