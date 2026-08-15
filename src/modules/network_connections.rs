use serde_json::json;

pub fn get_network_connections() -> serde_json::Value {
    let mut connections = Vec::new();

    #[cfg(unix)]
    {
        if let Ok(output) = crate::hidden_command!("ss").args(&["-tunap"]).output() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            for line in stdout.lines().skip(1) { // Skip header
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 5 {
                    let protocol = parts[0];
                    let state = if protocol.starts_with("udp") { "UNCONN" } else { parts[1] };
                    
                    // ss output format varies slightly, index might shift
                    let local_idx = if protocol.starts_with("udp") { 3 } else { 4 };
                    let remote_idx = if protocol.starts_with("udp") { 4 } else { 5 };
                    
                    if parts.len() > remote_idx {
                        connections.push(json!({
                            "protocol": protocol,
                            "state": state,
                            "local_address": parts[local_idx],
                            "remote_address": parts[remote_idx],
                        }));
                    }
                }
            }
        }
    }

    #[cfg(windows)]
    {
        if let Ok(output) = crate::hidden_command!("netstat").args(&["-ano"]).output() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            for line in stdout.lines().skip(4) { // Skip header lines
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 4 {
                    let protocol = parts[0];
                    let local = parts[1];
                    let remote = parts[2];
                    
                    let mut state = "UNKNOWN";
                    let mut pid = "0";
                    
                    if parts.len() >= 5 {
                        state = parts[3];
                        pid = parts[4];
                    } else if parts.len() == 4 {
                        // UDP has no state
                        pid = parts[3];
                    }

                    connections.push(json!({
                        "protocol": protocol,
                        "state": state,
                        "local_address": local,
                        "remote_address": remote,
                        "pid": pid,
                    }));
                }
            }
        }
    }

    // Advanced Anomaly Detection
    let mut anomalies_detected = Vec::new();
    for conn in &connections {
        if let Some(remote) = conn.get("remote_address").and_then(|v| v.as_str()) {
            if remote.ends_with(":4444") || remote.ends_with(":1337") {
                anomalies_detected.push(conn.clone());
            }
        }
    }

    if !anomalies_detected.is_empty() {
        println!("[NetworkMonitor] WARNING: Detected connections to suspicious ports!");
    }

    json!({
        "EventType": "NetworkConnectionsAudit",
        "connections": connections,
        "anomalies": anomalies_detected
    })
}
