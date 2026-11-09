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
                    
                    // ss output format: protocol, state, recv-q, send-q, local_addr:port, peer_addr:port, [users:(...)]
                    let local_idx = if protocol.starts_with("udp") { 3 } else { 4 };
                    let remote_idx = if protocol.starts_with("udp") { 4 } else { 5 };
                    
                    if parts.len() > remote_idx {
                        let local_addr = parts[local_idx];
                        let remote_addr = parts[remote_idx];

                        // Extract pid and process_name from users:(("name",pid=123,fd=4))
                        let mut pid_str = "0";
                        let mut proc_name = "";
                        for p in &parts[remote_idx + 1..] {
                            if p.contains("pid=") {
                                if let Some(pid_start) = p.find("pid=") {
                                    let rest = &p[pid_start + 4..];
                                    let pid_end = rest.find(|c: char| !c.is_ascii_digit()).unwrap_or(rest.len());
                                    pid_str = &rest[..pid_end];
                                }
                            }
                            if p.contains("((\"") {
                                if let Some(n_start) = p.find("((\"") {
                                    let rest = &p[n_start + 3..];
                                    if let Some(n_end) = rest.find('"') {
                                        proc_name = &rest[..n_end];
                                    }
                                }
                            }
                        }

                        // Parse host and port
                        let (rem_ip, rem_port) = match remote_addr.rfind(':') {
                            Some(idx) => (&remote_addr[..idx], &remote_addr[idx + 1..]),
                            None => (remote_addr, "0"),
                        };

                        connections.push(json!({
                            "protocol": protocol,
                            "state": state,
                            "local_address": local_addr,
                            "remote_address": remote_addr,
                            "remote_ip": rem_ip,
                            "remote_port": rem_port.parse::<u16>().unwrap_or(0),
                            "pid": pid_str.parse::<u32>().unwrap_or(0),
                            "process_name": proc_name,
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

                    let (rem_ip, rem_port) = match remote.rfind(':') {
                        Some(idx) => (&remote[..idx], &remote[idx + 1..]),
                        None => (remote, "0"),
                    };

                    connections.push(json!({
                        "protocol": protocol,
                        "state": state,
                        "local_address": local,
                        "remote_address": remote,
                        "remote_ip": rem_ip,
                        "remote_port": rem_port.parse::<u16>().unwrap_or(0),
                        "pid": pid.parse::<u32>().unwrap_or(0),
                        "process_name": "",
                    }));
                }
            }
        }
    }

    // Advanced Anomaly Detection
    let mut anomalies_detected = Vec::new();
    for conn in &connections {
        if let Some(remote) = conn.get("remote_address").and_then(|v| v.as_str()) {
            if remote.ends_with(":4444") || remote.ends_with(":1337") || remote.ends_with(":8888") || remote.ends_with(":9001") {
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
        "anomalies": anomalies_detected,
        "timestamp": chrono::Utc::now().to_rfc3339()
    })
}
