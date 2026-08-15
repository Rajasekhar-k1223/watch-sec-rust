use serde_json::json;
use std::time::{SystemTime, UNIX_EPOCH};

pub fn generate_timeline() -> serde_json::Value {
    let mut timeline = Vec::new();
    
    // Add current timestamp
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
    
    timeline.push(json!({
        "timestamp": now,
        "event": "Timeline Generation Started",
    }));

    // Add recent logins (last)
    if let Ok(output) = crate::hidden_command!("last").arg("-n").arg("5").output() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        for line in stdout.lines() {
            if !line.is_empty() && !line.starts_with("wtmp begins") {
                timeline.push(json!({
                    "timestamp": now,
                    "event": format!("Recent Login Activity: {}", line),
                }));
            }
        }
    }

    json!({
        "EventType": "ForensicTimelineReport",
        "EventsCount": timeline.len(),
        "Timeline": timeline
    })
}
