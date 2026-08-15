use serde_json::json;

pub fn track_location() -> serde_json::Value {
    let mut location_data = json!({"error": "Failed to retrieve location via curl"});

    // Quick and dirty IP Geolocation without introducing blocking reqwest calls 
    // into the async tokio main loop. First try curl, as it's cross platform.
    if let Ok(output) = crate::hidden_command!("curl")
        .args(&["-s", "--max-time", "5", "https://ipinfo.io/json"])
        .output()
    {
        if output.status.success() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(&stdout) {
                location_data = parsed;
            }
        } else {
            // Fallback for Windows if curl isn't available
            #[cfg(target_os = "windows")]
            {
                if let Ok(ps_output) = crate::hidden_command!("powershell")
                    .args(&["-NoProfile", "-Command", "(Invoke-RestMethod -Uri 'https://ipinfo.io/json' -TimeoutSec 5) | ConvertTo-Json"])
                    .output()
                {
                    if ps_output.status.success() {
                        let stdout = String::from_utf8_lossy(&ps_output.stdout);
                        if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(&stdout) {
                            location_data = parsed;
                        }
                    }
                }
            }
        }
    }

    json!({
        "EventType": "LocationTrackingReport",
        "LocationData": location_data
    })
}
