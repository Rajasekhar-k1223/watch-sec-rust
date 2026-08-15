use serde_json::{json, Value};

pub fn get_power_status() -> Value {
    let mut percent = 100;
    let mut plugged = true;
    let time_left = -1_i32;

    #[cfg(target_os = "linux")]
    {
        if let Ok(cap) = std::fs::read_to_string("/sys/class/power_supply/BAT0/capacity") {
            percent = cap.trim().parse().unwrap_or(100);
        }
        if let Ok(status) = std::fs::read_to_string("/sys/class/power_supply/BAT0/status") {
            plugged = status.trim() != "Discharging";
        }
    }
    
    #[cfg(target_os = "macos")]
    {
        if let Ok(out) = std::process::Command::new("pmset").arg("-g").arg("batt").output() {
            let out_str = String::from_utf8_lossy(&out.stdout);
            if out_str.contains("Battery") || out_str.contains("InternalBattery") {
                if let Some(p) = out_str.split('%').next().and_then(|s| s.split_whitespace().last()) {
                    percent = p.parse().unwrap_or(100);
                }
                plugged = out_str.contains("AC Power") || out_str.contains("charging");
            }
        }
    }

    #[cfg(target_os = "windows")]
    {
        if let Ok(out) = std::process::Command::new("wmic").args(&["path", "Win32_Battery", "get", "EstimatedChargeRemaining,BatteryStatus"]).output() {
            let out_str = String::from_utf8_lossy(&out.stdout);
            let lines: Vec<&str> = out_str.lines().filter(|l| !l.trim().is_empty()).collect();
            if lines.len() > 1 {
                let parts: Vec<&str> = lines[1].split_whitespace().collect();
                if parts.len() >= 2 {
                    if let Ok(status) = parts[0].parse::<u32>() {
                        plugged = status == 2; // 2 = AC
                    }
                    percent = parts[1].parse().unwrap_or(100);
                }
            }
        }
    }

    json!({
        "battery_percent": percent,
        "power_plugged": plugged,
        "time_left_min": time_left
    })
}
