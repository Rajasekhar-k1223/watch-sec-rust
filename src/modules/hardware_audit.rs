use serde_json::json;
use std::fs;

pub fn audit_hardware() -> serde_json::Value {
    let mut temp_c = "N/A".to_string();
    let mut battery_level = "N/A".to_string();

    // Check CPU Temp (Linux Thermal Zone & macOS sysctl)
    if let Ok(content) = fs::read_to_string("/sys/class/thermal/thermal_zone0/temp") {
        if let Ok(milli_celsius) = content.trim().parse::<f64>() {
            temp_c = format!("{:.1}°C", milli_celsius / 1000.0);
        }
    }
    
    #[cfg(target_os = "macos")]
    if temp_c == "N/A" {
        if let Ok(output) = crate::hidden_command!("sysctl").arg("-n").arg("machdep.xcpm.cpu_thermal_level").output() {
            let out_str = String::from_utf8_lossy(&output.stdout);
            if let Ok(thermal_level) = out_str.trim().parse::<i32>() {
                temp_c = format!("Thermal Level: {}", thermal_level);
            }
        }
    }

    // Check Battery Level
    if let Ok(content) = fs::read_to_string("/sys/class/power_supply/BAT0/capacity") {
        battery_level = format!("{}%", content.trim());
    }
    // Check GPU (Linux)
    let mut gpus = Vec::<String>::new();
    #[cfg(unix)]
    {
        if let Ok(output) = crate::hidden_command!("lspci").output() {
            let lspci_out = String::from_utf8_lossy(&output.stdout);
            for line in lspci_out.lines() {
                if line.to_lowercase().contains("vga") || line.to_lowercase().contains("3d controller") {
                    gpus.push(line.trim().to_string());
                }
            }
        }
    }

    let mut secure_enclave_status = "N/A".to_string();
    #[cfg(target_os = "macos")]
    {
        if let Ok(output) = crate::hidden_command!("system_profiler").arg("SPiBridgeDataType").output() {
            let sp_out = String::from_utf8_lossy(&output.stdout);
            if sp_out.contains("Apple T2 Security Chip") || sp_out.contains("Secure Enclave") {
                secure_enclave_status = "Active".to_string();
            } else {
                secure_enclave_status = "Not Detected".to_string();
            }
        }
    }

    json!({
        "EventType": "HardwareHealthReport",
        "CPUTemperature": temp_c,
        "BatteryCapacity": battery_level,
        "GPUs": gpus,
        "SecureEnclave": secure_enclave_status
    })
}
