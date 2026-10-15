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
        if let Ok(out) = crate::hidden_command!("pmset").arg("-g").arg("batt").output() {
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
        use wmi::{COMLibrary, WMIConnection};
        use serde::Deserialize;
        use windows::Win32::System::Power::{GetSystemPowerStatus, SYSTEM_POWER_STATUS};

        #[derive(Deserialize, Debug)]
        #[serde(rename_all = "PascalCase")]
        struct Win32Battery {
            pub estimated_charge_remaining: Option<u16>,
            pub battery_status: Option<u16>,
        }

        let mut wmi_success = false;

        if let Ok(com_con) = COMLibrary::new() {
            if let Ok(wmi_con) = WMIConnection::new(com_con.into()) {
                if let Ok(results) = wmi_con.raw_query::<Win32Battery>("SELECT EstimatedChargeRemaining, BatteryStatus FROM Win32_Battery") {
                    if let Some(battery) = results.first() {
                        if let Some(status) = battery.battery_status {
                            plugged = status == 2; // 2 = AC
                        }
                        if let Some(charge) = battery.estimated_charge_remaining {
                            percent = charge as i32;
                        }
                        wmi_success = true;
                    }
                }
            }
        }

        if !wmi_success {
            // WMI Failed (Service disabled or errored out). Fallback to Win32 API.
            unsafe {
                let mut status = SYSTEM_POWER_STATUS::default();
                if GetSystemPowerStatus(&mut status).is_ok() {
                    if status.BatteryLifePercent != 255 {
                        percent = status.BatteryLifePercent as i32;
                    }
                    plugged = status.ACLineStatus == 1;
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
