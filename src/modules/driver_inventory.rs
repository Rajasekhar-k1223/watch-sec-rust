use serde_json::json;
use std::fs;
use std::io::{BufRead, BufReader};

pub fn get_kernel_modules() -> serde_json::Value {
    #[allow(unused_mut)]
    let mut modules = Vec::<serde_json::Value>::new();

    // ── Linux: /proc/modules ────────────────────────────────────────────────
    #[cfg(target_os = "linux")]
    if let Ok(file) = fs::File::open("/proc/modules") {
        let reader = BufReader::new(file);
        for line in reader.lines() {
            if let Ok(l) = line {
                let parts: Vec<&str> = l.split_whitespace().collect();
                if !parts.is_empty() {
                    modules.push(json!({
                        "Name":   parts[0],
                        "Size":   parts.get(1).unwrap_or(&"0"),
                        "UsedBy": parts.get(2).unwrap_or(&"0"),
                        "State":  parts.get(4).unwrap_or(&"Unknown"),
                    }));
                }
            }
        }
    }

    // ── macOS: kmutil showloaded (modern) / kextstat fallback ───────────────
    #[cfg(target_os = "macos")]
    {
        // Try kmutil first (macOS 12+ / Apple Silicon)
        let loaded = crate::hidden_command!("kmutil")
            .args(&["showloaded", "--show", "loaded"])
            .output();

        if let Ok(out) = loaded {
            if out.status.success() {
                let out_str = String::from_utf8_lossy(&out.stdout);
                for line in out_str.lines().skip(1) {
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    if parts.len() >= 3 {
                        modules.push(json!({
                            "Name":   parts.last().unwrap_or(&"Unknown"),
                            "Size":   "0",
                            "UsedBy": "0",
                            "State":  "Loaded",
                        }));
                    }
                }
            }
        }

        // Fallback: kextstat (macOS 11 and earlier, still available on 12)
        if modules.is_empty() {
            if let Ok(output) = crate::hidden_command!("kextstat").output() {
                let out_str = String::from_utf8_lossy(&output.stdout);
                for line in out_str.lines().skip(1) {
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    if parts.len() >= 6 {
                        modules.push(json!({
                            "Name":   parts[5],
                            "Size":   parts[3],
                            "UsedBy": "0",
                            "State":  "Loaded",
                        }));
                    }
                }
            }
        }
    }

    // ── Windows: driverquery /fo csv ────────────────────────────────────────
    #[cfg(windows)]
    {
        // driverquery gives all installed kernel drivers and services — no PowerShell needed
        if let Ok(out) = crate::hidden_command!("driverquery")
            .args(&["/fo", "csv", "/nh"])
            .output()
        {
            let stdout = String::from_utf8_lossy(&out.stdout);
            for line in stdout.lines() {
                // CSV format: "ModuleName","DisplayName","DriverType","LinkDate"
                let parts: Vec<&str> = line.split(',').collect();
                if parts.len() >= 4 {
                    let name = parts[0].trim_matches('"');
                    let display = parts[1].trim_matches('"');
                    let kind = parts[2].trim_matches('"');
                    if !name.is_empty() {
                        modules.push(json!({
                            "Name":   name,
                            "Size":   "0",
                            "UsedBy": display,
                            "State":  kind,
                        }));
                    }
                }
            }
        }
    }

    println!("[DriverInventory] Found {} kernel modules/drivers loaded", modules.len());

    json!({
        "EventType":   "DriverInventory",
        "Modules":     modules,
        "ModuleCount": modules.len()
    })
}
