use serde_json::json;
use std::fs;
use std::io::{BufRead, BufReader};

pub fn get_kernel_modules() -> serde_json::Value {
    #[allow(unused_mut)]
    let mut modules = Vec::<serde_json::Value>::new();

    #[cfg(target_os = "linux")]
    if let Ok(file) = fs::File::open("/proc/modules") {
        let reader = BufReader::new(file);
        for line in reader.lines() {
            if let Ok(l) = line {
                let parts: Vec<&str> = l.split_whitespace().collect();
                if !parts.is_empty() {
                    modules.push(json!({
                        "Name": parts[0],
                        "Size": parts.get(1).unwrap_or(&"0"),
                        "UsedBy": parts.get(2).unwrap_or(&"0")
                    }));
                }
            }
        }
    }

    #[cfg(target_os = "macos")]
    if let Ok(output) = crate::hidden_command!("kextstat").output() {
        let out_str = String::from_utf8_lossy(&output.stdout);
        for line in out_str.lines().skip(1) { // Skip header
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 6 {
                modules.push(json!({
                    "Name": parts[5], // The bundle identifier (e.g. com.apple.kext...)
                    "Size": parts[3], // Wired size
                    "UsedBy": "0"     // Not directly mapped in kextstat default view
                }));
            }
        }
    }

    println!("[DriverInventory] Found {} kernel modules loaded in memory", modules.len());

    json!({
        "EventType": "DriverInventory",
        "Modules": modules,
        "ModuleCount": modules.len()
    })
}
