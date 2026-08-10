use serde_json::json;
use std::process::Command;

pub fn get_installed_packages() -> serde_json::Value {
    let mut packages = Vec::new();

    // Try dpkg-query for Debian/Ubuntu environments
    let output = crate::hidden_command!("dpkg-query")
        .arg("-W")
        .arg("-f=${Package} ${Version}\n")
        .output();

    if let Ok(out) = output {
        if out.status.success() {
            let stdout = String::from_utf8_lossy(&out.stdout);
            for line in stdout.lines() {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 2 {
                    packages.push(json!({
                        "Package": parts[0],
                        "Version": parts[1]
                    }));
                    // For performance and payload size, we limit this in our V1 release
                    if packages.len() >= 100 { 
                        break;
                    }
                }
            }
        }
    }

    println!("[PatchInventory] Enumerated {} software packages", packages.len());

    json!({
        "EventType": "PatchInventory",
        "Packages": packages,
        "PackageCount": packages.len()
    })
}
