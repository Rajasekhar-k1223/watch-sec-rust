use serde::{Serialize, Deserialize};
use std::sync::Mutex;
use lazy_static::lazy_static;
use std::time::{Instant, Duration};

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "PascalCase")]
pub struct InstalledSoftware {
    pub name: String,
    pub version: String,
    pub install_date: Option<String>,
}

lazy_static! {
    static ref SOFTWARE_CACHE: Mutex<Option<(String, Instant)>> = Mutex::new(None);
}

pub fn get_installed_software() -> String {
    // Check cache first (valid for 1 hour)
    {
        let cache = SOFTWARE_CACHE.lock().unwrap();
        if let Some((cached_json, timestamp)) = &*cache {
            // [FIX] Reduced cache from 1 hour to 5 minutes so newly installed software appears faster
            if timestamp.elapsed() < Duration::from_secs(300) {
                return cached_json.clone();
            }
        }
    }

    let mut software_list = Vec::new();

    if cfg!(target_os = "windows") {
        let output = crate::hidden_command!("powershell")
            .arg("-NoProfile")
            .arg("-Command")
            .arg("[Console]::OutputEncoding = [System.Text.Encoding]::UTF8; try { @(Get-ItemProperty HKLM:\\Software\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*, HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*, HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\* -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName -ne $null -and $_.SystemComponent -ne 1 -and $_.ParentKeyName -eq $null } | Select-Object DisplayName, DisplayVersion) | ConvertTo-Json -Compress } catch { '[]' }")
            .output();

        if let Ok(output) = output {
            let result_str = String::from_utf8_lossy(&output.stdout);
            let clean_str = result_str.trim().trim_start_matches('\u{FEFF}');
            if let Ok(apps) = serde_json::from_str::<Vec<serde_json::Value>>(clean_str) {
                for app in apps {
                    if let (Some(name), Some(version)) = (
                        app.get("DisplayName").and_then(|v| v.as_str()),
                        app.get("DisplayVersion").and_then(|v| v.as_str())
                    ) {
                        software_list.push(InstalledSoftware {
                            name: name.to_string(),
                            version: version.to_string(),
                            install_date: None,
                        });
                    }
                }
            }
        }
    } else {
        // We use dpkg-query as this agent runs on Linux
        let output = crate::hidden_command!("dpkg-query")
            .arg("-W")
            .arg("-f=${binary:Package} ${Version}\\n")
            .output();

        if let Ok(output) = output {
            if output.status.success() {
                let result_str = String::from_utf8_lossy(&output.stdout);
                for line in result_str.lines() {
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    if parts.len() >= 2 {
                        software_list.push(InstalledSoftware {
                            name: parts[0].to_string(),
                            version: parts[1].to_string(),
                            install_date: None,
                        });
                    }
                }
            }
        }
    }

    let result = serde_json::to_string(&software_list).unwrap_or_else(|_| "[]".to_string());
    
    // Update cache
    if let Ok(mut cache) = SOFTWARE_CACHE.lock() {
        *cache = Some((result.clone(), Instant::now()));
    }
    
    result
}
