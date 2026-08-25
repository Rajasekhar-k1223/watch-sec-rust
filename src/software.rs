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

    #[cfg(windows)]
    {
        use winreg::enums::*;
        use winreg::RegKey;

        let paths = vec![
            (RegKey::predef(HKEY_LOCAL_MACHINE), "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall"),
            (RegKey::predef(HKEY_LOCAL_MACHINE), "SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall"),
            (RegKey::predef(HKEY_CURRENT_USER), "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall"),
        ];
        
        for (hive, path) in paths {
            if let Ok(uninstall_key) = hive.open_subkey_with_flags(path, KEY_READ) {
                for key_name_res in uninstall_key.enum_keys().map(|x| x.unwrap_or_default()) {
                    if key_name_res.is_empty() { continue; }
                    
                    if let Ok(app_key) = uninstall_key.open_subkey_with_flags(&key_name_res, KEY_READ) {
                        // Skip system components
                        if let Ok(sys_comp) = app_key.get_value::<u32, _>("SystemComponent") {
                            if sys_comp == 1 { continue; }
                        }
                        
                        // Skip if it has a ParentKeyName (it's an update)
                        if app_key.get_value::<String, _>("ParentKeyName").is_ok() {
                            continue;
                        }
                        
                        if let Ok(name) = app_key.get_value::<String, _>("DisplayName") {
                            let version = app_key.get_value::<String, _>("DisplayVersion").unwrap_or_default();
                            software_list.push(InstalledSoftware {
                                name,
                                version,
                                install_date: None,
                            });
                        }
                    }
                }
            }
        }
    }
    
    #[cfg(not(windows))]
    {
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
