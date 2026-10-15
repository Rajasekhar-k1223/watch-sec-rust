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
    pub file_version: Option<String>,
    pub product_version: Option<String>,
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
        use std::os::windows::ffi::OsStrExt;
        use windows::core::PCWSTR;
        use windows::Win32::Storage::FileSystem::{GetFileVersionInfoSizeW, GetFileVersionInfoW, VerQueryValueW, VS_FIXEDFILEINFO};

        fn get_file_version_info(path: &str) -> Option<(String, String)> {
            let path_wide: Vec<u16> = std::ffi::OsStr::new(path).encode_wide().chain(std::iter::once(0)).collect();
            let pcwstr = PCWSTR(path_wide.as_ptr());
            
            unsafe {
                let mut handle = 0;
                let size = GetFileVersionInfoSizeW(pcwstr, Some(&mut handle));
                if size == 0 { return None; }
                
                let mut buffer: Vec<u8> = vec![0; size as usize];
                if GetFileVersionInfoW(pcwstr, handle, size, buffer.as_mut_ptr() as *mut _).is_err() {
                    return None;
                }
                
                let mut ptr = std::ptr::null_mut();
                let mut len = 0;
                let sub_block: Vec<u16> = std::ffi::OsStr::new("\\").encode_wide().chain(std::iter::once(0)).collect();
                let sub_pcwstr = PCWSTR(sub_block.as_ptr());
                
                if VerQueryValueW(buffer.as_ptr() as *const _, sub_pcwstr, &mut ptr, &mut len).as_bool() {
                    if len as usize >= std::mem::size_of::<VS_FIXEDFILEINFO>() {
                        let info = &*(ptr as *const VS_FIXEDFILEINFO);
                        let file_version = format!("{}.{}.{}.{}", 
                            (info.dwFileVersionMS >> 16) & 0xffff, info.dwFileVersionMS & 0xffff,
                            (info.dwFileVersionLS >> 16) & 0xffff, info.dwFileVersionLS & 0xffff
                        );
                        let prod_version = format!("{}.{}.{}.{}", 
                            (info.dwProductVersionMS >> 16) & 0xffff, info.dwProductVersionMS & 0xffff,
                            (info.dwProductVersionLS >> 16) & 0xffff, info.dwProductVersionLS & 0xffff
                        );
                        return Some((file_version, prod_version));
                    }
                }
            }
            None
        }

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
                            let mut version = app_key.get_value::<String, _>("DisplayVersion").unwrap_or_default();
                            
                            let mut exe_path = String::new();
                            if let Ok(icon) = app_key.get_value::<String, _>("DisplayIcon") {
                                exe_path = icon.split(',').next().unwrap_or("").trim_matches('"').to_string();
                            }
                            if exe_path.is_empty() || !exe_path.to_lowercase().ends_with(".exe") {
                                if let Ok(uninstall) = app_key.get_value::<String, _>("UninstallString") {
                                    let un = uninstall.split(" /").next().unwrap_or("").trim_matches('"').to_string();
                                    if un.to_lowercase().ends_with(".exe") {
                                        exe_path = un;
                                    }
                                }
                            }
                            
                            let mut file_version = None;
                            let mut product_version = None;

                            if !exe_path.is_empty() {
                                if let Some((fv, pv)) = get_file_version_info(&exe_path) {
                                    file_version = Some(fv.clone());
                                    product_version = Some(pv.clone());
                                    // [NEW] Dynamically prefer ProductVersion over registry string
                                    if !pv.is_empty() {
                                        version = pv;
                                    } else if !fv.is_empty() {
                                        version = fv;
                                    }
                                }
                            }
                                
                            if version.is_empty() {
                                version = "Unknown".to_string();
                            }

                            software_list.push(InstalledSoftware {
                                name,
                                version,
                                install_date: None,
                                file_version,
                                product_version,
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
                            file_version: None,
                            product_version: None,
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
