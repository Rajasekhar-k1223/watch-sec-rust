use serde_json::json;

pub fn get_installed_packages() -> serde_json::Value {
    let mut packages = Vec::new();

    #[cfg(not(windows))]
    {
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
                        if packages.len() >= 100 { break; }
                    }
                }
            }
        }
    }

    #[cfg(windows)]
    {
        use winreg::enums::*;
        use winreg::RegKey;
        use std::os::windows::ffi::OsStrExt;
        use windows::core::PCWSTR;
        use windows::Win32::Storage::FileSystem::{GetFileVersionInfoSizeW, GetFileVersionInfoW, VerQueryValueW, VS_FIXEDFILEINFO};

        fn clean_path(val: &str) -> String {
            let mut s = val.trim().to_string();
            if s.starts_with('"') {
                if let Some(idx) = s[1..].find('"') {
                    s = s[1..=idx].to_string();
                }
            }
            if let Some(idx) = s.rfind(',') {
                if s[idx+1..].parse::<u32>().is_ok() {
                    s = s[..idx].to_string();
                }
            }
            s
        }

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

        let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
        let paths = vec![
            "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall",
            "SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall"
        ];

        for path in paths {
            if let Ok(uninstall_key) = hklm.open_subkey_with_flags(path, KEY_READ) {
                for key_name in uninstall_key.enum_keys().filter_map(|k| k.ok()) {
                    if let Ok(app_key) = uninstall_key.open_subkey_with_flags(&key_name, KEY_READ) {
                        let display_name: Result<String, _> = app_key.get_value("DisplayName");
                        let display_version: Result<String, _> = app_key.get_value("DisplayVersion");
                        let display_icon: Result<String, _> = app_key.get_value("DisplayIcon");
                        
                        if let Ok(name) = display_name {
                            let mut ver = display_version.unwrap_or_else(|_| {
                                if let Ok(v) = app_key.get_value::<String, _>("Version") {
                                    return v;
                                }
                                if let (Ok(major), Ok(minor)) = (
                                    app_key.get_value::<u32, _>("VersionMajor"),
                                    app_key.get_value::<u32, _>("VersionMinor")
                                ) {
                                    return format!("{}.{}", major, minor);
                                }
                                "Unknown".to_string()
                            });
                            
                            let mut file_ver = ver.clone();
                            let mut prod_ver = ver.clone();

                            if let Ok(icon) = display_icon {
                                let exe_path = clean_path(&icon);
                                if let Some((fv, pv)) = get_file_version_info(&exe_path) {
                                    file_ver = fv;
                                    prod_ver = pv;
                                }
                            }

                            packages.push(json!({
                                "Package": name,
                                "Version": ver,
                                "FileVersion": file_ver,
                                "ProductVersion": prod_ver
                            }));
                            if packages.len() >= 300 { break; }
                        }
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
