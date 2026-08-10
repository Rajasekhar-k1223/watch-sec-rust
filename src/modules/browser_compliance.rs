use serde_json::json;
use std::fs;

pub fn audit_browsers() -> serde_json::Value {
    let mut extensions = Vec::new();
    
    #[cfg(not(target_os = "windows"))]
    let chrome_ext_path = std::env::var("HOME").unwrap_or_else(|_| "/root".to_string()) + "/.config/google-chrome/Default/Extensions";
    #[cfg(not(target_os = "windows"))]
    let mut paths_to_check = vec![("Chrome", chrome_ext_path)];
    
    #[cfg(target_os = "windows")]
    let appdata = std::env::var("LOCALAPPDATA").unwrap_or_else(|_| r"C:\Users\Default\AppData\Local".to_string());
    #[cfg(target_os = "windows")]
    let mut paths_to_check = vec![
        ("Chrome", format!(r"{}\Google\Chrome\User Data\Default\Extensions", appdata)),
        ("Edge", format!(r"{}\Microsoft\Edge\User Data\Default\Extensions", appdata))
    ];
    
    for (browser, ext_path) in paths_to_check {
        if let Ok(entries) = fs::read_dir(&ext_path) {
            for entry in entries.flatten() {
                if let Ok(file_type) = entry.file_type() {
                    if file_type.is_dir() {
                        if let Ok(name) = entry.file_name().into_string() {
                            extensions.push(json!({
                                "Browser": browser,
                                "ExtensionID": name,
                            }));
                        }
                    }
                }
            }
        }
    }

    json!({
        "EventType": "BrowserComplianceAudit",
        "ExtensionsFound": extensions.len(),
        "Extensions": extensions
    })
}
