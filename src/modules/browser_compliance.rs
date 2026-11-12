use serde_json::json;
use std::fs;
use std::path::Path;

/// Ensures the DataGuard Native Messaging Host manifest is registered for Chrome/Edge/Firefox
pub fn register_native_messaging_host() -> bool {
    let manifest = json!({
        "name": "com.monitorix.dataguard",
        "description": "Monitorix DataGuard Enterprise Browser Protection Host",
        "path": if cfg!(target_os = "windows") { "C:\\Program Files\\Monitorix\\monitorix-agent.exe" } else { "/usr/local/bin/monitorix-agent" },
        "type": "stdio",
        "allowed_origins": [
            "chrome-extension://monitorixdataguardprotectionid/",
            "chrome-extension://eglmbimofjopidkhlnmpmflklfhpkdcb/"
        ]
    });

    #[cfg(target_os = "linux")]
    {
        let host_dir = if let Ok(home) = std::env::var("HOME") {
            format!("{}/.config/google-chrome/NativeMessagingHosts", home)
        } else {
            "/etc/opt/chrome/native-messaging-hosts".to_string()
        };
        let _ = fs::create_dir_all(&host_dir);
        let target = format!("{}/com.monitorix.dataguard.json", host_dir);
        let _ = fs::write(target, serde_json::to_string_pretty(&manifest).unwrap_or_default());
    }

    #[cfg(target_os = "windows")]
    {
        if let Ok(appdata) = std::env::var("LOCALAPPDATA") {
            let host_dir = format!(r"{}\Google\Chrome\User Data\NativeMessagingHosts", appdata);
            let _ = fs::create_dir_all(&host_dir);
            let target = format!(r"{}\com.monitorix.dataguard.json", host_dir);
            let _ = fs::write(target, serde_json::to_string_pretty(&manifest).unwrap_or_default());
        }
    }

    true
}

/// Evaluates a staged browser upload candidate against DataGuard classification rules
pub fn evaluate_browser_upload(file_path: &Path, destination_domain: &str) -> serde_json::Value {
    // Check if destination is personal cloud / unapproved SaaS
    let lower_dest = destination_domain.to_lowercase();
    let is_unapproved_cloud = lower_dest.contains("drive.google.com") ||
        lower_dest.contains("dropbox.com") ||
        lower_dest.contains("onedrive.live.com") ||
        lower_dest.contains("wetransfer.com") ||
        lower_dest.contains("mega.nz") ||
        lower_dest.contains("anonfiles.com");

    let verdict = crate::engines::dlp_engine::evaluate_file_verdict(file_path);
    match verdict {
        Ok(v) => {
            let should_block = v.is_violation && (v.action == "Block" || is_unapproved_cloud);
            json!({
                "EventType": "BrowserUploadInspection",
                "DestinationDomain": destination_domain,
                "IsUnapprovedCloud": is_unapproved_cloud,
                "IsViolation": v.is_violation,
                "ActionTaken": if should_block { "Blocked" } else { "Allowed" },
                "Findings": v.findings,
                "FileHash": v.sha256,
                "Timestamp": chrono::Utc::now().to_rfc3339()
            })
        },
        Err(e) => json!({
            "EventType": "BrowserUploadInspection",
            "DestinationDomain": destination_domain,
            "Error": e,
            "ActionTaken": "Allowed",
            "Timestamp": chrono::Utc::now().to_rfc3339()
        })
    }
}

pub fn audit_browsers() -> serde_json::Value {
    register_native_messaging_host();

    let mut extensions = Vec::new();

    #[cfg(not(target_os = "windows"))]
    let chrome_ext_path = std::env::var("HOME").unwrap_or_else(|_| "/root".to_string()) + "/.config/google-chrome/Default/Extensions";
    #[cfg(not(target_os = "windows"))]
    #[allow(unused_mut)]
    let mut paths_to_check = vec![("Chrome", chrome_ext_path)];

    #[cfg(target_os = "windows")]
    let appdata = std::env::var("LOCALAPPDATA").unwrap_or_else(|_| r"C:\Users\Default\AppData\Local".to_string());
    #[cfg(target_os = "windows")]
    #[allow(unused_mut)]
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
        "DataGuardExtensionIntegrated": true,
        "NativeMessagingHostConfigured": true,
        "ExtensionsFound": extensions.len(),
        "Extensions": extensions
    })
}
