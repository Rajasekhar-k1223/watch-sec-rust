use serde_json::json;
use std::fs;
use std::path::Path;
use std::thread;
use std::time::Duration;

#[cfg(target_os = "windows")]
const DECOY_FILE: &str = "C:\\ProgramData\\2025_Financials.docx";
#[cfg(not(target_os = "windows"))]
const DECOY_FILE: &str = "/tmp/2025_Financials.docx";

pub fn deploy_decoy() {
    println!("[RansomwareDecoy] Deploying high-value decoy to {}", DECOY_FILE);
    let fake_data = "PK\x03\x04\x14\x00\x00\x00\x08\x00FAKE_DOCX_HEADER_DATA_DO_NOT_TRUST";
    let _ = fs::write(DECOY_FILE, fake_data);
}

pub fn watch_decoy(event_tx: tokio::sync::mpsc::UnboundedSender<serde_json::Value>) {
    thread::spawn(move || {
        let mut last_modified = std::time::SystemTime::UNIX_EPOCH;
        if let Ok(meta) = fs::metadata(DECOY_FILE) {
            if let Ok(mod_time) = meta.modified() {
                last_modified = mod_time;
            }
        }

        loop {
            thread::sleep(Duration::from_secs(2));
            
            // Check if file was deleted
            if !Path::new(DECOY_FILE).exists() {
                let alert = json!({
                    "EventType": "RansomwareDecoyTouched",
                    "Severity": "Critical",
                    "DetectionName": "Honeypot Decoy Deleted",
                    "FilePath": DECOY_FILE,
                });
                let _ = event_tx.send(alert);
                // Re-deploy after triggering
                deploy_decoy();
                continue;
            }

            // Check if file was modified
            if let Ok(meta) = fs::metadata(DECOY_FILE) {
                if let Ok(mod_time) = meta.modified() {
                    if mod_time > last_modified {
                        let alert = json!({
                            "EventType": "RansomwareDecoyTouched",
                            "Severity": "Critical",
                            "DetectionName": "Honeypot Decoy Modified/Encrypted",
                            "FilePath": DECOY_FILE,
                        });
                        let _ = event_tx.send(alert);
                        last_modified = mod_time;
                    }
                }
            }
        }
    });
}
