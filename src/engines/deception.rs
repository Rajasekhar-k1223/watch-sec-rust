use serde_json::json;
use std::fs;

#[cfg(target_os = "windows")]
const DECOY_FILE: &str = "C:\\ProgramData\\passwords.txt";
#[cfg(not(target_os = "windows"))]
const DECOY_FILE: &str = "/tmp/passwords.txt";

pub fn deploy_decoy() {
    println!("[DeceptionEngine] Deploying decoy file to {}", DECOY_FILE);
    let fake_creds = "admin:hunter2\nroot:password123\nbackup:admin2023\n";
    let _ = fs::write(DECOY_FILE, fake_creds);
}

pub fn evaluate_access(file_path: &str, event_tx: &tokio::sync::mpsc::UnboundedSender<serde_json::Value>) {
    if file_path == DECOY_FILE {
        println!("[DETECTION] Deception Engine Triggered! Someone opened the decoy file.");
        
        let alert = json!({
            "EventType": "DeceptionTriggered",
            "Severity": "Critical",
            "DetectionName": "Honeypot Credential Access",
            "FilePath": file_path,
        });
        
        let _ = event_tx.send(alert);
    }
}
