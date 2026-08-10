use regex::Regex;
use std::fs::File;
use std::io::Read;
use std::path::Path;
use serde_json::json;
use lazy_static::lazy_static;

lazy_static! {
    static ref CC_REGEX: Regex = Regex::new(r"\b(?:\d[ -]*?){13,16}\b").unwrap();
    static ref SSN_REGEX: Regex = Regex::new(r"\b\d{3}[ -]\d{2}[ -]\d{4}\b").unwrap();
    static ref AWS_REGEX: Regex = Regex::new(r"AKIA[0-9A-Z]{16}").unwrap();
}

pub fn scan_file(path: &Path, event_tx: &tokio::sync::mpsc::UnboundedSender<serde_json::Value>) {
    // Basic heuristic: skip known binary extensions to avoid freezing on massive files
    let ext = path.extension().and_then(|s| s.to_str()).unwrap_or("").to_lowercase();
    let skip_exts = ["exe", "dll", "so", "bin", "png", "jpg", "jpeg", "zip", "tar", "gz", "7z", "pdf"];
    if skip_exts.contains(&ext.as_str()) {
        return;
    }

    if let Ok(mut file) = File::open(path) {
        // Read up to 1MB to prevent memory exhaustion on massive text logs
        let mut buffer = vec![0; 1024 * 1024]; 
        if let Ok(count) = file.read(&mut buffer) {
            if count == 0 {
                return;
            }
            
            // Check for null bytes to verify it's actually text before regex scanning
            if buffer[..count].contains(&0) {
                return;
            }

            let content = String::from_utf8_lossy(&buffer[..count]);
            let mut violations = Vec::new();

            if CC_REGEX.is_match(&content) {
                violations.push("CreditCard");
            }
            if SSN_REGEX.is_match(&content) {
                violations.push("SSN");
            }
            if AWS_REGEX.is_match(&content) {
                violations.push("AWS_Secret");
            }

            if !violations.is_empty() {
                let payload = json!({
                    "EventType": "DlpViolation",
                    "FilePath": path.to_string_lossy(),
                    "Violations": violations,
                    "Severity": "Critical",
                });
                
                println!("[DLP Engine] VIOLATION DETECTED: {}", payload.to_string());
                let _ = event_tx.send(payload);
            }
        }
    }
}
