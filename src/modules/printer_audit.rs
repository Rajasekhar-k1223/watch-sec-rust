#[cfg(unix)]
use serde_json::json;
#[cfg(unix)]
use std::fs;
#[cfg(unix)]
use std::io::{BufRead, BufReader};

#[cfg(unix)]
pub fn audit_cups_print_jobs() -> Option<serde_json::Value> {
    // CUPS page log usually holds print job history
    let cups_log_path = "/var/log/cups/page_log";
    
    let mut jobs = Vec::new();
    
    if let Ok(file) = fs::File::open(cups_log_path) {
        let reader = BufReader::new(file);
        let mut lines = Vec::new();
        for line in reader.lines() {
            if let Ok(l) = line {
                lines.push(l);
            }
        }
        
        for l in lines.iter().rev().take(5) {
            let parts: Vec<&str> = l.split_whitespace().collect();
            if parts.len() >= 6 {
                jobs.push(json!({
                    "Printer": parts.get(0).unwrap_or(&"Unknown"),
                    "User": parts.get(1).unwrap_or(&"Unknown"),
                    "JobId": parts.get(2).unwrap_or(&"Unknown"),
                    "Time": parts.get(3).unwrap_or(&"Unknown"),
                    "Pages": parts.get(4).unwrap_or(&"Unknown")
                }));
            }
        }
    }

    if jobs.is_empty() {
        return None;
    }

    Some(json!({
        "Type": "PrinterAudit",
        "Details": format!("RecentJobs: {:?}, JobCount: {}", jobs, jobs.len())
    }))
}

#[cfg(windows)]
pub fn audit_cups_print_jobs() -> Option<serde_json::Value> {
    // Windows printer auditing requires Event Log hooking which is handled separately.
    // Return None here so we don't spam fake "PrintJob" events every 30 seconds.
    None
}
