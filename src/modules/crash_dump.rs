use serde_json::json;
use std::fs;

pub fn audit_crash_dumps() -> serde_json::Value {
    let mut crash_files = Vec::new();

    // Check /var/crash/
    if let Ok(entries) = fs::read_dir("/var/crash") {
        for entry in entries.flatten() {
            if let Ok(name) = entry.file_name().into_string() {
                crash_files.push(format!("/var/crash/{}", name));
            }
        }
    }

    // Check systemd coredump directory
    if let Ok(entries) = fs::read_dir("/var/lib/systemd/coredump") {
        for entry in entries.flatten() {
            if let Ok(name) = entry.file_name().into_string() {
                crash_files.push(format!("/var/lib/systemd/coredump/{}", name));
            }
        }
    }

    json!({
        "EventType": "CrashDumpAudit",
        "CrashDumpsFound": crash_files.len(),
        "CrashDumpFiles": crash_files
    })
}
