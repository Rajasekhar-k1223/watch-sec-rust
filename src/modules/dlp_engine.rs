use notify::{Watcher, RecursiveMode, Event, EventKind};
use std::path::{Path, PathBuf};
use std::fs;
use serde_json::json;
use chrono::Utc;
use std::sync::mpsc::channel;

pub fn start_dlp_monitor(event_tx: tokio::sync::mpsc::UnboundedSender<serde_json::Value>) {
    std::thread::spawn(move || {
        let mut watch_dirs = Vec::new();

        if cfg!(target_os = "windows") {
            watch_dirs.push(PathBuf::from(r"C:\Confidential"));
            if let Ok(userprofile) = std::env::var("USERPROFILE") {
                watch_dirs.push(PathBuf::from(&userprofile).join("Documents"));
                watch_dirs.push(PathBuf::from(&userprofile).join("Desktop"));
            }
        } else if let Ok(home) = std::env::var("HOME") {
            watch_dirs.push(PathBuf::from(&home).join("Confidential"));
            watch_dirs.push(PathBuf::from(&home).join("Documents"));
            watch_dirs.push(PathBuf::from(&home).join("Desktop"));
        } else {
            watch_dirs.push(PathBuf::from("/tmp/Confidential"));
        }

        let (tx, rx) = channel();
        let mut watcher = match notify::recommended_watcher(tx) {
            Ok(w) => w,
            Err(e) => {
                crate::log_msg(&format!("[DataGuard DLP] Failed to initialize watcher: {}", e));
                return;
            }
        };

        for dir in &watch_dirs {
            if !dir.exists() {
                let _ = fs::create_dir_all(dir);
            }
            if let Err(e) = watcher.watch(dir, RecursiveMode::Recursive) {
                crate::log_msg(&format!("[DataGuard DLP] Notice: could not watch {}: {}", dir.display(), e));
            } else {
                crate::log_msg(&format!("[DataGuard DLP] Active directory monitoring: {}", dir.display()));
            }
        }

        for res in rx {
            match res {
                Ok(Event { kind, paths, .. }) => {
                    if matches!(kind, EventKind::Modify(_) | EventKind::Create(_)) {
                        for path in paths {
                            if path.is_file() {
                                inspect_and_enforce_file(&path, &event_tx);
                            }
                        }
                    }
                }
                Err(e) => crate::log_msg(&format!("[DataGuard DLP] Watch error: {:?}", e)),
            }
        }
    });
}

fn inspect_and_enforce_file(path: &Path, event_tx: &tokio::sync::mpsc::UnboundedSender<serde_json::Value>) {
    // Utilize the DataGuard classification engine
    if let Ok(verdict) = crate::engines::dlp_engine::evaluate_file_verdict(path) {
        if verdict.is_violation {
            let msg = format!(
                "DATAGUARD VIOLATION [{}]: Sensitive findings ({}) in file: {}",
                verdict.action,
                verdict.findings.iter().map(|f| f.category.as_str()).collect::<Vec<&str>>().join(", "),
                path.display()
            );
            crate::log_msg(&format!("[DataGuard DLP] {}", msg));

            let payload = json!({
                "type": "FILE_DLP_VIOLATION",
                "severity": if verdict.action == "Block" { "Critical" } else { "High" },
                "action": verdict.action,
                "message": msg,
                "file_path": path.to_string_lossy(),
                "file_hash": verdict.sha256,
                "file_size": verdict.file_size,
                "findings": verdict.findings,
                "timestamp": Utc::now().to_rfc3339()
            });
            let _ = event_tx.send(payload);
        }
    }
}
