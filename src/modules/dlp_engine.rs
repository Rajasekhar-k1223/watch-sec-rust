use notify::{Watcher, RecursiveMode, Event, EventKind};
use std::path::PathBuf;
use std::fs;
use regex::Regex;
use serde_json::json;
use chrono::Utc;
use std::sync::mpsc::channel;

pub fn start_dlp_monitor(event_tx: tokio::sync::mpsc::UnboundedSender<serde_json::Value>) {
    std::thread::spawn(move || {
        let watch_dir = if cfg!(target_os = "windows") {
            PathBuf::from(r"C:\Confidential")
        } else if let Ok(home) = std::env::var("HOME") {
            PathBuf::from(home).join("Confidential")
        } else {
            PathBuf::from("/tmp/Confidential")
        };

        if !watch_dir.exists() {
            let _ = fs::create_dir_all(&watch_dir);
        }

        let (tx, rx) = channel();
        let mut watcher = match notify::recommended_watcher(tx) {
            Ok(w) => w,
            Err(e) => {
                crate::log_msg(&format!("[DLP] Failed to initialize watcher: {}", e));
                return;
            }
        };

        if let Err(e) = watcher.watch(&watch_dir, RecursiveMode::Recursive) {
            crate::log_msg(&format!("[DLP] Failed to watch {}: {}", watch_dir.display(), e));
            return;
        }

        crate::log_msg(&format!("[DLP] Monitoring directory: {}", watch_dir.display()));

        let email_re = Regex::new(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}").unwrap();
        let cc_re = Regex::new(r"\b(?:\d{4}[- ]?){3}\d{4}\b").unwrap();
        let ssn_re = Regex::new(r"\b\d{3}-\d{2}-\d{4}\b").unwrap();
        let kw_re = Regex::new(r"(?i)(confidential|secret|salary|password|invoice|internal only|restricted|project|contract|legal|financial)").unwrap();

        for res in rx {
            match res {
                Ok(Event { kind, paths, .. }) => {
                    if matches!(kind, EventKind::Modify(_) | EventKind::Create(_)) {
                        for path in paths {
                            if path.is_file() {
                                if let Ok(metadata) = fs::metadata(&path) {
                                    if metadata.len() > 5 * 1024 * 1024 {
                                        continue;
                                    }
                                    if let Ok(content) = fs::read_to_string(&path) {
                                        let mut hits = Vec::new();
                                        if email_re.is_match(&content) { hits.push("Email"); }
                                        if cc_re.is_match(&content) { hits.push("CreditCard"); }
                                        if ssn_re.is_match(&content) { hits.push("SSN"); }
                                        if kw_re.is_match(&content) { hits.push("SensitiveKeywords"); }

                                        if !hits.is_empty() {
                                            let msg = format!("DLP POLICY VIOLATION: Sensitive data ({}) detected in file: {}", hits.join(", "), path.display());
                                            crate::log_msg(&format!("[DLP] {}", msg));
                                            let payload = json!({
                                                "type": "FILE_DLP_VIOLATION",
                                                "severity": "Critical",
                                                "message": msg,
                                                "file_path": path.to_string_lossy(),
                                                "timestamp": Utc::now().to_rfc3339()
                                            });
                                            let _ = event_tx.send(payload);
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                Err(e) => crate::log_msg(&format!("[DLP] Watch error: {:?}", e)),
            }
        }
    });
}
