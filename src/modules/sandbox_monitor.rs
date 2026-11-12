use std::path::{Path, PathBuf};
use std::fs;
use notify::{Watcher, RecursiveMode, RecommendedWatcher, Config, EventKind};
use serde_json::json;
use std::sync::{Arc, Mutex};
use tokio::sync::mpsc::UnboundedSender;
use std::time::Duration;

pub fn start_sandbox_monitor(event_tx: UnboundedSender<serde_json::Value>, live_config: Arc<Mutex<crate::config::AgentConfig>>) {
    std::thread::spawn(move || {
        crate::log_msg("[Sandbox] Starting Monitorix Sovereign Sandbox Monitor on Downloads folders...");

        let (tx, rx) = std::sync::mpsc::channel();
        let mut watcher = match RecommendedWatcher::new(tx, Config::default()) {
            Ok(w) => w,
            Err(e) => {
                crate::log_msg(&format!("[Sandbox] Failed to init watcher: {:?}", e));
                return;
            }
        };

        #[cfg(target_os = "windows")]
        {
            if let Ok(entries) = fs::read_dir("C:\\Users") {
                for entry in entries.flatten() {
                    let path = entry.path();
                    if path.is_dir() {
                        let target_folders = vec!["Downloads", "Desktop", "Documents"];
                        for folder in target_folders {
                            let watch_dir = path.join(folder);
                            if watch_dir.exists() {
                                if let Err(e) = watcher.watch(&watch_dir, RecursiveMode::NonRecursive) {
                                    crate::log_msg(&format!("[Sandbox] Failed to watch {:?}: {:?}", watch_dir, e));
                                } else {
                                    crate::log_msg(&format!("[Sandbox] Watching {:?}", watch_dir));
                                }
                            }
                        }
                    }
                }
            }
        }
        #[cfg(not(target_os = "windows"))]
        {
            let home_dir_str = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
            let home_path = PathBuf::from(&home_dir_str);

            // Watch Downloads, Desktop, and Documents — same coverage as Windows
            let watch_folders = vec!["Downloads", "Desktop", "Documents"];
            for folder in watch_folders {
                let dir = home_path.join(folder);
                if !dir.exists() {
                    let _ = fs::create_dir_all(&dir);
                }
                match watcher.watch(&dir, RecursiveMode::NonRecursive) {
                    Ok(_) => crate::log_msg(&format!("[Sandbox] Watching {:?}", dir)),
                    Err(e) => crate::log_msg(&format!("[Sandbox] Failed to watch {:?}: {:?}", dir, e)),
                }
            }
        }

        // Listener loop
        for res in rx {
            if let Ok(event) = res {
                // Look for creation or modification of interesting files
                match event.kind {
                    EventKind::Create(_) | EventKind::Modify(_) => {
                        for path_buf in event.paths {
                            let path_str = path_buf.to_string_lossy().to_string();
                            
                            // Ignore our own pending files or temp browser downloads
                            if path_str.ends_with(".sandbox_pending") || path_str.ends_with(".crdownload") || path_str.ends_with(".part") {
                                continue;
                            }

                            // Cross-platform monitored extensions:
                            let monitored = [
                                ".exe", ".msi", ".bat", ".cmd", ".ps1",  // Windows
                                ".dmg", ".pkg",                            // macOS
                                ".deb", ".rpm", ".appimage",               // Linux
                                ".sh", ".zip", ".tar", ".gz",              // Scripts / archives
                                ".pdf", ".doc", ".docx", ".xls", ".xlsm", // Documents
                                ".js", ".vbs", ".jar",                     // Scripts
                            ];
                            if monitored.iter().any(|ext| path_str.ends_with(ext)) {
                                // Wait a moment for file write and Chrome's native virus scan to complete
                                std::thread::sleep(Duration::from_millis(3000));
                                
                                if let Ok(metadata) = fs::metadata(&path_buf) {
                                    if metadata.len() == 0 { continue; } // Still empty
                                    
                                    let max_size: u64 = 50 * 1024 * 1024; // 50MB limit
                                    let is_large = metadata.len() > max_size;
                                    
                                    // Check if Sandbox feature is enabled for this tenant
                                    let (backend_url, agent_id, machine_secret, enabled) = {
                                        let cfg = live_config.lock().unwrap();
                                        (cfg.backend_url.clone(), cfg.agent_id.clone(), cfg.machine_secret.clone(), cfg.sandbox_enabled)
                                    };

                                    if !enabled {
                                        // Feature disabled for this tenant — silently ignore download
                                        continue;
                                    }

                                    crate::log_msg(&format!("[Sandbox] Intercepting newly downloaded file: {}", path_str));
                                    
                                    // 1. Rename to .sandbox_pending
                                    let pending_path = format!("{}.sandbox_pending", path_str);
                                    if fs::rename(&path_buf, &pending_path).is_err() {
                                        continue; // File might be locked
                                    }

                                    // 2. Universal Local Hashing
                                    use ring::digest::{Context, SHA256};
                                    use std::io::Read;
                                    let mut file = match fs::File::open(&pending_path) {
                                        Ok(f) => f,
                                        Err(_) => {
                                            let _ = fs::rename(&pending_path, &path_str);
                                            continue;
                                        }
                                    };
                                    let mut context = Context::new(&SHA256);
                                    let mut buffer = [0; 8192];
                                    while let Ok(count) = file.read(&mut buffer) {
                                        if count == 0 { break; }
                                        context.update(&buffer[..count]);
                                    }
                                    let file_hash = hex::encode(context.finish().as_ref());

                                    // 3. Async Sandbox Check
                                    let b_url = backend_url.clone();
                                    let a_id = agent_id.clone();
                                    let m_sec = machine_secret.clone();
                                    let et_tx = event_tx.clone();
                                    let original_filename = path_buf.file_name().unwrap_or_default().to_string_lossy().into_owned();

                                    tokio::spawn(async move {
                                        // 0. Check Local Endpoint Verdict Cache (<0.5ms)
                                        use crate::engines::safeinstall_enforcer::SafeInstallEnforcer;
                                        if let Some(cached) = SafeInstallEnforcer::query_local_cache(&file_hash) {
                                            if cached.allow_execution {
                                                let _ = fs::rename(&pending_path, &path_str);
                                                println!("[Sandbox] File {} is SAFE (Local Cache Hit) and restored.", original_filename);
                                                return;
                                            } else {
                                                let quarantine_dir = PathBuf::from(if cfg!(target_os = "windows") { "C:\\ProgramData\\Monitorix\\Quarantine" } else { "/opt/monitorix/quarantine" });
                                                let _ = fs::create_dir_all(&quarantine_dir);
                                                let q_path = quarantine_dir.join(format!("{}_{}.quarantine", original_filename, chrono::Utc::now().timestamp()));
                                                let _ = fs::rename(&pending_path, &q_path);
                                                println!("[Sandbox] File {} QUARANTINED (Local Cache Block): {}", original_filename, cached.reason);
                                                return;
                                            }
                                        }

                                        // A. Hash-First API
                                        let ts = chrono::Utc::now().timestamp().to_string();
                                        let check_payload = json!({
                                            "agent_id": a_id,
                                            "filename": original_filename,
                                            "file_hash": file_hash
                                        });
                                        let check_body_str = check_payload.to_string();
                                        let check_sig = crate::api::generate_signature(&m_sec, &check_body_str, &ts);
                                        let check_url = format!("{}/api/sandbox/check_hash", b_url);
                                        
                                        let client = reqwest::Client::new();
                                        let mut final_status = String::from("UNKNOWN");
                                        let mut reason_str = String::new();
                                        
                                        if let Ok(resp) = client.post(&check_url)
                                            .header("Content-Type", "application/json")
                                            .header("X-Signature", check_sig)
                                            .header("X-Timestamp", &ts)
                                            .body(check_body_str)
                                            .send().await
                                        {
                                            if let Ok(json_resp) = resp.json::<serde_json::Value>().await {
                                                if let Some(st) = json_resp["status"].as_str() {
                                                    final_status = st.to_string();
                                                    reason_str = json_resp["reason"].as_str().unwrap_or("").to_string();
                                                }
                                            }
                                        }

                                        // B. Deep Analysis if UNKNOWN and < 50MB
                                        if final_status == "UNKNOWN" {
                                            if is_large {
                                                // Large files can't be uploaded, assume malicious or suspicious
                                                final_status = String::from("MALICIOUS");
                                                reason_str = String::from("Large file with unknown hash blocked by policy");
                                            } else {
                                                // Small file, upload full payload
                                                let file_bytes = fs::read(&pending_path).unwrap_or_default();
                                                use base64::{engine::general_purpose, Engine as _};
                                                let b64 = general_purpose::STANDARD.encode(&file_bytes);
                                                
                                                let analyze_payload = json!({
                                                    "agent_id": a_id,
                                                    "filename": original_filename,
                                                    "file_b64": b64
                                                });
                                                let analyze_body_str = analyze_payload.to_string();
                                                let ts2 = chrono::Utc::now().timestamp().to_string();
                                                let analyze_sig = crate::api::generate_signature(&m_sec, &analyze_body_str, &ts2);
                                                let analyze_url = format!("{}/api/sandbox/analyze", b_url);

                                                if let Ok(resp) = client.post(&analyze_url)
                                                    .header("Content-Type", "application/json")
                                                    .header("X-Signature", analyze_sig)
                                                    .header("X-Timestamp", &ts2)
                                                    .body(analyze_body_str)
                                                    .send().await
                                                {
                                                    if let Ok(json_resp) = resp.json::<serde_json::Value>().await {
                                                        if let Some(st) = json_resp["status"].as_str() {
                                                            final_status = st.to_string();
                                                            reason_str = json_resp["reason"].as_str().unwrap_or("").to_string();
                                                        }
                                                    }
                                                }
                                            }
                                        }

                                        // C. Handle Verdict & Cache in Local Store
                                        SafeInstallEnforcer::store_local_verdict(&file_hash, &final_status, &reason_str);

                                        if final_status == "SAFE" {
                                            let _ = fs::rename(&pending_path, &path_str);
                                            println!("[Sandbox] File {} is SAFE and restored.", original_filename);
                                        } else if final_status == "MALICIOUS" {
                                            // Secure Quarantine instead of deletion
                                            let quarantine_dir = PathBuf::from(if cfg!(target_os = "windows") { "C:\\ProgramData\\Monitorix\\Quarantine" } else { "/opt/monitorix/quarantine" });
                                            let _ = fs::create_dir_all(&quarantine_dir);
                                            let quarantine_path = quarantine_dir.join(format!("{}_{}.quarantine", original_filename, chrono::Utc::now().timestamp()));
                                            
                                            // Moving to quarantine
                                            if fs::rename(&pending_path, &quarantine_path).is_err() {
                                                // Fallback delete if move fails
                                                let _ = fs::remove_file(&pending_path);
                                            }
                                            
                                            println!("[Sandbox] File {} QUARANTINED! Reason: {}", original_filename, reason_str);
                                            let _ = et_tx.send(json!({
                                                "EventType": "SandboxThreatPrevented",
                                                "Filename": original_filename,
                                                "Reason": reason_str
                                            }));
                                        } else if final_status == "HOLD" {
                                            println!("[Sandbox] File {} is on HOLD pending administrator approval.", original_filename);
                                            let _ = et_tx.send(json!({
                                                "EventType": "SandboxFileHold",
                                                "Filename": original_filename,
                                                "Reason": reason_str,
                                                "Hash": file_hash
                                            }));
                                        } else {
                                            // Network failure or timeout: Fail-Closed enforcement (retain .sandbox_pending lock)
                                            crate::log_msg(&format!("[Sandbox] Verification pending or server unreachable for {}. Retaining lock.", original_filename));
                                        }
                                    });
                                }
                            }
                        }
                    },
                    _ => {}
                }
            }
        }
    });
}
