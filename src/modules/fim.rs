use std::collections::{HashMap, HashSet};
use std::fs;
use std::io::Read;
use serde_json::json;
use ring::digest::{Context, SHA256};
use tokio::sync::mpsc::UnboundedSender;
use std::sync::{Arc, Mutex};
use std::path::Path;
use notify::{Watcher, RecursiveMode, RecommendedWatcher, Config, EventKind};

fn compute_sha256(path: &str) -> Option<String> {
    let mut file = fs::File::open(path).ok()?;
    let mut context = Context::new(&SHA256);
    let mut buffer = [0; 4096];
    
    loop {
        let count = file.read(&mut buffer).ok()?;
        if count == 0 {
            break;
        }
        context.update(&buffer[..count]);
    }
    
    Some(hex::encode(context.finish().as_ref()))
}

pub fn start_fim(event_tx: UnboundedSender<serde_json::Value>, live_config: Arc<Mutex<crate::config::AgentConfig>>) {
    std::thread::spawn(move || {
        crate::log_msg("[FIM] Starting File Integrity Monitor with dynamic paths...");
        
        let (tx, rx) = std::sync::mpsc::channel();
        let mut watcher = match RecommendedWatcher::new(tx, Config::default()) {
            Ok(w) => w,
            Err(e) => {
                crate::log_msg(&format!("[FIM] Failed to init watcher: {:?}", e));
                return;
            }
        };
        
        let mut current_paths: HashSet<String> = HashSet::new();
        let baseline: HashMap<String, String> = HashMap::new(); // path -> hash
        
        let event_tx_clone = event_tx.clone();
        let baseline_clone = Arc::new(Mutex::new(baseline));
        let baseline_listener = Arc::clone(&baseline_clone);
        
        // Listener thread
        std::thread::spawn(move || {
            for res in rx {
                if let Ok(event) = res {
                    match event.kind {
                        EventKind::Modify(_) | EventKind::Create(_) | EventKind::Remove(_) => {
                            for path_buf in event.paths {
                                if let Some(path_str) = path_buf.to_str() {
                                    let path_str = path_str.to_string();
                                    
                                    // if it's a file, check hash
                                    if path_buf.is_file() {
                                        let new_hash_opt = compute_sha256(&path_str);
                                        let mut b = baseline_listener.lock().unwrap();
                                        
                                        if let Some(new_hash) = new_hash_opt {
                                            if let Some(old_hash) = b.get(&path_str) {
                                                if *old_hash != new_hash {
                                                    crate::log_msg(&format!("[FIM] ALERT: File changed - {}", path_str));
                                                    let alert = json!({
                                                        "EventType": "FileIntegrityAlert",
                                                        "Severity": "Critical",
                                                        "FilePath": path_str,
                                                        "OldHash": old_hash,
                                                        "NewHash": new_hash.clone(),
                                                        "Message": format!("Monitored file modified: {}", path_str)
                                                    });
                                                    let _ = event_tx_clone.send(alert);
                                                    b.insert(path_str, new_hash);
                                                }
                                            } else {
                                                b.insert(path_str, new_hash);
                                            }
                                        } else {
                                            // Deleted or unreadable
                                            if b.contains_key(&path_str) {
                                                crate::log_msg(&format!("[FIM] ALERT: File deleted - {}", path_str));
                                                let alert = json!({
                                                    "EventType": "FileIntegrityAlert",
                                                    "Severity": "Critical",
                                                    "FilePath": path_str,
                                                    "Message": format!("Monitored file deleted: {}", path_str)
                                                });
                                                let _ = event_tx_clone.send(alert);
                                                b.remove(&path_str);
                                            }
                                        }
                                    }
                                }
                            }
                        },
                        _ => {}
                    }
                }
            }
        });

        // Config polling loop
        loop {
            let (is_enabled, new_paths) = {
                if let Ok(lc) = live_config.lock() {
                    (lc.fim_enabled, lc.fim_paths.clone())
                } else {
                    (false, vec![])
                }
            };
            
            if is_enabled {
                let new_paths_set: HashSet<String> = new_paths.into_iter().collect();
                
                // Unwatch removed paths
                for p in current_paths.difference(&new_paths_set) {
                    let _ = watcher.unwatch(Path::new(p));
                    crate::log_msg(&format!("[FIM] Stopped watching: {}", p));
                }
                
                // Watch new paths
                for p in new_paths_set.difference(&current_paths) {
                    if Path::new(p).exists() {
                        if let Err(e) = watcher.watch(Path::new(p), RecursiveMode::Recursive) {
                            crate::log_msg(&format!("[FIM] Error watching {}: {:?}", p, e));
                        } else {
                            crate::log_msg(&format!("[FIM] Started watching: {}", p));
                            // Seed baseline
                            if Path::new(p).is_file() {
                                if let Some(h) = compute_sha256(p) {
                                    if let Ok(mut b) = baseline_clone.lock() {
                                        b.insert(p.clone(), h);
                                    }
                                }
                            }
                        }
                    }
                }
                
                current_paths = new_paths_set;
            } else {
                // Disabled, unwatch all
                for p in &current_paths {
                    let _ = watcher.unwatch(Path::new(p));
                }
                current_paths.clear();
            }

            std::thread::sleep(std::time::Duration::from_secs(10));
        }
    });
}
