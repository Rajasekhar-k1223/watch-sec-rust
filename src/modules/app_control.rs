use serde_json::json;
use std::path::Path;

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::SystemTime;

lazy_static::lazy_static! {
    static ref FILE_HASH_CACHE: Mutex<HashMap<std::path::PathBuf, (SystemTime, String)>> = Mutex::new(HashMap::new());
}

pub fn evaluate_process(pid_str: &str, name: &str, exe_path: Option<&Path>, blocked_apps: &[String], event_tx: &tokio::sync::mpsc::UnboundedSender<serde_json::Value>) {
    let name_lower = name.to_lowercase();
    
    // Optional hash computation with caching
    let file_hash = if let Some(path) = exe_path {
        let meta = std::fs::metadata(path).ok();
        let mod_time = meta.and_then(|m| m.modified().ok()).unwrap_or(SystemTime::UNIX_EPOCH);
        
        let mut cache = FILE_HASH_CACHE.lock().unwrap();
        if let Some((cached_time, cached_hash)) = cache.get(path) {
            if *cached_time == mod_time {
                Some(cached_hash.clone())
            } else {
                if let Ok(bytes) = std::fs::read(path) {
                    let hash = hex::encode(ring::digest::digest(&ring::digest::SHA256, &bytes));
                    cache.insert(path.to_path_buf(), (mod_time, hash.clone()));
                    Some(hash)
                } else {
                    None
                }
            }
        } else {
            if let Ok(bytes) = std::fs::read(path) {
                let hash = hex::encode(ring::digest::digest(&ring::digest::SHA256, &bytes));
                cache.insert(path.to_path_buf(), (mod_time, hash.clone()));
                Some(hash)
            } else {
                None
            }
        }
    } else {
        None
    };
    
    // Check against dynamically provided blocked apps list
    for banned in blocked_apps.iter() {
        let banned_lower = banned.to_lowercase();
        let match_name = name_lower.contains(&banned_lower);
        let match_hash = file_hash.as_ref().map_or(false, |h| h == &banned_lower);
        
        if match_name || match_hash {
            println!("[AppControl] Banned application detected: {}", name);
            
            // Enforce policy by killing the process
            let kill_result = crate::modules::process_control::kill_process(pid_str);
            let action_taken = if kill_result.is_ok() { "Killed" } else { "KillFailed" };

            // Send Alert
            let alert = json!({
                "EventType": "AppControlViolation",
                "Severity": "High",
                "ProcessName": name,
                "BannedRule": banned,
                "ActionTaken": action_taken,
                "PID": pid_str,
                "HashMatch": match_hash
            });
            
            let _ = event_tx.send(alert);
            break;
        }
    }
}
