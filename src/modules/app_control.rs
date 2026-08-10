use serde_json::json;
use lazy_static::lazy_static;
use std::path::Path;

pub fn evaluate_process(pid_str: &str, name: &str, exe_path: Option<&Path>, blocked_apps: &[String], event_tx: &tokio::sync::mpsc::UnboundedSender<serde_json::Value>) {
    let name_lower = name.to_lowercase();
    
    // Optional hash computation
    let file_hash = if let Some(path) = exe_path {
        std::fs::read(path).ok().map(|bytes| hex::encode(ring::digest::digest(&ring::digest::SHA256, &bytes)))
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
