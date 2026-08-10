use std::sync::RwLock;
use std::fs;
use serde_json::{json, Value};
use lazy_static::lazy_static;

lazy_static! {
    static ref GLOBAL_POLICY: RwLock<Value> = RwLock::new(default_policy());
}

fn default_policy() -> Value {
    json!({
        "telemetry": {
            "process_events": true,
            "network_events": true,
            "dlp_enabled": false
        },
        "response": {
            "process_kill_permission": false,
            "network_isolation_permission": false
        },
        "system": {
            "max_cpu_percent": 5,
            "update_channel": "stable"
        }
    })
}

pub fn load_policy(path: &str) {
    if let Ok(contents) = fs::read_to_string(path) {
        if let Ok(parsed) = serde_json::from_str::<Value>(&contents) {
            let mut policy = GLOBAL_POLICY.write().unwrap();
            *policy = parsed;
            println!("[POLICY] Loaded local policy from disk.");
            return;
        }
    }
    println!("[POLICY] No valid local policy found. Using safe defaults.");
}

pub fn update_policy(new_policy: Value, path: &str) -> Result<(), String> {
    {
        let mut policy = GLOBAL_POLICY.write().unwrap();
        *policy = new_policy.clone();
    }
    
    match fs::write(path, new_policy.to_string()) {
        Ok(_) => Ok(()),
        Err(e) => Err(format!("Failed to save policy: {}", e)),
    }
}

pub fn is_action_allowed(domain: &str, action_key: &str) -> bool {
    let policy = GLOBAL_POLICY.read().unwrap();
    if let Some(domain_val) = policy.get(domain) {
        if let Some(action_val) = domain_val.get(action_key) {
            return action_val.as_bool().unwrap_or(false);
        }
    }
    false
}
