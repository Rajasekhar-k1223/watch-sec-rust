use std::fs;
use std::path::PathBuf;
use serde_json::json;
use chrono::Utc;
use tokio::net::TcpListener;
use tokio::io::AsyncReadExt;
use std::collections::HashSet;
use lazy_static::lazy_static;
use std::sync::Mutex;

lazy_static! {
    static ref HONEY_FILES: Mutex<HashSet<String>> = Mutex::new(HashSet::new());
}

pub fn deploy_honeyfiles(agent_id: &str) {
    crate::log_msg("[Deception] Deploying Honeyfiles...");
    
    let mut base_dirs = vec![std::env::temp_dir()];
    if let Ok(home) = std::env::var("HOME").or_else(|_| std::env::var("USERPROFILE")) {
        base_dirs.push(PathBuf::from(home));
    }
    
    let bait_names = vec![
        "production_db_creds.txt",
        "aws_keys_backup.csv", 
        "root_password_temp.md"
    ];
    
    let mut files = HONEY_FILES.lock().unwrap();
    
    for name in bait_names {
        for dir in &base_dirs {
            let path = dir.join(name);
            let content = format!(
                "# MONITORIX DECEPTION TRAP ID: {}\n\
                 # DO NOT MODIFY. UNAUTHORIZED ACCESS IS LOGGED.\n\
                 generated_at: {}\n\
                 access_key: AKIAIOSFODNN7EXAMPLE\n\
                 secret_key: wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n",
                 agent_id, Utc::now().to_rfc3339()
            );
            
            if fs::write(&path, content).is_ok() {
                if let Some(p_str) = path.to_str() {
                    files.insert(p_str.to_string());
                }
            }
        }
    }
}

pub fn audit_traps() -> Vec<serde_json::Value> {
    let mut findings = Vec::new();
    let files = HONEY_FILES.lock().unwrap();
    
    for path in files.iter() {
        if !std::path::Path::new(path).exists() {
            findings.push(json!({
                "type": "DeceptionAlert",
                "severity": "Critical",
                "message": format!("Honeyfile deleted or moved: {}", path),
                "path": path,
                "timestamp": Utc::now().to_rfc3339()
            }));
        }
    }
    
    findings
}

pub async fn deploy_shadow_service(agent_id: String) {
    let port = 2222;
    crate::log_msg(&format!("[Deception] Deploying Shadow Service on 0.0.0.0:{}", port));
    
    let listener_result = TcpListener::bind(format!("0.0.0.0:{}", port)).await;
    match listener_result {
        Ok(listener) => {
            loop {
                if let Ok((mut socket, addr)) = listener.accept().await {
                    crate::log_msg(&format!("[Deception] Shadow Service hit by {}", addr));
                    
                    let event = json!({
                        "type": "DeceptionAlert",
                        "severity": "Critical",
                        "message": format!("Unauthorized scan/connection to Shadow Service (Port 2222) from {}", addr),
                        "source_ip": addr.ip().to_string(),
                        "agent_id": agent_id,
                        "timestamp": Utc::now().to_rfc3339()
                    });
                    
                    crate::c2::offline_queue::enqueue_event(&event);
                    
                    let mut buf = [0; 1024];
                    let _ = socket.read(&mut buf).await;
                }
            }
        }
        Err(e) => {
            crate::log_msg(&format!("[Deception] Failed to bind Shadow Service: {}", e));
        }
    }
}
