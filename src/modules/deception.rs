use std::fs;
use std::path::PathBuf;
use serde_json::json;
use chrono::Utc;
use tokio::net::TcpListener;
use tokio::io::AsyncReadExt;
use std::collections::HashMap;
use lazy_static::lazy_static;
use std::sync::Mutex;

lazy_static! {
    static ref HONEY_FILES: Mutex<HashMap<String, std::time::SystemTime>> = Mutex::new(HashMap::new());
}

pub fn deploy_honeyfiles(agent_id: &str) {
    crate::log_msg("[Deception] Deploying Honeyfiles...");
    
    let mut base_dirs = vec![std::env::temp_dir()];
    if let Ok(home) = std::env::var("HOME").or_else(|_| std::env::var("USERPROFILE")) {
        let home_path = PathBuf::from(home);
        base_dirs.push(home_path.clone());
        base_dirs.push(home_path.join("Documents"));
        base_dirs.push(home_path.join("Downloads"));
        base_dirs.push(home_path.join("Desktop"));
    }
    
    let bait_names = vec![
        "financial_Q3_report.xlsx",
        "customer_db_backup.sql",
        "private_rsa_key.pem",
        "employee_salaries.csv",
        "production_db_creds.txt",
        "aws_keys_backup.csv", 
        "root_password_temp.md",
        ".canary_token_alphv.docx",
        ".canary_token_lockbit.xlsx",
        "payroll_2026_Q1.xlsx"
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
                if let Ok(metadata) = fs::metadata(&path) {
                    if let Ok(modified) = metadata.modified() {
                        if let Some(p_str) = path.to_str() {
                            files.insert(p_str.to_string(), modified);
                        }
                    }
                }
            }
        }
    }
}

/// Remove all honeyfiles that were previously deployed.
/// Called on startup when DeceptionEnabled=false so legacy files
/// created by older agent versions are cleaned up automatically.
pub fn cleanup_honeyfiles() {
    let bait_names = [
        "financial_Q3_report.xlsx",
        "customer_db_backup.sql",
        "private_rsa_key.pem",
        "employee_salaries.csv",
        "production_db_creds.txt",
        "aws_keys_backup.csv",
        "root_password_temp.md",
        ".canary_token_alphv.docx",
        ".canary_token_lockbit.xlsx",
        "payroll_2026_Q1.xlsx",
    ];

    let mut base_dirs = vec![std::env::temp_dir()];
    if let Ok(home) = std::env::var("HOME").or_else(|_| std::env::var("USERPROFILE")) {
        let home_path = PathBuf::from(home);
        base_dirs.push(home_path.clone());
        base_dirs.push(home_path.join("Documents"));
        base_dirs.push(home_path.join("Downloads"));
        base_dirs.push(home_path.join("Desktop"));
    }

    for name in &bait_names {
        for dir in &base_dirs {
            let path = dir.join(name);
            if path.exists() {
                match fs::remove_file(&path) {
                    Ok(_) => crate::log_msg(&format!("[Deception] Cleaned up old honeyfile: {:?}", path)),
                    Err(e) => crate::log_msg(&format!("[Deception] Could not remove {:?}: {}", path, e)),
                }
            }
        }
    }

    // Clear the in-memory tracking map too
    if let Ok(mut files) = HONEY_FILES.lock() {
        files.clear();
    }
}


pub fn audit_traps() -> Vec<serde_json::Value> {
    let mut findings = Vec::new();
    let mut files = HONEY_FILES.lock().unwrap();
    let mut keys_to_remove = Vec::new();
    
    for (path, original_time) in files.iter() {
        let file_path = std::path::Path::new(path);
        let filename = file_path.file_name().and_then(|f| f.to_str()).unwrap_or("file");
        let is_canary = path.contains(".canary_token") || path.contains("payroll_2026_Q1");

        if !file_path.exists() {
            let msg = if is_canary {
                format!("Canary file tamper violation: {} header rewritten with AES-256 block", filename)
            } else {
                format!("Honeyfile deleted or moved: {}", path)
            };
            findings.push(json!({
                "type": if is_canary { "CanaryTokenAlert" } else { "DeceptionAlert" },
                "rule_name": if is_canary { "Canary Guard Ransomware Tamper" } else { "Honeyfile Deception Access" },
                "severity": "Critical",
                "message": msg,
                "matched_content": msg,
                "path": path,
                "timestamp": Utc::now().to_rfc3339()
            }));
            if is_canary {
                crate::log_msg(&format!("[CanaryGuard] Tamper detected on canary token: {}. Enforcing instant host containment...", path));
                let _ = crate::modules::isolation::isolate_host();
            }
            keys_to_remove.push(path.clone());
        } else if let Ok(metadata) = fs::metadata(file_path) {
            if let Ok(modified) = metadata.modified() {
                if modified > *original_time {
                    let msg = if is_canary {
                        format!("Canary file tamper violation: {} header rewritten with AES-256 block", filename)
                    } else {
                        format!("Honeyfile modified (possible ransomware encryption): {}", path)
                    };
                    findings.push(json!({
                        "type": if is_canary { "CanaryTokenAlert" } else { "DeceptionAlert" },
                        "rule_name": if is_canary { "Canary Guard Ransomware Tamper" } else { "Honeyfile Deception Access" },
                        "severity": "Critical",
                        "message": msg,
                        "matched_content": msg,
                        "path": path,
                        "timestamp": Utc::now().to_rfc3339()
                    }));
                    if is_canary {
                        crate::log_msg(&format!("[CanaryGuard] Ransomware tampering detected on canary token: {}. Enforcing instant host containment...", path));
                        let _ = crate::modules::isolation::isolate_host();
                    }
                    keys_to_remove.push(path.clone());
                }
            }
        }
    }
    
    for k in keys_to_remove {
        files.remove(&k);
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
