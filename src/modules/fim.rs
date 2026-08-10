use notify::{Watcher, RecursiveMode, EventKind};
use notify::event::ModifyKind;
use std::path::Path;
use ring::digest::{Context, SHA256};
use std::fs::File;
use std::io::Read;
use serde_json::json;

pub fn start(directories: Vec<&str>, event_tx: tokio::sync::mpsc::UnboundedSender<serde_json::Value>) {
    let dirs: Vec<String> = directories.into_iter().map(|s| s.to_string()).collect();
    
    std::thread::spawn(move || {
        let (tx, rx) = std::sync::mpsc::channel();
        
        let mut watcher = match notify::recommended_watcher(tx) {
            Ok(w) => w,
            Err(e) => {
                eprintln!("[FIM] Failed to create watcher: {}", e);
                return;
            }
        };

        for dir in &dirs {
            let path = Path::new(dir);
            if path.exists() {
                if let Err(e) = watcher.watch(path, RecursiveMode::Recursive) {
                    eprintln!("[FIM] Failed to watch {}: {}", dir, e);
                }
            } else {
                eprintln!("[FIM] Directory does not exist, skipping: {}", dir);
            }
        }
        
        println!("[FIM] Started watching directories");

        for res in rx {
            match res {
                Ok(event) => {
                    match event.kind {
                        EventKind::Create(_) | EventKind::Modify(ModifyKind::Data(_)) => {
                            for path in event.paths {
                                if path.is_file() {
                                    handle_modification(&path, &event.kind, &event_tx);
                                }
                            }
                        },
                        _ => {}
                    }
                },
                Err(e) => eprintln!("[FIM] watch error: {:?}", e),
            }
        }
    });
}

fn handle_modification(path: &Path, kind: &EventKind, event_tx: &tokio::sync::mpsc::UnboundedSender<serde_json::Value>) {
    let operation = match kind {
        EventKind::Create(_) => "CREATE",
        EventKind::Modify(_) => "MODIFY",
        EventKind::Access(_) => "ACCESS",
        _ => "UNKNOWN",
    };

    // Evaluate Deception Engine (Honeypot)
    crate::engines::deception::evaluate_access(path.to_str().unwrap_or(""), event_tx);

    let hash = match calculate_hash(path) {
        Ok(h) => h,
        Err(_) => return, // File might be locked, deleted, or we don't have permissions
    };
    
    let entropy = calculate_entropy(path).unwrap_or(0.0);
    
    // Check for ransomware indicators
    let mut action_type = "FileWrite";
    if let Some(ext) = path.extension() {
        if ext == "lock" || ext == "enc" || ext == "crypt" {
            action_type = "MassRename";
        } else if entropy > 7.5 {
            action_type = "HighEntropyWrite";
        }
    }
    
    // Evaluate via Ransomware Engine (passing PID 0 since notify doesn't provide PID)
    crate::engines::ransomware::evaluate_file_action(0, action_type, entropy);

    // Evaluate via DLP Engine if enabled
    if crate::modules::policy::is_action_allowed("telemetry", "dlp_enabled") {
        crate::engines::dlp_engine::scan_file(path, event_tx);
    }

    let payload = json!({
        "EventType": "FileIntegrityAlert",
        "FilePath": path.to_string_lossy(),
        "Operation": operation,
        "SHA256": hash,
        "Entropy": entropy,
        "Severity": "High",
    });

    println!("[FIM] Detected modification: {}", payload.to_string());
    let _ = event_tx.send(payload);
}

fn calculate_entropy(path: &Path) -> Result<f64, std::io::Error> {
    let mut file = File::open(path)?;
    let mut buffer = [0; 4096];
    let count = file.read(&mut buffer)?;
    
    if count == 0 {
        return Ok(0.0);
    }
    
    let mut frequencies = [0usize; 256];
    for &byte in &buffer[..count] {
        frequencies[byte as usize] += 1;
    }
    
    let mut entropy = 0.0;
    let len = count as f64;
    for &freq in &frequencies {
        if freq > 0 {
            let p = freq as f64 / len;
            entropy -= p * p.log2();
        }
    }
    
    Ok(entropy)
}

fn calculate_hash(path: &Path) -> Result<String, std::io::Error> {
    let mut file = File::open(path)?;
    let mut context = Context::new(&SHA256);
    let mut buffer = [0; 4096];

    loop {
        let count = file.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        context.update(&buffer[..count]);
    }

    Ok(hex::encode(context.finish().as_ref()))
}
