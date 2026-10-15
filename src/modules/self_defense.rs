use serde_json::json;
use std::fs::File;

pub fn start_watchdog(event_tx: tokio::sync::mpsc::UnboundedSender<serde_json::Value>) {
    println!("[SelfDefense] Initializing process watchdog, file locking, and signal handlers...");

    // Anti-Tamper: Lock our own files so they cannot be deleted or modified
    std::thread::spawn(|| {
        if let Ok(exe_path) = std::env::current_exe() {
            #[cfg(windows)]
            {
                use std::os::windows::fs::OpenOptionsExt;
                // FILE_SHARE_READ = 1. No write or delete sharing.
                let _exe_lock = std::fs::OpenOptions::new().read(true).share_mode(1).open(&exe_path);
                let _cfg_lock = std::fs::OpenOptions::new().read(true).share_mode(1).open("config.json");
                std::thread::park(); // Keep handles open indefinitely
            }
            #[cfg(not(windows))]
            {
                // On Linux, file locks are advisory, but we can hold a handle anyway.
                let _exe_lock = File::open(&exe_path);
                let _cfg_lock = File::open("config.json");
                std::thread::park();
            }
        }
    });

    let tx = event_tx.clone();
    tokio::spawn(async move {
        // In a production agent, we would bind to SIGINT, SIGTERM, and SIGKILL (if possible via kernel module)
        // Here we use tokio's cross-platform ctrl_c handler to simulate a graceful kill attempt.
        if let Ok(_) = tokio::signal::ctrl_c().await {
            let alert = json!({
                "EventType": "AgentTamperAlert",
                "Severity": "Critical",
                "Action": "SIGINT Received",
                "Message": "Agent process is being forcibly terminated by a local user."
            });
            println!("[SelfDefense] Dying Gasp: SIGINT received. Notifying C2...");
            let _ = tx.send(alert);
            
            // Allow a tiny delay for the message to be queued before exiting
            tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
            std::process::exit(0);
        }
    });
}
