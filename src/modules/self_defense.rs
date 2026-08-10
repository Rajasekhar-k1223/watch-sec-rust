use serde_json::json;

pub fn start_watchdog(event_tx: tokio::sync::mpsc::UnboundedSender<serde_json::Value>) {
    println!("[SelfDefense] Initializing process watchdog and signal handlers...");

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
