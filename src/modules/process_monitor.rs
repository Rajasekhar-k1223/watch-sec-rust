use serde_json::json;
use sysinfo::System;
use std::time::Duration;

pub fn start(
    event_tx: tokio::sync::mpsc::UnboundedSender<serde_json::Value>,
    live_config: std::sync::Arc<std::sync::Mutex<crate::config::AgentConfig>>,
) {
    std::thread::spawn(move || {
        let mut sys = System::new_all();
        // Use a dedicated HTTP client for direct REST delivery
        let http_client = reqwest::blocking::Client::builder()
            .timeout(Duration::from_secs(8))
            .build()
            .unwrap_or_default();

        loop {
            // Collect every 5 seconds — 1 second was flooding the event queue
            std::thread::sleep(Duration::from_secs(5));
            sys.refresh_processes();

            let (blocked_apps, backend_url, agent_id, machine_secret) = {
                let lc = live_config.lock().unwrap();
                (
                    lc.blocked_apps.clone(),
                    lc.backend_url.clone(),
                    lc.agent_id.clone(),
                    lc.machine_secret.clone(),
                )
            };

            let mut top_processes = Vec::new();

            for (pid, process) in sys.processes() {
                let cmdline = process.cmd().join(" ");

                // Evaluate for LotL attacks via Sigma Engine
                crate::engines::sigma_engine::evaluate_process(&cmdline, &event_tx);

                // Evaluate AppLocker (Application Control)
                crate::modules::app_control::evaluate_process(
                    &pid.to_string(),
                    process.name(),
                    process.exe(),
                    &blocked_apps,
                    &event_tx,
                );

                top_processes.push(json!({
                    "PID":               pid.as_u32(),
                    "PPID":              process.parent().map(|p| p.as_u32()).unwrap_or(0),
                    "Name":              process.name().to_string(),
                    "CommandLine":       cmdline,
                    "CPU_Usage":         process.cpu_usage(),
                    "Memory_Bytes":      process.memory(),
                    "Disk_Written_Bytes":process.disk_usage().total_written_bytes,
                    "Disk_Read_Bytes":   process.disk_usage().total_read_bytes,
                }));

                if top_processes.len() >= 100 {
                    break;
                }
            }

            let payload = json!({
                "EventType":    "ProcessSnapshot",
                "AgentId":      agent_id,
                "Processes":    top_processes,
                "ProcessCount": top_processes.len(),
                "Severity":     "Info",
            });

            println!(
                "[ProcessMonitor] Snapshot: {} processes",
                payload["ProcessCount"]
            );

            // 1. Send via gRPC event bus (existing pipeline)
            let _ = event_tx.send(payload.clone());

            // 2. Also POST directly to REST endpoint so the backend can emit
            //    agent_processes over Socket.IO immediately, bypassing Kafka lag.
            if !backend_url.is_empty() && !agent_id.is_empty() {
                let url = format!("{}/api/agents/{}/processes", backend_url, agent_id);
                let body = serde_json::to_string(&json!({
                    "Processes": &payload["Processes"]
                })).unwrap_or_default();
                let ts = chrono::Utc::now().timestamp().to_string();
                let sig = crate::api::generate_signature(&machine_secret, &body, &ts);
                let _ = http_client.post(&url)
                    .header("Content-Type", "application/json")
                    .header("X-Signature", &sig)
                    .header("X-Timestamp", &ts)
                    .body(body)
                    .send();
            }
        }
    });
}
