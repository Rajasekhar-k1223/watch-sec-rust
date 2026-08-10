use serde_json::json;
use sysinfo::System;
use std::time::Duration;
use tokio::time;

pub fn start(event_tx: tokio::sync::mpsc::UnboundedSender<serde_json::Value>, live_config: std::sync::Arc<std::sync::Mutex<crate::config::AgentConfig>>) {
    tokio::spawn(async move {
        let mut sys = System::new_all();
        // Poll every 1 seconds
        let mut interval = time::interval(Duration::from_secs(1));

        loop {
            interval.tick().await;
            sys.refresh_all();
            
            let blocked_apps = {
                let lc = live_config.lock().unwrap();
                lc.blocked_apps.clone()
            };

            let mut top_processes = Vec::new();

            for (pid, process) in sys.processes() {
                let cmdline = process.cmd().join(" ");
                
                // Evaluate for LotL attacks via Sigma Engine
                crate::engines::sigma_engine::evaluate_process(&cmdline, &event_tx);
                
                // Evaluate AppLocker (Application Control)
                crate::modules::app_control::evaluate_process(&pid.to_string(), process.name(), process.exe(), &blocked_apps, &event_tx);

                top_processes.push(json!({
                    "PID": pid.as_u32(),
                    "Name": process.name().to_string(),
                    "CommandLine": cmdline,
                    "CPU_Usage": process.cpu_usage(),
                    "Memory_Bytes": process.memory(),
                    "Disk_Written_Bytes": process.disk_usage().total_written_bytes,
                    "Disk_Read_Bytes": process.disk_usage().total_read_bytes,
                }));

                // Limit the number of processes to avoid massive payloads
                if top_processes.len() >= 100 {
                    break;
                }
            }

            let payload = json!({
                "EventType": "ProcessSnapshot",
                "Processes": top_processes,
                "ProcessCount": top_processes.len(),
                "Severity": "Info",
            });

            println!("[ProcessMonitor] Collected snapshot of {} processes", top_processes.len());
            let _ = event_tx.send(payload);
        }
    });
}
