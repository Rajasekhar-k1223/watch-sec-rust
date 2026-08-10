use serde_json::json;
use std::time::Duration;
use tokio::time;

pub fn start(event_tx: tokio::sync::mpsc::UnboundedSender<serde_json::Value>) {
    tokio::spawn(async move {
        // Poll every 60 seconds
        let mut interval = time::interval(Duration::from_secs(60));

        loop {
            interval.tick().await;
            
            // Re-use our existing hardware module to get the stats
            let stats = crate::hardware::get_hardware_stats();

            let mut temp = "Unknown".to_string();
            
            #[cfg(not(target_os = "macos"))]
            {
                let mut components = sysinfo::Components::new_with_refreshed_list();
                if let Some(c) = components.list().iter().next() {
                    temp = format!("{:.1}°C", c.temperature());
                }
            }

            #[cfg(target_os = "macos")]
            {
                // Attempt to read from osx-cpu-temp or powermetrics (fallback)
                if let Ok(output) = crate::hidden_command!("osx-cpu-temp").output() {
                    let out_str = String::from_utf8_lossy(&output.stdout);
                    temp = out_str.trim().to_string();
                } else {
                    temp = "SMC/IOKit Access Denied (Need root/osx-cpu-temp)".to_string();
                }
            }

            let payload = json!({
                "EventType": "SystemTelemetry",
                "CPU_Usage_Percent": stats.cpu_usage,
                "Memory_Usage_Percent": stats.mem_usage,
                "Disk_Usage_Percent": stats.disk_usage,
                "Temperature": temp,
                "Severity": "Info",
            });

            println!("[SystemMonitor] Collected system telemetry");
            let _ = event_tx.send(payload);
        }
    });
}
