use serde_json::json;
use sysinfo::System;
use std::time::Duration;
use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::io::Read;

/// Computes SHA-256 for a binary on disk with a 20MB guardrail.
fn compute_sha256(path: &Path) -> Option<String> {
    if let Ok(mut f) = std::fs::File::open(path) {
        let mut context = ring::digest::Context::new(&ring::digest::SHA256);
        let mut buffer = [0u8; 8192];
        let mut read_bytes: usize = 0;
        while let Ok(n) = f.read(&mut buffer) {
            if n == 0 { break; }
            context.update(&buffer[..n]);
            read_bytes += n;
            if read_bytes > 20 * 1024 * 1024 { break; }
        }
        let digest = context.finish();
        Some(hex::encode(digest.as_ref()))
    } else {
        None
    }
}

pub fn start(
    event_tx: tokio::sync::mpsc::UnboundedSender<serde_json::Value>,
    live_config: std::sync::Arc<std::sync::Mutex<crate::config::AgentConfig>>,
) {
    std::thread::spawn(move || {
        let mut sys = System::new_all();
        // Dedicated HTTP client for direct REST delivery
        let http_client = reqwest::blocking::Client::builder()
            .timeout(Duration::from_secs(8))
            .build()
            .unwrap_or_default();

        // EDR Lineage tracking state
        let mut pid_guid_map: HashMap<u32, (String, u64)> = HashMap::new();
        let mut known_pids: HashSet<u32> = HashSet::new();
        let mut sha256_cache: HashMap<String, String> = HashMap::new();
        let mut first_run = true;

        loop {
            // Collect every 5 seconds — balanced responsiveness and host CPU usage
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

            let safe_agent_id = if agent_id.is_empty() { "LOCAL_AGENT".to_string() } else { agent_id.clone() };
            let mut current_cycle_pids = HashSet::new();
            let mut top_processes = Vec::new();

            for (pid, process) in sys.processes() {
                let pid_u32 = pid.as_u32();
                current_cycle_pids.insert(pid_u32);
                let ppid_u32 = process.parent().map(|p| p.as_u32()).unwrap_or(0);
                let cmdline = process.cmd().join(" ");
                let start_time = process.start_time();
                let exe_path = process.exe().map(|p| p.to_string_lossy().to_string()).unwrap_or_default();
                let user_str = process.user_id().map(|u| u.to_string()).unwrap_or_else(|| "SYSTEM".to_string());

                // Deterministic execution GUID per process instance
                let process_guid = pid_guid_map.entry(pid_u32)
                    .or_insert_with(|| (format!("{}-{}-{}", safe_agent_id, pid_u32, start_time), start_time))
                    .0.clone();

                let parent_guid = if ppid_u32 > 0 {
                    pid_guid_map.get(&ppid_u32).map(|(g, _)| g.clone()).unwrap_or_else(|| "00000000-0000-0000-0000-000000000000".to_string())
                } else {
                    "00000000-0000-0000-0000-000000000000".to_string()
                };

                // Compute binary SHA-256 for newly spawned processes
                let is_new_process = !first_run && !known_pids.contains(&pid_u32);
                let mut binary_hash = String::new();
                if is_new_process && !exe_path.is_empty() {
                    binary_hash = sha256_cache.entry(exe_path.clone()).or_insert_with(|| {
                        compute_sha256(Path::new(&exe_path)).unwrap_or_default()
                    }).clone();
                }

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

                // If newly spawned process detected after initial warm-up, emit real-time EDR ProcessExecution event
                if is_new_process {
                    let exec_event = json!({
                        "EventType":         "ProcessExecution",
                        "AgentId":           safe_agent_id,
                        "PID":               pid_u32,
                        "PPID":              ppid_u32,
                        "ProcessGuid":       process_guid,
                        "ParentProcessGuid": parent_guid,
                        "Name":              process.name().to_string(),
                        "CommandLine":       cmdline,
                        "ExePath":           exe_path,
                        "User":              user_str,
                        "StartTime":         start_time,
                        "Sha256":            binary_hash,
                        "Severity":          "Info",
                        "Timestamp":         chrono::Utc::now().to_rfc3339()
                    });
                    let _ = event_tx.send(exec_event);
                }

                top_processes.push(json!({
                    "PID":                pid_u32,
                    "PPID":               ppid_u32,
                    "ProcessGuid":        process_guid,
                    "ParentProcessGuid":  parent_guid,
                    "Name":               process.name().to_string(),
                    "CommandLine":        cmdline,
                    "ExePath":            exe_path,
                    "User":               user_str,
                    "CPU_Usage":          process.cpu_usage(),
                    "Memory_Bytes":       process.memory(),
                    "Disk_Written_Bytes": process.disk_usage().total_written_bytes,
                    "Disk_Read_Bytes":    process.disk_usage().total_read_bytes,
                    "Timestamp":          chrono::Utc::now().to_rfc3339(),
                }));

                if top_processes.len() >= 100 {
                    break;
                }
            }

            // Prune dead PIDs from GUID and tracking maps
            pid_guid_map.retain(|pid, _| current_cycle_pids.contains(pid));
            known_pids = current_cycle_pids;
            first_run = false;

            let payload = json!({
                "EventType":    "ProcessSnapshot",
                "AgentId":      safe_agent_id,
                "Processes":    top_processes,
                "ProcessCount": top_processes.len(),
                "Severity":     "Info",
                "Timestamp":    chrono::Utc::now().to_rfc3339()
            });

            println!(
                "[ProcessMonitor] Snapshot: {} processes (Lineage GUIDs Active)",
                payload["ProcessCount"]
            );

            // 1. Send via gRPC event bus (existing pipeline)
            let _ = event_tx.send(payload.clone());

            // 2. Also POST directly to REST endpoint so the backend can emit
            //    agent_processes over Socket.IO immediately, bypassing Kafka lag.
            if !backend_url.is_empty() && !safe_agent_id.is_empty() {
                let url = format!("{}/api/agents/{}/processes", backend_url, safe_agent_id);
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
