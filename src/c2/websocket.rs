use crate::config::AgentConfig;
use futures_util::{SinkExt, StreamExt};
use serde_json::Value;
use std::time::Duration;
use tokio::time;
use tokio_tungstenite::{connect_async, tungstenite::protocol::Message};

lazy_static::lazy_static! {
    pub static ref WS_TX: std::sync::Mutex<Option<tokio::sync::mpsc::Sender<String>>> = std::sync::Mutex::new(None);
}

pub async fn start(config: AgentConfig, event_tx: tokio::sync::mpsc::UnboundedSender<Value>) {
    let mut backend_url = config.backend_url.clone();
    
    // Convert http/https to ws/wss
    if backend_url.starts_with("http://") {
        backend_url = backend_url.replace("http://", "ws://");
    } else if backend_url.starts_with("https://") {
        backend_url = backend_url.replace("https://", "wss://");
    }

    let ws_url = format!("{}/socket.io/?EIO=4&transport=websocket", backend_url);
    
    loop {
        println!("[WebSocket] Attempting to connect to {}", ws_url);
        
        match connect_async(&ws_url).await {
            Ok((ws_stream, _)) => {
                println!("[WebSocket] Connected successfully");
                let (mut write, mut read) = ws_stream.split();
                
                let (tx, mut rx) = tokio::sync::mpsc::channel::<String>(100);
                *crate::c2::websocket::WS_TX.lock().unwrap() = Some(tx);
                
                // Engine.IO Heartbeat interval (usually 25s, we ping every 20s to keep it alive)
                let mut ping_interval = time::interval(Duration::from_secs(20));

                loop {
                    tokio::select! {
                        Some(out_msg) = rx.recv() => {
                            if let Err(e) = write.send(Message::Text(out_msg.into())).await {
                                eprintln!("[WebSocket] Failed to send outbound msg: {}", e);
                                break;
                            }
                        }
                        _ = ping_interval.tick() => {
                            // Engine.IO ping is "2"
                            if let Err(e) = write.send(Message::Text("2".into())).await {
                                eprintln!("[WebSocket] Failed to send ping: {}", e);
                                break;
                            }
                        }
                        msg = read.next() => {
                            match msg {
                                Some(Ok(Message::Text(text))) => {
                                    handle_message(text.to_string(), &config, &event_tx);
                                }
                                Some(Ok(Message::Close(_))) => {
                                    println!("[WebSocket] Connection closed by server");
                                    break;
                                }
                                Some(Err(e)) => {
                                    eprintln!("[WebSocket] Read error: {}", e);
                                    break;
                                }
                                _ => {}
                            }
                        }
                    }
                }
            }
            Err(e) => {
                eprintln!("[WebSocket] Connection failed: {}. Retrying in 10s...", e);
            }
        }
        
        // Wait before reconnecting
        time::sleep(Duration::from_secs(10)).await;
    }
}

fn handle_message(text: String, config: &AgentConfig, event_tx: &tokio::sync::mpsc::UnboundedSender<Value>) {
    // Engine.IO open packet: respond with Socket.IO connect (40) containing agent auth
    if text.starts_with('0') {
        println!("[WebSocket] Received Engine.IO Open. Sending Socket.IO connect payload...");
        let auth_payload = serde_json::json!({
            "apiKey": config.tenant_api_key,
            "room": config.agent_id,
            "machineSecret": config.machine_secret
        });
        let handshake = format!("40{}", auth_payload);
        if let Some(ref tx) = *WS_TX.lock().unwrap() {
            let _ = tx.try_send(handshake);
        }
        return;
    }

    // Engine.IO ping from server ("2"): respond with pong ("3") to keep connection alive
    if text == "2" {
        if let Some(ref tx) = *WS_TX.lock().unwrap() {
            let _ = tx.try_send("3".to_string());
        }
        return;
    }

    // Engine.IO pong ("3")
    if text == "3" {
        return;
    }

    // Socket.IO event starts with "42"
    if text.starts_with("42") {
        let json_str = &text[2..];
        match serde_json::from_str::<Value>(json_str) {
            Ok(val) => {
                if let Some(arr) = val.as_array() {
                    if arr.len() >= 2 {
                        let event_name = arr[0].as_str().unwrap_or("Unknown");
                        let data = &arr[1];

                        if let Some(obj) = data.as_object() {
                            // Handle C2 authentication handshake events
                            if event_name == "identity_challenge" {
                                let challenge = obj.get("challenge").and_then(|v| v.as_str()).unwrap_or("");
                                if !challenge.is_empty() {
                                    let mut key_seed = config.tenant_api_key.as_bytes().to_vec();
                                    key_seed.extend_from_slice(config.machine_secret.as_bytes());
                                    let secret = ring::digest::digest(&ring::digest::SHA256, &key_seed);
                                    let s_key = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, secret.as_ref());
                                    let tag = ring::hmac::sign(&s_key, challenge.as_bytes());
                                    let sig_hex = hex::encode(tag.as_ref());

                                    let resp = serde_json::json!(["verify_identity", {
                                        "signature": sig_hex
                                    }]);
                                    let packet = format!("42{}", resp);
                                    if let Some(ref tx) = *WS_TX.lock().unwrap() {
                                        let _ = tx.try_send(packet);
                                    }
                                    println!("[WebSocket] Replied to identity_challenge.");
                                }
                                return;
                            }

                            if event_name == "identity_verified" {
                                println!("[WebSocket] ✓ Agent identity cryptographically verified with C2.");
                                return;
                            }

                            let signature = obj.get("signature").and_then(|v| v.as_str()).unwrap_or("");
                            let timestamp = obj.get("timestamp").and_then(|v| v.as_str()).unwrap_or("");
                            
                            // Reconstruct params
                            let mut params = std::collections::BTreeMap::new();
                            for (k, v) in obj {
                                if k != "signature" && k != "timestamp" {
                                    params.insert(k.clone(), v.clone());
                                }
                            }

                            if !crate::c2::verify::verify_command_signature(
                                event_name,
                                &params,
                                timestamp,
                                signature,
                                &config.tenant_api_key,
                                &config.machine_secret,
                            ) {
                                eprintln!("[SECURITY ALERT] Unsigned {} request rejected.", event_name);
                                return;
                            }

                            println!("[WebSocket] Verified Command: {}", event_name);

                            if event_name == "RemoteInput" {
                                let value = serde_json::to_value(params).unwrap_or(serde_json::Value::Null);
                                crate::modules::input_simulation::simulate_input(&value);
                            } else if event_name == "StartStream" {
                                match crate::modules::live_desktop::start_live_desktop(config.agent_id.clone()) {
                                    Ok(msg) => println!("[StartStream] {}", msg),
                                    Err(e) => eprintln!("[StartStream] Error: {}", e),
                                }
                            } else if event_name == "StopStream" {
                                match crate::modules::live_desktop::stop_live_desktop() {
                                    Ok(msg) => println!("[StopStream] {}", msg),
                                    Err(e) => eprintln!("[StopStream] Error: {}", e),
                                }
                            } else if event_name == "Remediation" {
                                let action = params.get("Action").and_then(|v| v.as_str()).unwrap_or("");
                                if action == "KillProcess" {
                                    if let Some(pid_val) = params.get("TargetPID") {
                                        let pid_str = if pid_val.is_string() {
                                            pid_val.as_str().unwrap().to_string()
                                        } else {
                                            pid_val.to_string()
                                        };
                                        match crate::modules::process_control::kill_process(&pid_str) {
                                            Ok(msg) => println!("[Remediation] {}", msg),
                                            Err(e) => eprintln!("[Remediation] Error: {}", e),
                                        }
                                    }
                                } else if action == "ExecuteScript" {
                                    let language = params.get("Language").and_then(|v| v.as_str()).unwrap_or("");
                                    let script = params.get("ScriptContent").and_then(|v| v.as_str()).unwrap_or("");
                                    match crate::modules::script_exec::execute_script(language, script) {
                                        Ok(msg) => println!("[Remediation] Script Output:\n{}", msg),
                                        Err(e) => eprintln!("[Remediation] Script Error:\n{}", e),
                                    }
                                } else if action == "SinkholeDNS" {
                                    if let Some(domains_val) = params.get("Domains").and_then(|v| v.as_array()) {
                                        let mut domains = Vec::new();
                                        for d in domains_val {
                                            if let Some(s) = d.as_str() {
                                                domains.push(s.to_string());
                                            }
                                        }
                                        match crate::modules::dns_monitor::sinkhole_domains(domains) {
                                            Ok(msg) => println!("[Remediation] DNS Sinkhole:\n{}", msg),
                                            Err(e) => eprintln!("[Remediation] DNS Sinkhole Error:\n{}", e),
                                        }
                                    }
                                } else if action == "DeployDeception" {
                                    crate::modules::deception::deploy_honeyfiles(&config.agent_id);
                                    let agent_id_clone = config.agent_id.clone();
                                    tokio::spawn(async move {
                                        crate::modules::deception::deploy_shadow_service(agent_id_clone).await;
                                    });
                                    println!("[Remediation] Deception engine deployed.");
                                } else if action == "ManageService" {
                                    let svc_name = params.get("ServiceName").and_then(|v| v.as_str()).unwrap_or("");
                                    let svc_action = params.get("ServiceAction").and_then(|v| v.as_str()).unwrap_or("");
                                    match crate::modules::service_control::manage_service(svc_name, svc_action) {
                                        Ok(msg) => println!("[Remediation] Service:\n{}", msg),
                                        Err(e) => eprintln!("[Remediation] Service Error:\n{}", e),
                                    }
                                } else if action == "LockSession" {
                                    match crate::modules::lockdown::lock_session() {
                                        Ok(msg) => println!("[Remediation] Lockdown:\n{}", msg),
                                        Err(e) => eprintln!("[Remediation] Lockdown Error:\n{}", e),
                                    }
                                } else if action == "StartPcap" {
                                    match crate::modules::pcap_engine::start_capture() {
                                        Ok(msg) => println!("[Remediation] PCAP:\n{}", msg),
                                        Err(e) => eprintln!("[Remediation] PCAP Error:\n{}", e),
                                    }
                                } else if action == "StopPcap" {
                                    match crate::modules::pcap_engine::stop_and_collect() {
                                        Ok(msg) => {
                                            println!("[Remediation] PCAP collected, queueing upload.");
                                            crate::c2::offline_queue::enqueue_event(&msg);
                                        },
                                        Err(e) => eprintln!("[Remediation] PCAP Error:\n{}", e),
                                    }
                                } else if action == "TriggerIOCScan" {
                                    let dir = params.get("TargetDirectory").and_then(|v| v.as_str()).unwrap_or("/").to_string();
                                    let hashes: Vec<String> = params.get("Hashes")
                                        .and_then(|v| v.as_array())
                                        .map(|arr| arr.iter().filter_map(|i| i.as_str().map(|s| s.to_string())).collect())
                                        .unwrap_or_default();
                                        
                                    // Spawn IOC scan in background to avoid blocking websocket
                                    tokio::spawn(async move {
                                        println!("[Remediation] Starting background IOC scan on '{}'...", dir);
                                        // In a real agent, we would send these results back via the event channel
                                        match tokio::task::spawn_blocking(move || crate::modules::ioc_scanner::scan_directory(&dir, hashes)).await {
                                            Ok(Ok(matches)) => {
                                                println!("[Remediation] IOC Scan completed. Found {} matches.", matches.len());
                                                for m in matches {
                                                    println!("  - Malicious File: {}", m);
                                                }
                                            }
                                            Ok(Err(e)) => eprintln!("[Remediation] IOC Scan Error: {}", e),
                                            Err(e) => eprintln!("[Remediation] IOC Scan Thread Panicked: {}", e),
                                        }
                                    });
                                } else if action == "IsolateNetwork" {
                                    let backend_ip = params.get("BackendIP").and_then(|v| v.as_str()).unwrap_or("127.0.0.1");
                                    match crate::modules::isolation::isolate_network(backend_ip) {
                                        Ok(msg) => println!("[Remediation] Network Isolation:\n{}", msg),
                                        Err(e) => eprintln!("[Remediation] Isolation Error:\n{}", e),
                                    }
                                } else if action == "UnisolateNetwork" {
                                    match crate::modules::isolation::unisolate_network() {
                                        Ok(msg) => println!("[Remediation] Network Unisolation:\n{}", msg),
                                        Err(e) => eprintln!("[Remediation] Unisolation Error:\n{}", e),
                                    }
                                } else if action == "TriggerForensicCollection" {
                                    let output_dir = params.get("OutputDirectory").and_then(|v| v.as_str()).unwrap_or("/tmp/monitorix_forensics");
                                    match crate::modules::collector::trigger_collection(output_dir) {
                                        Ok(msg) => println!("[Remediation] Forensic Collection:\n{}", msg),
                                        Err(e) => eprintln!("[Remediation] Forensic Collection Error:\n{}", e),
                                    }
                                } else if action == "UpdatePolicy" {
                                    if let Some(new_policy) = params.get("Policy") {
                                        let policy_path = "data/policy.json";
                                        let _ = std::fs::create_dir_all("data");
                                        let _ = crate::modules::rollback::backup_policy(policy_path);
                                        match crate::modules::policy::update_policy(new_policy.clone(), policy_path) {
                                            Ok(_) => println!("[Remediation] Policy updated successfully (and backed up)."),
                                            Err(e) => {
                                                eprintln!("[Remediation] Policy Update Error: {}. Rolling back...", e);
                                                let _ = crate::modules::rollback::rollback_policy(policy_path);
                                            }
                                        }
                                    } else {
                                        eprintln!("[Remediation] Missing 'Policy' parameter in UpdatePolicy command.");
                                    }
                                } else if action == "RollbackConfig" {
                                    let policy_path = "data/policy.json";
                                    match crate::modules::rollback::rollback_policy(policy_path) {
                                        Ok(msg) => println!("[Remediation] Config Rollback:\n{}", msg),
                                        Err(e) => eprintln!("[Remediation] Config Rollback Error:\n{}", e),
                                    }
                                } else if action == "LoadPlugin" {
                                    let plugin_path = params.get("PluginPath").and_then(|v| v.as_str()).unwrap_or("");
                                    match crate::engines::plugin_mgr::load_plugin(plugin_path) {
                                        Ok(msg) => println!("[Remediation] Plugin Loaded:\n{}", msg),
                                        Err(e) => eprintln!("[Remediation] Plugin Load Error:\n{}", e),
                                    }
                                } else if action == "ExecuteCommand" {
                                    let cmd = params.get("Command").and_then(|v| v.as_str()).unwrap_or("");
                                    match crate::modules::remote_shell::execute_command(cmd) {
                                        Ok(msg) => println!("[Remediation] Remote Shell Output:\n{}", msg),
                                        Err(e) => eprintln!("[Remediation] Remote Shell Error:\n{}", e),
                                    }
                                } else if action == "TriggerMemoryDump" {
                                    let pid = params.get("TargetPID").and_then(|v| {
                                        if v.is_string() { Some(v.as_str().unwrap().to_string()) } else { Some(v.to_string()) }
                                    }).unwrap_or_default();
                                    let output_dir = params.get("OutputDirectory").and_then(|v| v.as_str()).unwrap_or("/tmp/monitorix_dumps");
                                    match crate::modules::memory_dump::trigger_memory_dump(&pid, output_dir) {
                                        Ok(msg) => {
                                            println!("[Remediation] Memory Dump Generated: {}", msg["Message"]);
                                            crate::c2::offline_queue::enqueue_event(&msg);
                                        },
                                        Err(e) => eprintln!("[Remediation] Memory Dump Error:\n{}", e),
                                    }
                                } else if action == "TriggerYaraScan" {
                                    let file_path = params.get("TargetPath").and_then(|v| v.as_str()).unwrap_or("");
                                    let rule_path = params.get("RulePath").and_then(|v| v.as_str()).unwrap_or("");
                                    match crate::engines::yara_scanner::scan_file(file_path, rule_path) {
                                        Ok(msg) => println!("[Remediation] YARA Scan Output:\n{}", msg),
                                        Err(e) => eprintln!("[Remediation] YARA Scan Error:\n{}", e),
                                    }
                                } else if action == "PatchSoftware" {
                                    let software_name = params.get("SoftwareName").and_then(|v| v.as_str()).unwrap_or("");
                                    match crate::modules::updater::trigger_patch(software_name) {
                                        Ok(msg) => println!("[Remediation] Patch Output:\n{}", msg),
                                        Err(e) => eprintln!("[Remediation] Patch Error:\n{}", e),
                                    }
                                } else if action == "VulnerabilityReport" || action == "SOARIncident" {
                                    println!("[WebSocket] Received {} from Backend. Pushing to SDK flow.", action);
                                    let event = serde_json::json!({
                                        "event_type": action,
                                        "severity": "CRITICAL",
                                        "details": params
                                    });
                                    let _ = event_tx.send(event);
                                } else if action == "TriggerAgentUpdate" {
                                    let download_url = params.get("DownloadUrl").and_then(|v| v.as_str()).unwrap_or("");
                                    let expected_hash = params.get("ExpectedHash").and_then(|v| v.as_str()).unwrap_or("");
                                    let publisher_signature = params.get("PublisherSignature").and_then(|v| v.as_str()).unwrap_or("");
                                    let agent_id_cb = config.agent_id.clone();
                                    let backend_url_cb = config.backend_url.clone();
                                    let api_key_cb = config.tenant_api_key.clone();

                                    let progress_cb = Box::new(move |percent: u64| {
                                        println!("[Updater] WebSocket trigger download progress: {}%", percent);
                                        let report_url = format!("{}/api/agents/{}/update-progress", backend_url_cb, agent_id_cb);
                                        let client = reqwest::blocking::Client::builder()
                                            .timeout(std::time::Duration::from_secs(5))
                                            .build().unwrap_or_default();
                                        let _ = client.post(&report_url)
                                            .header("X-Tenant-Api-Key", &api_key_cb)
                                            .json(&serde_json::json!({"progress": percent, "status": "downloading"}))
                                            .send();
                                    });
                                    match crate::modules::updater::trigger_update(download_url, expected_hash, publisher_signature, progress_cb) {
                                        Ok(msg) => println!("[Remediation] Updater:\n{}", msg),
                                        Err(e) => eprintln!("[Remediation] Updater Error:\n{}", e),
                                    }
                                } else if action == "RollbackVersion" || action == "TriggerAgentRollback" || action == "AgentRollback" {
                                    let target_ver = params.get("TargetVersion").and_then(|v| v.as_str());
                                    match crate::modules::rollback::rollback_agent_binary(target_ver) {
                                        Ok(msg) => println!("[Remediation] Rollback Success:\n{}", msg),
                                        Err(e) => eprintln!("[Remediation] Rollback Error:\n{}", e),
                                    }
                                } else if action == "UploadFile" {
                                    let path = params.get("DestinationPath").and_then(|v| v.as_str()).unwrap_or("");
                                    let base64_content = params.get("FileContentBase64").and_then(|v| v.as_str()).unwrap_or("");
                                    match crate::modules::file_manager::upload_file(path, base64_content) {
                                        Ok(msg) => println!("[Remediation] File Upload:\n{}", msg),
                                        Err(e) => eprintln!("[Remediation] File Upload Error:\n{}", e),
                                    }
                                } else if action == "DownloadFile" {
                                    let path = params.get("SourcePath").and_then(|v| v.as_str()).unwrap_or("");
                                    match crate::modules::file_manager::download_file(path) {
                                        Ok(msg) => {
                                            println!("[Remediation] File Downloaded ({} bytes). Sending back to C2.", msg.len());
                                            // In reality, emit this back over websocket
                                        },
                                        Err(e) => eprintln!("[Remediation] File Download Error:\n{}", e),
                                    }
                                } else if action == "EnterSafeMode" {
                                    match crate::modules::lockdown::enter_safe_mode() {
                                        Ok(msg) => println!("[Remediation] Safe Mode:\n{}", msg),
                                        Err(e) => eprintln!("[Remediation] Safe Mode Error:\n{}", e),
                                    }
                                } else if action == "SetRecoveryCode" {
                                    let code = params.get("RecoveryCode").and_then(|v| v.as_str()).unwrap_or("");
                                    match crate::modules::lockdown::set_recovery_code(code) {
                                        Ok(msg) => println!("[Remediation] Recovery Code:\n{}", msg),
                                        Err(e) => eprintln!("[Remediation] Recovery Code Error:\n{}", e),
                                    }
                                } else if action == "EmergencyUnlock" {
                                    let code = params.get("RecoveryCode").and_then(|v| v.as_str()).unwrap_or("");
                                    match crate::modules::lockdown::emergency_unlock(code) {
                                        Ok(msg) => println!("[Remediation] Emergency Unlock:\n{}", msg),
                                        Err(e) => eprintln!("[Remediation] Emergency Unlock Error:\n{}", e),
                                    }
                                } else if action == "BlockBluetooth" {
                                    match crate::modules::peripheral_control::block_bluetooth() {
                                        Ok(msg) => println!("[Remediation] Peripheral Control:\n{}", msg),
                                        Err(e) => eprintln!("[Remediation] Peripheral Control Error:\n{}", e),
                                    }
                                } else if action == "BlockCamera" {
                                    match crate::modules::peripheral_control::block_camera() {
                                        Ok(msg) => println!("[Remediation] Peripheral Control:\n{}", msg),
                                        Err(e) => eprintln!("[Remediation] Peripheral Control Error:\n{}", e),
                                    }
                                } else if action == "BlockMicrophone" {
                                    match crate::modules::peripheral_control::block_microphone() {
                                        Ok(msg) => println!("[Remediation] Peripheral Control:\n{}", msg),
                                        Err(e) => eprintln!("[Remediation] Peripheral Control Error:\n{}", e),
                                    }
                                } else if action == "EditRegistry" {
                                    let path = params.get("RegistryPath").and_then(|v| v.as_str()).unwrap_or("");
                                    let key = params.get("RegistryKey").and_then(|v| v.as_str()).unwrap_or("");
                                    let value = params.get("RegistryValue").and_then(|v| v.as_str()).unwrap_or("");
                                    match crate::modules::windows_parity::edit_registry(path, key, value) {
                                        Ok(msg) => println!("[Remediation] Registry Editor:\n{}", msg),
                                        Err(e) => eprintln!("[Remediation] Registry Editor Error:\n{}", e),
                                    }
                                }
                            }
                        }
                    }
                }
            }
            Err(e) => {
                eprintln!("[WebSocket] Failed to parse Socket.IO JSON: {}", e);
            }
        }
    }
}
