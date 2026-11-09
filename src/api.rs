use crate::config::AgentConfig;
use crate::hardware::{get_hardware_stats, HardwareInfo};
use ring::{hmac, digest};
use reqwest::Client;
use serde::Serialize;
use serde_json::json;
use std::time::{SystemTime, UNIX_EPOCH};
use mac_address::get_mac_address;

#[derive(Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct HeartbeatPayload {
    pub agent_id: String,
    pub hostname: String,
    pub just_started: bool,
    pub tenant_api_key: String,
    pub cpu_usage: f64,
    pub memory_usage: f64,
    pub disk_usage: f64,
    pub network_in_mbps: f64,
    pub network_out_mbps: f64,
    pub local_ip: String,
    pub public_ip: String,
    pub latitude: f64,
    pub longitude: f64,
    pub country: String,
    pub installed_software_json: String,
    pub active_user: String,
    pub user_login_time: String,
    pub version: String,
    pub hardware: HardwareInfo,
    pub machine_secret: String,
    pub power_status: serde_json::Value,
}

fn get_primary_session() -> (String, String) {
    let mut active_user = "Unknown".to_string();
    let mut user_login_time = "Unknown".to_string();

    #[cfg(unix)]
    {
        if let Ok(output) = crate::hidden_command!("who").output() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            if let Some(line) = stdout.lines().next() {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 4 {
                    active_user = parts[0].to_string();
                    user_login_time = format!("{} {}", parts[2], parts[3]);
                }
            }
        }
        
        if active_user == "Unknown" {
            if let Ok(output) = crate::hidden_command!("whoami").output() {
                let user = String::from_utf8_lossy(&output.stdout).trim().to_string();
                if !user.is_empty() {
                    active_user = user;
                }
            }
        }
    }

    #[cfg(windows)]
    {
        use wmi::{COMLibrary, WMIConnection, WMIDateTime};
        use serde::Deserialize;

        #[derive(Deserialize, Debug)]
        #[serde(rename_all = "PascalCase")]
        struct Win32ComputerSystem {
            user_name: Option<String>,
        }

        #[derive(Deserialize, Debug)]
        #[serde(rename_all = "PascalCase")]
        struct Win32Process {
            name: String,
            creation_date: Option<WMIDateTime>,
        }

        let mut wmi_success = false;

        if let Ok(com_con) = COMLibrary::new() {
            if let Ok(wmi_con) = WMIConnection::new(com_con.into()) {
                if let Ok(results) = wmi_con.raw_query::<Win32ComputerSystem>("SELECT UserName FROM Win32_ComputerSystem") {
                    if let Some(cs) = results.first() {
                        if let Some(name) = &cs.user_name {
                            active_user = name.clone();
                            if let Some(idx) = active_user.find('\\') {
                                active_user = active_user[idx + 1..].to_string();
                            }
                            wmi_success = true;
                        }
                    }
                }
                
                if let Ok(results) = wmi_con.raw_query::<Win32Process>("SELECT Name, CreationDate FROM Win32_Process WHERE Name = 'explorer.exe'") {
                    if let Some(proc) = results.first() {
                        if let Some(cd) = proc.creation_date {
                            user_login_time = cd.0.format("%m/%d/%Y %H:%M").to_string();
                        }
                    }
                }
            }
        }
        
        if !wmi_success {
            let mut sys = sysinfo::System::new();
            sys.refresh_processes();
            
            for (_pid, process) in sys.processes() {
                if process.name().to_lowercase() == "explorer.exe" {
                    let start_time = process.start_time();
                    if let Some(dt) = chrono::NaiveDateTime::from_timestamp_opt(start_time as i64, 0) {
                        user_login_time = dt.format("%m/%d/%Y %H:%M").to_string();
                    }
                    if let Some(user_id) = process.user_id() {
                        active_user = user_id.to_string(); // Will be SID on Windows if sysinfo can't resolve it, but better than nothing
                    }
                    break;
                }
            }
        }

        if active_user.is_empty() || active_user == "Unknown" {
            if let Ok(output) = crate::hidden_command!("whoami").output() {
                let user = String::from_utf8_lossy(&output.stdout).trim().to_string();
                if !user.is_empty() {
                    let mut final_user = user;
                    if let Some(idx) = final_user.find('\\') {
                        final_user = final_user[idx + 1..].to_string();
                    }
                    active_user = final_user;
                }
            }
        }

        if active_user.is_empty() {
            active_user = "Unknown".to_string();
        }
    }

    (active_user, user_login_time)
}

pub fn generate_signature(secret: &str, body: &str, timestamp: &str) -> String {
    let signing_key = digest::digest(&digest::SHA256, secret.as_bytes());
    let key = hmac::Key::new(hmac::HMAC_SHA256, signing_key.as_ref());
    let msg = format!("{}|{}", body, timestamp);
    let signature = hmac::sign(&key, msg.as_bytes());
    hex::encode(signature.as_ref())
}

#[allow(dead_code)]
fn generate_events_signature(secret: &str, body: &str, timestamp: &str) -> String {
    // The Python backend is inconsistent: /events does NOT SHA256 the secret before HMAC,
    // and it does NOT use a pipe '|' between body and timestamp.
    let key = hmac::Key::new(hmac::HMAC_SHA256, secret.as_bytes());
    let msg = format!("{}{}", body, timestamp);
    let signature = hmac::sign(&key, msg.as_bytes());
    hex::encode(signature.as_ref())
}

pub async fn send_heartbeat(client: &Client, config: &AgentConfig) -> Result<AgentConfig, Box<dyn std::error::Error>> {
    crate::log_msg("[Heartbeat] Calling get_hardware_stats()...");
    let stats = get_hardware_stats();
    
    crate::log_msg("[Heartbeat] Calling get_network_info()...");
    let network_info = crate::network::get_network_info(client).await;
    
    crate::log_msg("[Heartbeat] Calling get_installed_software()...");
    let installed_software_json = crate::software::get_installed_software();
    
    let hostname = sysinfo::System::host_name().unwrap_or_else(|| "Unknown".to_string());
    
    let machine_secret = if config.machine_secret.is_empty() {
        if let Ok(Some(mac)) = get_mac_address() {
            mac.to_string()
        } else {
            "Unknown".to_string()
        }
    } else {
        config.machine_secret.clone()
    };

    crate::log_msg("[Heartbeat] Calling get_power_status()...");
    let power_status = crate::modules::power_monitor::get_power_status();

    let (active_user, user_login_time) = get_primary_session();
    crate::log_msg("[Heartbeat] Generating payload...");
    
    let payload = HeartbeatPayload {
        agent_id: config.agent_id.clone(),
        hostname,
        just_started: false,
        tenant_api_key: config.tenant_api_key.clone(),
        cpu_usage: stats.cpu_usage,
        memory_usage: stats.mem_usage,
        disk_usage: stats.disk_usage,
        network_in_mbps: 0.0,
        network_out_mbps: 0.0,
        local_ip: network_info.local_ip,
        public_ip: network_info.public_ip,
        latitude: network_info.latitude,
        longitude: network_info.longitude,
        country: network_info.country,
        installed_software_json,
        active_user,
        user_login_time,
        version: format!("v{}", env!("CARGO_PKG_VERSION")),
        hardware: stats.hw_info,
        machine_secret: machine_secret.clone(),
        power_status,
    };

    let body = serde_json::to_string(&payload)?;
    
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)?
        .as_secs()
        .to_string();
    
    let signing_key = if !machine_secret.is_empty() { &machine_secret } else { &config.tenant_api_key };
    let signature = generate_signature(signing_key, &body, &timestamp);
    let url = format!("{}/api/agent/heartbeat", config.backend_url);

    crate::log_msg(&format!("[Heartbeat] Sending POST to {}", url));
    let res = client.post(&url)
        .header("Content-Type", "application/json")
        .header("X-Signature", signature)
        .header("X-Timestamp", timestamp)
        .body(body)
        .send()
        .await?;
    crate::log_msg("[Heartbeat] Received HTTP response!");

    let mut updated_config = config.clone();
    updated_config.machine_secret = machine_secret.clone();

    if res.status().is_success() {
        crate::log_msg("[Heartbeat] Successfully sent heartbeat.");

        crate::log_msg("[Heartbeat] Waiting for response text...");
        if let Ok(response_body) = res.text().await {
            crate::log_msg("[Heartbeat] Parsing response JSON...");
            if let Ok(json) = serde_json::from_str::<serde_json::Value>(&response_body) {
                // --- Parse all feature toggles and settings from heartbeat config ---
                if let Some(cfg) = json.get("config") {
                    // Helper closures
                    let bool_field = |key: &str, alt: Option<&str>| -> bool {
                        cfg.get(key)
                            .or_else(|| alt.and_then(|k| cfg.get(k)))
                            .and_then(|v| v.as_bool())
                            .unwrap_or(false)
                    };
                    let u64_field = |key: &str, default: u64| -> u64 {
                        cfg.get(key).and_then(|v| v.as_u64()).unwrap_or(default)
                    };
                    let str_vec_field = |key: &str| -> Vec<String> {
                        cfg.get(key)
                            .and_then(|v| v.as_array())
                            .map(|arr| arr.iter().filter_map(|v| v.as_str().map(String::from)).collect())
                            .or_else(|| {
                                // Also accept JSON-encoded string e.g. "[\"path1\",\"path2\"]"
                                cfg.get(key)
                                    .and_then(|v| v.as_str())
                                    .and_then(|s| serde_json::from_str::<Vec<String>>(s).ok())
                            })
                            .unwrap_or_default()
                    };

                    // Feature toggles (accept both legacy and v2.0 names)
                    updated_config.mail_monitor_enabled    = bool_field("MailMonitorEnabled",          Some("MailIntelligenceEnabled"));
                    updated_config.screenshots_enabled     = bool_field("ScreenshotsEnabled",           Some("VisualActivityEnabled"));
                    updated_config.input_audit_enabled     = bool_field("KeyloggerEnabled",             Some("InputAuditEnabled"));
                    updated_config.clipboard_audit_enabled = bool_field("ClipboardMonitorEnabled",      Some("ClipboardAuditEnabled"));
                    updated_config.usb_blocking_enabled    = bool_field("UsbBlockingEnabled",           Some("UsbComplianceEnabled"));
                    updated_config.shadow_audit_enabled    = bool_field("ShadowMonitorEnabled",         Some("ShadowAuditEnabled"));
                    updated_config.voice_enabled           = bool_field("SpeechMonitorEnabled",         Some("VoiceIntelligenceEnabled"));
                    updated_config.network_audit_enabled   = bool_field("NetworkMonitoringEnabled",     Some("NetworkAuditEnabled"));
                    updated_config.dlp_enabled             = bool_field("FileDlpEnabled",              Some("DataLossPreventionEnabled"));
                    updated_config.vulnerability_intelligence_enabled = bool_field("VulnerabilityIntelligenceEnabled", None);
                    updated_config.sandbox_enabled         = bool_field("SandboxEnabled",              Some("DynamicSandboxEnabled"));

                    // Settings
                    updated_config.screenshot_interval     = u64_field("ScreenshotInterval", 300).max(5);
                    updated_config.screenshot_quality      = u64_field("ScreenshotQuality",  80).min(100) as u32;
                    updated_config.shadow_paths            = str_vec_field("ShadowPaths");
                    updated_config.blocked_apps            = str_vec_field("BlockedApps");
                    
                    updated_config.fim_enabled             = bool_field("FileIntegrityMonitoringEnabled", None);
                    updated_config.fim_paths               = str_vec_field("FimPaths");
                    // DeceptionEnabled: controls whether honeyfiles are dropped on the next agent start
                    updated_config.deception_enabled       = bool_field("DeceptionEnabled", None);

                    crate::log_msg(&format!(
                        "[Config] Toggles → screenshots={} input_audit={} voice={} shadow={} mail={} dlp={} deception={} sandbox={}",
                        updated_config.screenshots_enabled, updated_config.input_audit_enabled,
                        updated_config.voice_enabled, updated_config.shadow_audit_enabled,
                        updated_config.mail_monitor_enabled, updated_config.dlp_enabled,
                        updated_config.deception_enabled, updated_config.sandbox_enabled
                    ));
                }

                // --- Handle OTA update request ---
                if let Some(update_required) = json.get("UpdateRequired").and_then(|v| v.as_bool()) {
                    if update_required {
                        let update_url       = json.get("UpdateUrl").and_then(|v| v.as_str()).unwrap_or("");
                        let update_hash      = json.get("UpdateHash").and_then(|v| v.as_str()).unwrap_or("");
                        let update_signature = json.get("UpdateSignature").and_then(|v| v.as_str()).unwrap_or("");

                        crate::log_msg(&format!("[Heartbeat] Server requested update. URL: {}", update_url));

                        let url = update_url.to_string();
                        let hash = update_hash.to_string();
                        let sig  = update_signature.to_string();
                        
                        let agent_id_cb = config.agent_id.clone();
                        let backend_url_cb = config.backend_url.clone();
                        let api_key_cb = config.tenant_api_key.clone();
                        
                        let backend_url_err = config.backend_url.clone();
                        let agent_id_err = config.agent_id.clone();
                        let api_key_err = config.tenant_api_key.clone();

                        std::thread::spawn(move || {
                            let progress_cb = move |percent: u64| {
                                let report_url = format!("{}/api/agents/{}/update-progress", backend_url_cb, agent_id_cb);
                                let client = reqwest::blocking::Client::builder()
                                    .timeout(std::time::Duration::from_secs(5))
                                    .build().unwrap_or_default();
                                let _ = client.post(&report_url)
                                    .header("X-Tenant-Api-Key", &api_key_cb)
                                    .json(&serde_json::json!({"progress": percent, "status": "downloading"}))
                                    .send();
                            };
                            
                            if let Err(e) = crate::modules::updater::trigger_update(&url, &hash, &sig, Box::new(progress_cb)) {
                                crate::log_msg(&format!("[Updater] Update failed: {}", e));
                                let report_url = format!("{}/api/agents/{}/update-progress", backend_url_err, agent_id_err);
                                let client = reqwest::blocking::Client::builder()
                                    .timeout(std::time::Duration::from_secs(5))
                                    .build().unwrap_or_default();
                                let _ = client.post(&report_url)
                                    .header("X-Tenant-Api-Key", &api_key_err)
                                    .json(&serde_json::json!({"progress": 0, "status": format!("error: {}", e)}))
                                    .send();
                            }
                        });
                    }
                }
            }
        }
    } else {
        crate::log_msg(&format!("[Heartbeat] Failed: HTTP {}", res.status()));
    }

    Ok(updated_config)
}

/// Lightweight telemetry — only CPU, memory, and network. Cheap to call every 5s.
/// Does NOT collect disk, software, hardware inventory, or IP geolocation.
/// The backend uses this data only for the real-time Socket.IO dashboard update.
pub async fn send_telemetry(client: &Client, config: &AgentConfig) -> Result<(), Box<dyn std::error::Error>> {
    let quick = crate::hardware::get_quick_stats();
    let network_mbps = crate::network::get_network_bandwidth();

    let machine_secret = if !config.machine_secret.is_empty() {
        config.machine_secret.clone()
    } else {
        if let Ok(Some(mac)) = get_mac_address() { mac.to_string() } else { "Unknown".to_string() }
    };

    let payload = serde_json::json!({
        "AgentId": config.agent_id,
        "TenantApiKey": config.tenant_api_key,
        "MachineSecret": machine_secret,
        "CpuUsage": quick.cpu_usage,
        "MemoryUsage": quick.mem_usage,
        "NetworkInMbps": network_mbps.0,
        "NetworkOutMbps": network_mbps.1,
        "TotalNetworkInGB": network_mbps.2,
        "TotalNetworkOutGB": network_mbps.3,
        "ActiveNicName": network_mbps.4,
        "Status": "Online",
        // Telemetry-only marker so the backend doesn't store a full report row
        "TelemetryOnly": true,
    });

    let body = serde_json::to_string(&payload)?;
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)?
        .as_secs()
        .to_string();

    let signing_key = if !config.machine_secret.is_empty() {
        &config.machine_secret
    } else {
        &config.tenant_api_key
    };
    let signature = generate_signature(signing_key, &body, &timestamp);
    let url = format!("{}/api/agent/telemetry", config.backend_url);

    let res = client.post(&url)
        .header("Content-Type", "application/json")
        .header("X-Signature", signature)
        .header("X-Timestamp", timestamp)
        .body(body)
        .send()
        .await;

    // Telemetry failures are silent — we don't want to spam the log every 5s
    if let Ok(r) = res {
        if !r.status().is_success() && r.status().as_u16() != 404 {
            crate::log_msg(&format!("[Telemetry] Failed: HTTP {}", r.status()));
        }
    }

    Ok(())
}

#[allow(dead_code)]
pub async fn send_events(client: &Client, config: &AgentConfig, events: &[serde_json::Value]) -> Result<(), Box<dyn std::error::Error>> {
    // 1. Drain pending offline buffer (up to 50 events per batch)
    let mut all_events = crate::modules::offline_buffer::drain_spool(50);
    all_events.extend_from_slice(events);

    if all_events.is_empty() {
        return Ok(());
    }

    let payload = json!({
        "agent_id": config.agent_id,
        "tenant_api_key": config.tenant_api_key,
        "events": all_events
    });

    let body = serde_json::to_string(&payload)?;
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)?
        .as_secs()
        .to_string();
    
    let signature = generate_events_signature(&config.tenant_api_key, &body, &timestamp);
    let url = format!("{}/api/agent/events", config.backend_url);

    match client.post(&url)
        .header("Content-Type", "application/json")
        .header("X-Signature", signature)
        .header("X-Timestamp", timestamp)
        .body(body)
        .send()
        .await
    {
        Ok(res) => {
            if res.status().is_success() {
                crate::log_msg(&format!("[EventDispatcher] Successfully sent {} events (including replayed offline spool).", all_events.len()));
            } else {
                crate::log_msg(&format!("[EventDispatcher] Server returned HTTP {}. Spooling events to offline buffer.", res.status()));
                let _ = crate::modules::offline_buffer::spool_events(&all_events);
            }
        }
        Err(e) => {
            crate::log_msg(&format!("[EventDispatcher] Network offline or unreachable ({}). Spooling {} events to offline disk buffer.", e, all_events.len()));
            let _ = crate::modules::offline_buffer::spool_events(&all_events);
        }
    }

    Ok(())
}
