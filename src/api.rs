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
    }

    #[cfg(windows)]
    {
        let script = r#"
$user = "Unknown"
$time = "Unknown"
try {
    $cs = Get-WmiObject -Class Win32_ComputerSystem
    if ($cs.UserName) { $user = $cs.UserName }
} catch {}
try {
    $explorer = Get-Process -Name explorer -ErrorAction SilentlyContinue | Sort-Object StartTime | Select-Object -First 1
    if ($explorer) {
        $time = $explorer.StartTime.ToString("MM/dd/yyyy HH:mm")
        if ($user -eq "Unknown") {
            $expUser = Get-Process -Name explorer -IncludeUserName -ErrorAction SilentlyContinue | Select-Object -First 1
            if ($expUser -and $expUser.UserName) { $user = $expUser.UserName }
        }
    }
} catch {}
if ($user -match '.*\\(.*)') { $user = $matches[1] }
Write-Output "$user|||$time"
"#;
        if let Ok(output) = crate::hidden_command!("powershell")
            .args(&["-NoProfile", "-Command", script])
            .output() 
        {
            let out_str = String::from_utf8_lossy(&output.stdout);
            let parts: Vec<&str> = out_str.trim().split("|||").collect();
            if parts.len() >= 2 {
                active_user = parts[0].trim().to_string();
                user_login_time = parts[1].trim().to_string();
            } else if parts.len() == 1 {
                active_user = parts[0].trim().to_string();
            }
            
            if active_user.is_empty() {
                active_user = "Unknown".to_string();
            }
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

fn generate_events_signature(secret: &str, body: &str, timestamp: &str) -> String {
    // The Python backend is inconsistent: /events does NOT SHA256 the secret before HMAC,
    // and it does NOT use a pipe '|' between body and timestamp.
    let key = hmac::Key::new(hmac::HMAC_SHA256, secret.as_bytes());
    let msg = format!("{}{}", body, timestamp);
    let signature = hmac::sign(&key, msg.as_bytes());
    hex::encode(signature.as_ref())
}

pub async fn send_heartbeat(client: &Client, config: &AgentConfig) -> Result<AgentConfig, Box<dyn std::error::Error>> {
    let stats = get_hardware_stats();
    
    let network_info = crate::network::get_network_info(client).await;
    let installed_software_json = crate::software::get_installed_software();
    
    // Get hostname
    let hostname = sysinfo::System::host_name().unwrap_or_else(|| "Unknown".to_string());
    
    // Get MAC address for machine secret if empty
    let machine_secret = if config.machine_secret.is_empty() {
        if let Ok(Some(mac)) = get_mac_address() {
            mac.to_string()
        } else {
            "Unknown".to_string()
        }
    } else {
        config.machine_secret.clone()
    };

    let (active_user, user_login_time) = get_primary_session();
    let network_mbps = crate::network::get_network_bandwidth();

    let payload = HeartbeatPayload {
        agent_id: config.agent_id.clone(),
        hostname,
        just_started: false,
        tenant_api_key: config.tenant_api_key.clone(),
        cpu_usage: stats.cpu_usage,
        memory_usage: stats.mem_usage,
        disk_usage: stats.disk_usage,
        network_in_mbps: network_mbps.0,
        network_out_mbps: network_mbps.1,
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
        machine_secret,
        power_status: crate::modules::power_monitor::get_power_status(),
    };

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
    let url = format!("{}/api/agent/heartbeat", config.backend_url);

    let res = client.post(&url)
        .header("Content-Type", "application/json")
        .header("X-Signature", signature)
        .header("X-Timestamp", timestamp)
        .body(body)
        .send()
        .await?;

    let mut updated_config = config.clone();

    if res.status().is_success() {
        crate::log_msg("[Heartbeat] Successfully sent heartbeat.");

        // Parse the response body
        if let Ok(response_body) = res.text().await {
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

                    // Settings
                    updated_config.screenshot_interval     = u64_field("ScreenshotInterval", 300).max(30);
                    updated_config.screenshot_quality      = u64_field("ScreenshotQuality",  80).min(100) as u32;
                    updated_config.shadow_paths            = str_vec_field("ShadowPaths");
                    updated_config.blocked_apps            = str_vec_field("BlockedApps");

                    crate::log_msg(&format!(
                        "[Config] Toggles → screenshots={} input_audit={} voice={} shadow={} mail={} dlp={}",
                        updated_config.screenshots_enabled, updated_config.input_audit_enabled,
                        updated_config.voice_enabled, updated_config.shadow_audit_enabled,
                        updated_config.mail_monitor_enabled, updated_config.dlp_enabled,
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

                        std::thread::spawn(move || {
                            if let Err(e) = crate::modules::updater::trigger_update(&url, &hash, &sig) {
                                crate::log_msg(&format!("[Updater] Update failed: {}", e));
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

pub async fn send_events(client: &Client, config: &AgentConfig, events: &[serde_json::Value]) -> Result<(), Box<dyn std::error::Error>> {
    if events.is_empty() {
        return Ok(());
    }

    let payload = json!({
        "agent_id": config.agent_id,
        "tenant_api_key": config.tenant_api_key,
        "events": events
    });

    let body = serde_json::to_string(&payload)?;
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)?
        .as_secs()
        .to_string();
    
    let signature = generate_events_signature(&config.tenant_api_key, &body, &timestamp);
    let url = format!("{}/api/agent/events", config.backend_url);

    let res = client.post(&url)
        .header("Content-Type", "application/json")
        .header("X-Signature", signature)
        .header("X-Timestamp", timestamp)
        .body(body)
        .send()
        .await?;

    if res.status().is_success() {
        crate::log_msg(&format!("[EventDispatcher] Successfully sent {} events.", events.len()));
    } else {
        crate::log_msg(&format!("[EventDispatcher] Failed to send events: HTTP {}", res.status()));
    }

    Ok(())
}
