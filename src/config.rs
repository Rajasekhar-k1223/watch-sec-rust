use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentConfig {
    // ── Persisted fields (from config.json) ──────────────────────────────────
    #[serde(rename = "BackendUrl")]
    pub backend_url: String,
    #[serde(rename = "AgentId", default)]
    pub agent_id: String,
    #[serde(rename = "TenantApiKey", default)]
    pub tenant_api_key: String,
    #[serde(rename = "MachineSecret", default)]
    pub machine_secret: String,

    // ── Runtime feature toggles (from heartbeat response) ────────────────────
    // These are never saved to config.json — updated each heartbeat cycle.
    #[serde(skip)] pub mail_monitor_enabled:    bool,   // MailMonitorEnabled / MailIntelligenceEnabled
    #[serde(skip)] pub screenshots_enabled:     bool,   // VisualActivityEnabled
    #[serde(skip)] pub input_audit_enabled:     bool,   // InputAuditEnabled / KeyloggerEnabled
    #[serde(skip)] pub clipboard_audit_enabled: bool,   // ClipboardAuditEnabled
    #[serde(skip)] pub usb_blocking_enabled:    bool,   // UsbComplianceEnabled
    #[serde(skip)] pub shadow_audit_enabled:    bool,   // ShadowAuditEnabled
    #[serde(skip)] pub voice_enabled:           bool,   // VoiceIntelligenceEnabled
    #[serde(skip)] pub network_audit_enabled:   bool,   // NetworkAuditEnabled
    #[serde(skip)] pub dlp_enabled:             bool,   // DataLossPreventionEnabled
    #[serde(skip)] pub vulnerability_intelligence_enabled: bool, // VulnerabilityIntelligenceEnabled
    #[serde(skip)] pub sandbox_enabled:         bool,   // SandboxEnabled / RedRainbowEnabled

    // ── Runtime settings (from heartbeat response) ────────────────────────────
    #[serde(skip)] pub screenshot_interval:     u64,    // ScreenshotInterval (seconds)
    #[serde(skip)] pub screenshot_quality:      u32,    // ScreenshotQuality (0-100)
    #[serde(skip)] pub shadow_paths:            Vec<String>, // ShadowPaths
    #[serde(skip)] pub blocked_apps:            Vec<String>, // BlockedApps
    #[serde(skip)] pub fim_enabled:             bool,
    #[serde(skip)] pub fim_paths:               Vec<String>,
    #[serde(skip)] pub deception_enabled:        bool,   // DeceptionEnabled — deploy honeyfiles
}

impl Default for AgentConfig {
    fn default() -> Self {
        AgentConfig {
            backend_url:             "https://agent-apis.elsea.co.in".to_string(),
            agent_id:                "agent-rust-dev".to_string(),
            tenant_api_key:          "dev-key".to_string(),
            machine_secret:          "".to_string(),
            // Feature toggles — all off by default
            mail_monitor_enabled:    false,
            screenshots_enabled:     false,
            input_audit_enabled:     false,
            clipboard_audit_enabled: false,
            usb_blocking_enabled:    false,
            shadow_audit_enabled:    false,
            voice_enabled:           false,
            network_audit_enabled:   false,
            dlp_enabled:             false,
            vulnerability_intelligence_enabled: false,
            sandbox_enabled:         false,
            // Settings
            screenshot_interval:     300,
            screenshot_quality:      80,
            shadow_paths:            Vec::new(),
            blocked_apps:            Vec::new(),
            fim_enabled:             false,
            fim_paths:               Vec::new(),
            deception_enabled:       false,
        }
    }
}

/// Returns the path to config.json, always resolved relative to the running executable.
/// This ensures the config is found whether the agent is run from Task Scheduler,
/// a service, the command line, or any other working directory.
fn config_path() -> PathBuf {
    let exe_dir = std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|d| d.to_path_buf()))
        .unwrap_or_else(|| PathBuf::from("."));
    exe_dir.join("config.json")
}

pub fn load_config() -> AgentConfig {
    let path = config_path();
    if !path.exists() {
        eprintln!("[Boot] config.json not found at {:?}, using defaults.", path);
        return AgentConfig::default();
    }

    match fs::read_to_string(&path) {
        Ok(data) => {
            // Strip BOM if present
            let data = if data.starts_with('\u{FEFF}') {
                &data[3..]
            } else {
                &data
            };
            
            match serde_json::from_str::<AgentConfig>(data) {
                Ok(cfg) => {
                    println!("[Boot] Loaded config from {:?}", path);
                    cfg
                },
                Err(e) => {
                    eprintln!("[Boot] Failed to parse config.json: {}", e);
                    AgentConfig::default()
                }
            }
        }
        Err(e) => {
            eprintln!("[Boot] Failed to read config.json: {}", e);
            AgentConfig::default()
        }
    }
}

pub fn save_config(cfg: &AgentConfig) -> std::io::Result<()> {
    let path = config_path();
    let data = serde_json::to_string_pretty(cfg)?;
    fs::write(&path, data)?;
    println!("[Config] config.json saved to {:?}", path);
    Ok(())
}

