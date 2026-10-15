#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

#[macro_export]
macro_rules! hidden_command {
    ($program:expr) => {{
        #[allow(unused_mut)]
        let mut cmd = std::process::Command::new($program);
        #[cfg(target_os = "windows")]
        {
            use std::os::windows::process::CommandExt;
            cmd.creation_flags(0x08000000);
        }
        cmd
    }};
}

mod api;
mod c2;
mod config;
mod hardware;
mod network;
mod software;
pub mod modules;
pub mod engines;

use reqwest::Client;
use std::io::Write;
use std::sync::Mutex;
use std::time::Duration;
use tokio::time;

// ── Global file logger (Windows: writes to agent.log beside the EXE) ─────────
static LOG_FILE: Mutex<Option<std::fs::File>> = Mutex::new(None);

fn init_file_logger() {
    if let Some(exe_dir) = std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|d| d.to_path_buf()))
    {
        let log_path = exe_dir.join("agent.log");
        if let Ok(f) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&log_path)
        {
            if let Ok(mut guard) = LOG_FILE.lock() {
                *guard = Some(f);
            }
        }
    }
}

/// Write a message to stdout AND to agent.log (Windows) simultaneously.
pub fn log_msg(msg: &str) {
    println!("{}", msg);
    if let Ok(mut guard) = LOG_FILE.lock() {
        if let Some(ref mut f) = *guard {
            let ts = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);
            let _ = writeln!(f, "[{}] {}", ts, msg);
        }
    }
}

/// Convenience macro — same signature as println!
#[macro_export]
macro_rules! agent_log {
    ($($arg:tt)*) => { $crate::log_msg(&format!($($arg)*)) };
}

#[tokio::main]
async fn main() {
    // CRITICAL: Install rustls crypto provider FIRST before any TLS operations.
    // Required by rustls 0.23+ (pulled in by tokio-tungstenite 0.30).
    // Using `let _ =` because install_default() errors if called twice (safe to ignore).
    let _ = rustls::crypto::ring::default_provider().install_default();

    if let Ok(exe_path) = std::env::current_exe() {
        if let Some(parent) = exe_path.parent() {
            let _ = std::env::set_current_dir(parent);
        }
    }

    init_file_logger();

    // Check for --worker flag to determine if we are the watchdog or the worker
    let args: Vec<String> = std::env::args().collect();
    let is_worker = args.iter().any(|a| a.contains("--worker"));
    let is_enroll = args.iter().any(|a| a.contains("--enroll"));
    
    // Do not run Watchdog if we are just enrolling
    if !is_worker && !is_enroll {
        log_msg("[Boot] Starting in Watchdog Mode...");
        let current_exe = std::env::current_exe().expect("Failed to get current executable path");

        #[cfg(target_os = "windows")]
        {
            let exe_path = current_exe.to_string_lossy().to_string();
            log_msg("[Persistence] Ensuring Windows Scheduled Task exists...");
            let out = crate::hidden_command!("schtasks")
                .args(&[
                    "/Create",
                    "/F",
                    "/TN", "MonitorixAgent",
                    "/TR", &exe_path,
                    "/SC", "ONSTART",
                    "/RL", "HIGHEST"
                ])
                .output();
            if let Ok(res) = out {
                if !res.status.success() {
                    // Fallback to ONLOGON if not running as admin
                    let _ = crate::hidden_command!("schtasks")
                        .args(&[
                            "/Create",
                            "/F",
                            "/TN", "MonitorixAgent",
                            "/TR", &exe_path,
                            "/SC", "ONLOGON"
                        ])
                        .output();
                }
            }
        }

        loop {
            log_msg("[Watchdog] Spawning worker process...");
            let mut cmd = crate::hidden_command!(&current_exe);
            cmd.arg("--worker");
            
            // Forward existing arguments
            for arg in args.iter().skip(1) {
                if arg != "--worker" {
                    cmd.arg(arg);
                }
            }
            
            match cmd.spawn() {
                Ok(mut child) => {
                    match child.wait() {
                        Ok(status) => {
                            if status.success() {
                                log_msg("[Watchdog] Worker exited gracefully (code 0). Watchdog exiting.");
                                std::process::exit(0);
                            } else {
                                log_msg(&format!("[Watchdog] Worker exited with {}. Restarting in 5 seconds...", status));
                                std::thread::sleep(std::time::Duration::from_secs(5));
                            }
                        }
                        Err(e) => {
                            log_msg(&format!("[Watchdog] Failed to wait on worker: {}. Restarting in 5 seconds...", e));
                            std::thread::sleep(std::time::Duration::from_secs(5));
                        }
                    }
                }
                Err(e) => {
                    log_msg(&format!("[Watchdog] Failed to spawn worker: {}. Retrying in 5 seconds...", e));
                    std::thread::sleep(std::time::Duration::from_secs(5));
                }
            }
        }
    }

    log_msg("[Boot] Monitorix Rust Agent (Worker) starting...");
    log_msg(&format!("[Boot] OS: {}", std::env::consts::OS));

    // Set panic hook FIRST so any crash is captured to agent.log
    std::panic::set_hook(Box::new(|info| {
        let msg = format!("[PANIC] Agent crashed: {}", info);
        crate::log_msg(&msg);
    }));

    let mut session_id: u32 = 1;
    #[cfg(target_os = "windows")]
    {
        unsafe {
            windows::Win32::System::RemoteDesktop::ProcessIdToSessionId(
                std::process::id(),
                &mut session_id,
            );
        }
        log_msg(&format!("[Boot] Detected Windows Session ID: {}", session_id));
        
        if session_id == 0 {
            let args: Vec<String> = std::env::args().collect();
            if !args.iter().any(|a| a == "--escaped") {
                log_msg("[Boot] Trapped in Session 0! Attempting to escape via PowerShell and schtasks...");
                let script = r#"
                    $user = (Get-WmiObject -Class Win32_ComputerSystem).UserName
                    if ($user) {
                        Write-Host $user
                    }
                "#;
                let output = crate::hidden_command!("powershell")
                    .args(&["-NoProfile", "-Command", script])
                    .output();
                    
                if let Ok(out) = output {
                    let active_user = String::from_utf8_lossy(&out.stdout).trim().to_string();
                    if !active_user.is_empty() {
                        log_msg(&format!("[Boot] Found active user: {}", active_user));
                        let exe_path = std::env::current_exe().unwrap().to_string_lossy().to_string();
                        
                        let _ = crate::hidden_command!("schtasks")
                            .args(&["/Create", "/F", "/TN", "MonitorixEscape", "/TR", &format!("\"{}\" --escaped", exe_path), "/SC", "ONCE", "/ST", "00:00", "/RU", &active_user])
                            .output();
                            
                        let _ = crate::hidden_command!("schtasks")
                            .args(&["/Run", "/TN", "MonitorixEscape"])
                            .output();
                            
                        log_msg("[Boot] Triggered escape task. SYSTEM agent continuing in Session 0.");
                        // Do NOT exit here! The SYSTEM agent must stay alive to handle updates and network monitoring.
                    } else {
                        log_msg("[Boot] Failed to find active user. Cannot escape.");
                    }
                }
            }
        }
    }

    // Single instance lock (per session)
    let lock_port = 48392 + session_id as u16;
    let _instance_lock = match std::net::TcpListener::bind(format!("127.0.0.1:{}", lock_port)) {
        Ok(listener) => listener,
        Err(_) => {
            log_msg(&format!("[Boot] Another agent instance is already running in Session {}. Exiting.", session_id));
            std::process::exit(0);
        }
    };

    log_msg(&format!("[Boot] Config path: {:?}", std::env::current_exe()
        .ok().and_then(|p| p.parent().map(|d| d.join("config.json")))));
    log_msg("[Boot] Loading config...");
    let config = config::load_config();

    log_msg(&format!("[Boot] Backend URL: {}", config.backend_url));
    log_msg(&format!("[Boot] Agent ID:    {}", config.agent_id));
    log_msg(&format!("[Boot] Enrolled:    {}", !config.machine_secret.is_empty()));

    log_msg("[Boot] Starting background hardware sampler...");
    crate::hardware::start_background_sampler();

    log_msg("[Boot] Building HTTP client...");
    let client = match Client::builder()
        .timeout(Duration::from_secs(10))
        .use_rustls_tls()
        .tls_built_in_root_certs(true)
        .trust_dns(true)
        .build()
    {
        Ok(c) => { log_msg("[Boot] HTTP client ready."); c }
        Err(e) => {
            log_msg(&format!("[Boot] FATAL: Failed to build HTTP client: {}", e));
            std::process::exit(1);
        }
    };

    let mut config = config;

    let mut enroll_pin: Option<String> = None;
    for arg in &args {
        if arg == "--enroll" {
            if let Some(pos) = args.iter().position(|a| a == "--enroll") {
                if pos + 1 < args.len() {
                    enroll_pin = Some(args[pos + 1].clone());
                }
            }
        } else if arg.starts_with("--enroll ") {
            if let Some(pin) = arg.split_whitespace().nth(1) {
                enroll_pin = Some(pin.to_string());
            }
        }
    }

    if let Some(pin) = enroll_pin {
        let pin = &pin;
        // Skip re-enrollment if already enrolled
        if !config.machine_secret.is_empty() {
            log_msg("[Enrollment] Already enrolled (MachineSecret present). Skipping re-enrollment.");
            std::process::exit(0);
        }
        log_msg(&format!("[Enrollment] Attempting to enroll with PIN: {}", pin));

        let hostname = sysinfo::System::host_name().unwrap_or_else(|| "rust-agent-sys".to_string());
        
        if config.agent_id.is_empty() || config.agent_id == "agent-rust-dev" {
            config.agent_id = hostname.clone();
        }

        let payload = serde_json::json!({
            "AgentId": config.agent_id,
            "Hostname": hostname,
            "JustStarted": true,
            "TenantApiKey": pin,
        });

        let url = format!("{}/api/agent/register", config.backend_url);
        let resp = client.post(&url)
            .json(&payload)
            .send()
            .await;

        match resp {
            Ok(response) => {
                if response.status().is_success() {
                    if let Ok(json) = response.json::<serde_json::Value>().await {
                        if let Some(secret) = json.get("machine_secret").and_then(|v| v.as_str()) {
                            config.machine_secret = secret.to_string();
                            if let Err(e) = config::save_config(&config) {
                                eprintln!("[Enrollment] Failed to save config: {}", e);
                                std::process::exit(1);
                            }
                            println!("[Enrollment] Agent successfully enrolled! MachineSecret acquired.");
                            std::process::exit(0);
                        } else {
                            eprintln!("[Enrollment] Server response missing 'machine_secret'.");
                            std::process::exit(1);
                        }
                    } else {
                        eprintln!("[Enrollment] Failed to parse JSON response.");
                        std::process::exit(1);
                    }
                } else {
                    eprintln!("[Enrollment] Enrollment failed with status: {}. Is the PIN correct?", response.status());
                    std::process::exit(1);
                }
            },
            Err(e) => {
                eprintln!("[Enrollment] Network request failed: {}", e);
                std::process::exit(1);
            }
        }
    }

    log_msg("[Boot] Starting agent main loop...");

    // Spawn Behavioral Audit Loop
    let activity_client = client.clone();
    let activity_config = config.clone();
    tokio::spawn(async move {
        let mut interval = time::interval(Duration::from_secs(2)); // Live Activity audit every 2s
        
        // Session activity is chunked inside the session_activity module natively.

        loop {
            interval.tick().await;

            let mut is_service = false;
            #[cfg(target_os = "windows")]
            {
                unsafe {
                    let mut s_id = 0;
                    windows::Win32::System::RemoteDesktop::ProcessIdToSessionId(
                        std::process::id(),
                        &mut s_id,
                    );
                    if s_id == 0 {
                        is_service = true;
                    }
                }
            }

            if is_service {
                // Background service in Session 0 cannot see UI. Skip activity tracking to avoid
                // false 'Idle' logs.
                continue;
            }

            let active_window = modules::session_activity::get_active_window().await;

            if let Some(mut activity) = active_window {
                // --- System is ACTIVE: report the active window ---
                if let Some(obj) = activity.as_object_mut() {
                    obj.insert("AgentId".to_string(), serde_json::json!(activity_config.agent_id));
                    obj.insert("TenantApiKey".to_string(), serde_json::json!(activity_config.machine_secret));
                    obj.insert("Timestamp".to_string(), serde_json::json!(chrono::Utc::now().to_rfc3339()));
                    
                    let url = format!("{}/api/events/activity", activity_config.backend_url);
                    let body = serde_json::to_string(&activity).unwrap_or_default();
                    let timestamp_str = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs()
                        .to_string();
                    let signature = crate::api::generate_signature(&activity_config.tenant_api_key, &body, &timestamp_str);

                    let _ = activity_client.post(&url)
                        .header("Content-Type", "application/json")
                        .header("X-Signature", signature)
                        .header("X-Timestamp", timestamp_str)
                        .body(body)
                        .send()
                        .await;

                }
            }
        }
    });

    // Deploy Deception Engine Decoys
    let mut is_primary_agent = true;
    #[cfg(target_os = "windows")]
    {
        if session_id != 0 {
            // Check if the service holds the primary lock
            if std::net::TcpListener::bind("127.0.0.1:48392").is_err() {
                is_primary_agent = false;
                log_msg("[Boot] Running in UI Helper Mode. Background scans and C2 disabled.");
            }
        }
    }

    if is_primary_agent && config.deception_enabled {
        log_msg("[Boot] Deception mode enabled — deploying decoy files...");
        engines::deception::deploy_decoy();
        
        // Deploy Ransomware Decoys
        engines::ransomware_decoy::deploy_decoy();
    } else if is_primary_agent {
        log_msg("[Boot] Deception mode disabled — skipping decoy deployment.");
    }
    // ── Shared live config ─────────────────────────────────────────────────────
    // The heartbeat response updates runtime toggles (e.g. MailMonitorEnabled).
    // Wrap in an Arc<Mutex<>> so background loops can read the latest value.
    use std::sync::{Arc, Mutex as StdMutex};
    let live_config = Arc::new(StdMutex::new(config.clone()));

    // Event Dispatcher Channel
    let (event_tx, mut event_rx) = tokio::sync::mpsc::unbounded_channel::<serde_json::Value>();

    // Start Command Receiver (WebSocket)
    if is_primary_agent {
        let c2_config = config.clone();
        let c2_tx = event_tx.clone();
        tokio::spawn(async move {
            c2::websocket::start(c2_config, c2_tx).await;
        });
    }

    if is_primary_agent {
        let sb_tx = event_tx.clone();
        let sb_cfg = live_config.clone();
        modules::sandbox_monitor::start_sandbox_monitor(sb_tx, sb_cfg);
    }
    let rest_client = client.clone();
    if is_primary_agent {
        tokio::spawn(async move {
            let mut interval = time::interval(std::time::Duration::from_secs(60));
            loop {
                interval.tick().await;
                let pending = crate::c2::offline_rest_queue::flush_rest_queue();
                for req in pending {
                    let orig_req = req.clone();
                    let mut req_builder = if req.method == "POST" {
                        rest_client.post(&req.url)
                    } else {
                        rest_client.get(&req.url)
                    };
                    for (k, v) in req.headers {
                        req_builder = req_builder.header(k, v);
                    }
                    let res = req_builder.body(req.body).send().await;
                    if res.is_err() {
                        // Put back if it fails again
                        crate::c2::offline_rest_queue::enqueue_rest_request(orig_req);
                    }
                }
            }
        });
    }

    // Event Dispatcher Channel (Moved up)

    if is_primary_agent {
        // Start Ransomware Decoy Watcher
        engines::ransomware_decoy::watch_decoy(event_tx.clone());

        // Initialize eBPF Kernel Tracing (Linux Only)
        engines::ebpf_tracer::start_ebpf_tracer(event_tx.clone());

        // Start Self-Defense Watchdog
        modules::self_defense::start_watchdog(event_tx.clone());

        // Use OS-appropriate paths for File Integrity Monitoring
        // FIM initialization moved below
    }


    if is_primary_agent {
        // Start Process and System Monitors
        modules::process_monitor::start(event_tx.clone(), Arc::clone(&live_config));
        modules::system_monitor::start(event_tx.clone());
        modules::session_activity::start_live_telemetry(event_tx.clone());
        // Deception Engine Initialization — only if explicitly enabled in policy
        if config.deception_enabled {
            crate::log_msg("[Boot] DeceptionEnabled=true — deploying honeyfiles to user folders...");
            crate::modules::deception::deploy_honeyfiles(&config.agent_id);
            let deception_agent_id = config.agent_id.clone();
            tokio::spawn(async move {
                crate::modules::deception::deploy_shadow_service(deception_agent_id).await;
            });
        } else {
            crate::log_msg("[Boot] DeceptionEnabled=false — cleaning up any legacy honeyfiles...");
            crate::modules::deception::cleanup_honeyfiles();
        }
        // Start asynchronous watchdogs
        crate::modules::dlp_engine::start_dlp_monitor(event_tx.clone());

        crate::modules::usb_monitor::start_usb_monitor(event_tx.clone(), Arc::clone(&live_config));
        crate::modules::fim::start_fim(event_tx.clone(), Arc::clone(&live_config));
    }
    
    // Fallback: Read initial config if present
    // Start AV and Firewall Security Scans
    let security_tx = event_tx.clone();
    // Clones for feature-gated upload closures
    let live_config_scan    = Arc::clone(&live_config);
    let upload_client       = client.clone();
    let upload_backend_url  = config.backend_url.clone();
    let upload_agent_id     = config.agent_id.clone();
    let upload_machine_secret = config.machine_secret.clone();
    let upload_tenant_key   = config.tenant_api_key.clone();

    if is_primary_agent {
        tokio::spawn(async move {
            // Screenshot interval is configurable — check live_config each iteration
        let _last_screenshot = std::time::Instant::now();
        // [FIX] Reduced security scan interval from 1 hour to 5 minutes so vulnerabilities are detected quickly!
        let mut scan_interval = time::interval(std::time::Duration::from_secs(300)); 
        let mut ticks = 0;
        loop {
            scan_interval.tick().await;
            ticks += 1;
            
            let (deception_findings, av_status, fw_status, session_status, mem_alerts, usbs, local_users, startup_programs, network_connections, cis_report, cron_audit, patch_inv) = tokio::task::spawn_blocking(|| {
                let d = crate::modules::deception::audit_traps();
                let av = modules::av_monitor::check_av_status();
                let fw = modules::firewall_monitor::check_firewall_status();
                let ss = modules::session_audit::get_active_sessions();
                let ma = modules::memory_scanner::scan_memory();
                let u = modules::usb_monitor::get_connected_usbs();
                let lu = modules::local_users::get_local_users();
                let sp = modules::startup_programs::get_startup_programs();
                let nc = modules::network_connections::get_network_connections();
                let cr = modules::cis_audit::perform_audit();
                let ca = modules::cron_audit::audit_scheduled_tasks();
                let pi = modules::patch_inventory::get_installed_packages();
                (d, av, fw, ss, ma, u, lu, sp, nc, cr, ca, pi)
            }).await.unwrap();

            for finding in deception_findings {
                let _ = security_tx.send(finding);
            }
            
            let _ = security_tx.send(av_status);
            let _ = security_tx.send(fw_status);
            let _ = security_tx.send(session_status);

            for alert in mem_alerts {
                let _ = security_tx.send(alert);
            }
            
            if !usbs.is_empty() {
                let usb_event = serde_json::json!({
                    "type": "UsbConnected",
                    "devices": usbs,
                });
                let _ = security_tx.send(usb_event);
            }

            let _ = security_tx.send(local_users);
            let _ = security_tx.send(startup_programs);
            let _ = security_tx.send(network_connections);
            let _ = security_tx.send(cis_report);
            let _ = security_tx.send(cron_audit);
            let _ = security_tx.send(patch_inv.clone());
            
            // GAP 5 & 6: SBOM Reporting & Vulnerability Scan Trigger
            let (is_vuln_on, local_agent_id) = {
                let lc = live_config_scan.lock().unwrap();
                (lc.vulnerability_intelligence_enabled, upload_agent_id.clone())
            };
            
            if is_vuln_on {
                let client_clone = upload_client.clone();
                let sbom_url = format!("{}/api/agents/{}/sbom", upload_backend_url, local_agent_id);
                let scan_url = format!("{}/api/vulnerabilities/scan/{}", upload_backend_url, local_agent_id);
                let payload = patch_inv.clone();
                tokio::spawn(async move {
                    // 1. Post SBOM
                    let _ = client_clone.post(&sbom_url)
                        .header("Content-Type", "application/json")
                        .json(&payload)
                        .send()
                        .await;
                    // 2. Trigger Vuln Scan
                    let _ = client_clone.post(&scan_url)
                        .send()
                        .await;
                });
            }
            let driver_inv = modules::driver_inventory::get_kernel_modules();
            let _ = security_tx.send(driver_inv);



            if let Some(printer_audit) = modules::printer_audit::audit_cups_print_jobs() {
                let _ = security_tx.send(printer_audit.clone());
                
                // GAP 4: Print audit not uploaded
                let mut printer_payload = printer_audit.clone();
                let ts = chrono::Utc::now().timestamp().to_string();
                if let Some(obj) = printer_payload.as_object_mut() {
                    obj.insert("Type".to_string(), serde_json::json!("PrintJob"));
                    obj.insert("AgentId".to_string(), serde_json::json!(upload_agent_id.clone()));
                    obj.insert("Timestamp".to_string(), serde_json::json!(chrono::Utc::now().to_rfc3339()));
                }
                let client_clone = upload_client.clone();
                let url = format!("{}/api/events/report", upload_backend_url);
                let body_str = serde_json::to_string(&printer_payload).unwrap_or_default();
                let sig = crate::api::generate_signature(&upload_machine_secret, &body_str, &ts);
                
                tokio::spawn(async move {
                    let _ = client_clone.post(&url)
                        .header("Content-Type", "application/json")
                        .header("X-Signature", sig)
                        .header("X-Timestamp", ts)
                        .body(body_str)
                        .send()
                        .await;
                });
            }

            let periph_audit = modules::peripheral_audit::audit_peripherals();
            let _ = security_tx.send(periph_audit);

            let cert_inv = modules::certificate_inventory::get_certificates();
            let _ = security_tx.send(cert_inv);

            let browser_audit = modules::browser_compliance::audit_browsers();
            let _ = security_tx.send(browser_audit);

            let dns_audit = modules::dns_monitor::check_dns_config();
            let _ = security_tx.send(dns_audit);

            let timeline_report = modules::timeline::generate_timeline();
            let _ = security_tx.send(timeline_report);

            let net_ifaces = modules::network_interfaces::audit_interfaces();
            let _ = security_tx.send(net_ifaces);

            let bandwidth_report = modules::bandwidth_monitor::check_bandwidth();
            let _ = security_tx.send(bandwidth_report);

            let vpn_report = modules::vpn_detection::detect_vpn();
            let _ = security_tx.send(vpn_report);

            let boot_report = modules::boot_monitor::audit_boot();
            let _ = security_tx.send(boot_report);

            let crash_report = modules::crash_dump::audit_crash_dumps();
            let _ = security_tx.send(crash_report);

            let fw_comp = modules::firewall_compliance::audit_firewall();
            let _ = security_tx.send(fw_comp);

            let admin_audit = modules::local_admin_audit::audit_admins();
            let _ = security_tx.send(admin_audit);

            let pass_policy = modules::password_policy::audit_password_policy();
            let _ = security_tx.send(pass_policy);

            // Read live config snapshot for this tick
            let (screenshots_on, screenshot_interval, input_audit_on,
                 shadow_on, shadow_paths, voice_on, mail_on, _vuln_on,
                 clipboard_audit_on,
                 agent_id, backend_url, machine_secret, tenant_key) = {
                let lc = live_config_scan.lock().unwrap();
                (lc.screenshots_enabled, lc.screenshot_interval,
                 lc.input_audit_enabled, lc.shadow_audit_enabled,
                 lc.shadow_paths.clone(), lc.voice_enabled,
                 lc.mail_monitor_enabled, lc.dlp_enabled,
                 lc.clipboard_audit_enabled,
                 upload_agent_id.clone(), upload_backend_url.clone(),
                 upload_machine_secret.clone(), upload_tenant_key.clone())
            };

            // Capture for internal event bus even when upload disabled
            let clipboard = modules::clipboard_audit::audit_clipboard();
            let _ = security_tx.send(clipboard);

            let location = modules::location_tracking::track_location();
            let _ = security_tx.send(location);

            let dhcp_audit = modules::dhcp_monitor::audit_dhcp();
            let _ = security_tx.send(dhcp_audit);

            let audio_audit = modules::peripheral_control::audit_audio_monitoring();
            let _ = security_tx.send(audio_audit);

            // Deep Checks (Every 60 mins / 12 ticks) to save CPU/Memory
            if ticks % 12 == 0 {
                let mem_scan = crate::engines::memory_scan::scan_memory();
                let _ = security_tx.send(mem_scan);

                let exploit_scan = crate::engines::memory_scan::detect_exploits();
                let _ = security_tx.send(exploit_scan);
                
                let hw_audit = modules::hardware_audit::audit_hardware();
                let _ = security_tx.send(hw_audit);
                
                let event_logs = modules::event_logs::fetch_auth_logs();
                let _ = security_tx.send(event_logs);
            }

            let reg_monitor = modules::windows_parity::monitor_registry();
            let _ = security_tx.send(reg_monitor);

            let shadow_copy_status = modules::windows_parity::monitor_shadow_copies();
            let _ = security_tx.send(shadow_copy_status);

            // ── Input Audit (Keylogger) ───────────────────────────────────────
            if input_audit_on {
                modules::input_audit::sample_keystrokes();
                if let Some(keystroke_report) = modules::input_audit::flush_keystroke_buffer() {
                    let mut payload = keystroke_report;
                    if let Some(obj) = payload.as_object_mut() {
                        obj.insert("AgentId".to_string(),     serde_json::json!(agent_id));
                        // obj.insert("TenantApiKey".to_string(), serde_json::json!(machine_secret));
                    }
                    let url = format!("{}/api/events/report", backend_url);
                    let body_str = serde_json::to_string(&payload).unwrap_or_default();
                    let ts = chrono::Utc::now().timestamp().to_string();
                    let sig = crate::api::generate_signature(&machine_secret, &body_str, &ts);
                    let _ = upload_client.post(&url)
                        .header("Content-Type", "application/json")
                        .header("X-Signature", sig)
                        .header("X-Timestamp", ts)
                        .body(body_str)
                        .send()
                        .await;
                }
            }

            // ── Shadow File Monitor ───────────────────────────────────────────
            // Correct backend endpoint: POST /api/uploads/shadow (not /api/agents/{id}/shadow-upload)
            // Backend also verifies optional content_sha256 field.
            if shadow_on && !shadow_paths.is_empty() {
                let shadow_uploads = modules::shadow_monitor::drain_upload_queue();
                for sf in shadow_uploads {
                    let mut payload = sf.clone();
                    // Compute SHA256 of the raw bytes from file_b64 for forensic integrity
                    let sha256_hex = if let Some(b64) = sf.get("file_b64").and_then(|v| v.as_str()) {
                        // Simple hex SHA256 via ring crate already in deps
                        use ring::digest;
                        let raw = b64.as_bytes();
                        let hash = digest::digest(&digest::SHA256, raw);
                        hex::encode(hash.as_ref())
                    } else {
                        String::new()
                    };
                    if let Some(obj) = payload.as_object_mut() {
                        obj.insert("agent_id".to_string(),       serde_json::json!(agent_id));
                        obj.insert("TenantApiKey".to_string(),   serde_json::json!(machine_secret));
                        obj.insert("content_sha256".to_string(), serde_json::json!(sha256_hex));
                    }
                    let body_str = serde_json::to_string(&payload).unwrap_or_default();
                    let ts  = chrono::Utc::now().timestamp().to_string();
                    let sig = crate::api::generate_signature(&machine_secret, &body_str, &ts);
                    let url = format!("{}/api/uploads/shadow", backend_url);
                    let res = upload_client.post(&url)
                        .header("Content-Type", "application/json")
                        .header("X-Signature",   sig.clone())
                        .header("X-Timestamp",   ts.clone())
                        .body(body_str.clone())
                        .send()
                        .await;
                    if res.is_err() {
                        crate::c2::offline_rest_queue::enqueue_rest_request(crate::c2::offline_rest_queue::RestPayload {
                            url,
                            method: "POST".to_string(),
                            headers: std::collections::HashMap::from([
                                ("Content-Type".to_string(), "application/json".to_string()),
                                ("X-Signature".to_string(), sig),
                                ("X-Timestamp".to_string(), ts),
                            ]),
                            body: body_str.into_bytes(),
                        });
                    }
                    crate::log_msg(&format!("[ShadowMonitor] Uploaded shadow file to backend (or queued)."));
                }
            }

            // ── Voice / Speech Recording ─────────────────────────────────────
            // Correct URL: POST /api/speech/upload/{agent_id}  (agent_id in path)
            if voice_on {
                let voice_client   = upload_client.clone();
                // FIX GAP 11: agent_id is in the URL path, not just the body (Actually, backend expects just /api/speech/upload)
                let voice_url      = format!("{}/api/speech/upload", backend_url);
                let voice_agent_id = agent_id.clone();
                let voice_secret   = machine_secret.clone();
                let voice_key      = tenant_key.clone();
                tokio::task::spawn_blocking(move || {
                    if let Some(audio_payload) = modules::voice_recorder::record_chunk() {
                        let mut payload = audio_payload;
                        if let Some(obj) = payload.as_object_mut() {
                            obj.insert("agent_id".to_string(),     serde_json::json!(voice_agent_id));
                            obj.insert("TenantApiKey".to_string(), serde_json::json!(voice_secret));
                        }
                        let body_str = serde_json::to_string(&payload).unwrap_or_default();
                        let ts  = chrono::Utc::now().timestamp().to_string();
                        let sig = crate::api::generate_signature(&voice_key, &body_str, &ts);
                        let rt  = tokio::runtime::Handle::try_current();
                        if let Ok(handle) = rt {
                            handle.block_on(async {
                                let res = voice_client.post(&voice_url)
                                    .header("Content-Type", "application/json")
                                    .header("X-Signature", sig.clone())
                                    .header("X-Timestamp",  ts.clone())
                                    .body(body_str.clone())
                                    .send()
                                    .await;
                                if res.is_err() {
                                    crate::c2::offline_rest_queue::enqueue_rest_request(crate::c2::offline_rest_queue::RestPayload {
                                        url: voice_url.clone(),
                                        method: "POST".to_string(),
                                        headers: std::collections::HashMap::from([
                                            ("Content-Type".to_string(), "application/json".to_string()),
                                            ("X-Signature".to_string(), sig),
                                            ("X-Timestamp".to_string(), ts),
                                        ]),
                                        body: body_str.into_bytes(),
                                    });
                                }
                            });
                        }
                        crate::log_msg("[VoiceRecorder] Uploaded audio chunk to backend.");
                    }
                });
            }

            // ── Mail Intelligence ─────────────────────────────────────────────
            if mail_on {
                let mut mail_events = modules::mail_monitor::capture_mail_events();
                mail_events.extend(modules::webmail_monitor::capture_webmail_events());
                for evt in mail_events {
                    let mail_url = format!("{}/api/mail/", backend_url);
                    let mut payload = evt.clone();
                    if let Some(obj) = payload.as_object_mut() {
                        obj.insert("AgentId".to_string(),      serde_json::json!(agent_id));
                        obj.insert("TenantApiKey".to_string(), serde_json::json!(machine_secret));
                        obj.insert("Timestamp".to_string(),    serde_json::json!(chrono::Utc::now().to_rfc3339()));
                    }
                    let _ = upload_client.post(&mail_url)
                        .header("Content-Type", "application/json")
                        .json(&payload)
                        .send()
                        .await;
                }
            }
        }
    });

    let config_clone = config.clone();
    
    // Initialize Local SDK Broadcaster
    let sdk_tx = modules::local_sdk::start_sdk_server();
    let sigma_engine = modules::sigma_lite::SigmaLiteEngine::new();
    let mut ransomware_shield = modules::ransomware::RansomwareShield::new();

    // Initialize gRPC Telemetry Stream
    let (grpc_tx, grpc_rx) = tokio::sync::mpsc::channel(10000);
    tokio::spawn(async move {
        if let Ok(mut grpc_client) = crate::c2::grpc_client::GrpcTelemetryClient::connect(&config_clone).await {
            if let Err(e) = grpc_client.stream_events(grpc_rx).await {
                eprintln!("[gRPC] Stream closed with error: {}", e);
            }
        } else {
            eprintln!("[gRPC] Failed to connect to Gateway");
        }
    });

    tokio::spawn(async move {
        let mut flush_interval = time::interval(Duration::from_secs(10));
        
        loop {
            tokio::select! {
                Some(event) = event_rx.recv() => {
                    // Check if this is a push-down from the backend (WebSocket)
                    if let Some(ev_type) = event.get("event_type").and_then(|t| t.as_str()) {
                        if ev_type == "VulnerabilityReport" || ev_type == "SOARIncident" {
                            let _ = sdk_tx.send(event.clone()); // Broadcast to Local SDK
                            continue; // DO NOT send back to gRPC (prevents loops)
                        }
                    }

                    // Enrich event with MITRE ATT&CK Context
                    let enriched_event = crate::engines::mitre_mapper::enrich_event(event);
                    
                    // Evaluate Sigma Rules locally
                    if let Some(event_type) = enriched_event.get("type").and_then(|t| t.as_str()) {
                        if event_type == "ProcessCreate" {
                            if let Some(cmdline) = enriched_event.get("command_line").and_then(|c| c.as_str()) {
                                if let Some(sigma_alert) = sigma_engine.evaluate_event(event_type, cmdline) {
                                    let _ = sdk_tx.send(sigma_alert.clone()); // Broadcast to Local SDK
                                    let _ = grpc_tx.send(sigma_alert).await;
                                }
                            }
                        }
                    }

                    // Evaluate Ransomware heuristics
                    if let Some(event_type) = enriched_event.get("type").and_then(|t| t.as_str()) {
                        if event_type == "FileWrite" || event_type == "FileRename" {
                            if let Some(pid) = enriched_event.get("pid").and_then(|p| p.as_u64()) {
                                let action = if event_type == "FileWrite" { "HighEntropyWrite" } else { "MassRename" };
                                let entropy = enriched_event.get("entropy").and_then(|e| e.as_f64()).unwrap_or(0.0);
                                if ransomware_shield.evaluate_file_action(pid as u32, action, entropy) {
                                    let rw_alert = serde_json::json!({
                                        "event_type": "DetectionAlert",
                                        "severity": "CRITICAL",
                                        "detection_name": "Ransomware Behavior Detected",
                                        "rule_id": "RANSOM-001",
                                    });
                                    let _ = sdk_tx.send(rw_alert.clone());
                                    let _ = grpc_tx.send(rw_alert).await;
                                }
                            }
                        }
                    }
                    
                    // Send to gRPC, fallback to offline queue if disconnected
                    if grpc_tx.send(enriched_event.clone()).await.is_err() {
                        crate::c2::offline_queue::enqueue_event(&enriched_event);
                    }
                }
                _ = flush_interval.tick() => {
                    // Check and flush offline queue periodically
                    let offline_events = crate::c2::offline_queue::flush_queue();
                    if !offline_events.is_empty() {
                        for ev in offline_events {
                            if grpc_tx.send(ev.clone()).await.is_err() {
                                crate::c2::offline_queue::enqueue_event(&ev);
                            }
                        }
                    }
                }
            }
        }
    });
    } // End of is_primary_agent block

    // --- USER SESSION LOOP ---
    // Start this loop unconditionally so that User Session agents can capture screenshots and clipboard.
    let user_live_config = Arc::clone(&live_config);
    let user_upload_client = client.clone();
    tokio::spawn(async move {
        let mut last_screenshot = std::time::Instant::now().checked_sub(std::time::Duration::from_secs(3600)).unwrap_or_else(std::time::Instant::now);
        let mut last_clipboard = std::time::Instant::now().checked_sub(std::time::Duration::from_secs(3600)).unwrap_or_else(std::time::Instant::now);
        let mut scan_interval = time::interval(std::time::Duration::from_secs(5));
        loop {
            scan_interval.tick().await;

            let (screenshots_on, screenshot_interval, clipboard_audit_on,
                 agent_id, backend_url, machine_secret, tenant_key) = {
                let lc = user_live_config.lock().unwrap();
                (lc.screenshots_enabled, lc.screenshot_interval, lc.clipboard_audit_enabled,
                 lc.agent_id.clone(), lc.backend_url.clone(), lc.machine_secret.clone(), lc.tenant_api_key.clone())
            };

            // ── Screenshot Upload ──
            let secs_since_last = last_screenshot.elapsed().as_secs();
            if screenshots_on && secs_since_last >= screenshot_interval {
                last_screenshot = std::time::Instant::now();
                if let Some(screenshot_payload) = crate::modules::screenshot_capture::capture_screenshot() {
                    let mut payload = screenshot_payload.clone();
                    if let Some(obj) = payload.as_object_mut() {
                        obj.insert("agent_id".to_string(), serde_json::json!(agent_id));
                        obj.remove("_EventType");
                    }
                    let url = format!("{}/api/screenshots/upload", backend_url);
                    let body_str = serde_json::to_string(&payload).unwrap_or_default();
                    let ts = chrono::Utc::now().timestamp().to_string();
                    let sig = crate::api::generate_signature(&machine_secret, &body_str, &ts);
                    
                    let client_clone = user_upload_client.clone();
                    let tenant_key_clone = tenant_key.clone();
                    tokio::spawn(async move {
                        let _ = client_clone.post(&url)
                            .header("Content-Type", "application/json")
                            .header("X-Signature", sig)
                            .header("X-Timestamp", ts)
                            .header("X-Tenant-Api-Key", &tenant_key_clone)
                            .body(body_str)
                            .send()
                            .await;
                        crate::log_msg("[Screenshot] Uploaded to backend.");
                    });
                }
            }

            // ── Clipboard Audit ──
            let secs_since_last_clipboard = last_clipboard.elapsed().as_secs();
            // Default to 60s clipboard audit to save CPU from powershell spawns
            if clipboard_audit_on && secs_since_last_clipboard >= 60 {
                last_clipboard = std::time::Instant::now();
                let clipboard = crate::modules::clipboard_audit::audit_clipboard();
                if let Some(contents) = clipboard.get("ClipboardContents").and_then(|v| v.as_str()) {
                    if !contents.is_empty() && contents != "[Clipboard is empty]" {
                        let lower_contents = contents.to_lowercase();
                        let keywords = ["password", "confidential", "secret", "credit card", "api_key"];
                        let is_alert = keywords.iter().any(|k| lower_contents.contains(k));
                        let severity = if is_alert { "High" } else { "Low" };

                        let payload = serde_json::json!({
                            "Type":      "ClipboardCapture",
                            "AgentId":  agent_id,
                            "Details":   contents,
                            "Timestamp": chrono::Utc::now().to_rfc3339(),
                            "IsAlert":   is_alert,
                            "Severity":  severity,
                        });
                        let url = format!("{}/api/events/report", backend_url);
                        let body_str = serde_json::to_string(&payload).unwrap_or_default();
                        let ts = chrono::Utc::now().timestamp().to_string();
                        let sig = crate::api::generate_signature(&machine_secret, &body_str, &ts);
                        
                        let client_clone = user_upload_client.clone();
                        tokio::spawn(async move {
                            let _ = client_clone.post(&url)
                                .header("Content-Type", "application/json")
                                .header("X-Signature", sig)
                                .header("X-Timestamp", ts)
                                .body(body_str)
                                .send()
                                .await;
                        });
                    }
                }
            }
        }
    });

    let mut interval = time::interval(Duration::from_secs(30)); // Full heartbeat every 30s — expensive sysinfo refresh_all

    // ── Real-time lightweight telemetry loop (every 5s) ──────────────────────
    // Sends CPU + memory + network to the backend for Socket.IO live updates.
    // Uses get_quick_stats() which only calls refresh_cpu_usage + refresh_memory.
    // This is ~10x cheaper than the full heartbeat and keeps the dashboard live.
    let tele_client = client.clone();
    let tele_config = config.clone();
    let tele_live = Arc::clone(&live_config);
    tokio::spawn(async move {
        // Stagger the start by 2s so it doesn't overlap with the first heartbeat
        time::sleep(Duration::from_secs(2)).await;
        let mut tele_interval = time::interval(Duration::from_secs(5));
        loop {
            tele_interval.tick().await;
            // Read the latest config (may be updated by heartbeat)
            let current_config = {
                tele_live.lock().map(|lc| lc.clone()).unwrap_or_else(|_| tele_config.clone())
            };
            if let Err(e) = api::send_telemetry(&tele_client, &current_config).await {
                // Silent — telemetry is best-effort
                let _ = e;
            }
        }
    });

    loop {
        crate::log_msg("[Main] Waiting for interval.tick()...");
        interval.tick().await;
        crate::log_msg("[Main] Calling send_heartbeat...");
        match api::send_heartbeat(&client, &config).await {
            Ok(updated) => {
                crate::log_msg("[Main] send_heartbeat returned Ok");
                if let Ok(mut lc) = live_config.lock() {
                    *lc = updated.clone();
                }
                if updated.shadow_audit_enabled && !config.shadow_audit_enabled {
                    let paths = updated.shadow_paths.clone();
                    crate::log_msg(&format!("[ShadowMonitor] Starting watcher on {} paths.", paths.len()));
                    modules::shadow_monitor::start_shadow_watcher(paths);
                }
                config = updated;
            }
            Err(e) => {
                crate::log_msg(&format!("[Main] [Error] Failed to send heartbeat: {}", e));
                eprintln!("[Error] Failed to send heartbeat: {}", e);
            }
        }
    }
}
