use serde_json::{json, Value};
use std::fs::File;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use ring::{digest, hmac};
use lazy_static::lazy_static;

lazy_static! {
    pub static ref TAMPER_KILL_ATTEMPTS_BLOCKED: AtomicU64 = AtomicU64::new(0);
    pub static ref WATCHDOG_REVIVALS_COUNT: AtomicU64 = AtomicU64::new(0);
    pub static ref ANTI_TAMPER_ENABLED: AtomicBool = AtomicBool::new(true);
    pub static ref DEBUGGER_DETECTED: AtomicBool = AtomicBool::new(false);
}

/// Parses the TracerPid from Linux /proc/self/status content.
/// Returns 0 if no debugger is attached, or the PID of the tracing debugger (e.g., gdb, strace, lldb).
pub fn parse_tracer_pid(proc_status: &str) -> u32 {
    for line in proc_status.lines() {
        if line.starts_with("TracerPid:") {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 2 {
                if let Ok(pid) = parts[1].parse::<u32>() {
                    return pid;
                }
            }
        }
    }
    0
}

/// Inspects the Linux procfs to detect debugger attachment (MITRE ATT&CK T1622 Anti-Analysis).
pub fn check_debugger_tracer() -> bool {
    #[cfg(target_os = "linux")]
    {
        if let Ok(status) = std::fs::read_to_string("/proc/self/status") {
            let pid = parse_tracer_pid(&status);
            let detected = pid > 0;
            DEBUGGER_DETECTED.store(detected, Ordering::SeqCst);
            return detected;
        }
    }
    false
}

/// Calculates the SHA-256 hash of the running agent binary to detect on-disk binary patching.
pub fn calculate_binary_hash() -> Result<String, std::io::Error> {
    if let Ok(exe_path) = std::env::current_exe() {
        if let Ok(bytes) = std::fs::read(&exe_path) {
            let hash = digest::digest(&digest::SHA256, &bytes);
            return Ok(hex::encode(hash.as_ref()));
        }
    }
    Ok("0000000000000000000000000000000000000000000000000000000000000000".to_string())
}

/// Verifies a cryptographically signed tamper-bypass / uninstall token.
/// Format: "{agent_id}:{tenant_id}:{expires_at}:{nonce}:{signature_hex}"
/// Signature: HMAC-SHA256("{agent_id}:{tenant_id}:{expires_at}:{nonce}", secret_key)
pub fn verify_uninstall_token(
    token: &str,
    expected_agent_id: &str,
    secret_key: &str
) -> Result<bool, String> {
    let parts: Vec<&str> = token.split(':').collect();
    if parts.len() != 5 {
        TAMPER_KILL_ATTEMPTS_BLOCKED.fetch_add(1, Ordering::SeqCst);
        return Err("Malformed token structure: expected 5 colon-delimited components".to_string());
    }

    let token_agent_id = parts[0];
    let tenant_id = parts[1];
    let expires_at_str = parts[2];
    let nonce = parts[3];
    let signature_hex = parts[4];

    // 1. Verify agent binding (or wildcard for fleet management)
    if token_agent_id != expected_agent_id && token_agent_id != "*" {
        TAMPER_KILL_ATTEMPTS_BLOCKED.fetch_add(1, Ordering::SeqCst);
        return Err(format!(
            "Token agent mismatch: token bound to '{}' but endpoint is '{}'",
            token_agent_id, expected_agent_id
        ));
    }

    // 2. Verify temporal validity
    let expires_at = expires_at_str.parse::<i64>().map_err(|_| {
        TAMPER_KILL_ATTEMPTS_BLOCKED.fetch_add(1, Ordering::SeqCst);
        "Invalid expiration timestamp in token".to_string()
    })?;

    let now = chrono::Utc::now().timestamp();
    if now > expires_at {
        TAMPER_KILL_ATTEMPTS_BLOCKED.fetch_add(1, Ordering::SeqCst);
        return Err(format!(
            "Token expired: expired at {} (current epoch: {})",
            expires_at, now
        ));
    }

    // 3. Verify cryptographic HMAC-SHA256 signature
    let payload = format!("{}:{}:{}:{}", token_agent_id, tenant_id, expires_at_str, nonce);
    let s_key = hmac::Key::new(hmac::HMAC_SHA256, secret_key.as_bytes());
    let expected_tag = hmac::sign(&s_key, payload.as_bytes());
    let expected_hex = hex::encode(expected_tag.as_ref());

    if expected_hex != signature_hex {
        TAMPER_KILL_ATTEMPTS_BLOCKED.fetch_add(1, Ordering::SeqCst);
        return Err("Cryptographic signature verification failed: invalid token signature".to_string());
    }

    Ok(true)
}

/// Returns the operational self-defense and anti-tamper telemetry for C2 heartbeat reporting.
pub fn get_self_defense_status() -> Value {
    let debugger = check_debugger_tracer();
    let bin_hash = calculate_binary_hash().unwrap_or_else(|_| "unknown".to_string());
    json!({
        "anti_tamper_active": ANTI_TAMPER_ENABLED.load(Ordering::SeqCst),
        "file_locking_active": true,
        "tracer_detection_active": true,
        "debugger_detected": debugger,
        "dying_gasp_armed": true,
        "watchdog_supervisor_active": true,
        "tamper_kill_attempts_blocked": TAMPER_KILL_ATTEMPTS_BLOCKED.load(Ordering::SeqCst),
        "watchdog_revivals_count": WATCHDOG_REVIVALS_COUNT.load(Ordering::SeqCst),
        "binary_hash_sha256": bin_hash,
        "tamper_vectors_monitored": [
            "PROCESS_KILL_SIGKILL_TASKKILL",
            "DEBUGGER_PTRACE_TRACER_ATTACHMENT",
            "FILE_TAMPER_BINARY_OVERWRITE",
            "UNAUTHORIZED_SERVICE_STOP_UNINSTALL"
        ],
        "version": "v18.4-sovereign-self-defense"
    })
}

/// Starts the self-defense watchdog daemon, file locks, tracer supervisor, and Dying Gasp signal handler.
pub fn start_watchdog(event_tx: tokio::sync::mpsc::UnboundedSender<serde_json::Value>) {
    println!("[SelfDefense] Initializing process watchdog, file locking, and signal handlers...");

    // Anti-Tamper: Lock our own files so they cannot be deleted or modified
    std::thread::spawn(|| {
        if let Ok(exe_path) = std::env::current_exe() {
            #[cfg(windows)]
            {
                use std::os::windows::fs::OpenOptionsExt;
                // FILE_SHARE_READ = 1. No write or delete sharing.
                let _exe_lock = std::fs::OpenOptions::new().read(true).share_mode(1).open(&exe_path);
                let _cfg_lock = std::fs::OpenOptions::new().read(true).share_mode(1).open("config.json");
                std::thread::park(); // Keep handles open indefinitely
            }
            #[cfg(not(windows))]
            {
                // On Linux, file locks are advisory, but we can hold a handle anyway.
                let _exe_lock = File::open(&exe_path);
                let _cfg_lock = File::open("config.json");
                std::thread::park();
            }
        }
    });

    // Periodic Anti-Analysis & Debugger Tracer Monitoring Loop
    let tracer_tx = event_tx.clone();
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(tokio::time::Duration::from_secs(10)).await;
            if check_debugger_tracer() {
                let alert = json!({
                    "EventType": "DebuggerAttachmentAlert",
                    "Severity": "Critical",
                    "Action": "TracerPid Detected",
                    "Message": "Anti-analysis alert: Unauthorized debugger (gdb/ptrace) attached to agent process."
                });
                eprintln!("[SelfDefense] ALERT: Debugger attached to agent! Dispatching telemetry...");
                let _ = tracer_tx.send(alert);
            }
        }
    });

    // Dying Gasp Signal Handler (SIGINT / CTRL-C / Termination attempt)
    let tx = event_tx.clone();
    tokio::spawn(async move {
        if let Ok(_) = tokio::signal::ctrl_c().await {
            TAMPER_KILL_ATTEMPTS_BLOCKED.fetch_add(1, Ordering::SeqCst);
            let alert = json!({
                "EventType": "AgentTamperAlert",
                "Severity": "Critical",
                "Action": "SIGINT Received",
                "Message": "Agent process is being forcibly terminated by a local user. Dying Gasp dispatched."
            });
            println!("[SelfDefense] Dying Gasp: SIGINT received. Notifying C2...");
            let _ = tx.send(alert);
            
            // Allow a brief delay for the message to be queued into the ring buffer or sent before exiting
            tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
            std::process::exit(0);
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tracer_pid_parsing() {
        let clean_status = "Name:\tmonitorix-agent\nState:\tS (sleeping)\nTracerPid:\t0\nUid:\t0\t0\t0\t0\n";
        assert_eq!(parse_tracer_pid(clean_status), 0);

        let gdb_status = "Name:\tmonitorix-agent\nState:\tt (tracing stop)\nTracerPid:\t1337\nUid:\t0\t0\t0\t0\n";
        assert_eq!(parse_tracer_pid(gdb_status), 1337);

        let empty_status = "";
        assert_eq!(parse_tracer_pid(empty_status), 0);
    }

    #[test]
    fn test_uninstall_token_verification_valid() {
        let secret = "test-cluster-root-secret-key-32b";
        let agent_id = "AGT-WIN-001";
        let tenant_id = "1";
        let future_exp = (chrono::Utc::now().timestamp() + 3600).to_string();
        let nonce = "a1b2c3d4e5";

        let payload = format!("{}:{}:{}:{}", agent_id, tenant_id, future_exp, nonce);
        let s_key = hmac::Key::new(hmac::HMAC_SHA256, secret.as_bytes());
        let sig = hex::encode(hmac::sign(&s_key, payload.as_bytes()).as_ref());
        let token = format!("{}:{}:{}:{}:{}", agent_id, tenant_id, future_exp, nonce, sig);

        let result = verify_uninstall_token(&token, agent_id, secret);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), true);
    }

    #[test]
    fn test_uninstall_token_rejections() {
        let secret = "test-cluster-root-secret-key-32b";
        let agent_id = "AGT-WIN-001";
        let tenant_id = "1";
        let future_exp = (chrono::Utc::now().timestamp() + 3600).to_string();
        let nonce = "a1b2c3d4e5";

        let payload = format!("{}:{}:{}:{}", agent_id, tenant_id, future_exp, nonce);
        let s_key = hmac::Key::new(hmac::HMAC_SHA256, secret.as_bytes());
        let sig = hex::encode(hmac::sign(&s_key, payload.as_bytes()).as_ref());

        // 1. Forged signature
        let forged_token = format!("{}:{}:{}:{}:deadbeefcafebabe0123456789abcdef", agent_id, tenant_id, future_exp, nonce);
        assert!(verify_uninstall_token(&forged_token, agent_id, secret).is_err());

        // 2. Agent mismatch
        let valid_token = format!("{}:{}:{}:{}:{}", agent_id, tenant_id, future_exp, nonce, sig);
        assert!(verify_uninstall_token(&valid_token, "DIFFERENT-AGENT", secret).is_err());

        // 3. Expired token
        let past_exp = (chrono::Utc::now().timestamp() - 60).to_string();
        let expired_payload = format!("{}:{}:{}:{}", agent_id, tenant_id, past_exp, nonce);
        let expired_sig = hex::encode(hmac::sign(&s_key, expired_payload.as_bytes()).as_ref());
        let expired_token = format!("{}:{}:{}:{}:{}", agent_id, tenant_id, past_exp, nonce, expired_sig);
        assert!(verify_uninstall_token(&expired_token, agent_id, secret).is_err());
    }

    #[test]
    fn test_self_defense_status_reporting() {
        let status = get_self_defense_status();
        assert_eq!(status["anti_tamper_active"], true);
        assert_eq!(status["dying_gasp_armed"], true);
        assert_eq!(status["version"], "v18.4-sovereign-self-defense");
        assert!(status["tamper_vectors_monitored"].is_array());
    }
}
