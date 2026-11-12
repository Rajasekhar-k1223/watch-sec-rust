#![allow(unused_imports)]
use serde_json::{json, Value};
use chrono::Utc;
use std::collections::HashSet;
use std::sync::Mutex;
use lazy_static::lazy_static;

lazy_static! {
    static ref SEEN_TITLES: Mutex<HashSet<String>> = Mutex::new(HashSet::new());
}

/// DLP keyword patterns that indicate sensitive data exfiltration via webmail
const DLP_KEYWORDS: &[&str] = &[
    "password", "secret", "confidential", "api_key", "apikey",
    "private key", "ssh key", "credentials", "passphrase",
    "token", "bearer", "authorization", "ssn", "social security",
    "credit card", "cvv", "bank account", "routing number",
];

/// Capture heuristic webmail events synchronously for the main loop
pub fn capture_webmail_events() -> Vec<Value> {
    let mut events = Vec::new();
    let current_title = get_active_window_title();
    
    if current_title.is_empty() {
        return events;
    }

    let lower_title = current_title.to_lowercase();
    let is_webmail = lower_title.contains("compose") || 
                     lower_title.contains("new message") ||
                     lower_title.contains("gmail") || 
                     lower_title.contains("outlook") ||
                     lower_title.contains("yahoo mail") ||
                     lower_title.contains("protonmail") ||
                     lower_title.contains("webmail");
                     
    if is_webmail {
        let mut seen_guard = SEEN_TITLES.lock().unwrap();
        if !seen_guard.contains(&current_title) {
            seen_guard.insert(current_title.clone());
            
            crate::log_msg(&format!("[WebmailMonitor] Detected Webmail session: {}", current_title));
            
            // Capture real live dynamic clipboard as body heuristic
            let draft_body = capture_draft_body();
            let risk = assess_dlp_risk(&draft_body);
            
            events.push(json!({
                "EventType": "WebmailActivity",
                "Sender": "local_user@endpoint",
                "Recipient": "Unknown (Heuristic)",
                "Subject": current_title,
                "BodyPreview": draft_body,
                "HasAttachments": false,
                "AttachmentNames": "",
                "Attachments": [],
                "RiskLevel": risk,
                "Timestamp": Utc::now().to_rfc3339(),
            }));
        }
    }
    events
}

fn assess_dlp_risk(body: &str) -> &'static str {
    let lower = body.to_lowercase();
    for kw in DLP_KEYWORDS {
        if lower.contains(kw) {
            return "High";
        }
    }
    "Normal"
}

fn capture_draft_body() -> String {
    // Dynamic cross-platform clipboard capture using arboard
    if let Ok(mut cb) = arboard::Clipboard::new() {
        if let Ok(text) = cb.get_text() {
            if !text.is_empty() {
                let sample: String = text.chars().take(500).collect();
                return format!("[Dynamic Live Clipboard] {}", sample);
            }
        }
    }

    // Fallback on Linux to xclip if display server isolation applies
    #[cfg(not(target_os = "windows"))]
    {
        if let Ok(out) = crate::hidden_command!("xclip")
            .args(&["-selection", "clipboard", "-o"])
            .output()
        {
            let text = String::from_utf8_lossy(&out.stdout).to_string();
            if !text.is_empty() {
                return format!("[Dynamic XClip Capture] {}", &text[..text.len().min(500)]);
            }
        }
    }

    "[No active clipboard text detected during compose session]".to_string()
}

// ── Platform-specific active window title detection ───────────────────────────

#[cfg(target_os = "linux")]
fn get_active_window_title() -> String {
    // Try xdotool first (most reliable on X11)
    if let Ok(out) = crate::hidden_command!("xdotool")
        .args(&["getactivewindow", "getwindowname"])
        .output()
    {
        let title = String::from_utf8_lossy(&out.stdout).trim().to_string();
        if !title.is_empty() {
            return title;
        }
    }

    // Fallback: xprop
    if let Ok(out) = crate::hidden_command!("xprop")
        .args(&["-root", "_NET_ACTIVE_WINDOW"])
        .output()
    {
        let stdout = String::from_utf8_lossy(&out.stdout);
        // Look for window ID: _NET_ACTIVE_WINDOW(WINDOW): window id # 0x...
        if let Some(id_part) = stdout.split('#').nth(1) {
            let win_id = id_part.trim().split_whitespace().next().unwrap_or("").trim();
            if !win_id.is_empty() && win_id != "0x0" {
                if let Ok(name_out) = crate::hidden_command!("xprop")
                    .args(&["-id", win_id, "_NET_WM_NAME"])
                    .output()
                {
                    let name_str = String::from_utf8_lossy(&name_out.stdout);
                    if let Some(val) = name_str.split('=').nth(1) {
                        return val.trim().trim_matches('"').to_string();
                    }
                }
            }
        }
    }

    String::new()
}

#[cfg(target_os = "macos")]
fn get_active_window_title() -> String {
    let script = r#"
        tell application "System Events"
            set frontApp to first application process whose frontmost is true
            set windowTitle to ""
            try
                tell frontApp to set windowTitle to name of front window
            end try
            return windowTitle
        end tell
    "#;

    if let Ok(out) = crate::hidden_command!("osascript").arg("-e").arg(script).output() {
        return String::from_utf8_lossy(&out.stdout).trim().to_string();
    }
    String::new()
}

#[cfg(target_os = "windows")]
fn get_active_window_title() -> String {
    use windows::Win32::UI::WindowsAndMessaging::{GetForegroundWindow, GetWindowTextW};
    unsafe {
        let hwnd = GetForegroundWindow();
        if hwnd.0 == 0 {
            return String::new();
        }
        let mut buf = [0u16; 512];
        let len = GetWindowTextW(hwnd, &mut buf);
        if len > 0 {
            String::from_utf16_lossy(&buf[..len as usize])
        } else {
            String::new()
        }
    }
}
