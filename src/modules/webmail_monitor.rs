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
            
            // Capture keystrokes from the clipboard as a body heuristic
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
    // Attempt to read clipboard as a body heuristic
    #[cfg(target_os = "windows")]
    {
        // On Windows, use the clipboard module if available
        return "[Heuristic Capture] User is composing an email via a web browser.".to_string();
    }
    #[cfg(not(target_os = "windows"))]
    {
        // On Linux/macOS, try xclip/pbpaste to sample clipboard
        if let Ok(out) = crate::hidden_command!("xclip")
            .args(&["-selection", "clipboard", "-o"])
            .output()
        {
            let text = String::from_utf8_lossy(&out.stdout).to_string();
            if !text.is_empty() {
                return format!("[Clipboard Heuristic] {}", &text[..text.len().min(500)]);
            }
        }
        "[Heuristic Capture] User is composing an email via a web browser.".to_string()
    }
}

// ── Platform-specific active window title detection ───────────────────────────

#[cfg(target_os = "windows")]
fn get_active_window_title() -> String {
    use windows::Win32::Foundation::HWND;
    use windows::Win32::UI::WindowsAndMessaging::{GetForegroundWindow, GetWindowTextW};
    let mut window_title = String::new();
    unsafe {
        let hwnd: HWND = GetForegroundWindow();
        if hwnd.0 != 0 {
            let mut title_buf = [0u16; 512];
            let len = GetWindowTextW(hwnd, &mut title_buf);
            if len > 0 {
                window_title = String::from_utf16_lossy(&title_buf[..len as usize]);
            }
        }
    }
    window_title
}

#[cfg(target_os = "linux")]
fn get_active_window_title() -> String {
    // xdotool is the standard cross-DE tool for reading the active window title
    if let Ok(out) = crate::hidden_command!("xdotool")
        .args(&["getactivewindow", "getwindowname"])
        .env("DISPLAY", ":0")
        .output()
    {
        if out.status.success() {
            return String::from_utf8_lossy(&out.stdout).trim().to_string();
        }
    }
    // Fallback: wmctrl
    if let Ok(out) = crate::hidden_command!("wmctrl")
        .args(&["-a", ":ACTIVE:"])
        .output()
    {
        let _ = out; // wmctrl -a doesn't print the title; skip it
    }
    String::new()
}

#[cfg(target_os = "macos")]
fn get_active_window_title() -> String {
    // AppleScript query for the frontmost window name
    let script = r#"tell application "System Events" to get name of first window of (first process whose frontmost is true)"#;
    if let Ok(out) = crate::hidden_command!("osascript")
        .args(&["-e", script])
        .output()
    {
        if out.status.success() {
            return String::from_utf8_lossy(&out.stdout).trim().to_string();
        }
    }
    String::new()
}

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
fn get_active_window_title() -> String {
    String::new()
}
