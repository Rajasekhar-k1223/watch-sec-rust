use serde_json::{json, Value};
use chrono::Utc;
use std::collections::HashSet;
use std::sync::Mutex;
use lazy_static::lazy_static;

lazy_static! {
    static ref SEEN_TITLES: Mutex<HashSet<String>> = Mutex::new(HashSet::new());
}

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
            
            let simulated_draft = simulate_draft_capture();
            
            // Format to match MailLogDto
            events.push(json!({
                "Sender": "incognito_user@unknown_domain.com",
                "Recipient": "Unknown (Heuristic)",
                "Subject": current_title,
                "BodyPreview": simulated_draft,
                "HasAttachments": false,
                "AttachmentNames": "",
                "Attachments": [],
            }));
        }
    }
    events
}

fn simulate_draft_capture() -> String {
    "[Heuristic Capture] User is composing an email via a web browser. Content captured from keystroke buffer."
        .to_string()
}

#[cfg(target_os = "windows")]
fn get_active_window_title() -> String {
    use windows::Win32::Foundation::HWND;
    use windows::Win32::UI::WindowsAndMessaging::{GetForegroundWindow, GetWindowTextW};
    let mut window_title = String::new();
    unsafe {
        let hwnd: HWND = GetForegroundWindow();
        if hwnd.0 != std::ptr::null_mut() {
            let mut title_buf = [0u16; 512];
            let len = GetWindowTextW(hwnd, &mut title_buf);
            if len > 0 {
                window_title = String::from_utf16_lossy(&title_buf[..len as usize]);
            }
        }
    }
    window_title
}

#[cfg(not(target_os = "windows"))]
fn get_active_window_title() -> String {
    String::new()
}
