use serde_json::json;

/// Platform-specific save path
#[cfg(target_os = "windows")]
const SAVE_PATH: &str = "C:\\Users\\Public\\monitorix_screenshot.png";
#[cfg(target_os = "linux")]
const SAVE_PATH: &str = "/tmp/monitorix_screenshot.png";
#[cfg(target_os = "macos")]
const SAVE_PATH: &str = "/tmp/monitorix_screenshot.png";

/// Capture the primary screen, base64-encode the PNG, and return an upload-ready payload.
/// Returns None if capture fails (e.g. no display).
pub fn capture_screenshot() -> Option<serde_json::Value> {
    let captured = do_capture();
    if !captured {
        return None;
    }

    // Read saved PNG bytes
    let img_bytes = match std::fs::read(SAVE_PATH) {
        Ok(b) if !b.is_empty() => {
            // Clean up the temporary file immediately so it doesn't consume disk space
            let _ = std::fs::remove_file(SAVE_PATH);
            b
        },
        _ => return None,
    };

    // Base64-encode using stdlib (no extra crate needed)
    let b64 = base64_encode(&img_bytes);

    // Filename: timestamp-based
    let ts = chrono::Utc::now();
    let filename = format!("screenshot_{}.png", ts.format("%Y%m%d_%H%M%S"));

    Some(json!({
        "file_b64":  b64,
        "filename":  filename,
        "timestamp": ts.to_rfc3339(),
        "is_alert":  false,
        // Internal status field for event bus (not sent to /api/screenshots/upload)
        "_EventType": "ScreenshotReady",
    }))
}

// ── Platform capture implementations ─────────────────────────────────────────

#[cfg(target_os = "linux")]
fn do_capture() -> bool {
    // Try scrot first, then gnome-screenshot as fallback
    if let Ok(out) = crate::hidden_command!("scrot")
        .env("DISPLAY", ":0")
        .arg("--overwrite")
        .arg(SAVE_PATH)
        .output()
    {
        if out.status.success() {
            return true;
        }
    }
    // Fallback: import (ImageMagick)
    if let Ok(out) = crate::hidden_command!("import")
        .args(&["-window", "root", SAVE_PATH])
        .env("DISPLAY", ":0")
        .output()
    {
        return out.status.success();
    }
    false
}

#[cfg(target_os = "macos")]
fn do_capture() -> bool {
    crate::hidden_command!("screencapture")
        .args(&["-x", SAVE_PATH])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

#[cfg(target_os = "windows")]
fn do_capture() -> bool {
    let mut s_id = 0;
    unsafe {
        let _ = windows::Win32::System::RemoteDesktop::ProcessIdToSessionId(
            std::process::id(),
            &mut s_id,
        );
    }
    
    // NATIVE APPROACH: Execute our secondary helper binary instead of powershell
    let exe_path = "C:\\Program Files\\Monitorix\\monitorix-screencapture.exe";

    if s_id == 0 {
        // Find the active interactive user (e.g. RDP session)
        let mut active_user = String::new();
        if let Ok(output) = crate::hidden_command!("cmd").args(&["/c", "query user | findstr /i active"]).output() {
            let out_str = String::from_utf8_lossy(&output.stdout);
            let parts: Vec<&str> = out_str.split_whitespace().collect();
            if !parts.is_empty() {
                active_user = parts[0].trim_start_matches('>').to_string();
            }
        }

        if active_user.is_empty() {
            return false; // No active user to capture
        }

        // Schedule and run the task in the active user's session
        let _ = crate::hidden_command!("schtasks")
            .args(&["/Create", "/TN", "MonitorixCapture", "/TR", exe_path, "/SC", "ONCE", "/ST", "00:00", "/RU", &active_user, "/IT", "/F"])
            .output();
            
        let _ = crate::hidden_command!("schtasks")
            .args(&["/Run", "/TN", "MonitorixCapture"])
            .output();
            
        std::thread::sleep(std::time::Duration::from_millis(1500)); // Allow time to capture
        
        let _ = crate::hidden_command!("schtasks")
            .args(&["/Delete", "/TN", "MonitorixCapture", "/F"])
            .output();
            
        return true;
    }

    // Interactive user session -> run helper directly
    let out = crate::hidden_command!(exe_path).output();
    out.map(|o| o.status.success()).unwrap_or(false)
}

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
fn do_capture() -> bool { false }

// ── Pure-stdlib base64 encoder (RFC 4648) ────────────────────────────────────
// Avoids adding the `base64` crate dependency.

const B64_CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

pub fn base64_encode(input: &[u8]) -> String {
    let mut out = String::with_capacity(((input.len() + 2) / 3) * 4);
    for chunk in input.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = if chunk.len() > 1 { chunk[1] as u32 } else { 0 };
        let b2 = if chunk.len() > 2 { chunk[2] as u32 } else { 0 };
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(B64_CHARS[((n >> 18) & 0x3F) as usize] as char);
        out.push(B64_CHARS[((n >> 12) & 0x3F) as usize] as char);
        out.push(if chunk.len() > 1 { B64_CHARS[((n >> 6) & 0x3F) as usize] as char } else { '=' });
        out.push(if chunk.len() > 2 { B64_CHARS[(n & 0x3F) as usize] as char } else { '=' });
    }
    out
}
