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
pub fn capture_gdi_direct() -> bool {
    unsafe {
        let hwnd = windows::Win32::UI::WindowsAndMessaging::GetDesktopWindow();
        let hdc_screen = windows::Win32::Graphics::Gdi::GetDC(hwnd);
        if hdc_screen.is_invalid() {
            return false;
        }
        let hdc_mem = windows::Win32::Graphics::Gdi::CreateCompatibleDC(hdc_screen);
        if hdc_mem.is_invalid() {
            let _ = windows::Win32::Graphics::Gdi::ReleaseDC(hwnd, hdc_screen);
            return false;
        }

        let width = windows::Win32::UI::WindowsAndMessaging::GetSystemMetrics(windows::Win32::UI::WindowsAndMessaging::SM_CXSCREEN);
        let height = windows::Win32::UI::WindowsAndMessaging::GetSystemMetrics(windows::Win32::UI::WindowsAndMessaging::SM_CYSCREEN);

        if width <= 0 || height <= 0 {
            let _ = windows::Win32::Graphics::Gdi::DeleteDC(hdc_mem);
            let _ = windows::Win32::Graphics::Gdi::ReleaseDC(hwnd, hdc_screen);
            return false;
        }

        let hbm = windows::Win32::Graphics::Gdi::CreateCompatibleBitmap(hdc_screen, width, height);
        if hbm.is_invalid() {
            let _ = windows::Win32::Graphics::Gdi::DeleteDC(hdc_mem);
            let _ = windows::Win32::Graphics::Gdi::ReleaseDC(hwnd, hdc_screen);
            return false;
        }

        let h_old = windows::Win32::Graphics::Gdi::SelectObject(hdc_mem, hbm);

        // Copy screen to memory DC
        let _ = windows::Win32::Graphics::Gdi::BitBlt(
            hdc_mem, 0, 0, width, height, hdc_screen, 0, 0, windows::Win32::Graphics::Gdi::SRCCOPY,
        );

        // Get bitmap bits
        let mut bmi: windows::Win32::Graphics::Gdi::BITMAPINFO = std::mem::zeroed();
        bmi.bmiHeader.biSize = std::mem::size_of::<windows::Win32::Graphics::Gdi::BITMAPINFOHEADER>() as u32;
        bmi.bmiHeader.biWidth = width;
        bmi.bmiHeader.biHeight = -height; // Top-down
        bmi.bmiHeader.biPlanes = 1;
        bmi.bmiHeader.biBitCount = 32;
        bmi.bmiHeader.biCompression = windows::Win32::Graphics::Gdi::BI_RGB.0 as u32;

        let mut buffer: Vec<u8> = vec![0; (width * height * 4) as usize];
        let lines = windows::Win32::Graphics::Gdi::GetDIBits(
            hdc_screen,
            hbm,
            0,
            height as u32,
            Some(buffer.as_mut_ptr() as *mut _),
            &mut bmi,
            windows::Win32::Graphics::Gdi::DIB_RGB_COLORS,
        );

        // Cleanup GDI
        let _ = windows::Win32::Graphics::Gdi::SelectObject(hdc_mem, h_old);
        let _ = windows::Win32::Graphics::Gdi::DeleteObject(hbm);
        let _ = windows::Win32::Graphics::Gdi::DeleteDC(hdc_mem);
        let _ = windows::Win32::Graphics::Gdi::ReleaseDC(hwnd, hdc_screen);

        if lines <= 0 {
            return false;
        }

        // Convert BGRA to RGBA for image crate
        for chunk in buffer.chunks_exact_mut(4) {
            let b = chunk[0];
            let r = chunk[2];
            chunk[0] = r;
            chunk[2] = b;
            chunk[3] = 255;
        }

        if let Some(img) = image::ImageBuffer::<image::Rgba<u8>, _>::from_raw(width as u32, height as u32, buffer) {
            img.save(SAVE_PATH).is_ok()
        } else {
            false
        }
    }
}

#[cfg(target_os = "windows")]
fn capture_powershell() -> bool {
    let script = r#"
Add-Type -AssemblyName System.Windows.Forms,System.Drawing
$s = [System.Windows.Forms.Screen]::PrimaryScreen.Bounds
$b = New-Object System.Drawing.Bitmap $s.Width, $s.Height
$g = [System.Drawing.Graphics]::FromImage($b)
$g.CopyFromScreen($s.Location, [System.Drawing.Point]::Empty, $s.Size)
$b.Save('C:\Users\Public\monitorix_screenshot.png')
$g.Dispose()
$b.Dispose()
"#;
    let out = crate::hidden_command!("powershell")
        .args(&["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", script])
        .output();
    out.map(|o| o.status.success()).unwrap_or(false) && std::path::Path::new(SAVE_PATH).exists()
}

#[cfg(target_os = "windows")]
fn do_capture() -> bool {
    // 1. Direct in-process Win32 GDI capture (ultra-fast, native, zero dependencies)
    if capture_gdi_direct() {
        return true;
    }

    // 2. Fallback to PowerShell Screen Capture (standard on all Windows versions)
    if capture_powershell() {
        return true;
    }

    // 3. Fallback: check helper binary if available
    let helper_locations = [
        std::env::current_exe().ok().and_then(|p| p.parent().map(|d| d.join("monitorix-screencapture.exe"))),
        Some(std::path::PathBuf::from("C:\\Program Files\\Monitorix\\monitorix-screencapture.exe")),
    ];

    for loc in helper_locations.iter().flatten() {
        if loc.exists() {
            let out = crate::hidden_command!(loc.to_str().unwrap_or("")).output();
            if out.map(|o| o.status.success()).unwrap_or(false) && std::path::Path::new(SAVE_PATH).exists() {
                return true;
            }
        }
    }

    // 4. Fallback for Session 0 (system service) -> execute via schtasks in active user's desktop session
    let mut s_id = 0;
    unsafe {
        let _ = windows::Win32::System::RemoteDesktop::ProcessIdToSessionId(
            std::process::id(),
            &mut s_id,
        );
    }

    if s_id == 0 {
        if let Ok(output) = crate::hidden_command!("cmd").args(&["/c", "query user | findstr /i active"]).output() {
            let out_str = String::from_utf8_lossy(&output.stdout);
            let parts: Vec<&str> = out_str.split_whitespace().collect();
            if !parts.is_empty() {
                let active_user = parts[0].trim_start_matches('>');
                if let Ok(current_exe) = std::env::current_exe() {
                    let exe_str = current_exe.to_string_lossy().to_string();
                    let _ = crate::hidden_command!("schtasks")
                        .args(&["/Create", "/TN", "MonitorixCapture", "/TR", &format!("\"{}\" --screencapture", exe_str), "/SC", "ONCE", "/ST", "00:00", "/RU", active_user, "/IT", "/F"])
                        .output();
                    let _ = crate::hidden_command!("schtasks").args(&["/Run", "/TN", "MonitorixCapture"]).output();
                    std::thread::sleep(std::time::Duration::from_millis(1500));
                    let _ = crate::hidden_command!("schtasks").args(&["/Delete", "/TN", "MonitorixCapture", "/F"]).output();
                    if std::path::Path::new(SAVE_PATH).exists() {
                        return true;
                    }
                }
            }
        }
    }

    false
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
