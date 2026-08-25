use serde_json::json;

use lazy_static::lazy_static;
use std::sync::Mutex;
use std::time::Instant;

lazy_static! {
    static ref LAST_WINDOW: Mutex<Option<(String, String, Instant)>> = Mutex::new(None);
}

pub async fn get_active_window() -> Option<serde_json::Value> {
    let mut window_title = String::new();
    #[allow(unused_assignments)]
    let mut process_name = String::new();

    #[allow(unused_mut)]
    let mut url = String::new();

    #[cfg(unix)]
    {
        // Try to use xdotool if available (Linux X11)
        if let Ok(Ok(output)) = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            tokio::process::Command::new("xdotool").arg("getactivewindow").arg("getwindowname").output()
        ).await {
            window_title = String::from_utf8_lossy(&output.stdout).trim().to_string();
            process_name = "Unknown(Linux)".to_string();
        }
        
        // For macOS, xdotool isn't standard. Use osascript to get the active app.
        if cfg!(target_os = "macos") && window_title.is_empty() {
            if let Ok(Ok(output)) = tokio::time::timeout(
                std::time::Duration::from_secs(5),
                tokio::process::Command::new("osascript")
                    .arg("-e")
                    .arg("tell application \"System Events\" to get name of first application process whose frontmost is true")
                    .output()
            ).await {
                window_title = String::from_utf8_lossy(&output.stdout).trim().to_string();
                process_name = window_title.clone();
            }
        }

        // Check for Linux/Mac Lock Screens
        let lower_title = window_title.to_lowercase();
        if lower_title.contains("lock") || lower_title.contains("screensaver") || lower_title == "loginwindow" {
            // Force empty so it triggers the "System Idle" logic below
            window_title = String::new();
        }
    }

    #[cfg(windows)]
    {
        use windows::Win32::Foundation::{HWND, MAX_PATH};
        use windows::Win32::UI::WindowsAndMessaging::{GetForegroundWindow, GetWindowTextW, GetWindowThreadProcessId};
        use windows::Win32::System::Threading::{OpenProcess, QueryFullProcessImageNameW, PROCESS_QUERY_LIMITED_INFORMATION};
        use std::os::windows::ffi::OsStringExt;
        use std::ffi::OsString;

        unsafe {
            let hwnd: HWND = GetForegroundWindow();
            if hwnd.0 != std::ptr::null_mut() {
                let mut title_buf = [0u16; 512];
                let len = GetWindowTextW(hwnd, &mut title_buf);
                if len > 0 {
                    window_title = String::from_utf16_lossy(&title_buf[..len as usize]);
                }

                let mut pid: u32 = 0;
                GetWindowThreadProcessId(hwnd, Some(&mut pid));
                
                if pid > 0 {
                    if let Ok(process_handle) = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) {
                        let mut exe_path_buf = [0u16; MAX_PATH as usize];
                        let mut path_len = MAX_PATH;
                        if QueryFullProcessImageNameW(process_handle, windows::Win32::System::Threading::PROCESS_NAME_FORMAT(0), windows::core::PWSTR(exe_path_buf.as_mut_ptr()), &mut path_len).is_ok() {
                            let full_path = OsString::from_wide(&exe_path_buf[..path_len as usize]).to_string_lossy().into_owned();
                            if let Some(name) = std::path::Path::new(&full_path).file_name() {
                                process_name = name.to_string_lossy().into_owned();
                            } else {
                                process_name = full_path;
                            }
                        }
                        let _ = windows::Win32::Foundation::CloseHandle(process_handle);
                    }
                }
            }
        }
    }

    if window_title.is_empty() || process_name.to_lowercase() == "logonui.exe" {
        // [FIX] When the system is locked or Secure Desktop is active, GetForegroundWindow() returns NULL,
        // or it may return the LogonUI.exe process.
        // Instead of ignoring this and crediting the locked time to the last active application, 
        // we explicitly track it as "System Idle" to close the previous app's duration.
        window_title = "System Idle".to_string();
        process_name = "System".to_string();
    }

    let now = Instant::now();
    let mut last_window_guard = LAST_WINDOW.lock().unwrap();
    
    // Check if the window changed
    if let Some((last_title, last_process, last_time)) = last_window_guard.as_ref() {
        if last_title == &window_title && last_process == &process_name {
            // Window hasn't changed, do not emit a new event yet
            return None;
        }
        
        // Window changed, calculate duration for the previous window
        let duration = now.duration_since(*last_time).as_secs_f64();
        let payload = Some(json!({
            "ActivityType": "AppFocus",
            "ProcessName": last_process,
            "WindowTitle": last_title,
            "Url": if url.is_empty() { serde_json::Value::Null } else { serde_json::Value::String(url.clone()) },
            "DurationSeconds": duration,
        }));
        
        // Update the tracked window to the new one
        *last_window_guard = Some((window_title, process_name, now));
        return payload;
    } else {
        // First time seeing a window, just start tracking it
        *last_window_guard = Some((window_title, process_name, now));
        return None;
    }
}
