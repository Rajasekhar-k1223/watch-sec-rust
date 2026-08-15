/// shadow_monitor.rs — Shadow File Monitor
/// Watches configured ShadowPaths for newly created / modified files.
/// Reads each changed file, base64-encodes it, and returns an upload payload
/// for POST /api/agents/{agent_id}/shadow-upload (or /api/events/report).
///
/// ShadowPaths are configured by the backend in the heartbeat response:
///   config.ShadowPaths = ["/home/user/Documents", "C:\\Users\\user\\Desktop"]
///
/// Uses the `notify` crate (already in Cargo.toml) for real-time file watching.

use serde_json::{json, Value};
use std::collections::VecDeque;
use std::sync::Mutex;
use std::path::Path;

/// Queue of shadow upload payloads ready to POST to backend
#[allow(dead_code)]
static UPLOAD_QUEUE: Mutex<VecDeque<Value>> = Mutex::new(VecDeque::new());

/// Start watching the given paths. Called once during agent init when
/// ShadowAuditEnabled = true. Spawns a background std::thread using notify.
pub fn start_shadow_watcher(paths: Vec<String>) {
    if paths.is_empty() {
        return;
    }
    std::thread::spawn(move || {
        watch_paths(paths);
    });
}

/// Drain the upload queue — call from main scan loop to POST queued shadow files.
pub fn drain_upload_queue() -> Vec<Value> {
    BUFFER_PUSH.lock()
        .map(|mut q| q.drain(..).collect())
        .unwrap_or_default()
}

// Alias for clarity
use std::sync::Mutex as StdMutex;
static BUFFER_PUSH: StdMutex<VecDeque<Value>> = StdMutex::new(VecDeque::new());

fn watch_paths(paths: Vec<String>) {
    use notify::{Watcher, RecursiveMode, Event, EventKind};
    use notify::event::{CreateKind, ModifyKind, DataChange};
    use std::sync::mpsc;

    let (tx, rx) = mpsc::channel::<Result<Event, notify::Error>>();

    let mut watcher = match notify::recommended_watcher(tx) {
        Ok(w) => w,
        Err(e) => {
            crate::log_msg(&format!("[ShadowMonitor] Failed to create watcher: {}", e));
            return;
        }
    };

    for path_str in &paths {
        let path = Path::new(path_str);
        if path.exists() {
            if let Err(e) = watcher.watch(path, RecursiveMode::Recursive) {
                crate::log_msg(&format!("[ShadowMonitor] Cannot watch {}: {}", path_str, e));
            } else {
                crate::log_msg(&format!("[ShadowMonitor] Watching: {}", path_str));
            }
        }
    }

    for result in rx {
        let Ok(event) = result else { continue; };

        // Only act on file create or data-write events
        let is_relevant = matches!(
            event.kind,
            EventKind::Create(CreateKind::File)
            | EventKind::Modify(ModifyKind::Data(DataChange::Content))
            | EventKind::Modify(ModifyKind::Data(DataChange::Any))
        );

        if !is_relevant { continue; }

        for path in &event.paths {
            // Skip directories, very large files (> 5 MB), temp files
            let Ok(meta) = std::fs::metadata(path) else { continue; };
            if meta.is_dir() { continue; }
            if meta.len() > 5 * 1024 * 1024 { continue; }

            let file_name = path.file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("unknown")
                .to_string();

            // Skip hidden / temp files
            if file_name.starts_with('.') || file_name.ends_with(".tmp") { continue; }

            let Ok(bytes) = std::fs::read(path) else { continue; };
            let b64 = base64_encode(&bytes);

            let payload = json!({
                "filename":   file_name,
                "path":       path.to_string_lossy(),
                "size":       meta.len(),
                "file_b64":   b64,
                "timestamp":  chrono::Utc::now().to_rfc3339(),
            });

            crate::log_msg(&format!(
                "[ShadowMonitor] Queued shadow copy: {} ({} bytes)", file_name, meta.len()
            ));

            if let Ok(mut q) = BUFFER_PUSH.lock() {
                q.push_back(payload);
            }
        }
    }
}

// ── Pure-stdlib base64 encoder (same as screenshot_capture) ─────────────────
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
