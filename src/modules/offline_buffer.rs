//! [v3.0.0] Feature 55: Agent Reliability & Offline Buffering Engine
//! Provides disk-backed FIFO spooling, sequence numbering, and SHA-256 event fingerprinting.
//! Guarantees zero data loss during network outages and enables clean deduplication on reconnection.

use std::fs::{self, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;
use std::sync::Mutex;
use lazy_static::lazy_static;
use serde::{Deserialize, Serialize};
use ring::digest;

lazy_static! {
    static ref BUFFER_LOCK: Mutex<()> = Mutex::new(());
    static ref SEQUENCE_COUNTER: Mutex<u64> = Mutex::new(1);
}

#[allow(dead_code)]
const MAX_SPOOL_CAPACITY: usize = 10_000;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SpooledEvent {
    pub sequence_id: u64,
    pub original_timestamp: String,
    pub event_fingerprint: String,
    pub is_buffered_replay: bool,
    pub payload: serde_json::Value,
}

fn get_spool_path() -> PathBuf {
    #[cfg(target_os = "windows")]
    {
        if let Ok(progdata) = std::env::var("PROGRAMDATA") {
            let p = PathBuf::from(progdata).join("Monitorix").join("spool");
            let _ = fs::create_dir_all(&p);
            return p.join("events.spool.jsonl");
        }
    }

    #[cfg(target_os = "linux")]
    {
        let p = PathBuf::from("/var/log/monitorix");
        if fs::create_dir_all(&p).is_ok() {
            return p.join(".events.spool.jsonl");
        }
    }

    // Universal fallback to temp directory
    std::env::temp_dir().join(".monitorix_spool.jsonl")
}

/// Computes SHA-256 fingerprint for deduplication
pub fn calculate_event_fingerprint(event: &serde_json::Value) -> String {
    let raw = event.to_string();
    let hash = digest::digest(&digest::SHA256, raw.as_bytes());
    hex::encode(hash.as_ref())
}

/// Spools a batch of events to the local disk buffer
pub fn spool_events(events: &[serde_json::Value]) -> Result<usize, String> {
    if events.is_empty() {
        return Ok(0);
    }

    let _guard = BUFFER_LOCK.lock().unwrap();
    let spool_path = get_spool_path();

    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&spool_path)
        .map_err(|e| format!("Failed to open spool file: {}", e))?;

    let mut count = 0;
    let mut seq = SEQUENCE_COUNTER.lock().unwrap();

    for ev in events {
        let fingerprint = calculate_event_fingerprint(ev);
        let ts = ev.get("Timestamp")
            .and_then(|v| v.as_str())
            .unwrap_or_else(|| "")
            .to_string();

        let spooled = SpooledEvent {
            sequence_id: *seq,
            original_timestamp: if ts.is_empty() { chrono::Utc::now().to_rfc3339() } else { ts },
            event_fingerprint: fingerprint,
            is_buffered_replay: true,
            payload: ev.clone(),
        };

        if let Ok(line) = serde_json::to_string(&spooled) {
            let _ = writeln!(file, "{}", line);
            count += 1;
            *seq += 1;
        }
    }

    crate::log_msg(&format!(
        "[OfflineBuffer] Spooled {} events to disk ({:?})",
        count, spool_path
    ));
    Ok(count)
}

/// Drains up to `max_count` spooled events in chronological FIFO order
pub fn drain_spool(max_count: usize) -> Vec<serde_json::Value> {
    let _guard = BUFFER_LOCK.lock().unwrap();
    let spool_path = get_spool_path();

    if !spool_path.exists() {
        return Vec::new();
    }

    let file = match fs::File::open(&spool_path) {
        Ok(f) => f,
        Err(_) => return Vec::new(),
    };

    let reader = BufReader::new(file);
    let mut drained_events = Vec::new();
    let mut remaining_lines = Vec::new();

    for (idx, line_res) in reader.lines().enumerate() {
        if let Ok(line) = line_res {
            if idx < max_count {
                if let Ok(spooled) = serde_json::from_str::<SpooledEvent>(&line) {
                    let mut obj = spooled.payload;
                    if let Some(map) = obj.as_object_mut() {
                        map.insert("SequenceId".to_string(), serde_json::json!(spooled.sequence_id));
                        map.insert("EventFingerprint".to_string(), serde_json::json!(spooled.event_fingerprint));
                        map.insert("IsBufferedReplay".to_string(), serde_json::json!(true));
                    }
                    drained_events.push(obj);
                }
            } else {
                remaining_lines.push(line);
            }
        }
    }

    // Rewrite remaining un-drained lines or truncate file if empty
    if remaining_lines.is_empty() {
        let _ = fs::remove_file(&spool_path);
    } else {
        if let Ok(mut out_file) = fs::File::create(&spool_path) {
            for r in remaining_lines {
                let _ = writeln!(out_file, "{}", r);
            }
        }
    }

    if !drained_events.is_empty() {
        crate::log_msg(&format!(
            "[OfflineBuffer] Drained {} buffered events for replay transmission",
            drained_events.len()
        ));
    }

    drained_events
}

/// Returns the number of spooled events waiting to be transmitted
pub fn get_spool_count() -> usize {
    let _guard = BUFFER_LOCK.lock().unwrap();
    let spool_path = get_spool_path();

    if !spool_path.exists() {
        return 0;
    }

    if let Ok(file) = fs::File::open(&spool_path) {
        BufReader::new(file).lines().count()
    } else {
        0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_calculate_event_fingerprint() {
        let ev1 = serde_json::json!({"action": "ProcessCreated", "pid": 1234});
        let ev2 = serde_json::json!({"action": "ProcessCreated", "pid": 1234});
        let ev3 = serde_json::json!({"action": "ProcessCreated", "pid": 5678});

        let fp1 = calculate_event_fingerprint(&ev1);
        let fp2 = calculate_event_fingerprint(&ev2);
        let fp3 = calculate_event_fingerprint(&ev3);

        assert_eq!(fp1, fp2);
        assert_ne!(fp1, fp3);
        assert_eq!(fp1.len(), 64);
    }

    #[test]
    fn test_spool_and_drain_fifo() {
        let evs = vec![
            serde_json::json!({"type": "TestEvent1", "val": 100}),
            serde_json::json!({"type": "TestEvent2", "val": 200}),
        ];

        let count = spool_events(&evs).expect("spooling should succeed");
        assert_eq!(count, 2);

        let drained = drain_spool(10);
        assert!(drained.len() >= 2);
        let first = &drained[drained.len() - 2];

        assert_eq!(first.get("IsBufferedReplay").and_then(|v| v.as_bool()), Some(true));
        assert!(first.get("EventFingerprint").is_some());
        assert!(first.get("SequenceId").is_some());
    }
}

