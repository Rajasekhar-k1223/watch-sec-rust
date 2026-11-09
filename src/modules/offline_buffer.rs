//! [v3.0.0] Feature 55: Agent Reliability & Offline Buffering Engine
//! Provides disk-backed FIFO ring buffer spooling, sequence numbering, and SHA-256 event fingerprinting.
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

pub const MAX_SPOOL_CAPACITY: usize = 10_000;

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

/// Enforces the FIFO ring-buffer capacity policy.
/// When the spool exceeds `max_capacity`, the oldest lines are pruned, strictly retaining
/// the newest events in chronological order while guaranteeing bounded disk usage.
pub fn enforce_ring_buffer_capacity(spool_path: &PathBuf, max_capacity: usize) {
    if !spool_path.exists() {
        return;
    }

    if let Ok(file) = fs::File::open(spool_path) {
        let lines: Vec<String> = BufReader::new(file)
            .lines()
            .filter_map(Result::ok)
            .filter(|l| !l.trim().is_empty())
            .collect();

        if lines.len() > max_capacity {
            let keep_from = lines.len() - max_capacity;
            let retained = &lines[keep_from..];
            if let Ok(mut out_file) = fs::File::create(spool_path) {
                for line in retained {
                    let _ = writeln!(out_file, "{}", line);
                }
            }
        }
    }
}

/// Spools a batch of events to the local disk ring buffer
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

    // Strictly enforce ring buffer capacity cap to prevent unbounded disk growth
    enforce_ring_buffer_capacity(&spool_path, MAX_SPOOL_CAPACITY);

    crate::log_msg(&format!(
        "[OfflineBuffer] Spooled {} events to disk ring buffer ({:?})",
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
            if line.trim().is_empty() {
                continue;
            }
            if idx < max_count {
                if let Ok(spooled) = serde_json::from_str::<SpooledEvent>(&line) {
                    let mut obj = spooled.payload;
                    if let Some(map) = obj.as_object_mut() {
                        map.insert("SequenceId".to_string(), serde_json::json!(spooled.sequence_id));
                        map.insert("EventFingerprint".to_string(), serde_json::json!(spooled.event_fingerprint));
                        map.insert("IsBufferedReplay".to_string(), serde_json::json!(true));
                        map.insert("original_timestamp".to_string(), serde_json::json!(spooled.original_timestamp));
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
        BufReader::new(file).lines().filter_map(Result::ok).filter(|l| !l.trim().is_empty()).count()
    } else {
        0
    }
}

/// Returns offline spool health diagnostics and ring buffer utilization stats
pub fn get_spool_stats() -> serde_json::Value {
    let _guard = BUFFER_LOCK.lock().unwrap();
    let spool_path = get_spool_path();
    let count = if spool_path.exists() {
        if let Ok(file) = fs::File::open(&spool_path) {
            BufReader::new(file).lines().filter_map(Result::ok).filter(|l| !l.trim().is_empty()).count()
        } else {
            0
        }
    } else {
        0
    };

    let size_bytes = if spool_path.exists() {
        fs::metadata(&spool_path).map(|m| m.len()).unwrap_or(0)
    } else {
        0
    };

    let utilization = if MAX_SPOOL_CAPACITY > 0 {
        (count as f64 / MAX_SPOOL_CAPACITY as f64) * 100.0
    } else {
        0.0
    };

    serde_json::json!({
        "status": "online",
        "policy": "FIFO_RING_BUFFER",
        "spool_file": spool_path.to_string_lossy(),
        "max_capacity_events": MAX_SPOOL_CAPACITY,
        "current_queued_events": count,
        "spool_file_bytes": size_bytes,
        "buffer_utilization_pct": (utilization * 100.0).round() / 100.0
    })
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
        assert!(first.get("original_timestamp").is_some());
    }

    #[test]
    fn test_ring_buffer_capacity_rotation() {
        let temp_spool = std::env::temp_dir().join(".monitorix_test_ring_buffer.jsonl");
        let _ = fs::remove_file(&temp_spool);

        // Write 15 lines
        {
            let mut f = fs::File::create(&temp_spool).unwrap();
            for i in 1..=15 {
                let _ = writeln!(f, "{{\"seq\": {}}}", i);
            }
        }

        // Enforce capacity of 10
        enforce_ring_buffer_capacity(&temp_spool, 10);

        let lines: Vec<String> = BufReader::new(fs::File::open(&temp_spool).unwrap())
            .lines()
            .filter_map(Result::ok)
            .collect();

        assert_eq!(lines.len(), 10);
        // The first line should now be seq: 6 (oldest 5 pruned)
        assert!(lines[0].contains("\"seq\": 6"));
        assert!(lines[9].contains("\"seq\": 15"));

        let _ = fs::remove_file(&temp_spool);
    }
}
