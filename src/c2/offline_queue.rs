use std::fs::{self, OpenOptions};
use std::io::{Write, BufReader, BufRead};
use serde_json::Value;
use std::sync::Mutex;
use lazy_static::lazy_static;

const QUEUE_FILE: &str = "data/offline_events.jsonl";
const MAX_QUEUE_SIZE_BYTES: u64 = 100 * 1024 * 1024; // 100 MB

lazy_static! {
    static ref QUEUE_LOCK: Mutex<()> = Mutex::new(());
}

pub fn enqueue_event(event: &Value) {
    let _lock = QUEUE_LOCK.lock().unwrap();
    let _ = fs::create_dir_all("data");
    
    // Check size limit
    if let Ok(metadata) = fs::metadata(QUEUE_FILE) {
        if metadata.len() > MAX_QUEUE_SIZE_BYTES {
            // Simplified FIFO: Clear the file if it exceeds limit to prevent disk exhaustion
            // A production implementation would truncate the oldest lines.
            println!("[OFFLINE QUEUE] Size limit exceeded (100MB). Truncating queue.");
            let _ = fs::remove_file(QUEUE_FILE);
        }
    }

    if let Ok(mut file) = OpenOptions::new().create(true).append(true).open(QUEUE_FILE) {
        let mut line = event.to_string();
        line.push('\n');
        let _ = file.write_all(line.as_bytes());
    }
}

pub fn flush_queue() -> Vec<Value> {
    let _lock = QUEUE_LOCK.lock().unwrap();
    let mut events = Vec::new();
    
    if let Ok(file) = fs::File::open(QUEUE_FILE) {
        let reader = BufReader::new(file);
        for line in reader.lines() {
            if let Ok(line_str) = line {
                if let Ok(val) = serde_json::from_str(&line_str) {
                    events.push(val);
                }
            }
        }
    }
    
    // Clear the queue after reading
    let _ = fs::remove_file(QUEUE_FILE);
    events
}
