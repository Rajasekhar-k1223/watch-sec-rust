use std::fs::{self, OpenOptions};
use std::io::{Write, BufReader, BufRead};
use std::collections::HashMap;
use std::sync::Mutex;
use serde::{Serialize, Deserialize};
use lazy_static::lazy_static;

const REST_QUEUE_FILE: &str = "data/offline_rest.jsonl";
const MAX_QUEUE_SIZE_BYTES: u64 = 15 * 1024 * 1024; // 15 MB to prevent massive RAM spikes on parse

lazy_static! {
    static ref REST_QUEUE_LOCK: Mutex<()> = Mutex::new(());
}

#[derive(Serialize, Deserialize, Clone)]
pub struct RestPayload {
    pub url: String,
    pub method: String,
    pub headers: HashMap<String, String>,
    pub body: Vec<u8>,
}

pub fn enqueue_rest_request(payload: RestPayload) {
    let _lock = REST_QUEUE_LOCK.lock().unwrap();
    let _ = fs::create_dir_all("data");
    
    if let Ok(metadata) = fs::metadata(REST_QUEUE_FILE) {
        if metadata.len() > MAX_QUEUE_SIZE_BYTES {
            println!("[REST QUEUE] Size limit exceeded. Truncating.");
            let _ = fs::remove_file(REST_QUEUE_FILE);
        }
    }

    if let Ok(mut file) = OpenOptions::new().create(true).append(true).open(REST_QUEUE_FILE) {
        if let Ok(json) = serde_json::to_string(&payload) {
            let mut line = json;
            line.push('\n');
            let _ = file.write_all(line.as_bytes());
        }
    }
}

pub fn flush_rest_queue() -> Vec<RestPayload> {
    let _lock = REST_QUEUE_LOCK.lock().unwrap();
    let mut payloads = Vec::new();
    
    if let Ok(file) = fs::File::open(REST_QUEUE_FILE) {
        let reader = BufReader::new(file);
        for line in reader.lines() {
            if let Ok(line_str) = line {
                if let Ok(val) = serde_json::from_str::<RestPayload>(&line_str) {
                    payloads.push(val);
                }
            }
        }
    }
    
    let _ = fs::remove_file(REST_QUEUE_FILE);
    payloads
}
